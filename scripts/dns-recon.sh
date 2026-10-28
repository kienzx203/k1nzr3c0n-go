#!/usr/bin/env bash
# dns-recon.sh — red-team DNS reconnaissance via dig (no heavy deps).
#
# Modules (all on by default):
#   enum      NS/SOA + A/AAAA/MX/CNAME + TXT/SPF(expanded)/DMARC/CAA/SRV
#   fp        DNS server fingerprint (version.bind / hostname.bind)
#   axfr      zone transfer against every NS (the jackpot if misconfigured)
#   nsec      DNSSEC check -> NSEC zone-walk (full zone) / flag NSEC3 for cracking
#   brute     wordlist brute-force — built-in ~200 devops/internal words MERGED
#             with -w FILE (deduped); --no-builtin uses only the file
#   perm      permutations of discovered hosts (dev-/stg-/test-/-staging/numbered)
#   resolve   resolve every discovered host -> IP (NSEC/AXFR names carry no IP);
#             flags hosts pointing to internal RFC1918 IPs (split-horizon leak)
#   ptr       reverse DNS on discovered IPs + /24 neighbours
#   svc       ACTIVE (opt-in: --svc) — harvest hostnames from HTTP/TLS of the
#             discovered IPs: cert SAN, redirect Location, Docker-Registry /v2/
#             Bearer realm. Finds hosts that have NO DNS record at all.
#   classify  flag RFC1918/internal IPs leaked in public DNS + split-horizon,
#             and derive internal /24 ranges from them (internal_subnets.txt)
#
# Usage:
#   ./dns-recon.sh <domain> [-w wordlist] [-o outdir] [-t threads]
#                  [-r resolver] [--only mod1,mod2] [--skip mod1,mod2]
#                  [--no-builtin] [--quiet]
#   -w merges the file with the built-in words (deduped); --no-builtin = file only
#
# Output: <outdir>/  subdomains.txt  ips.txt  internal_ips.txt  internal_subnets.txt
#                    internal_hosts.txt  resolved.txt  zone_nsec.txt  ptr.txt
#                    records.txt  interesting.txt  summary.txt
#
# Authorized testing only. Zone walking / brute-force touch the target's DNS.
set -uo pipefail

# ── args ──────────────────────────────────────────────────────────────────────
DOMAIN=""; OUT=""; WORDLIST=""; THREADS=40; RESOLVER="1.1.1.1"
ONLY=""; SKIP=""; QUIET=0; NO_BUILTIN=0; DO_SVC=0
RESOLVERS_PUB="1.1.1.1 8.8.8.8 9.9.9.9"
usage() { grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    -w) WORDLIST="$2"; shift 2;;
    -o) OUT="$2"; shift 2;;
    -t) THREADS="$2"; shift 2;;
    -r) RESOLVER="$2"; RESOLVERS_PUB="$2"; shift 2;;
    --only) ONLY="$2"; shift 2;;
    --skip) SKIP="$2"; shift 2;;
    --quiet) QUIET=1; shift;;
    --no-builtin) NO_BUILTIN=1; shift;;   # with -w: use ONLY the file, skip built-in words
    --svc) DO_SVC=1; shift;;              # enable ACTIVE service-layer harvest (HTTP/TLS probes)
    -h|--help) usage 0;;
    -*) echo "unknown flag: $1" >&2; usage 1;;
    *) DOMAIN="$1"; shift;;
  esac
done
[ -n "$DOMAIN" ] || usage 1
command -v dig >/dev/null || { echo "dig not found (apt install dnsutils)" >&2; exit 1; }
DOMAIN="${DOMAIN#*://}"; DOMAIN="${DOMAIN%%/*}"; DOMAIN="${DOMAIN%.}"
OUT="${OUT:-dnsrecon-$DOMAIN}"; mkdir -p "$OUT"

# ── colors / logging ──────────────────────────────────────────────────────────
if [ -t 1 ] && [ "$QUIET" = 0 ]; then
  C_H=$'\e[1;36m'; C_OK=$'\e[1;32m'; C_WARN=$'\e[1;33m'; C_BAD=$'\e[1;31m'; C_DIM=$'\e[2m'; C_0=$'\e[0m'
else C_H=; C_OK=; C_WARN=; C_BAD=; C_DIM=; C_0=; fi
hdr()  { printf '\n%s══ %s %s\n' "$C_H" "$*" "$C_0"; }
ok()   { printf '  %s+%s %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$C_0" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$C_BAD" "$C_0" "$*"; }
note() { [ "$QUIET" = 1 ] || printf '  %s%s%s\n' "$C_DIM" "$*" "$C_0"; }

want() { # want <module>
  local m="$1"
  [ -n "$ONLY" ] && { [[ ",$ONLY," == *",$m,"* ]] && return 0 || return 1; }
  [ -n "$SKIP" ] && { [[ ",$SKIP," == *",$m,"* ]] && return 1; }
  return 0
}

# ── helpers ───────────────────────────────────────────────────────────────────
D="$DOMAIN"
RE_IP4='([0-9]{1,3}\.){3}[0-9]{1,3}'
RE_INTERNAL='^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|127\.)'
# scope regex: a host that equals D or ends in .D (dots escaped)
DE="${D//./\\.}"
inscope() { grep -iE "(^|\.)${DE}\$"; }

add_subs()  { tr 'A-Z' 'a-z' | sed 's/\.$//; s/^\*\.//; s/^[._]*//' | inscope | sort -u >> "$OUT/.subs"; }
add_ips()   { grep -oE "$RE_IP4" | sort -u >> "$OUT/.ips"; }

: > "$OUT/.subs"; : > "$OUT/.ips"; : > "$OUT/records.txt"
NS_LIST=""; NS_IPS=""

# ── enum: NS/SOA + records ────────────────────────────────────────────────────
enum() {
  hdr "Records — $D"
  NS_LIST=$(dig +short NS "$D" @"$RESOLVER" 2>/dev/null | sed 's/\.$//' | sort -u)
  [ -n "$NS_LIST" ] && ok "NS: $(echo $NS_LIST | tr '\n' ' ')"
  { echo "# NS"; echo "$NS_LIST"; } >> "$OUT/records.txt"
  for ns in $NS_LIST; do
    nsip=$(dig +short A "$ns" @"$RESOLVER" 2>/dev/null | grep -oE "$RE_IP4" | head -1)
    [ -n "$nsip" ] && NS_IPS="$NS_IPS $nsip"
    echo "$ns" | add_subs
  done
  local soa; soa=$(dig +short SOA "$D" @"$RESOLVER" 2>/dev/null)
  [ -n "$soa" ] && { note "SOA: $soa"; echo "# SOA: $soa" >> "$OUT/records.txt"; }

  for rr in A AAAA MX CNAME NS CAA; do
    local v; v=$(dig +short "$rr" "$D" @"$RESOLVER" 2>/dev/null)
    [ -n "$v" ] && { echo "# $rr"; echo "$v"; } >> "$OUT/records.txt"
  done
  dig +short A "$D" @"$RESOLVER" 2>/dev/null | add_ips
  dig +short MX "$D" @"$RESOLVER" 2>/dev/null | awk '{print $2}' | add_subs

  # TXT / SPF (expand includes, 2 levels) / DMARC / DKIM common selectors
  hdr "TXT / SPF / DMARC"
  local txt; txt=$(dig +short TXT "$D" @"$RESOLVER" 2>/dev/null)
  [ -n "$txt" ] && { echo "$txt" | sed 's/^/  /'; echo "# TXT"; echo "$txt"; } >> "$OUT/records.txt"
  echo "$txt" | grep -qi 'v=spf1' && { warn "SPF present — expanding includes"; expand_spf "$D" 2 | sed 's/^/    /'; }
  local dmarc; dmarc=$(dig +short TXT "_dmarc.$D" @"$RESOLVER" 2>/dev/null)
  [ -n "$dmarc" ] && { ok "DMARC: $dmarc"; echo "# DMARC: $dmarc" >> "$OUT/records.txt"; }
  for sel in default google selector1 selector2 k1 dkim mail smtp; do
    local dk; dk=$(dig +short TXT "$sel._domainkey.$D" @"$RESOLVER" 2>/dev/null)
    [ -n "$dk" ] && ok "DKIM selector '$sel' exists"
  done
  # common SRV
  for s in _sip._tcp _sip._udp _sips._tcp _ldap._tcp _kerberos._tcp _autodiscover._tcp _xmpp-server._tcp; do
    local sv; sv=$(dig +short SRV "$s.$D" @"$RESOLVER" 2>/dev/null)
    [ -n "$sv" ] && { ok "SRV $s: $sv"; echo "$sv" | awk '{print $4}' | add_subs; }
  done
}
expand_spf() {
  local name="$1" depth="${2:-2}"; [ "$depth" -le 0 ] && return
  dig +short TXT "$name" @"$RESOLVER" 2>/dev/null | tr -d '"' | tr ' ' '\n' | while read -r tok; do
    case "$tok" in
      ip4:*) echo "${tok#ip4:}";;
      ip6:*) echo "${tok#ip6:}";;
      include:*|redirect=*) local inc="${tok#include:}"; inc="${inc#redirect=}"; echo "include -> $inc"; expand_spf "$inc" $((depth-1));;
    esac
  done
}

# ── fingerprint ───────────────────────────────────────────────────────────────
fp() {
  hdr "DNS server fingerprint"
  for ns in $NS_LIST; do
    local v; v=$(dig +short CH TXT version.bind "@$ns" 2>/dev/null | tr -d '"')
    [ -n "$v" ] && warn "$ns version.bind: $v"
    local hn; hn=$(dig +short CH TXT hostname.bind "@$ns" 2>/dev/null | tr -d '"')
    [ -n "$hn" ] && note "$ns hostname.bind: $hn"
  done
}

# ── AXFR ──────────────────────────────────────────────────────────────────────
axfr() {
  hdr "AXFR zone transfer"
  local hit=0
  for ns in $NS_LIST; do
    local tgt="$ns" nsip; nsip=$(dig +short A "$ns" @"$RESOLVER" 2>/dev/null | grep -oE "$RE_IP4" | head -1)
    [ -n "$nsip" ] && tgt="$nsip"
    local z; z=$(dig +time=6 +tries=1 AXFR "$D" "@$tgt" 2>/dev/null)
    local n; n=$(printf '%s\n' "$z" | grep -cE "[[:space:]]IN[[:space:]]")
    if [ "${n:-0}" -gt 2 ]; then
      bad "AXFR SUCCEEDED on $ns ($n records) — FULL ZONE DISCLOSURE"
      printf '%s\n' "$z" | awk '{print $1}' | add_subs
      printf '%s\n' "$z" | grep -oE "$RE_IP4" | add_ips
      printf '%s\n' "$z" > "$OUT/axfr_$ns.txt"; hit=1
    else
      note "$ns: refused"
    fi
  done
  [ "$hit" = 1 ] || ok "no NS allowed AXFR (expected)"
}

# ── NSEC / DNSSEC zone walk ───────────────────────────────────────────────────
nsec() {
  hdr "DNSSEC / NSEC zone walk"
  local dk; dk=$(dig +short DNSKEY "$D" @"$RESOLVER" 2>/dev/null)
  [ -z "$dk" ] && { ok "no DNSSEC — NSEC walk N/A (use brute instead)"; return; }
  if [ -n "$(dig +short NSEC3PARAM "$D" @"$RESOLVER" 2>/dev/null)" ]; then
    warn "DNSSEC uses NSEC3 (hashed) — walk needs cracking: nsec3map / nsec3walker"
    return
  fi
  local nsip; nsip=$(echo "$NS_IPS" | awk '{print $1}')
  [ -z "$nsip" ] && nsip="$RESOLVER"
  warn "DNSSEC with plain NSEC detected — walking zone via $nsip"
  local cur="$D." i next n=0; : > "$OUT/zone_nsec.txt"
  for ((i=0;i<30000;i++)); do
    next=$(dig +dnssec +time=4 +tries=2 +noall +authority A "0.$cur" "@$nsip" 2>/dev/null \
      | awk -v c="$cur" '$4=="NSEC" && $1==c {print $5; exit}')
    [ -z "$next" ] && next=$(dig +dnssec +noall +authority A "0.$cur" "@$nsip" 2>/dev/null | awk '$4=="NSEC"{print $5; exit}')
    [ -z "$next" ] && break
    [ "$next" = "$D." ] && break
    grep -qxF "${next%.}" "$OUT/zone_nsec.txt" && break
    echo "${next%.}" >> "$OUT/zone_nsec.txt"; cur="$next"; n=$((n+1))
    [ $((n % 100)) -eq 0 ] && note "...walked $n"
  done
  bad "NSEC walk dumped $n zone records -> zone_nsec.txt"
  sed 's/\.$//' "$OUT/zone_nsec.txt" | add_subs
}

# ── wildcard detection ────────────────────────────────────────────────────────
WILDCARD_IP=""
detect_wildcard() {
  local r="rnd$RANDOM$RANDOM.$D"
  WILDCARD_IP=$(dig +short A "$r" @"$RESOLVER" 2>/dev/null | grep -oE "$RE_IP4" | head -1)
  [ -n "$WILDCARD_IP" ] && warn "wildcard DNS: *.$D -> $WILDCARD_IP (brute results matching it are filtered)"
}

# ── brute-force ───────────────────────────────────────────────────────────────
WORDS_BUILTIN='www mail smtp imap pop pop3 webmail ns ns1 ns2 ns3 mx mx1 vpn gw gateway
remote portal api api1 api2 api-internal apigw admin administrator root dev dev1 dev2 devel
development stg stage staging uat qa qc test test1 test2 sandbox demo lab lab1 preprod prod
production internal intranet corp office home git gitlab gitea bitbucket svn jenkins ci cd
drone teamcity bamboo argocd argo rancher k8s kube kubernetes kubeadm openshift nomad consul
vault etcd zookeeper kafka rabbitmq nats mq redis memcached minio s3 ceph swift
nexus artifactory harbor registry docker-registry docker dockerreg dockerhub hub images image
repo repository packages npm pypi maven grafana prometheus prom alertmanager thanos loki
victoriametrics graphite statsd telegraf jaeger zipkin tempo kibana elastic elasticsearch es
logstash fluentd fluent graylog splunk opensearch kql sonar sonarqube sonarcloud fortify
checkmarx nessus openvas qualys wazuh ossec soc siem elk mysql mariadb postgres postgresql pg
pgadmin phpmyadmin adminer mongo mongodb cassandra clickhouse influxdb cockroach db db1 db2
database sql mssql oracle backup backups dump dumps old archive storage files file ftp sftp ftps
tftp nas share smb webdav portainer traefik nginx haproxy apache tomcat jboss wildfly
weblogic websphere iis kong apisix tyk gravitee ingress ingress-nginx lb loadbalancer proxy
reverse-proxy bastion jump jumpbox jumphost ssh rdp vnc teamviewer anydesk citrix
keycloak okta auth0 ldap ad freeipa authentik authelia sso idp oauth oidc saml cas dex
hydra kratos monitor monitoring status statuspage health healthcheck metrics uptime zabbix
nagios icinga cacti observium librenms pandora netdata collectd dashboard dash grafana1
jira confluence wiki redmine mantis bugzilla youtrack servicedesk helpdesk zendesk freshdesk
crm erp sap salesforce dynamics hr payroll finance accounting billing invoice
mail2 mx2 relay mailgw exchange owa autodiscover enterpriseregistration enterpriseenrollment
lyncdiscover sip skype teams webex zoom jitsi matrix mattermost rocketchat slack
cdn static assets media img video vod stream live edge origin cache cache1 waf uuwaf
beta alpha canary blue green v1 v2 v3 new old2 legacy tmp temp cloud cloud1 cloud2 aws azure gcp'
brute() {
  hdr "Brute-force"
  local wl="$OUT/.wl"
  # built-in words are ALWAYS merged with -w (deduped), unless --no-builtin.
  {
    [ "$NO_BUILTIN" = 1 ] || printf '%s\n' $WORDS_BUILTIN
    [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ] && tr -d '\r' < "$WORDLIST"
  } | sed 's/[[:space:]].*//; /^#/d; /^$/d' | tr 'A-Z' 'a-z' | sort -u > "$wl"
  local n; n=$(wc -l < "$wl")
  local srcs="built-in"; [ -n "$WORDLIST" ] && srcs="$([ "$NO_BUILTIN" = 1 ] && echo "$WORDLIST" || echo "built-in + $WORDLIST")"
  note "testing $n names ($srcs) x resolver $RESOLVER (threads=$THREADS)"
  detect_wildcard
  export DE RE_IP4 RESOLVER WILDCARD_IP
  sed "s/\$/.$D/" "$wl" | xargs -P "$THREADS" -I{} bash -c '
    h="{}"
    a=$(dig +short +time=2 +tries=1 A "$h" @"$RESOLVER" 2>/dev/null | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
    typ=A
    if [ -z "$a" ]; then a=$(dig +short +time=2 +tries=1 CNAME "$h" @"$RESOLVER" 2>/dev/null | head -1); typ=CNAME; fi
    [ -z "$a" ] && exit 0
    [ "$typ" = A ] && [ -n "$WILDCARD_IP" ] && [ "$a" = "$WILDCARD_IP" ] && exit 0
    printf "%s\t%s\t%s\n" "$h" "$typ" "$a"
  ' | sort -u > "$OUT/.brute"
  awk '{print $1}' "$OUT/.brute" | add_subs
  grep -oE "$RE_IP4" "$OUT/.brute" | add_ips
  local bn; bn=$(wc -l < "$OUT/.brute")
  ok "brute resolved $bn hosts"
  [ "$bn" -gt 0 ] && column -t "$OUT/.brute" 2>/dev/null | sed 's/^/  /' | head -60
}

# ── permutation ───────────────────────────────────────────────────────────────
perm() {
  hdr "Permutations of discovered hosts"
  [ -s "$OUT/.subs" ] || { note "no hosts yet"; return; }
  local base; base=$(sed "s/\.$DE\$//" "$OUT/.subs" | grep -vxF "$D" | awk 'length<30' | sort -u | head -80)
  local pfx="dev stg staging test uat prod internal new old admin api v2 2 standby backup" out="$OUT/.permwl"
  : > "$out"
  while read -r b; do
    [ -z "$b" ] && continue
    for p in $pfx; do echo "$p-$b"; echo "$b-$p"; done
    echo "${b}2"; echo "${b}-new"
  done <<< "$base" | sort -u > "$out"
  local n; n=$(wc -l < "$out"); note "generated $n permutations, resolving"
  export RESOLVER WILDCARD_IP
  sed "s/\$/.$D/" "$out" | xargs -P "$THREADS" -I{} bash -c '
    h="{}"; a=$(dig +short +time=2 +tries=1 A "$h" @"$RESOLVER" 2>/dev/null | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
    [ -z "$a" ] && exit 0
    [ -n "$WILDCARD_IP" ] && [ "$a" = "$WILDCARD_IP" ] && exit 0
    printf "%s\t%s\n" "$h" "$a"
  ' | sort -u > "$OUT/.perm"
  awk '{print $1}' "$OUT/.perm" | add_subs
  grep -oE "$RE_IP4" "$OUT/.perm" | add_ips
  ok "permutation found $(wc -l < "$OUT/.perm") new hosts"
}

# ── resolve all discovered hosts (NSEC/AXFR names carry no IP) ────────────────
resolve_all() {
  hdr "Resolving all discovered hosts -> IP"
  sort -u "$OUT/.subs" > "$OUT/.allsubs"
  local n; n=$(wc -l < "$OUT/.allsubs")
  [ "$n" -gt 0 ] || { note "nothing to resolve"; return; }
  note "resolving $n hosts (threads=$THREADS)"
  export RESOLVER
  xargs -P "$THREADS" -I{} bash -c '
    h="{}"; a=$(dig +short +time=2 +tries=1 A "$h" @"$RESOLVER" 2>/dev/null | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
    for ip in $a; do printf "%s\t%s\n" "$h" "$ip"; done' < "$OUT/.allsubs" | sort -u > "$OUT/resolved.txt"
  grep -oE "$RE_IP4" "$OUT/resolved.txt" | add_ips
  # host -> internal-IP map (the crown-jewel leak)
  awk -v re="$RE_INTERNAL" '{ ip=$2; if (ip ~ re) print }' "$OUT/resolved.txt" | sort -u > "$OUT/internal_hosts.txt"
  local rh ih; rh=$(awk '{print $1}' "$OUT/resolved.txt" | sort -u | wc -l); ih=$(wc -l < "$OUT/internal_hosts.txt")
  ok "resolved $rh hosts -> resolved.txt"
  [ "$ih" -gt 0 ] && { bad "$ih hosts point to INTERNAL IPs (split-horizon leak) -> internal_hosts.txt"; sed 's/^/    /' "$OUT/internal_hosts.txt" | head -25; }
}

# ── reverse DNS ───────────────────────────────────────────────────────────────
ptr() {
  hdr "Reverse DNS (PTR)"
  : > "$OUT/ptr.txt"
  sort -u "$OUT/.ips" > "$OUT/ips.txt"
  # PTR for each discovered IP
  while read -r ip; do
    [ -z "$ip" ] && continue
    local p; p=$(dig +short -x "$ip" @"$RESOLVER" 2>/dev/null | sed 's/\.$//')
    [ -n "$p" ] && { printf '%s\t%s\n' "$ip" "$p" >> "$OUT/ptr.txt"; echo "$p" | add_subs; }
  done < "$OUT/ips.txt"
  local n; n=$(wc -l < "$OUT/ptr.txt")
  ok "$n PTR records"
  [ "$n" -gt 0 ] && sed 's/^/  /' "$OUT/ptr.txt" | head -40
}

# ── service-layer hostname harvest (finds hosts with NO DNS record) ───────────
# A DNS tool is blind to names that only live at the HTTP/TLS layer — e.g. an
# internal container registry whose name is published nowhere in DNS but leaks in:
#   - the TLS cert SAN presented by the gateway/ingress
#   - a redirect Location header
#   - a Docker Registry 401 WWW-Authenticate: Bearer realm="https://<name>/..."
# We probe the IPs dig already found (:443 cert + / and /v2/ responses).
svc() {
  hdr "Service harvest (cert SAN / redirect / registry /v2 realm)"
  command -v openssl >/dev/null || warn "openssl missing — cert SAN harvest skipped"
  sort -u "$OUT/.ips" > "$OUT/.svcips"
  local n; n=$(wc -l < "$OUT/.svcips"); [ "$n" -gt 0 ] || { note "no IPs to probe"; return; }
  note "probing $n IPs (:443 cert SAN, / + /v2/ realm & redirects)"
  export D HRE="[a-z0-9_.-]+\.${DE}"
  xargs -P "$THREADS" -I{} bash -c '
    ip="{}"
    # 1) TLS certificate SAN
    echo | timeout 7 openssl s_client -connect "$ip:443" -servername "$D" 2>/dev/null \
      | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -oiE "$HRE"
    # 2) redirect Location + Docker-Registry realm (/v2/) + any WWW-Authenticate
    for u in "https://$ip/" "https://$ip/v2/" "http://$ip/"; do
      timeout 7 curl -skI -H "Host: $D" --max-time 7 "$u" 2>/dev/null \
        | grep -iE "^location:|^www-authenticate:|realm=|docker-distribution" | grep -oiE "$HRE"
    done
  ' < "$OUT/.svcips" 2>/dev/null | tr "A-Z" "a-z" | sort -u > "$OUT/.svcharvest"
  comm -23 "$OUT/.svcharvest" <(sort -u "$OUT/.subs") 2>/dev/null > "$OUT/svc_new_hosts.txt" || cp "$OUT/.svcharvest" "$OUT/svc_new_hosts.txt"
  cat "$OUT/.svcharvest" | add_subs
  local nn; nn=$(wc -l < "$OUT/svc_new_hosts.txt")
  if [ "$nn" -gt 0 ]; then bad "$nn hostname(s) harvested from service responses (NOT in DNS!) -> svc_new_hosts.txt"; sed 's/^/    /' "$OUT/svc_new_hosts.txt" | head -25
  else ok "no new hostnames leaked by services"; fi
}

# ── classify + summary ────────────────────────────────────────────────────────
classify() {
  hdr "Classification"
  sort -u "$OUT/.subs" > "$OUT/subdomains.txt"
  sort -u "$OUT/.ips" > "$OUT/ips.txt"
  grep -E "$RE_INTERNAL" "$OUT/ips.txt" 2>/dev/null | sort -u > "$OUT/internal_ips.txt" || true
  grep -iE 'docker|registr|harbor|nexus|argo|rancher|k8s|kube|openshift|vault|etcd|consul|gitlab|gitea|jenkins|bamboo|drone|teamcity|sonar|nessus|grafana|prometheus|kibana|elastic|logstash|graylog|splunk|redis|mongo|postgres|mysql|clickhouse|minio|rabbitmq|kafka|keycloak|ldap|sso|vpn|bastion|jump|admin|portainer|traefik|kong|apisix|ingress|internal|intranet|pentest|sectest|ssrf|rce|backup|dump|staging|\bstg\b|\btest\b|\bdev\b|\buat\b|poc|sandbox|phpmyadmin|pgadmin|adminer' "$OUT/subdomains.txt" 2>/dev/null | sort -u > "$OUT/interesting.txt" || true

  local ni; ni=$(wc -l < "$OUT/internal_ips.txt" 2>/dev/null || echo 0)
  : > "$OUT/internal_subnets.txt"
  if [ "${ni:-0}" -gt 0 ]; then
    bad "$ni RFC1918/internal IPs LEAKED in public DNS -> internal_ips.txt"
    sed 's/^/    /' "$OUT/internal_ips.txt" | head -20
    # derive internal /24 ranges (inferred from the leaked IPs — not a confirmed mask)
    awk -F. 'NF>=3{print $1"."$2"."$3".0/24"}' "$OUT/internal_ips.txt" | sort | uniq -c | sort -rn \
      | awk '{printf "%-20s %s IPs\n", $2, $1}' > "$OUT/internal_subnets.txt"
    warn "internal /24 ranges (inferred) -> internal_subnets.txt"
    sed 's/^/    /' "$OUT/internal_subnets.txt"
  fi
  # split-horizon hint: hosts that resolve on auth NS but not on public resolver
  local hi; hi=$(wc -l < "$OUT/interesting.txt" 2>/dev/null || echo 0)
  [ "${hi:-0}" -gt 0 ] && warn "$hi high-value hosts -> interesting.txt"

  {
    echo "domain:        $D"
    echo "subdomains:    $(wc -l < "$OUT/subdomains.txt")"
    echo "unique IPs:    $(wc -l < "$OUT/ips.txt")"
    echo "internal IPs:  $ni"
    echo "internal nets: $([ -f "$OUT/internal_subnets.txt" ] && wc -l < "$OUT/internal_subnets.txt" || echo 0)"
    echo "internal hosts:$([ -f "$OUT/internal_hosts.txt" ] && wc -l < "$OUT/internal_hosts.txt" || echo 0)"
    echo "interesting:   $hi"
    echo "zone (NSEC):   $([ -f "$OUT/zone_nsec.txt" ] && wc -l < "$OUT/zone_nsec.txt" || echo 0)"
    echo "nameservers:   $(echo $NS_LIST | tr '\n' ' ')"
  } > "$OUT/summary.txt"
}

# ── run ───────────────────────────────────────────────────────────────────────
printf '%s┌─ DNS recon: %s%s\n' "$C_H" "$D" "$C_0"
want enum     && enum
want fp       && fp
want axfr     && axfr
want nsec     && nsec
want brute    && brute
want perm     && perm
want resolve  && resolve_all
want ptr      && ptr
# svc is ACTIVE (HTTP/TLS probes) — opt-in via --svc or --only svc
{ [ "$DO_SVC" = 1 ] || { [ -n "$ONLY" ] && [[ ",$ONLY," == *",svc,"* ]]; }; } && svc
classify
rm -f "$OUT"/.subs "$OUT"/.ips "$OUT"/.wl "$OUT"/.brute "$OUT"/.perm "$OUT"/.permwl "$OUT"/.allsubs 2>/dev/null
hdr "Summary"; sed 's/^/  /' "$OUT/summary.txt"
printf '\n%soutput dir: %s/%s\n' "$C_OK" "$OUT" "$C_0"
