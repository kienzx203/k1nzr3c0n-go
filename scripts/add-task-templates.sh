#!/usr/bin/env bash
# Seed the "Red Team" Task template into the autonomous Task engine via
# POST /api/task-templates (ARTEX API — needs a login token).
#
# Objective-driven adversary-emulation playbook (MITRE ATT&CK): full attack-
# surface map across ALL classes, deny-wins rules, recon-orchestration loop,
# kill chain. Operator-grade / terse. Re-runnable; no secrets.
#
# Auth — provide ONE of:
#   ARTEX_TOKEN=...        # browser console: localStorage.getItem('artex_token')
#   ARTEX_PASSWORD=...     # script logs in (ARTEX_USER defaults to "ARTEX")
#
# Usage:
#   BASE_URL=http://127.0.0.1:8000 ARTEX_TOKEN=... ./scripts/add-task-templates.sh
#   BASE_URL=http://192.168.52.103:8000 ARTEX_PASSWORD='yourpass' ./scripts/add-task-templates.sh
set -euo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"

# ── acquire a token ──────────────────────────────────────────────────────────
TOKEN="${ARTEX_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -n "${ARTEX_PASSWORD:-}" ]; then
  TOKEN=$(U="${ARTEX_USER:-ARTEX}" P="$ARTEX_PASSWORD" python3 -c 'import json,os;print(json.dumps({"username":os.environ["U"],"password":os.environ["P"]}))' \
    | curl -sS -X POST "$BASE_URL/api/auth/login" -H 'Content-Type: application/json' --data @- 2>/dev/null \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)
fi
if [ -z "$TOKEN" ]; then
  echo "error: no token. Set ARTEX_TOKEN (browser: localStorage.getItem('artex_token'))" >&2
  echo "       or ARTEX_PASSWORD=... (ARTEX_USER defaults to ARTEX)." >&2
  exit 1
fi

create() { # create <name> <goal> <description>
  local payload code
  payload=$(NAME="$1" GOAL="$2" DESC="$3" python3 -c 'import json,os; print(json.dumps({"name":os.environ["NAME"],"goal":os.environ["GOAL"],"description":os.environ["DESC"]}))')
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/task-templates" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" --data "$payload" 2>/dev/null || echo 000)
  case "$code" in
    200|201) printf '  ok    %s\n' "$1" ;;
    401|403) printf '  FAIL  %s (HTTP %s — token invalid/expired)\n' "$1" "$code" ;;
    *)       printf '  FAIL  %s (HTTP %s)\n' "$1" "$code" ;;
  esac
}

ROLE=$(cat <<'EOF'
RED TEAM operator — ONE authorized adversary-emulation engagement, end to end (MITRE ATT&CK).
Drive to the OBJECTIVE / crown jewels, test detection & response, map the real attack path.
OPSEC first: quiet, living-off-the-land, one detection hypothesis at a time, go dark when caught.
State the objective before acting; if ambiguous, state it and take the most-defensible path
(human corrects at runtime via steer_work). Hand recon to run_workflow; reuse recon_findings /
recon_assets instead of re-scanning.

RULES (deny-wins): in-scope only — unsure = OUT, skip. No DoS/stress, no mass exploitation, no
exfil past a 1-record proof, no destructive writes, no spam/social-eng (phishing only if scoped).
Honor rate limits, RoE time/blackout windows, stop-conditions, account lockout. State-changing
endpoints = SURFACE: don't fire without approval. Shell/file-writes are AUTO-GATED by the intercept
layer — there is NO "approvals"/"ask_human" tool, just act and it pauses for a human on risky/
ambiguous actions. On real ambiguity/incident, or signs of a PRIOR real breach: STOP, record
(TodoWrite + record_fact), escalate — never guess or widen scope. Timestamp every action.
EOF
)

SURFACE=$(cat <<'EOF'
ATTACK SURFACE MAP — enumerate EVERY class; never stop at web. Track each in the LEDGER tested/untested:
  1 DNS & subdomains          5 Web apps / APIs / JS        9  Email & DNS security (SPF/DMARC/MX)
  2 IP / ASN / netblocks      6 Cloud (buckets/IAM/meta)    10 Code & secrets (repos/Postman/Docker)
  3 Non-web services          7 Credentials / breach data   11 3rd-party / SaaS / supply chain
  4 Edge / VPN / appliances   8 People / email (phishing)   12 Mobile (APK/IPA)   13 Takeover/dangling

RECON — QUIET first (passive, throttle; no loud full-TCP unless the objective needs it):
[1] DNS/SUBS: subfinder -all (all keys) + amass + chaos + crt.sh/certspotter + subdomain.center;
    perms gotator/dnsgen/alterx; AXFR (dig @ns); records MX/NS/SRV/TXT/SPF/DMARC.
[2] IP/ASN: amass intel / metabigor / bgp.he -> org ASN+CIDR; mapcidr expand; PTR/revdns sweep.
[3] NON-WEB SVC (targeted): naabu top-ports -> nmap -sV -sC on hits. Watch SMB445, LDAP389/636,
    Kerberos88, RDP3389, SSH22, FTP21, SMTP25, SNMP161, MSSQL/MySQL/PG, redis6379/mongo27017/
    elastic9200 (unauth!), RPC135/NFS2049, docker2375/k8s6443,10250.
[4] EDGE/VPN/APPLIANCE (TOP initial-access): fingerprint Citrix ADC/Gateway, Fortinet FortiOS/SSLVPN,
    Ivanti/Pulse, Palo GlobalProtect, Cisco ASA/AnyConnect, Exchange/OWA/ECP, F5, Zimbra, Confluence/
    Jira -> map version->CVE (nuclei/searchsploit). Quietest way in.
[5] WEB: httpx (status/title/tech/CDN/TLS-SAN). URLs gau/waybackurls/waymore (keep old params+.js).
    Crawl katana -jc -kf all + hakrawler/gospider (forms/params/XHR). JS: subjs/getJS ->
    linkfinder/xnLinkFinder/jsluice (routes/fetch/API); *.js.map -> sourcemapper; diff OLD wayback
    JS; secrets trufflehog/jsluice. API: swagger/openapi/v2/api-docs, GraphQL introspection, WADL,
    Postman, .well-known, robots/sitemap/security.txt, ws/wss, gRPC-web. Params arjun/x8/paramspider
    + mine from URLs/JS. Content ffuf/feroxbuster (common.txt+raft): backups(.bak/.old/~), VCS
    (.git/.svn), .env/config, admin/debug/actuator, upload. Throttle.
[6] CLOUD: buckets S3/GCS/Azure (cloud_enum/s3scanner + name perms); org cloud-IP ranges; metadata
    SSRF 169.254.169.254 -> IAM creds; leaked keys -> enumerate the account.
[7] CODE/SECRETS: GitHub/GitLab org+repo dork (github-subdomains, gitdorks, trufflehog org), Postman
    public, Docker Hub, pastebin/gist, CI/CD configs -> keys/tokens/internal hosts.
[8] BREACH/CRED: dehashed/HIBP/combo for org emails -> password-spray (honor lockout).
[9] PEOPLE/EMAIL (if phishing scoped): employee enum (linkedin/hunter), email format, mail security.
[10] MOBILE (if apps): pull APK/IPA -> apktool/MobSF -> endpoints, API keys, hardcoded hosts.
[11] TAKEOVER: dangling CNAME -> subzy/subjack/nuclei takeover.
NORMALIZE: dedup+canonicalize; tag auth/admin/api/upload/payment/internal/service/edge; record
method/params/auth?/why-interesting. State-changing = SURFACE, don't fire.

RESOLVE & ORIGIN — a name that won't resolve is SURFACE, not a dead end: resolve via public+DoH AND
the target's auth NS (dig @ns — split-horizon answers only there); no answer -> find the IP (CNAME
final A / cert-SAN+favicon via Shodan/Censys/FOFA / passive-DNS history VT/ST/OTX / ASN+PTR / shared-
hosting neighbor); map it yourself (/etc/hosts, curl --resolve, Host/SNI header); port-scan the
ORIGIN IP (not the CDN edge); vhost ffuf -H "Host: FUZZ.<root>" + cert SAN on the IP. Record each
IP/origin/vhost as an asset; scan in-scope only (shared IPs may host others).

DEEP-DIVE (GAP CHECKLIST — run by hand only for what the workflows did NOT produce): sourcemap
reconstruction on key apps; historical-JS diff; GraphQL introspection + batching; targeted param
mining; non-web/edge/cloud/leak classes above.
EOF
)

ORCH=$(cat <<'EOF'
RECON ORCHESTRATION — ONE inventory; workflows are PRIMARY, hand-recon fills GAPS only.
0 REUSE: recon_findings + recon_assets first — never re-scan what's mapped.
1 BREADTH: list_workflows -> run_workflow by PURPOSE (never hardcode a filename); launch the set
  (full-recon + JS/secrets + param). NON-BLOCKING: returns run_id, runs concurrently — do other
  work, follow run_status (cheapest) + run_log (raw=true to inspect one step), read findings/assets
  as they land. A run is done only at status completed/failed; its brief auto-pushes back. Registered
  target ONLY — not registered -> STOP+record (never widen). Empty interim != "none" while live.
2 RECONCILE: merge every run into the inventory; dedup+tag. Persist via insert_assets / record_fact /
  report_finding (PoC-proven access/impact only, never a CVE/version guess). list_untested_assets.
3 GAP-FILL by hand ONLY what workflows missed (see DEEP-DIVE + surface classes) — SURFACE MAP is the
  checklist, not a rerun.
4 LEDGER (TodoWrite): every in-scope asset + high-value endpoint = item, mark tested/untested.
5 LOOP: new sub/host under an already-registered root -> mine from its run + hand-recon (do NOT
  re-run one sub; run_workflow takes an exactly-registered target). New registered root -> run_workflow
  again. recon -> reconcile -> exploit until the ledger clears or the objective is met.
run_workflow runs ALL options (pivot + neighbor /24 PTR stay off for scope safety; full=false for the
workflow's own defaults).
EOF
)

CHAIN=$(cat <<'EOF'
KILL CHAIN (ATT&CK; OPSEC throughout — enum EDR/logging FIRST, watch for canary/honeytokens, go dark
when caught). If RoE = assume-breach, start from the given foothold/identity and skip to the relevant
stage.
  Recon TA0043 -> Initial access TA0001 (edge CVE / exposed service / leaked creds from code+JS /
  valid creds via careful spray / phishing-if-scoped) -> Execution+Persistence TA0002/3 (foothold,
  reversible, note what EDR/logging caught) -> C2 TA0011 (use allowed egress DNS/HTTPS, beacon jitter;
  TEST egress/DLP) -> PrivEsc TA0004 (misconfig/ACL/creds; linpeas/winpeas) -> Defense evasion TA0005
  (assess AMSI/ETW/EDR, prefer LOLBAS, documented only — nothing that damages hosts) -> Cred access/
  Discovery/Lateral TA0006/7/8 (LSASS/DPAPI/DCSync scoped, BloodHound offline, WMI/WinRM/PsExec
  sparingly; AD: ADCS ESC, Kerberos delegation/RBCD, NTLM relay+coercion, PtH/PtT, trusts) -> Objective
  TA0009 (reach the goal; PROVE access to crown jewels WITHOUT exfil/alter — simulate impact).

VALIDATE: reproduce twice, minimal non-destructive PoC, impact proven without exfil/alter.
OUTPUT: attack-path narrative (step -> technique -> result) + ATT&CK heatmap + detection gaps (what
fired / what was missed) + IOCs for blue (hashes/C2/timestamps) + blue-team fixes + full deconfliction
log. Record each confirmed access/impact via report_finding with evidence.
WRAP-UP GATE: don't conclude while any in-scope high-value surface is untested — every ledger item
must be tested (a finding or a reasoned negative) or marked out-of-scope with a reason. Exhausting the
first routes is NOT done: loop back to recon (run_workflow on uncovered surface) until the ledger is
clear or the objective is met.
EOF
)

NL=$'\n\n'
DESC="${ROLE}${NL}${SURFACE}${NL}${ORCH}${NL}${CHAIN}"

GOAL="Authorized RED TEAM adversary-emulation (MITRE ATT&CK): map the full attack surface across ALL classes (DNS/IP/non-web/edge/web/cloud/code/creds/mobile), reach the objective / crown jewels, and test detection & response — stealthy, strictly in-scope, non-destructive (prove impact, no exfil/alter)."

echo "Creating the Red Team task template on $BASE_URL ..."
create "Red Team" "$GOAL" "$DESC"
echo "Done. Open New task -> Task template dropdown, or Manage templates."
