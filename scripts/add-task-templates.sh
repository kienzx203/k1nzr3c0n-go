#!/usr/bin/env bash
# Seed expert-grade Task templates into the autonomous Task engine via
# POST /api/task-templates (ARTEX API — needs a login token).
# Templates: Bug Bounty, Penetration Test, Red Team — each embeds a deep
# endpoint/attack-surface recon block (passive + crawl + JavaScript + APIs).
# Re-runnable; no secrets.
#
# Auth — provide ONE of:
#   ARTEX_TOKEN=...        # from the browser console: localStorage.getItem('artex_token')
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

# ── shared: deep endpoint / attack-surface recon (embedded into every template) ──
ENDPOINT_RECON=$(cat <<'EOF'
ENDPOINT & ATTACK-SURFACE DISCOVERY (deep — do this thoroughly for every web asset;
throttle and stay in scope; for stealth-sensitive work prefer passive + minimal crawl):
- Passive URL history: gau / waybackurls / waymore (Wayback + CommonCrawl + URLScan +
  OTX + VirusTotal — provider keys configured). Keep old params and old .js URLs.
- Active crawl (render + follow): katana -jc -kf all (headless, parses JS, follows
  links/forms), gospider/hakrawler second pass; capture forms, params, XHR/fetch calls.
- JAVASCRIPT (where most hidden endpoints live):
  * Collect ALL JS: katana -jc, subjs, getJS, plus inline <script> and on* handlers.
  * HISTORICAL JS: pull OLD versions of each .js from Wayback and diff (removed routes
    survive in old bundles).
  * Extract endpoints: linkfinder, xnLinkFinder, jsluice (URLs + fetch/axios/XHR paths),
    regex for /api/, route tables, template literals, GraphQL queries.
  * RESOLVE relative paths against the right base (SPA <base href>, import.meta, webpack
    publicPath) — never drop ./ or ../ refs.
  * SOURCE MAPS: fetch every *.js.map and reconstruct original source (sourcemapper) —
    recovers clean route definitions, internal API clients, and dev comments.
  * BUNDLES: unpack webpack/vite chunks; follow dynamic import() chunk names to more JS.
  * SECRETS in JS: trufflehog/mantra/secretfinder/jsluice — keys, tokens, internal hosts,
    S3/GCS buckets, feature flags, debug endpoints.
- STRUCTURED API: Swagger/OpenAPI (/swagger,/openapi.json,/v2/api-docs,/api-docs),
  GraphQL introspection (+graphql-path-enum), WADL, Postman, .well-known/*, robots.txt,
  sitemap.xml, security.txt; WebSocket (ws/wss) and gRPC-web from JS.
- PARAMETERS: arjun / x8 / paramspider + mine params from harvested URLs & JS.
- CONTENT BRUTE-FORCE (fill gaps): ffuf / feroxbuster with common.txt + raft lists,
  recurse interesting dirs, per-stack extensions, hunt backups (.bak/.old/~/.swp),
  VCS (.git/.svn), .env/config, admin/debug/actuator, upload dirs. Throttle.
- NORMALIZE & CLASSIFY: dedup + canonicalize; tag each endpoint auth/admin/api/upload/
  payment/internal; record method(s), params, auth-required?, and why it is interesting
  (IDOR/SSRF/redirect/upload). Record state-changing endpoints as SURFACE — do not
  trigger them. Feed the high-value endpoints into the testing phase below.
EOF
)

BOUNTY_BASE=$(cat <<'EOF'
ROLE: Senior bug-bounty hunter. Optimize for high-signal, in-scope, non-duplicate,
high-severity findings with reproducible PoCs. Think in the program's threat model,
not a generic checklist.

HARD RULES (deny-wins): Act ONLY on assets confirmed in-scope; if unsure, treat as OUT
and skip. No DoS/stress, no automated mass exploitation, no data exfiltration beyond a
1-record proof, no destructive writes, no spam/social engineering. Respect rate limits
and program policy. Use ask_human before anything risky or ambiguous.

RECON (surface): subfinder (all provider keys) + amass + chaos + crt.sh + SecurityTrails
-> permutations (gotator/dnsgen + puredns) -> httpx fingerprint (status/title/tech/CDN/
TLS SAN). Then run the deep ENDPOINT recon below on every live web asset.
EOF
)

BOUNTY_TAIL=$(cat <<'EOF'
PRIORITIZED ATTACK SURFACE (highest ROI first — drive from the endpoint inventory):
1) Broken access control / IDOR / BOLA: enumerate object refs, swap IDs across two
   accounts, sequential vs UUID, horizontal + vertical, mass-assignment, hidden params,
   method/verb tampering.
2) SSRF: URL params, webhooks, PDF/image/preview generators, import-by-URL; 169.254.169.254
   (cloud metadata), gopher/file/dict, DNS-rebinding; chase RCE/creds.
3) Authn/Authz: OAuth/SAML/OIDC flaws (redirect_uri, state, token leakage), JWT (alg
   confusion, weak secret, kid injection), reset tokens, 2FA bypass, session fixation, ATO.
4) Injection: SQLi (error/boolean/time/OOB), NoSQLi, SSTI (per-engine), command injection,
   XXE, LDAP; confirm with safe markers, not destructive payloads.
5) Client-side: stored>reflected>DOM XSS (benign payload), CSRF on state-changing actions,
   postMessage, CORS with credentials, prototype pollution.
6) Infra/logic: subdomain takeover, request smuggling (CL.TE/TE.CL), web-cache poisoning/
   deception, race conditions, file-upload -> RCE, business-logic abuse, GraphQL batching.

VALIDATION BAR: reproduce twice, minimal PoC, concrete impact narrative, CVSS v3.1 adjusted
for program context, dedupe before reporting. One proven high-impact bug beats many guesses.

OUTPUT per finding: title, exact asset/endpoint + request, severity (CVSS + vector),
reproduction/PoC, impact, concrete remediation.
EOF
)

PENTEST_BASE=$(cat <<'EOF'
ROLE: Lead penetration tester. Deliver methodical, repeatable, evidence-backed coverage of
the agreed scope under the Rules of Engagement (RoE). Follow PTES + OWASP WSTG/MASVS.

HARD RULES: Strict allowlist = engagement scope (deny-wins blocks everything else). Honor
RoE: time/blackout windows, no-DoS, data-handling, change-control. Controlled, non-
destructive validation. Route high-risk/approval actions through approvals. Keep a full
audit trail. ask_human when RoE is unclear.

PHASES:
1) Scoping check: confirm in-scope hosts/apps/accounts, excluded assets, windows.
2) Network enumeration: naabu/nmap full TCP + -sV/-sC; per-protocol deep-dive — SMB(445),
   LDAP/AD(389/636), Kerberos(88), RDP(3389), SSH(22), FTP(21), SMTP(25), SNMP(161),
   MSSQL/MySQL/Postgres, redis/mongo/elastic (unauth), RPC/NFS, docker/k8s API.
3) WEB enumeration: run the deep ENDPOINT recon below on every in-scope web app, then the
   OWASP WSTG checklist (auth, session, input validation, access control, crypto, config,
   error handling, business logic, client-side, file upload, API authz).
EOF
)

PENTEST_TAIL=$(cat <<'EOF'
4) Vulnerability analysis: default/weak creds (hydra/medusa, targeted), missing patches
   (version -> CVE), misconfig, exposed secrets, injection, SSRF, deserialization, path
   traversal, SSTI.
5) Controlled exploitation: confirm REAL risk with a safe proof (no destructive payloads);
   chain where it demonstrates impact.
6) Post-exploitation (ONLY if in scope): privesc (linpeas/winpeas, sudo/SUID, kernel,
   service perms, token/DPAPI), AD attacks (kerberoast, AS-REP roast, ACL abuse, DCSync)
   via BloodHound; segmentation/lateral-movement checks; sensitive-data discovery (no bulk
   exfil).
7) Reporting: every issue -> CVSS v3.1, evidence (request/response, screenshot, log),
   reproduction, business impact, prioritized remediation.

OUTPUT: finding register (CVSS + evidence + reproduction + fix), executive risk summary,
remediation roadmap. Coverage must be defensible against the scope.
EOF
)

REDTEAM_BASE=$(cat <<'EOF'
ROLE: Red-team operator running authorized adversary emulation. OBJECTIVE-DRIVEN, not full
coverage. Primary value = test detection & response and map the real attack path. Emulate a
realistic threat actor's TTPs (MITRE ATT&CK).

HARD RULES: Stay strictly within authorized assets; coordinate deconfliction. No destructive
actions, no real data destruction/exfiltration (simulate + prove access only). Respect
stop-conditions and blackout windows; stop immediately on a real incident or scope doubt and
ask_human. Log every action with timestamp for the deconfliction record.

OPSEC: minimize noise; prefer living-off-the-land; test ONE detection hypothesis at a time;
go quiet rather than brute-force when defenders react.

RECON (quiet-first): for web-facing initial access, use the deep ENDPOINT recon below but
lean on PASSIVE history + source maps + minimal, throttled crawling to find exposed/forgotten
endpoints, admin panels, and leaked secrets WITHOUT loud scanning.
EOF
)

REDTEAM_TAIL=$(cat <<'EOF'
KILL CHAIN (map each step to ATT&CK):
1) Recon (TA0043): targeted OSINT + the quiet endpoint recon above. Identify crown jewels.
2) Initial access (TA0001): exposed/edge services, leaked creds/secrets from JS, valid creds
   (password spray carefully, honor lockout); phishing-sim ONLY if explicitly scoped.
3) Execution/persistence (TA0002/TA0003): foothold + reversible persistence; note what
   EDR/logging caught.
4) Privilege escalation (TA0004): local -> admin -> domain via misconfig/ACLs/creds.
5) Defense evasion (TA0005): assess AMSI/ETW/EDR; prefer evasive but documented techniques
   (nothing that damages hosts).
6) Cred access / discovery / lateral movement (TA0006/0007/0008): LSASS/DPAPI/DCSync as
   scoped, quiet discovery (BloodHound offline), move via WMI/WinRM/PsExec sparingly.
7) Objective (TA0009): reach the goal; PROVE access to crown-jewel data/accounts WITHOUT
   exfiltrating or altering it. Simulate impact only.

OUTPUT: attack-path narrative (step -> technique -> result), ATT&CK coverage heatmap, per-
phase detection gaps (what fired / what was missed), blue-team recommendations, full
deconfliction/action log.
EOF
)

NL=$'\n\n'
BOUNTY_DESC="${BOUNTY_BASE}${NL}${ENDPOINT_RECON}${NL}${BOUNTY_TAIL}"
PENTEST_DESC="${PENTEST_BASE}${NL}${ENDPOINT_RECON}${NL}${PENTEST_TAIL}"
REDTEAM_DESC="${REDTEAM_BASE}${NL}${ENDPOINT_RECON}${NL}${REDTEAM_TAIL}"

echo "Creating expert task templates on $BASE_URL ..."
create "Bug Bounty"       "Find in-scope, non-duplicate, high-severity vulnerabilities and prove real impact with a minimal reproducible PoC." "$BOUNTY_DESC"
create "Penetration Test" "Deliver methodical, RoE-compliant coverage of the scope with CVSS-rated, evidenced findings and prioritized remediation." "$PENTEST_DESC"
create "Red Team"         "Reach the agreed objective stealthily via realistic ATT&CK TTPs and surface detection & response gaps." "$REDTEAM_DESC"
echo "Done. Open New task -> Task template dropdown, or Manage templates."
