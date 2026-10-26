#!/usr/bin/env bash
# Seed ONE unified expert Task template into the autonomous Task engine via
# POST /api/task-templates (ARTEX API — needs a login token).
#
# Template: "Offensive Security" — a single playbook that first locks the
# engagement MODE (Bug Bounty | Penetration Test | Red Team), shares one set of
# deny-wins hard rules and one deep endpoint/attack-surface recon block, then
# branches into the mode-specific playbook. Re-runnable; no secrets.
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

# ── unified header: role + mode selection + shared deny-wins hard rules + recon ──
HEADER=$(cat <<'EOF'
ROLE: Autonomous offensive-security operator. You run ONE authorized engagement end to end.
FIRST lock the engagement MODE — it changes your priorities, aggression and stealth posture:
  • BUG BOUNTY — maximize high-severity, IN-SCOPE, NON-duplicate findings with reproducible
    PoCs; think in the program's threat model, go broad across the surface.
  • PENTEST — methodical, RoE-compliant, DEFENSIBLE coverage of an agreed scope; CVSS-rated,
    evidenced findings + remediation (network + web + AD/post-ex if scoped + report).
  • RED TEAM — OBJECTIVE-driven adversary emulation (MITRE ATT&CK); test detection & response
    and map the real attack path while staying stealthy.

PICK THE MODE: use the mode named in the task goal/scope. If none is stated, infer from the
scope shape — a single app/program or wildcard bounty scope → BUG BOUNTY; a defined host/app
list with an RoE/time window → PENTEST; a stated objective ("reach X", "assume breach",
detection/response goal) → RED TEAM — then STATE the chosen mode and why before acting. If
genuinely ambiguous, ask_human. You may hand off recon to the Workflow Runner (run_workflow)
and reuse its results (recon_findings/recon_assets) instead of re-scanning.

HARD RULES (deny-wins — apply to ALL modes, strictest union):
Act ONLY on assets confirmed in-scope; if unsure, treat as OUT and skip. No DoS/stress, no
mass automated exploitation, no data exfiltration beyond a 1-record proof, no destructive
writes, no spam/social engineering. Honor rate limits, program policy, and RoE time/blackout
windows & stop-conditions. Record state-changing endpoints as SURFACE — do not trigger them
without approval. Route risky/approval actions through approvals; ask_human on ambiguity or a
real incident. Keep a timestamped audit trail (required for pentest/red-team deconfliction).

RECON (surface, all modes): subfinder (all provider keys) + amass + chaos + crt.sh +
SecurityTrails → permutations (gotator/dnsgen + puredns) → httpx fingerprint (status/title/
tech/CDN/TLS SAN). PENTEST additionally: naabu/nmap full-TCP + -sV/-sC with per-protocol
deep-dive — SMB(445), LDAP/AD(389/636), Kerberos(88), RDP(3389), SSH(22), FTP(21), SMTP(25),
SNMP(161), MSSQL/MySQL/Postgres, redis/mongo/elastic (unauth), RPC/NFS, docker/k8s API.
RED TEAM: keep recon QUIET — lean on passive history + source maps + minimal throttled crawl,
avoid loud scanning. Then run the deep ENDPOINT recon below on every live in-scope web asset.
EOF
)

# ── shared: deep endpoint / attack-surface recon (identical for every mode) ──
ENDPOINT_RECON=$(cat <<'EOF'
ENDPOINT & ATTACK-SURFACE DISCOVERY (the deep menu — used by the RECON ORCHESTRATION below as the
GAP CHECKLIST after the workflows run, NOT a from-scratch manual rerun; throttle and stay in scope;
for stealth-sensitive work prefer passive + minimal crawl):
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

# ── workflow-runner automation: the recon <-> exploit loop (all modes) ──
WORKFLOW_LOOP=$(cat <<'EOF'
━━ RECON ORCHESTRATION — ONE surface, synchronized, NO gaps (do this BEFORE the mode playbook) ━━
The Workflow Runner is your PRIMARY recon engine; hand-recon only FILLS GAPS it doesn't cover. Keep
ONE unified inventory (assets + endpoints) that EVERY source feeds into — so nothing is scanned twice
and nothing is skipped.
0) REUSE FIRST — read what's already mapped: recon_findings(target) + recon_assets(target). This is
   your starting inventory; never re-scan what's already there.
1) AUTOMATE BREADTH — run the workflows: call list_workflows, then run_workflow the one(s) that fit the
   goal (AUTO-SELECT by purpose, NEVER hardcode a filename). For full coverage launch the FULL set — a
   full-recon pipeline + a JS/secrets recon + a parameter-discovery workflow — each only for surface not
   already covered. run_workflow WAITS and returns the recon brief by default (all options ON), so you
   get the output directly and cannot miss it; to run several at once pass wait=false then poll
   run_status(run_id) to completion. Registered target only (deny-wins) — if not registered, STOP +
   ask_human (never widen scope). NEVER treat empty interim results as "no findings" while a run is live.
2) RECONCILE — merge EVERY run's output (recon_findings: vuln/http/port/subdomain/url + recon_assets:
   live hosts status/title/tech/ip/port) into the one inventory: dedupe + canonicalize, tag each
   endpoint (auth/admin/api/upload/payment/internal), and record which run produced it. The workflows
   already cover most of the ENDPOINT DISCOVERY menu above (passive URLs, JS/secrets, params, dirs) —
   so do NOT repeat those by hand.
3) GAP-FILL BY HAND — only now, and ONLY for what the workflows did NOT produce: source-map
   reconstruction on key apps, deep JS endpoint extraction on high-value hosts, targeted param mining,
   GraphQL introspection — use the ENDPOINT DISCOVERY menu above as the GAP CHECKLIST, not a from-scratch
   rerun.
4) COVERAGE LEDGER (anti-miss) — with TodoWrite, list EVERY in-scope live asset and high-value endpoint
   as an item and mark it tested / untested as you work. This ledger is how you guarantee nothing is
   skipped: you may wrap up ONLY when no high-value in-scope surface is still untested (or it is
   explicitly out of scope, with a reason).
5) LOOP — whenever triage or exploitation reveals NEW subdomains/hosts/params, run_workflow AGAIN scoped
   to that new surface (narrow), reconcile it into the inventory + ledger, and continue
   recon -> reconcile -> exploit until the ledger is clear or the objective is met.
run_workflow enables ALL of a workflow's options for max coverage (pivot scan + neighbor /24 PTR sweep
stay off for scope safety; pass full=false for the workflow's own defaults). Pick workflows by PURPOSE
from list_workflows — new workflows appear there automatically, so never assume a fixed filename.
EOF
)

# ── per-mode playbooks (branch on the MODE chosen above) ──
BOUNTY=$(cat <<'EOF'
━━ [BUG BOUNTY] prioritized attack surface (highest ROI first — drive from the inventory) ━━
1) Broken access control / IDOR / BOLA: enumerate object refs, swap IDs across two accounts,
   sequential vs UUID, horizontal + vertical, mass-assignment, hidden params, verb tampering.
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
EOF
)

PENTEST=$(cat <<'EOF'
━━ [PENTEST] phased coverage (after the network + web enumeration in RECON above) ━━
Follow PTES + OWASP WSTG/MASVS. Confirm in-scope hosts/apps/accounts, exclusions and windows
first. Run the OWASP WSTG checklist on every web app (auth, session, input validation, access
control, crypto, config, error handling, business logic, client-side, file upload, API authz).
Then:
4) Vulnerability analysis: default/weak creds (hydra/medusa, targeted), missing patches
   (version -> CVE), misconfig, exposed secrets, injection, SSRF, deserialization, path
   traversal, SSTI.
5) Controlled exploitation: confirm REAL risk with a safe proof (no destructive payloads);
   chain where it demonstrates impact.
6) Post-exploitation (ONLY if in scope): privesc (linpeas/winpeas, sudo/SUID, kernel, service
   perms, token/DPAPI), AD attacks (kerberoast, AS-REP roast, ACL abuse, DCSync) via
   BloodHound; segmentation/lateral-movement checks; sensitive-data discovery (no bulk exfil).
7) Reporting: every issue -> CVSS v3.1, evidence (request/response, screenshot, log),
   reproduction, business impact, prioritized remediation.
EOF
)

REDTEAM=$(cat <<'EOF'
━━ [RED TEAM] kill chain (OPSEC: minimize noise, prefer living-off-the-land, test ONE
detection hypothesis at a time, go quiet when defenders react; map each step to ATT&CK) ━━
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
EOF
)

FOOTER=$(cat <<'EOF'
━━ VALIDATION BAR (all modes) ━━
Reproduce twice, minimal NON-destructive PoC, concrete impact narrative. Bug Bounty: dedupe
before reporting and adjust CVSS v3.1 for program context — one proven high-impact bug beats
many guesses. Pentest: CVSS v3.1 per issue; coverage must be defensible against the scope.

━━ OUTPUT (by mode) ━━
• BUG BOUNTY: per finding — title, exact asset/endpoint + request, severity (CVSS + vector),
  reproduction/PoC, impact, concrete remediation.
• PENTEST: finding register (CVSS + evidence + reproduction + fix) + executive risk summary +
  remediation roadmap.
• RED TEAM: attack-path narrative (step -> technique -> result) + ATT&CK coverage heatmap +
  per-phase detection gaps (what fired / what was missed) + blue-team recommendations + full
  deconfliction/action log.

━━ WRAP-UP GATE (no gaps) ━━
Before concluding, re-check the COVERAGE LEDGER: every in-scope live asset and high-value endpoint
must be either tested (with a result — vuln, or a reasoned negative) or explicitly marked
out-of-scope/not-applicable with a reason. Do NOT wrap up while any high-value in-scope surface is
still untested, and do NOT stop just because the first routes were exhausted — loop back to recon
(run_workflow on uncovered surface) until the ledger is clear or the objective is met.
EOF
)

NL=$'\n\n'
DESC="${HEADER}${NL}${ENDPOINT_RECON}${NL}${WORKFLOW_LOOP}${NL}${BOUNTY}${NL}${PENTEST}${NL}${REDTEAM}${NL}${FOOTER}"

GOAL="Run an authorized offensive-security engagement: auto-select the mode (Bug Bounty, Penetration Test, or Red Team) from the scope/RoE, map the attack surface, and deliver reproducible in-scope findings (or reach the objective) with evidence — strictly in scope, non-destructive."

echo "Creating the unified offensive-security task template on $BASE_URL ..."
create "Offensive Security" "$GOAL" "$DESC"
echo "Done. Open New task -> Task template dropdown, or Manage templates."
