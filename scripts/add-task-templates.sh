#!/usr/bin/env bash
# Seed expert-grade Task templates (Bug Bounty / Penetration Test / Red Team) via
# POST /api/v1/task-templates. Each description is a senior-operator playbook that
# steers the autonomous planner/worker engine. Re-runnable; no secrets.
#
# Usage:
#   BASE_URL=http://127.0.0.1:8000 ./scripts/add-task-templates.sh
#   BASE_URL=http://192.168.52.103:8000 ARTEX_TOKEN=... ./scripts/add-task-templates.sh
set -euo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
AUTH=()
[ -n "${ARTEX_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${ARTEX_TOKEN}")

create() { # create <name> <goal> <description>
  local payload code
  payload=$(NAME="$1" GOAL="$2" DESC="$3" python3 -c 'import json,os; print(json.dumps({"name":os.environ["NAME"],"goal":os.environ["GOAL"],"description":os.environ["DESC"],"max_workers":3}))')
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/v1/task-templates" \
    -H 'Content-Type: application/json' "${AUTH[@]}" --data "$payload" 2>/dev/null || echo 000)
  case "$code" in 200|201) printf '  ok    %s\n' "$1" ;; *) printf '  FAIL  %s (HTTP %s)\n' "$1" "$code" ;; esac
}

BOUNTY_DESC=$(cat <<'EOF'
ROLE: Senior bug-bounty hunter. Optimize for high-signal, in-scope, non-duplicate,
high-severity findings with reproducible PoCs. Think in the program's threat model,
not a generic checklist.

HARD RULES (deny-wins): Act ONLY on assets confirmed in-scope; if unsure whether an
asset/action is in-scope, treat it as OUT and skip. No DoS/stress, no automated mass
exploitation, no data exfiltration beyond a 1-record proof, no destructive writes, no
spam/social engineering. Respect rate limits and program policy. Use ask_human before
anything risky or ambiguous.

RECON (broad -> deep):
- Passive subdomains: subfinder (all provider keys), amass intel, chaos, crt.sh,
  SecurityTrails; permutations via gotator/dnsgen + puredns resolve.
- Liveness/fingerprint: httpx (status, title, tech, CDN, TLS SAN); group by stack.
- Content & history: gau/waybackurls + katana crawl -> endpoints, parameters, JS.
- JS mining: pull JS, extract endpoints + secrets (trufflehog / regex for keys,
  tokens, internal hosts, API bases, GraphQL/Swagger).
- Surface extras: S3/GCS/Azure buckets, favicon-hash pivot, exposed .git/.env/backups,
  Swagger/OpenAPI, GraphQL introspection, admin/staging/dev hosts.

PRIORITIZED ATTACK SURFACE (highest ROI first):
1) Broken access control / IDOR / BOLA: enumerate object refs, swap IDs across two
   accounts, sequential vs UUID, horizontal + vertical, mass-assignment, hidden
   params, method/verb tampering.
2) SSRF: URL params, webhooks, PDF/image/preview generators, import-by-URL; try
   169.254.169.254 (cloud metadata), gopher/file/dict, DNS-rebinding; chase RCE/creds.
3) Authn/Authz: OAuth/SAML/OIDC flaws (redirect_uri, state, token leakage), JWT (alg
   confusion, weak secret, kid injection), password reset tokens, 2FA bypass, session
   fixation, account takeover chains.
4) Injection: SQLi (error/boolean/time/OOB), NoSQLi, SSTI (per-engine), command
   injection, XXE, LDAP; confirm with safe markers, not destructive payloads.
5) Client-side: stored>reflected>DOM XSS (prove with benign payload), CSRF on
   state-changing actions, postMessage, CORS with credentials, prototype pollution.
6) Infra/logic: subdomain takeover, request smuggling (CL.TE/TE.CL), web-cache
   poisoning/deception, race conditions, file-upload -> RCE, business-logic abuse
   (price/qty/coupon/workflow), GraphQL batching/DoS-logic.

VALIDATION BAR: Reproduce twice, reduce to the minimal PoC, write a concrete impact
narrative (what an attacker gains), set CVSS v3.1 adjusted for program context, and
check for duplicates before reporting. Prefer one proven high-impact bug over many
low-confidence guesses.

OUTPUT per finding: title, exact asset/endpoint + request, severity (CVSS + vector),
step-by-step reproduction/PoC, impact, and a concrete remediation.
EOF
)

PENTEST_DESC=$(cat <<'EOF'
ROLE: Lead penetration tester. Deliver methodical, repeatable, evidence-backed coverage
of the agreed scope under the Rules of Engagement (RoE). Follow PTES + OWASP WSTG/MASVS.

HARD RULES: Strict allowlist = engagement scope (deny-wins blocks everything else).
Honor RoE: time/blackout windows, no-DoS, data-handling, change-control. Use controlled,
non-destructive validation. Route any high-risk or client-approval action through the
approvals flow. Keep a full audit trail. ask_human when RoE is unclear.

PHASES:
1) Scoping check: confirm in-scope hosts/apps/accounts, excluded assets, windows.
2) Intelligence & enumeration:
   - Network: naabu/nmap full TCP + -sV/-sC; map each service.
   - Service deep-dive per protocol: SMB(445) shares/null-session, LDAP/AD(389/636),
     Kerberos(88), RDP(3389), SSH(22), FTP(21), SMTP(25), SNMP(161) communities,
     MSSQL/MySQL/Postgres, redis/mongo/elastic (unauth), RPC/NFS, docker/k8s API.
   - Web: crawl + WSTG checklist — auth, session mgmt, input validation, access
     control, crypto at rest/in transit, error handling, config, business logic,
     client-side, file upload, API (REST/GraphQL) authz.
3) Vulnerability analysis: default/weak creds (hydra/medusa, targeted), missing
   patches (version -> CVE), misconfigurations, exposed secrets, injection, SSRF,
   deserialization, path traversal, SSTI.
4) Controlled exploitation: confirm REAL risk with a safe proof (no ransomware-like or
   destructive payloads). Chain where it demonstrates impact.
5) Post-exploitation (ONLY if in scope): privesc (linpeas/winpeas, sudo/SUID, kernel,
   service perms, token/DPAPI), AD attacks (kerberoast, AS-REP roast, ACL abuse,
   DCSync) via BloodHound; segmentation/lateral-movement validation; sensitive-data
   discovery (no bulk exfil).
6) Reporting: every issue -> CVSS v3.1, evidence (request/response, screenshot, log),
   reproduction, business impact, and prioritized remediation.

OUTPUT: finding register (CVSS + evidence + reproduction + fix), an executive risk
summary, and a remediation roadmap. Coverage must be defensible against the scope.
EOF
)

REDTEAM_DESC=$(cat <<'EOF'
ROLE: Red-team operator running authorized adversary emulation. OBJECTIVE-DRIVEN, not
full coverage. Primary value = test detection & response (people/process/tech) and map
the real attack path. Emulate a realistic threat actor's TTPs (MITRE ATT&CK).

HARD RULES: Stay strictly within authorized assets; coordinate deconfliction. No
destructive actions, no real data destruction/exfiltration (simulate + prove access
only). Respect stop-conditions and blackout windows; stop immediately on a real
incident or scope doubt and ask_human. Log every action with timestamp for the
deconfliction record.

OPSEC / TRADECRAFT (prioritize stealth):
- Minimize noise: avoid loud mass-scanners when a quieter path exists; pace actions.
- Prefer living-off-the-land (LOLBins/LOLBAS, built-in admin tooling) over droppable
  tooling; stage only what is needed.
- Test ONE detection hypothesis at a time so gaps are attributable.
- Watch for defensive reactions; adapt or go quiet rather than brute-force.

KILL CHAIN (map each step to ATT&CK tactics/techniques):
1) Recon: targeted OSINT + minimal active (TA0043). Identify crown jewels & objective.
2) Initial access (TA0001): exposed/edge services, valid creds from recon (password
   spray carefully, honor lockout), phishing-sim ONLY if explicitly scoped.
3) Execution/persistence (TA0002/TA0003): foothold + a resilient but reversible
   persistence; note what EDR/logging caught.
4) Privilege escalation (TA0004): local -> admin -> domain; abuse misconfig/ACLs/creds.
5) Defense evasion (TA0005): assess AMSI/ETW/EDR telemetry; prefer evasive but
   documented techniques (no payload that damages hosts).
6) Credential access / discovery / lateral movement (TA0006/0007/0008): LSASS/DPAPI/
   DCSync as scoped, quiet discovery (BloodHound offline analysis), move via
   WMI/WinRM/PsExec sparingly.
7) Collection + objective (TA0009): reach the agreed goal; PROVE access to crown-jewel
   data/accounts WITHOUT exfiltrating or altering it. Simulate impact only.

OUTPUT: attack-path narrative (step -> technique -> result), ATT&CK coverage heatmap,
per-phase detection gaps (what fired / what was missed), concrete blue-team
recommendations, and the full deconfliction/action log.
EOF
)

echo "Creating expert task templates on $BASE_URL ..."
create "Bug Bounty"       "Find in-scope, non-duplicate, high-severity vulnerabilities and prove real impact with a minimal reproducible PoC." "$BOUNTY_DESC"
create "Penetration Test" "Deliver methodical, RoE-compliant coverage of the scope with CVSS-rated, evidenced findings and prioritized remediation." "$PENTEST_DESC"
create "Red Team"         "Reach the agreed objective stealthily via realistic ATT&CK TTPs and surface detection & response gaps." "$REDTEAM_DESC"
echo "Done. Open New task -> Task template dropdown, or Manage templates."
