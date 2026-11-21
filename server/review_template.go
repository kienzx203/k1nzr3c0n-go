package server

import (
	"errors"
	"log"

	"github.com/Autumn-27/artex/db"
)

// reviewTemplateName is the stable identity of the seeded preset (name is unique, so the
// seed is idempotent: a second startup hits ErrTaskTemplateNameConflict and is a no-op).
const reviewTemplateName = "Source Code Review + PoC"

// reviewTemplateDescription is the professional brief fed to the agents as the task
// description. It encodes the full review methodology and names the deterministic tools
// (review_seed/review_coverage/review_report, sast_scan, list_endpoints, list_code_units)
// so the run is high-recall, no-miss, and ends in a reproducible PoC + consolidated report.
const reviewTemplateDescription = `AUTHORIZED SECURITY SOURCE-CODE REVIEW + PROOF-OF-CONCEPT.

MISSION: review the target source EXHAUSTIVELY — every endpoint considered against EVERY
vulnerability class, no function/endpoint/class silently skipped — confirm each real issue
with a reproducible Proof-of-Concept, and deliver a professional report. HYBRID scope: reason
over the SOURCE and, when a running instance is available, validate against it — STOP AT POC
(demonstrate impact; do not weaponize, pivot, exfiltrate, or persist).

TARGET SOURCE
- Source to review: your working directory and/or the path(s) in the "REVIEW SOURCE" /
  uploaded-files block. If the goal gives a git/archive URL not yet local, fetch it first.
- Treat the target as READ-ONLY. Use Write/Edit only for your OWN PoC scripts in a scratch dir.

STEP 0 — ORIENT BEFORE YOU HUNT (the three mental models that make the hard classes findable)
Do this first; without it, access-control, logic and second-order bugs get reviewed shallowly.
0a. THREAT MODEL: identify trust boundaries (where untrusted data enters), and the ASSETS
    worth protecting (authentication, PII, money/transactions, admin functions, secrets).
    Prioritise review depth toward endpoints that touch these crown jewels.
0b. AUTHORIZATION MODEL: enumerate the roles/principals and, for each sensitive object,
    its OWNERSHIP rule (who may read/modify it). You cannot judge IDOR/BOLA or missing-authz
    per endpoint without this model — build it from the auth/middleware/policy code first.
0c. STORE MAP: list what writes user-controlled data into each table/file/cache/session and
    what later READS it back — this is the map you need to trace stored-XSS / second-order SQLi.
0d. DEPENDENCIES & SECRETS: run sca_scan(<source dir>) — REAL SCA that checks every declared
    dependency version against OSV.dev and returns the actual CVE/GHSA ids + the fixed
    version (do NOT guess CVEs from memory; use this tool's authoritative output). For each
    vulnerable library, confirm it is actually used/reachable before rating impact. Also scan
    the tree AND, if a .git exists, git history for committed secrets/keys.

STEP 1 — BUILD THE DENOMINATOR (deterministic, no eyeballing)
- review_seed(<source dir>): records EVERY function (SAST inventory), EVERY endpoint (routes
  with convention routing EXPANDED + class/method paths COMPOSED + non-HTTP entries:
  GraphQL/WebSocket/queue/cron/CLI/serverless) and every template/config file.
- sast_scan(<source dir>): taint candidates + non-taint detectors (BROKEN_ACCESS_CONTROL,
  IDOR, HARDCODED_SECRET, WEAK_CRYPTO, MASS_ASSIGNMENT, CSRF, stored/second-order,
  template XSS/SSTI). list_endpoints / list_code_units read the same inventory.

STEP 2 — THE REVIEW MATRIX: EVERY ENDPOINT × EVERY VULNERABILITY CLASS (risk-based depth)
For EACH endpoint (and each function/template/config), consider EVERY class in the checklist
and record a verdict for each — one of:
  • vulnerable (→ confirm + PoC + report),
  • reviewed-safe (read the code; say WHY: parameterized/context-correct-encoder/constant/
    proper-authz at file:line),
  • N/A (give a CONCRETE code reason, e.g. "no DB access in this handler → SQLi N/A", "no
    HTML/response output → XSS N/A"). N/A is a judgement tied to the code, NEVER a rubber
    stamp to clear the gate.
Allocate DEPTH by risk: spend real effort where the endpoint's inputs/sinks and the Step-0
assets make a class plausible; dismiss implausible classes fast with the one-line reason.
This keeps "every endpoint × every class" honest AND tractable — it does not license skipping.
Per endpoint: find the handler, trace data flow through every reachable function (code_refs
for cross-file), identify every untrusted input (query/body/headers/cookies/path/uploaded/
deserialized/second-order-from-store per your Step-0 store map), and judge each class.
Record with review_mark(unit, classes=[classes you actually judged], verdict=reviewed|
vulnerable|na) for EVERY unit — an unmarked unit stays pending and blocks completion.

CLASS CHECKLIST (the "all lỗ hổng" set):
A. Injection: SQL, NoSQL, OS-command, LDAP, XPath, XQuery, code/eval, template(SSTI),
   header/CRLF, log, ORM-raw, argument injection.
B. XSS: reflected, stored/second-order, DOM; template unescaped output (|safe, {!! !!},
   v-html, innerHTML, dangerouslySetInnerHTML).
C. Access control: missing authn, missing authz, IDOR/BOLA, broken function-level authz,
   privilege escalation, forced browsing, mass assignment/over-posting. (Use the Step-0b model.)
D. SSRF (direct + redirect/DNS), open redirect, request smuggling.
E. File: path traversal, LFI/RFI, arbitrary file read/write/delete, unrestricted upload,
   zip-slip, XXE.
F. Deserialization/object injection (gadget chains), prototype pollution.
G. Authn & session: weak/replayable tokens, missing expiry, fixation, JWT alg/signature
   flaws, password/reset logic, 2FA bypass.
H. Business logic & race: TOCTOU, workflow/step bypass, price/quantity tampering, replay,
   insecure state transitions.
I. Crypto & secrets: weak algo/mode (MD5/SHA1/DES/ECB/RC4), static/predictable IV/key/salt,
   bad randomness, disabled TLS verification, hardcoded secrets.
J. Config: CSRF (state-change w/o token on cookie-auth), permissive CORS+credentials, exposed
   debug/admin endpoints, default creds, verbose errors, missing security headers, clickjacking.
K. Availability: ReDoS, unbounded allocation/recursion, decompression bombs.
L. Memory safety (C/C++/unsafe): buffer overflow, UAF, double-free, OOB, integer overflow,
   format string.
M. Dependencies (SCA): known-vulnerable library/framework versions — from sca_scan (OSV
   CVEs + fixed version), reported with the real CVE id, not a guessed one.

STEP 3 — CONFIRM (evidence + CONFIDENCE, not blind suppression)
A candidate is REAL only when the entry is attacker-reachable AND no effective validation/
sanitizer/encoding sits on the path. Read the actual code; adversarially test every sanitizer
(right context? bypassable?). A constant/hardcoded arg, a correct parameterized query, a
context-correct encoder, or a proper access check means NOT a vulnerability. But do NOT
suppress a plausible issue just to look clean: if you cannot fully prove or disprove it,
report it as "suspected" with a confidence level and exactly what is unresolved — never drop
it silently. Goal: every report is evidence-backed and confidence-rated; nothing real hidden.

STEP 4 — POC (+ chaining)
For each confirmed issue build the minimal reproducible request/input/command demonstrating
impact, with exact steps + observed evidence (prefer a benign proof: canary read, reflected
marker, observable error). Also consider CHAINS: combine lower-severity issues (e.g. open
redirect + token leak, IDOR + mass-assignment) into a higher-impact scenario and note it.

STEP 5 — REPORT (professional)
report_finding for each issue with the STANDARD source→sink: source (file:line of untrusted
input), sink (file:line of dangerous op), flow (path across files + the sanitizer absent/
bypassed), AND: a CWE id, a CVSS v3.1 vector+score, a severity, a confidence, a concrete
remediation (with a fixed-code snippet where useful), and the PoC. Disposition EVERY sast_scan
candidate (confirmed → report, or false-positive WITH a concrete reason). Then review_report()
once for the consolidated, severity-ranked deliverable; open it with a short EXECUTIVE SUMMARY
(overall risk posture + count by severity). Write the report in the user's language (default
Vietnamese if the task is in Vietnamese).

COMPLETION GATE (no-miss, ENGINE-ENFORCED) — NOT done until:
  (1) review_coverage() shows pending = 0 — every endpoint/function/template/config reviewed,
      each judged against the full class checklist (vulnerable / reviewed-safe / N/A-with-reason); and
  (2) every sast_scan candidate is dispositioned.
Then deliver review_report().

PRINCIPLES: exhaustive recall (every endpoint × every class considered; depth by risk; nothing
silently skipped), evidence-backed + confidence-rated findings (report real issues even when
only "suspected" — never hide them, never invent them), honest conclusions, stop at PoC.`

// reviewTemplateGoal is the crisp, checkable acceptance statement.
const reviewTemplateGoal = `Complete the full REVIEW MATRIX: every endpoint (and every function, template, config) ` +
	`judged against EVERY vulnerability class — each cell vulnerable / reviewed-safe / N/A, ` +
	`each with a concrete code reason, depth allocated by risk (review_coverage pending = 0; ` +
	`every sast_scan candidate dispositioned). Build the threat model, authorization model and ` +
	`store map first; include a dependency (SCA) + git-secrets pass. Each confirmed vulnerability ` +
	`has a standard source→sink, CWE, CVSS, confidence, reproducible PoC and concrete remediation; ` +
	`plausible-but-unproven issues are reported as "suspected" (never hidden, never invented). ` +
	`Deliver one consolidated review_report with an executive summary, in the user's language. ` +
	`No endpoint, function, or vulnerability class silently skipped.`

// seedVulnReviewSkill consolidates the ~110 per-vulnerability agents into ONE skill
// (appsec-vuln-verify) bound to the three review agents, then prunes those agents from the
// list. Runs ONCE (flag-guarded) so a user's own custom agents are never touched later.
// The SAST engine itself is unaffected — it reads the per-class knowledge from its own
// skills/ folder + agents.py, not from the DB agent rows.
func (s *Server) seedVulnReviewSkill() {
	const flag = "vuln_agents_to_skill_v1"
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	for _, key := range []string{"worker", "planner", "mainagent"} {
		if a, err := s.m.pg.GetAgentByKey(key); err == nil && a != nil {
			if err := s.m.pg.ToggleSkillVisibility(a.ID, "appsec-vuln-verify", true); err != nil {
				log.Printf("[agents] could not bind appsec-vuln-verify to %s: %v", key, err)
			}
		}
	}
	// NOTE: no agent pruning here — k1nzr3c0n does not have the per-vulnerability agents that
	// SAST_k1nz had, so there is nothing to clean and a blanket DELETE could remove k1nzr3c0n's
	// own custom agents. We only bind the consolidated skill.
	log.Printf("[agents] bound appsec-vuln-verify skill to worker/planner/mainagent")
}

// seedReviewTaskTemplate presets the professional review template once. Idempotent: the
// template name is unique, so a re-run is a no-op (name conflict is swallowed).
func (s *Server) seedReviewTaskTemplate() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	in := db.TaskTemplateInput{
		Name:        reviewTemplateName,
		Description: reviewTemplateDescription,
		Goal:        reviewTemplateGoal,
		Mission:     "review-source",
	}
	_, err := s.m.pg.CreateTaskTemplate(in)
	switch {
	case err == nil:
		log.Printf("[templates] seeded the %q task template", reviewTemplateName)
	case errors.Is(err, db.ErrTaskTemplateNameConflict):
		// already present — refresh its content if this build's default changed, so the
		// deep-review methodology stays current without a user having to recreate it.
		s.refreshReviewTaskTemplate(in)
	default:
		log.Printf("[templates] could not seed %q template: %v", reviewTemplateName, err)
	}
}

// refreshReviewTaskTemplate overwrites the seeded template's description/goal when the
// shipped default has changed (matched by name). It never touches a user's OWN templates.
func (s *Server) refreshReviewTaskTemplate(in db.TaskTemplateInput) {
	list, err := s.m.pg.ListTaskTemplates()
	if err != nil {
		return
	}
	for _, t := range list {
		if t.Name != reviewTemplateName {
			continue
		}
		if t.Description == in.Description && t.Goal == in.Goal && t.Mission == in.Mission {
			return // already current
		}
		if _, err := s.m.pg.UpdateTaskTemplate(t.ID, in); err != nil {
			log.Printf("[templates] could not refresh %q template: %v", reviewTemplateName, err)
		} else {
			log.Printf("[templates] refreshed the %q task template to the current default", reviewTemplateName)
		}
		return
	}
}
