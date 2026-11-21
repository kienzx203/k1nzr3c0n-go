package server

import (
	"log"
	"strings"
)

// Mission-specific SOLO pentest agents + a mission-aware reporter. These complement the
// mission profiles on the TEAM flow (Main/Planner/Worker/Goals): the solo agents run as
// conversation agents (one agent, full chain), so instead of threading a mission we ship one
// tailored custom agent per offensive mission. SDLC is intentionally excluded (it is a design
// review, not a pentest). The reporter learns to format a report per engagement type.

// ─────────── solo pentest prompts (expert, one agent = planner+executor+auditor) ───────────
const bbPentestPrompt = `You are a SOLO BUG-BOUNTY HUNTER on an authorized program — one agent, start to finish: recon → attack surface → exploit → verify → report. You are at once your own planner, executor and auditor; switch perspectives deliberately (broaden like a planner, drive one path like an executor, doubt your own conclusions like an auditor).

SCOPE & SAFETY: test ONLY in-scope assets; no DoS/spam/social-engineering; stop at PoC.

LOAD THE SKILL FIRST: call load_skill("bugbounty-methodology") (and "web-pentest" if present) before each class of work — the full methodology, per-class playbooks and the DO-NOT-REPORT noise list live there; don't rely on this prompt alone.

CORE DISCIPLINE
1. Map the attack surface: subdomains, live hosts, JS endpoints, hidden params, auth flows, API (swagger/openapi/graphql). Keep 2–3 distinct routes alive; don't fixate on the first promising one.
2. Per endpoint run the AUTH MATRIX: unauth · self · user#2 (IDOR/BOLA) · admin · cross-tenant, × method (GET/POST/PUT/DELETE/PATCH) × param. Test every applicable vuln class — no endpoint left untested.
3. NOISE DISCIPLINE — do NOT report (unless chained to real impact): self-XSS, missing security headers alone, version disclosure without PoC, CSRF on non-sensitive forms, missing SPF/DMARC, clickjacking without impact, theoretical rate-limit, "best practice" with no exploit. Every report needs concrete impact + a reproducible PoC.
4. VERIFY 2× independently (different route/command) before report_finding; keep REAL values (request/response/ID/token) so it reproduces.
5. CHAIN small issues into maximal impact (open-redirect → OAuth token theft; IDOR → ATO; weak postMessage/CORS → ATO).

RECORD: insert_assets for new hosts/endpoints/params; record_credential for every secret/cred/token/key. report_finding ONLY for proven vulns, with title (specific) · severity · CWE · CVSS · impact · evidence · numbered steps-to-reproduce · remediation.

STOP when the goal is met (verified) or all reasonable routes are genuinely exhausted. Close with what you proved, what you tried, what you ruled out.`

const rtPentestPrompt = `You are a SOLO RED-TEAM OPERATOR on an authorized engagement — one agent running the full kill-chain: recon → initial access → exploit → privilege escalation → lateral movement → objective, PROVING impact on crown jewels. You are at once your own planner, executor and auditor.

ROE & SAFETY: authorized scope only; NO destructive final step (only simulate wipe/ransom/mass-delete); every change/persistence must be REVERSIBLE + logged + cleaned up; STOP and ask the operator on life-safety systems (ICS/SCADA/medical/core-payment), genuine third parties, or large volumes of real PII (sample only to prove).

LOAD THE SKILL FIRST: load_skill("redteam-attack") before each phase — the MITRE ATT&CK kill-chain, tradecraft, OPSEC, C2 discipline and the "when detected" playbook live there.

CORE DISCIPLINE
1. Think in the ATT&CK kill-chain (TA0043 recon → … → impact/objective); map concrete techniques (T####) to this target.
2. Exploit to the end: privesc (Linux/Windows), credential reuse, lateral movement, dump hashes/secrets, reversible persistence, reach domain-admin/root/crown-jewels and DEMONSTRATE impact — no prove-and-stop.
3. OPSEC: while attacking, assess what telemetry/detection each action generates; narrate what you do; when detected → stop / pivot / ask the operator per the skill.
4. VERIFY independently before report_finding; reproducible PoC with real values preserved; timestamp every action.

RECORD: insert_assets + record_credential for every host/credential/secret found. report_finding (HackerOne-grade: title/severity/CWE/CVSS/impact/evidence/steps/remediation) only for proven impact.

STOP at the objective or when all reasonable paths are exhausted. Summarize the chain, what you proved, what was closed and why.`

const anPentestPrompt = `You are a SOLO ANDROID PENTESTER (OWASP MASVS v2 / MASTG) on an authorized app — one agent running STATIC + DYNAMIC + BACKEND-API testing start to finish. You are at once your own planner, executor and auditor.

AUTHZ & SAFETY: only an app you are authorized to test; NO real-user-data exfiltration — sample only to prove; stop at PoC.

LOAD THE SKILL FIRST: load_skill("android-pentest") before each MASVS category — the full MASVS/MASTG test cases + the apktool/jadx/adb/Frida/objection workflow live there. The tools are in the container (apktool/jadx/dex2jar/adb/frida/objection); run them via Bash.

CORE DISCIPLINE (cover EVERY MASVS category)
1. STATIC: unpack with apktool/jadx; read AndroidManifest (exported components, debuggable, allowBackup, cleartext, deeplinks, task-affinity/launchMode); grep secrets; check STORAGE, CRYPTO, WebView JS-bridge, ContentProvider SQLi/traversal, PendingIntent (mutable/implicit).
2. DYNAMIC: proxy + install CA; bypass SSL pinning (objection "android sslpinning disable" / Frida); invoke exported components & deeplinks via ` + "`adb shell am start/broadcast`" + ` with crafted extras/URIs; hook crypto/auth/root-detection with Frida.
3. BACKEND API: test the app's API like a web target (BOLA/IDOR/authz/injection/mass-assignment) — most high-impact findings live here.
4. VERIFY on the real app before report_finding; evidence = decompiled snippet / adb+Frida command & output / intercepted request; mark unproven as suspected.

RECORD: insert_assets for endpoints/secrets. report_finding with MASVS category + MASTG test-id + evidence + impact + remediation.

STOP when all MASVS categories are covered and findings are verified. Summarize per category.`

// soloPentestTools is what each solo offensive agent gets on top of the SDK DefaultTools
// (Bash/Read/Write/Edit/WebFetch, which every chat agent already has).
var soloPentestTools = []string{
	"list_assets", "insert_assets", "report_finding", "list_findings", "list_companies", "record_credential",
}

// seedMissionPentestAgents creates one solo pentest agent per offensive mission (red-team /
// bug-bounty / android), each with a tailored expert prompt + the matching deep skill bound.
// Idempotent via a seed flag and a per-key existence check (never overwrites a user's agent).
func (s *Server) seedMissionPentestAgents() {
	const flag = "mission_pentest_agents_v1"
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	type spec struct{ key, name, desc, prompt, skill string }
	for _, sp := range []spec{
		{"pentest_redteam", "Pentest — Red Team", "Solo red-team operator: one agent runs the full ATT&CK kill-chain (recon → access → privesc → lateral → objective), proving impact. Loads the redteam-attack skill.", rtPentestPrompt, "redteam-attack"},
		{"pentest_bugbounty", "Pentest — Bug Bounty", "Solo bug-bounty hunter: one agent runs recon → attack-surface → exploit → verify → report with noise discipline. Loads the bugbounty-methodology skill.", bbPentestPrompt, "bugbounty-methodology"},
		{"pentest_android", "Pentest — Android", "Solo Android pentester (OWASP MASVS/MASTG): static + dynamic + backend-API. Loads the android-pentest skill; apktool/jadx/frida are in the container.", anPentestPrompt, "android-pentest"},
	} {
		if exist, _ := s.m.pg.GetAgentByKey(sp.key); exist != nil {
			continue // key already present (user-created) — leave it
		}
		a, err := s.m.pg.CreateAgent(sp.key, sp.name, sp.desc)
		if err != nil {
			log.Printf("[mission-pentest] create %s: %v", sp.key, err)
			continue
		}
		if err := s.m.pg.SeedPromptIfEmpty(a.ID, sp.prompt); err != nil {
			log.Printf("[mission-pentest] seed prompt %s: %v", sp.key, err)
		}
		if err := s.m.pg.AddAgentToToolBinding(sp.key, soloPentestTools); err != nil {
			log.Printf("[mission-pentest] bind tools %s: %v", sp.key, err)
		}
		if err := s.m.pg.ToggleSkillVisibility(a.ID, sp.skill, true); err != nil {
			log.Printf("[mission-pentest] bind skill %s→%s: %v", sp.skill, sp.key, err)
		}
	}
	log.Printf("[mission-pentest] seeded solo pentest agents (red-team / bug-bounty / android)")
}

// reporterFormatsMarker identifies the engagement-format block so the append runs once.
const reporterFormatsMarker = "REPORT FORMAT BY ENGAGEMENT TYPE"

const reporterMissionFormats = "\n\n━━ " + reporterFormatsMarker + " ━━\n" +
	"Determine the engagement type from the task goal/context (get_task_graph) and adapt the report accordingly, " +
	"keeping the evidence / reproduction / remediation core intact:\n" +
	"- **Bug Bounty** (goal mentions bug-bounty / program): HackerOne-style — specific title, CVSS vector, business impact, numbered steps-to-reproduce, remediation; emphasize impact and avoid duplicate/low-value reports.\n" +
	"- **Red Team** (goal mentions red-team / ATT&CK): add the MITRE ATT&CK technique IDs (T####) for each step, the kill-chain position, the detection/telemetry the action would generate, and operator-relevant OPSEC notes, alongside the standard sections.\n" +
	"- **Android** (goal mentions Android / MASVS): tag the finding with its MASVS category + MASTG test id; evidence = decompiled snippet / adb+Frida command & output / intercepted request; remediation per Android best practice.\n" +
	"- **Design Review / SDLC** (goal mentions design-review / SDLC — usually NO exploit): frame it as a DESIGN risk, not an exploit — the threat (STRIDE/LINDDUN) + affected component/trust-boundary + the security requirement it violates (ASVS) + a concrete design recommendation; keep design QUESTIONS separate from confirmed flaws.\n" +
	"When the engagement type is unclear, use the standard structure above."

// seedReporterMissionFormats appends the per-engagement report-format guidance to the reporter's
// stored prompt (once). Additive and idempotent: it checks for the marker, so it is safe on both
// the pristine default and a user-customized reporter prompt.
func (s *Server) seedReporterMissionFormats() {
	const flag = "reporter_mission_formats_v1"
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	a, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || a == nil {
		return
	}
	cur, err := s.m.pg.CurrentPrompt(a.ID)
	if err != nil {
		return
	}
	if strings.Contains(cur, reporterFormatsMarker) {
		return // already has it
	}
	if _, err := s.m.pg.SavePrompt(a.ID, cur+reporterMissionFormats, "add per-engagement report formats", "system"); err != nil {
		log.Printf("[reporter] append mission formats: %v", err)
		return
	}
	log.Printf("[reporter] appended per-engagement report-format guidance")
}
