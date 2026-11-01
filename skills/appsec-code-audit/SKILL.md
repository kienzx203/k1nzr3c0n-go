---
name: appsec-code-audit
description: Use for SYSTEMATIC white-box / grey-box bug hunting over an application — turning one bug into a bug CLASS (variant analysis), running SAST (CodeQL/Semgrep/SARIF) + dependency audit, parsing a Burp Suite project to map traffic/endpoints, scanning APK/Firebase, and ALWAYS false-positive-checking before reporting. Modeled on the Trail of Bits skills workflow.
metadata:
  type: offensive
  phase: vulnerability-analysis
  tools: codeql, semgrep, weggli, burp, apktool, jadx, SARIF, trivy, osv-scanner
---

# AppSec Code Audit — systematic, not scattershot

Hunt bugs as a WORKFLOW, not isolated pokes. When you have source, a Burp
project, an APK, or even one confirmed bug, this is how to turn it into thorough,
evidence-backed coverage. (Modeled on the Trail of Bits `skills` marketplace.)

## 1. Map the attack surface first
- **Burp project parsing**: pull the sitemap + proxy history → the real endpoints,
  params, auth flows, and interesting responses. Prioritize authenticated,
  state-changing, and file/ID-handling endpoints.
- **Source**: identify entry points (routes/handlers), sinks (exec/query/file/
  deserialize/SSRF), and the dataflow between them. Note the frameworks + their
  known footguns.
- **Mobile**: APK → `apktool`/`jadx` → manifests, exported components, secrets,
  endpoints; **Firebase** → open DB/storage rules, misconfigured RTDB/Firestore.

## 2. Static analysis (SAST) — breadth, then triage
- Run **Semgrep** (fast, taint rules) and/or **CodeQL** (deep dataflow); export
  **SARIF** so results are structured and diffable. See the semgrep-sast skill
  for rule-writing.
- **Dependency / SCA**: `osv-scanner` / `trivy` / `npm|pip audit` → known-vuln
  deps, then check they're REACHABLE (a vuln in unused code is INFO, not a bug).
- Treat every SAST hit as a LEAD, not a finding. Rank by sink severity +
  reachability + auth boundary crossed.

## 3. Variant analysis — one bug → the bug CLASS
The highest-leverage move. When you confirm ONE bug:
1. Abstract it: what is the ROOT pattern (missing authz check? an unsanitized sink?
   a dangerous API used one way)?
2. Write a Semgrep/CodeQL/`weggli` query that matches that pattern.
3. Sweep the WHOLE codebase for every other instance. One IDOR usually means ten.
4. Each new instance gets the same PoC + FP-check treatment.

## 4. False-positive check — MANDATORY before reporting
A SAST hit or a reflected string is NOT a bug. Before `[CONFIRMED]` (see
finding-discipline):
- Trace the FULL path from a real attacker-controlled source to the sink; confirm
  no sanitizer/guard/framework protection breaks it.
- Reproduce it live (or in a harness) with a minimal non-destructive PoC, twice.
- Rule out: dead code, internal-only entry, already-escaped output, WAF/CSP that
  neutralizes it, a control the SAST tool couldn't see.
- Mark the verdict (confirmed / false-positive) so it's never re-chased.

## 5. Package for the deliverable
Confirmed bugs → `report_finding` with the PoC + evidence; the engagement write-up
follows the report-writing skill. Map each finding to CWE/ATT&CK, and note the
variant sweep (which other instances you checked and cleared).

## Discipline
Authorized scope only; SAST/Burp parsing is read-only but the PoC step touches the
target — keep it non-destructive and in-scope. Reachability + a live PoC are the
bar; no CONFIRMED from a tool hit alone.
