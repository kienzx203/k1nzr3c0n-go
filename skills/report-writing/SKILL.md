---
name: report-writing
description: Use when writing the FINAL engagement deliverable — the red-team / pentest report. Structures the attack-path narrative, MITRE ATT&CK heatmap, findings, detection & response (purple), IOCs for blue, and prioritized remediation. Invoke at the end of an engagement (or at a reporting checkpoint), after findings are recorded.
metadata:
  type: reporting
  phase: closeout
---

# Report Writing — the engagement deliverable

The server's `/api/report` gives you the **Findings** table (severity + evidence per finding).
That is NOT the report. A red-team deliverable also tells the **story** (how the objective was
reached), maps it to **ATT&CK**, and hands the blue team everything they need to **detect and
fix** it. This skill is that structure. Write it to the engagement **workspace** as markdown.

## Iron rules (inherit the finding-discipline skill)
- **No `[CONFIRMED]` without proof.** Every claim of access/impact maps to an evidence artifact
  (traffic, screenshot, file on disk). A plausible step you did not execute is NOT in the report —
  record it as a *reachable, untested path* instead.
- **Non-destructive, impact simulated.** State what you proved and how, never what you "could have".
- **Every technique gets an ATT&CK ID** (`Txxxx[.xxx]`). Every finding gets a remediation.
- Business-readable at the top, technically exact below. No raw scan dumps.

## Required sections (in order)

1. **Executive summary** — 1 paragraph for leadership: what was authorized, the worst demonstrated
   impact (crown jewels reached?), the 3 highest risks, and the overall detection posture. No jargon.
2. **Scope, RoE & deconfliction** — authorized targets (names AND IPs), assume-breach vs black-box,
   time window, exclusions, and the **deconfliction log** (source IPs, accounts/implants used, any
   notifications) so blue can separate the test from a real incident.
3. **Attack-path narrative** — the engagement chronologically. For each step:
   `step → ATT&CK tactic/technique (Txxxx) → result → evidence ref`. Show the CHAIN from initial
   access to objective; branch points and dead ends noted briefly.
4. **MITRE ATT&CK heatmap** — a table of tactics × techniques actually USED (TA0001→TA0040), one row
   per technique: `technique | where | detected? (fired/missed/unknown)`. This doubles as the
   coverage + detection view.
5. **Findings** — pull the `/api/report` Findings table; per finding: severity, affected asset,
   `[CONFIRMED]` PoC (reproducible, minimal), impact, and the ATT&CK technique it maps to.
6. **Detection & response (purple)** — per key action: **what fired** (alert/log) vs **what was
   missed**; name the **detection gaps** (no telemetry / no alert / alert ignored). If you had no
   blue-side visibility, say so and list what SHOULD have fired.
7. **IOCs for the blue team** — callback/C2 domains+IPs, file hashes, created/modified accounts,
   persistence artifacts, and **timestamps**, so blue can hunt and confirm cleanup.
8. **Remediation** — prioritized (P0→P3), each mapped to the finding/technique it closes, with the
   concrete fix (patch/config/arch) AND the detection to add. Group quick wins vs structural.
9. **Appendix** — tooling + versions, full timeline, and the **cleanup/reversion log** (every change
   made and reverted: persistence removed, test accounts deleted, files cleaned).

## How to assemble
- Pull findings from `/api/report` (or `recon_findings`); pull the surface/path from the graph
  (`recon_graph`) and your pinned `graph_note` leads; pull observations from your `record_fact`s.
- Write the narrative + ATT&CK + purple sections from your own executed steps — only steps you
  actually ran with real tooling. Save the document in the workspace; attach key evidence.
- If the engagement isn't finished, write an **interim** report with the same structure and mark
  open/deferred items — never fabricate a conclusion to look complete.
