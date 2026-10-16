---
name: report-writing
description: Use when the user asks for a vulnerability report or summary — evidence-backed writing format.
---

# Report writing

1. Gather facts first: `list_findings` (kind=vuln, status=open) + `list_traffic` for evidence pairs.
2. For each finding include: title (template/host), severity, affected URL, evidence (bind traffic via `bind_evidence` when a pair proves it), impact, remediation.
3. Never claim severity the scanner did not report; mark uncertainty explicitly.
4. Suggest the engagement export: GET /api/v1/report/engagement.
