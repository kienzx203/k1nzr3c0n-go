---
name: web-recon
description: Use when starting recon on a new web target — the recommended step order, workflow var tuning and how to triage results.
---

# Web recon playbook

1. Register the target first: `create_target` with scope patterns. Never scan unregistered hosts.
2. First pass: launch "01-full-recon-pipeline.yaml". Useful var overrides:
   - `run_screenshot=false` when the box is slow
   - `nuclei_rl=50` behind restrictive networks
   - `run_deep_portscan=false` to skip the long tail scan
3. Monitor with `get_run_status` (don't poll logs more than once a minute).
4. On completion: `list_findings` (kind=vuln, severity critical/high first), then ingest hosts via `insert_asset`.
5. Triage: mark known-FP templates with `patch_finding status="fp"`.
6. Summarize for the user: counts by severity + top hosts, no raw dumps.
