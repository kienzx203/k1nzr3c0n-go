---
name: workflow-control
description: Use when launching, tuning, following, or stopping a k1nzr3c0n recon workflow — the full CONTROL side of the agent⇄workflow relationship (choose → describe/tune → launch → follow → stop). Covers running a TARGETED or STEALTH variant instead of the max-coverage default, and recovering/cancelling runs. Complements `recon-engine` (the read/graph side).
---

# Workflow Control (choose → tune → launch → follow → stop)

The agent does NOT scan; it DRIVES workflows. This skill is the control half; the
read half (graph/findings/assets) is in `recon-engine`.

## 1 — Choose
- `list_workflows` → every workflow + one-line description. Pick by PURPOSE, never hardcode a name.
  Typical set: broad surface mapping (full recon), discovery-only, JS/secrets, parameter discovery.
- Run SEVERAL when the goal is broad (e.g. full-recon + JS/secrets + params) — they are independent.

## 2 — Describe & tune (the key to not over-scanning)
- `describe_workflow(workflow)` → that workflow's **vars** (tunable options) + description + step count.
  READ THIS before running anything non-default — it is how you run a precise variant.
- `run_workflow` has two modes:
  - **`full=true` (default)** — turns ON every option for MAX coverage (except the pivot scan and the
    neighbor /24 PTR sweep, kept off for scope safety). Use for a first broad map of a target you own.
  - **`full=false` + explicit `vars`** — a TARGETED/STEALTH variant. Set only what you need; everything
    else stays at the workflow's own default.
- Common tunes (confirm names with `describe_workflow`):
  - **Stealth / quiet**: `run_workflow(target, 01-…, full=false, vars={run_portscan:"false", run_nuclei:"false", run_afrog:"false", run_screenshot:"false"})` — passive/light only, no loud scans.
  - **Authenticated param discovery**: the param workflow exposes `session_cookie` / `auth_header` /
    `custom_header` / `method` — pass the operator's session so it fuzzes behind auth.
  - **Scope-sensitive options stay OFF** unless the operator says org-wide: pivot scans, neighbor-CIDR
    sweeps (these can touch third-party/out-of-scope assets).

## 3 — Launch
- `run_workflow(target, workflow[, vars, full, wait])` — target MUST be REGISTERED with a deny-wins scope;
  not registered → STOP, tell the operator, never self-widen. NON-BLOCKING by default: returns a `run_id`
  and runs CONCURRENTLY. The finished brief is pushed back into the task automatically.

## 4 — Follow (don't busy-poll)
- `run_status(run_id)` — cheapest progress check.
- `run_log(run_id[, offset, raw])` — tail live step output (progress-only by default; advance `offset` by
  the prior `total`; `raw=true` only to inspect one step).
- `recon_runs(target[, status=running])` — recover a `run_id` you lost to a context compaction, or list
  what's still in flight. Never wrap up while a launched run is unread.
- Read results as they land with `recon_graph` / `recon_findings` / `recon_assets` (see `recon-engine`).

## 5 — Stop
- `stop_workflow(run_id)` — cancel a run you launched by mistake, one drifting out of scope, or when the
  operator says stop. Find the id with `recon_runs(target, status=running)` if lost. Relaunch with
  `run_workflow` if needed.

## Boundaries
- Only run against REGISTERED targets (deny-wins scope). Reuse before re-scan: check `recon_graph`/
  `recon_findings` first — never re-run recon you already have. Leave heavy/loud scanning to the
  Workflow Runner; keep scope-sensitive pivots OFF unless explicitly authorized.
