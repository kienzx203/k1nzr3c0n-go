---
name: recon-engine
description: Use whenever a task needs recon on a target — how the task agent drives the k1nzr3c0n Workflow Runner and reads back the attack surface. The authoritative wiring between the agent and the engine's four channels — WORKFLOW (run/list/status), LOG (live tail), GRAPH (relationship map), and DB (findings/assets) — plus how to persist results. Load before launching or triaging any recon.
---

# Recon Engine Linkage (task agent ⇄ workflow · log · graph · DB)

The task agent does NOT scan by hand. It drives the **Workflow Runner** and reads
results back through four channels. Hold the loop below; never hold raw scan dumps
in context — persist, then drop.

```
                    ┌──────────────────────────────────────────────┐
   task agent  ───▶ │  run_workflow ──launches──▶  Workflow Runner  │
                    └──────────────────────────────────────────────┘
        ▲  ▲  ▲                    │ writes workspace files
        │  │  │                    ▼
        │  │  └── LOG   ◀── run_log(run_id)       live step tail / warnings
        │  └───── GRAPH ⇄  recon_graph(target | run_id)  surface map (read; run_id = run delta)
        │                  graph_note(target,node)       pin a lead back onto a node (write)
        └──────── DB    ◀── recon_findings / recon_assets / recon_runs(target)
                           run_status(run_id)       progress / counts
```

## The four channels (exact tool names)

**WORKFLOW — choose, tune, launch, stop** (full control lifecycle in the `workflow-control` skill)
- `list_workflows` — every workflow + description. CHOOSE by description; never hardcode.
- `describe_workflow(workflow)` — that workflow's tunable `vars` + step count. Read it to run a
  TARGETED/STEALTH variant (set `vars` + `full=false`) instead of the max-coverage default.
- `run_workflow(target, workflow[, vars, wait, full])` — launch against a target; an
  unknown target is AUTO-REGISTERED (default scope = domain + subdomains) and runs —
  no need to register first. `workflow` is the file name, e.g.
  `01-full-recon-pipeline.yaml`. **Non-blocking by default** → returns a `run_id` and
  runs CONCURRENTLY while you keep working. `full=true` (default) = max coverage;
  `full=false` + explicit `vars` = a precise/quiet run. `wait=true` blocks and returns
  the brief inline. The finished brief is ALSO pushed back into the task — but do NOT
  wrap up while a run is unread.
  **TARGETED scan** — focus a run on specific hosts you saw in the graph. CLEANEST: the dedicated
  `05-scan-hosts.yaml` workflow (resolve + httpx + ports + nuclei on a host set, NO passive discovery):
  `run_workflow(target, "05-scan-hosts.yaml", vars={"target_hosts":"a.ex.com,b.ex.com"})`. On the big
  pipelines you can instead set `vars={"target_hosts":"…", "run_passive":"false"}` + `full=false`.
  target_hosts is comma/space-separated and still passes the target scope filter (out-of-scope drop).
- `stop_workflow(run_id)` — cancel a wrong / out-of-scope / stuck run.

**LOG — follow live**
- `run_status(run_id)` — cheapest progress check (status, step counts, findings so far).
  Poll until `completed`/`failed`/`paused`.
- `run_log(run_id[, offset, limit, raw])` — tail the LIVE log while other work continues.
  Default = progress skeleton only (step start/done + one-line stats); pass `raw=true`
  only to inspect one step's detailed output. To tail new lines, pass the previous
  response's `total` as `offset`. Empty interim results ≠ "no findings".

**GRAPH — see the whole surface (4 modes, cheapest first — don't dump the full map by reflex)**
- `recon_graph(target, summary=true)` — counts by type + findings-by-severity. START HERE to size
  the surface cheaply, then drill.
- `recon_graph(target, q="admin")` — SEARCH: matching nodes (host/ip/url/param/finding) as a flat
  list. Token-light; use to find a specific host/panel/param.
- `recon_graph(target, node="h:host")` — DRILL one node + its neighbours (ids come from a prior
  map/search). Walk pivots/chains step by step.
- `recon_graph(target)` — FULL relationship map (every host with IPs/ports/provider/URLs/paths/
  params/findings; IPs with ASN/subnet; domain buckets/secrets/certs/dns/intel). Bounded by
  `hosts` (default 400, highest-risk first); a `truncated` map says what was dropped — NARROW with
  q/node instead of raising the cap. Call again as runs finish (rebuilds live per completed step).
- `recon_graph(target, run_id="<id>", …)` — **RUN DELTA**: scope ANY of the 4 modes to the surface
  ONE run produced (rebuilt live per finished step). While following a run, `recon_graph(target,
  run_id, summary=true)` shows what IT just added — far cheaper than re-reading the whole target map
  each poll. Add `delta=true` for the TRUE diff (only nodes this run added that NO prior run had:
  `{total_new, counts_by_type, new_nodes}`) — the precise "what's new" when re-scanning a mapped
  target. Omit `run_id` for the target-wide (all-runs-merged) graph. (summary/map reads also carry the
  target's `annotations` so your pinned leads show in the same response.)
- `graph_note(target, node[, tag, note])` — **WRITE a lead back onto a node** (recon_graph is
  read-only; this is the agent's write channel). e.g. `node="h:admin.example.com", tag="priority",
  note="login panel, default-cred + SQLi candidate"`. It persists — shows in the graph viewer and
  survives a context compaction. With NO node it LISTS your pinned leads. Use it to mark what to
  attack next, flag false-positives, and recover your own leads after a compaction.

**DB — exhaustive lists + run recovery**
- `recon_findings(target)` — flat list of findings for the target.
- `recon_assets(target)` — flat list of discovered assets (hosts/services/endpoints).
- `recon_runs(target[, status])` — this target's runs {run_id, workflow, status, started}. Use it to
  RECOVER a run_id lost to a context compaction so no launched run is left unread; `status=running`
  shows what is still in flight.

> **Two finding stores — reconcile both, don't confuse them.** `recon_findings` / `recon_graph` are the
> RECON-TOOL findings (nuclei/afrog/takeover/secrets from workflows) — the SIGNALS you triage and attack.
> Your OWN confirmed/exploited findings (`report_finding`) live in a SEPARATE store — read them with
> `list_findings`. The engines are decoupled (no shared DB), so your `report_finding`s do NOT appear in
> `recon_findings`/`recon_graph`. Before attacking: check `recon_findings` (what recon found) AND
> `list_findings` (what you already proved — don't re-prove it); use `list_untested_assets` for coverage.

## The loop (do this, in order)

1. **Check first (cheap → narrow).** `recon_graph(target, summary=true)` to size the surface,
   then `recon_graph(target, q=…)` / `recon_findings` / `recon_assets` to inspect what's there.
   If it already has live hosts + ports + urls/params enough to attack, SKIP scanning (step 5).
2. **Pick & launch** only the gaps. `list_workflows` → `run_workflow(target, <chosen>)`
   (non-blocking). Launch SEVERAL when the goal is broad (full-recon + JS/secrets + params).
3. **Follow live.** While it runs, `run_log(run_id)` + `run_status(run_id)`; keep reconning in
   parallel. Lost the run_id (compaction)? `recon_runs(target, status=running)` to recover it —
   never leave a launched run unread.
4. **See the surface** as results land: `recon_graph(target, run_id, summary=true)` for the
   DELTA of the run you're following (what it just added), or `recon_graph(target, summary=true)`
   for the whole target; then drill with `q=`/`node=` for pivots & chains; full map only when you
   truly need it all. **Pin leads** as you spot them: `graph_note(target, node, tag="priority",
   note=…)` so they survive a compaction and you don't re-derive them.
5. **VERIFY — never trust the log.** A workflow finding is a LEAD, not a fact: the tool may have
   false-positived, or the issue may already be patched. Before you treat any signal as real — and
   ALWAYS before `report_finding` — INDEPENDENTLY reproduce it yourself: re-run the exact check with
   your own tools (curl, a single nuclei template, the matching offensive skill), or a TARGETED run
   (`05-scan-hosts.yaml` / `target_hosts`) scoped to that host. Confirm it twice, non-destructively.
   Record the verdict with `graph_note(node, tag="verified"|"false-positive", note=…)` so neither you
   nor a later pass re-chases it. Reading the log is step 0 of verification, never the end of it.
6. **HUNT — the workflow is a BASELINE, not the ceiling.** Actively find what it could NOT: the vhost
   matrix (every collected name × every in-scope IP, non-resolving names INCLUDED — a dead domain is
   often a vhost on a known IP), authenticated crawl/params after login, JS/sourcemap-derived endpoints,
   logic & access-control flaws, and the DEEP-DIVE gap checklist. Every new host/param/endpoint →
   `insert_assets` + loop back to step 1 for THAT surface (targeted run), so discovery COMPOUNDS instead
   of stopping at the workflow's output.
7. **Route & attack** — map the surface to the matching offensive domain skill and INVOKE it
   (`recon-to-attack`: web → `web-pentest`, AD/network ports → `active-directory-attack`/`network-attack`,
   cloud → `cloud-security`, secrets → `red-team-ops`, a shell → `privesc-*`/`edr-evasion`, …), driven by
   the graph not blind scanning (procedure: `recon-first-pentest`; discipline: `scope-/opsec-/finding-discipline`).
8. **Persist immediately, then drop raw output:**
   - new asset/host/service/endpoint/cred → `insert_assets` (asset graph)
   - a conclusion/observation → `record_fact` (exploration graph, with `intent_id`)
   - a confirmed, REPRODUCED vuln → `report_finding` (with a minimal PoC) — only after step 5
   Only saved results survive a context compaction — never keep scan dumps in-head.
9. **New surface found mid-attack** (new subdomain/host/param) → narrow loop back to step 1
   for THAT surface only, not a full re-scan — launch a TARGETED run with
   `vars={"target_hosts":"<the new hosts>", "run_passive":"false"}` (+ the scan toggles you need),
   then follow its delta with `recon_graph(target, run_id)`.

## Boundaries

- `run_workflow` AUTO-REGISTERS an unknown target with a default scope (the domain +
  its subdomains) and proceeds — the operator authorized this, so you don't stop to
  register. You STILL never scan OUTSIDE that scope: shared/CDN IPs are host-only, and
  ASN/neighbor/org-wide IPs stay OUT candidates until proven target-dedicated.
- Reuse before re-scan: never re-run what `recon_findings`/`recon_graph` already shows.
- Do NOT launch workflows on your own initiative unless the goal/operator calls for recon;
  prefer reading the existing graph first.
- Leave heavy/loud scanning to the Workflow Runner; the agent's job is choose → follow →
  read → triage → validate → persist.
