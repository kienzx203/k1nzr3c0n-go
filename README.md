# k1nzr3c0n-go

Single-binary Go rewrite of the [K1NZR3C0N](https://github.com/) Python stack
(FastAPI + Celery + Redis + beat → **one Go binary**). Same SQLite schema, same
REST/WebSocket API, same workflow YAML format — the original React frontend and
workflows run unchanged.

> **Legal:** only use against targets you own or have explicit written
> permission to test. Scope enforcement (deny-wins) is built in, but final
> responsibility is yours.

## What replaces what

| Python original | Go port |
|---|---|
| FastAPI app (`:8000`) | `net/http` server + embedded SPA (`internal/api`) |
| Celery worker + Redis queue | goroutine worker pool (`internal/runner`) |
| Redis pubsub `logs:{run_id}` | in-process bus (`internal/bus`) |
| Celery beat (cron) | minute ticker + robfig/cron (`internal/schedule`) |
| SQLAlchemy + SQLite | `database/sql` + modernc.org/sqlite, same schema (`internal/store`) |
| workflow.py engine | `internal/workflow` (load/includes/template/Kahn/levels/fanout/pause) |
| tasks.py parsers | `internal/parsers` |
| scope.py deny-wins | `internal/scope` |
| webhooks | `internal/notify` |
| ptyprocess terminal | creack/pty (`/ws/terminal/{id}`) |
| report.py | `internal/report` |
| tools.py inventory | `internal/toolsmeta` (subset, pragmatic) |

## Quick start

```bash
# build (frontend is prebuilt into static/; rebuild with cd frontend && npm run build)
go build -o k1nzr3c0n ./cmd/k1nzr3c0n

# run everything (API + workers + scheduler) — base dir layout:
#   $K1NZR3C0N_BASE/{workflows,wordlists,static,runs/k1nzr3c0n.db}
K1NZR3C0N_BASE=/opt/k1nzr3c0n K1NZR3C0N_ADDR=:8000 ./k1nzr3c0n serve
```

CLI (parity with the Python `k1nzr3c0n` command):

```bash
./k1nzr3c0n validate workflows/01-full-recon-pipeline.yaml
./k1nzr3c0n plan -w workflows/02-js-secrets-recon.yaml -t example.com
./k1nzr3c0n run    -w workflows/02-js-secrets-recon.yaml -t example.com --vars nuclei_rl=50
```

Environment: `K1NZR3C0N_BASE`, `K1NZR3C0N_ADDR` (:8000), `K1NZR3C0N_API_TOKEN`
(bearer auth for `/api/*`, `?token=` for websockets), `K1NZR3C0N_WORKERS` (2),
`K1NZR3C0N_WEBHOOK_URL` / `K1NZR3C0N_WEBHOOK_USERNAME` (Discord/Slack),
`K1NZR3C0N_TASK_TIME_LIMIT` (43200s).

## Verified parity (e2e on this machine)

- All 3 shipped workflows (01 = 95 steps, fanouts, conditionals) load + validate:
  58 levels, max parallelism 29 — identical to Python topology
- Deny-wins scope gate (403 on `oos` targets), scope audit rows
- Run lifecycle: queued → running → paused (exit-75 semantics, pause between
  levels, `resume.json` checkpoint) → resume → completed; cancel kills process
  groups (SIGTERM→SIGKILL); task time limit enforced (default 43200s)
- Live WebSocket `/ws/runs/{id}`: `log_meta` / `log` / `step` / `done` frames
- Findings parsers: nuclei/httpx/naabu/subdomains/katana/gau (delete-then-insert,
  incremental mid-run re-parse after the `httpx`/`screenshot`/... step ids)
- New-asset detection (cross-run diff + dedupe), asset inventory per host:port
- Schedules CRUD + cron trigger + `next_run_at`; keys UI (27 providers, masking,
  subfinder/uncover provider-config injection at run start); reports + drafts;
  wordlist/workflow upload; system reset; PTY terminal (`/ws/terminal/{id}`,
  session takeover close 4000)
- **Full tool registry (105 tools / 8 wordlists, generated 1:1 from tools.py)**
  with in-place updates: GitHub release asset download (zip/tar/gz/zip_tar/
  binary/deb), `pip3 install --upgrade`, `git pull --ff-only`, wordlist
  re-download; version check (installed vs latest, DB-version-wins, GitHub
  rate-limit aware) — verified by actually installing ffuf (zip) and metabigor
  (tar.gz) from live GitHub releases
- Maintenance jobs (Celery beat parity): workspace cleanup >30d (keep-list),
  daily tool version check (04:00), `nuclei -ut` (04:30), once per local day
- `/health` reports live scheduler `beat.last_tick`

Environment additions: `GITHUB_TOKEN` (raises the GitHub API rate limit from
60 to 5000 req/hr — recommended for the daily version check),
`K1NZR3C0N_BIN_DIR` (tool install dir, default `/usr/local/bin`).

## Known simplifications vs Python

- `/api/v1/network/*` diagnostics are simplified (no `dig` spawning)
- gowitness screenshot metadata (url/title per png) is matched by filename
  convention, not by parsing `gowitness.sqlite3`
- The opencode reverse-proxy (`/opencode/*`) and `/api/event` SSE are not ported
- backup/restore admin utilities are not ported

## Layout

```
cmd/k1nzr3c0n      serve + CLI (run/validate/plan/list)
internal/workflow  engine: YAML, includes, {var} templates, topo, levels,
                   parallel exec, fanout, timeout/retries, pause/resume/cancel
internal/runner    worker pool, run lifecycle, API-key injection, webhooks
internal/api       REST /api/v1 (+legacy /api), WS /ws/*, SPA, auth, CORS
internal/store     SQLite (schema-compatible with the Python DB — drop-in)
internal/parsers   findings scanners + new-asset diff
internal/scope     deny-wins target registry
internal/schedule  cron scheduler + daily maintenance (cleanup/version check/nuclei -ut)
internal/toolsmeta full tool registry (generated from tools.py) + update engine
frontend/          original React/Vite app (builds into ../static)
static/            built SPA served by the Go binary
workflows/         workflow YAMLs (copied from the Python project)
scripts/           helper scripts invoked by workflow steps
internal/toolsmeta/gen_catalog.py + catalog_gen.go — regenerate the catalog
                   after editing the Python TOOLS list
```
