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
1. Build & Deploy lên Kali
# Trên máy Kali (hoặc copy cả thư mục k1nzr3c0n-go sang):
cd k1nzr3c0n-go
bash build.sh                    # build frontend (nếu chưa có) + binary
sudo mkdir -p /opt/k1nzr3c0n
sudo cp -r k1nzr3c0n workflows wordlists static scripts deploy /opt/k1nzr3c0n/

# Chạy như service:
sudo cp deploy/k1nzr3c0n-go.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now k1nzr3c0n-go
2. Chạy trực tiếp (test nhanh)
K1NZR3C0N_BASE=/opt/k1nzr3c0n ./k1nzr3c0n serve     # mở http://:8000
Env quan trọng:
Biến	Mặc định	Ý nghĩa
K1NZR3C0N_BASE	.	Gốc chứa workflows/ wordlists/ static/ runs/
K1NZR3C0N_ADDR	:8000	Port server
K1NZR3C0N_WORKERS	2	Số run chạy song song
K1NZR3C0N_API_TOKEN	(rỗng)	Bật auth: /api/* cần Authorization: Bearer <token>, WS cần ?token=
K1NZR3C0N_WEBHOOK_URL	(rỗng)	Discord/Slack nhận alert run + vuln critical
GITHUB_TOKEN	(rỗng)	Nâng rate-limit check version tool 60→5000 req/h
3. Luồng sử dụng Web UI (http://localhost:8000)
1. Targets → Add target: example.com, scope *.example.com, mode bounty — đây là cổng deny-wins, target nào mode oos sẽ bị chặn 403 khi chạy
2. Keys → dán API key (Shodan, SecurityTrails, Chaos, GitHub…) — tự inject vào subfinder/uncover config + env khi run
3. Runs → New run: chọn workflow (01-full-recon-pipeline = full 95 steps) + target + override vars → Launch
4. Vào run detail xem live logs (WebSocket), step progress, findings đổ về giữa chừng
5. Findings → triage (open/fp/resolved, notes, tags), nút Resolve duplicates
6. Inventory → host:port sống qua các run, kèm screenshot
7. Schedules → cron recon định kỳ (0 3 * * *), bật alert new-assets
8. Tools → Check versions → Update all (tải binary thật từ GitHub về /usr/local/bin, cần chạy quyền ghi — hoặc set K1NZR3C0N_BIN_DIR)
9. Terminal → bash ngay trong browser
Tự động mỗi ngày: dọn workspace >30 ngày (giữ kết quả + screenshots), check tool version 04:00, nuclei -ut 04:30.
4. CLI (không cần UI)
./k1nzr3c0n validate workflows/01-full-recon-pipeline.yaml   # kiểm tra + xem levels
./k1nzr3c0n plan -w workflows/02-js-secrets-recon.yaml -t example.com
./k1nzr3c0n run -w workflows/02-js-secrets-recon.yaml -t example.com \
    --vars nuclei_rl=50 --continue-on-error -o runs/manual1
# Resume sau khi pause (exit 75) hoặc crash:
./k1nzr3c0n run ... -o runs/manual1 --resume
5. Lưu ý vận hành
- Pause chỉ có hiệu lực giữa các level — step đang chạy (vd. port scan dài) sẽ chạy xong mới pause
- Cancel giết process group ngay (SIGTERM→SIGKILL) — findings đã thu vẫn được parse
- Tool rebuild_only (42/105) không update in-place được — đó là giới hạn của chính bản gốc (cài qua install.sh lúc build máy)
- DB tương thích drop-in với bản Python: trỏ K1NZR3C0N_BASE vào thư mục cũ là dùng được luôn lịch sử runs/findings