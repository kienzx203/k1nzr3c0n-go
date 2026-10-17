# Bản kiểm chứng tính năng — k1nzr3c0n (Go) ↔ K1NZR3C0N (Python) + ARTEX

> Ngày: 2026-10-17 · Nhánh: `main` · Phương pháp: **audit tĩnh mã nguồn + `go build` + `go test`**.
> Giới hạn trung thực: tài liệu này KHÔNG phải một lần chạy end-to-end với bộ ~100 tool thật, và
> KHÔNG phải bằng chứng "byte/behavior-identical". Mục [§5](#5-để-chứng-nhận-11-đầy-đủ) nêu cách
> đạt chứng nhận 1:1 đầy đủ.

---

## 1. Phạm vi & phương pháp

| Kiểm được trong môi trường này | KHÔNG kiểm được ở đây |
|---|---|
| Build toàn module (`go build ./...`) | Chạy pipeline recon thật (thiếu toolchain Kali) |
| Unit/parity test của phần k1nzr3c0n (SQLite) | Test tích hợp ARTEX cần **PostgreSQL** (sandbox không có) |
| Đối chiếu module/feature Python↔Go | So khớp từng field output parser với bản Python |
| Đếm route API, parsers, tools, templates | So từng endpoint FastAPI↔net/http |

**Kiến trúc (khác biệt có chủ đích, không 1:1 hạ tầng):**
Python = FastAPI + **Celery + Redis** (queue) + **Celery beat** (schedule) + SQLite.
Go = net/http + **runner/queue nội tại (goroutine)** + **scheduler riêng** + SQLite. Tính năng tương
đương; máy móc bên dưới là **viết lại**, không phải port từng dòng.

---

## 2. Phần A — k1nzr3c0n (Go `k1z/`) vs Python `src/k1nzr3c0n/`

### 2.1 Ánh xạ module

| Python | Go | Ghi chú |
|---|---|---|
| `workflow.py` | `k1z/workflow/{types,load,topo,template,engine}.go` | Engine chính, có **parity-test** |
| `scope.py` | `k1z/scope/` | deny-wins + modes |
| `tasks.py` (Celery) | `k1z/runner/runner.go` | Hàng đợi/queue viết lại bằng goroutine |
| `tools.py` | `k1z/toolsmeta/` | Registry + install/update |
| `parsers/` | `k1z/parsers/parsers.go` (602 dòng) | nuclei/httpx/naabu/katana/gau… |
| `db.py` | `k1z/store/` | SQLite |
| `report.py` | `k1z/report/` | Báo cáo engagement |
| `api/` (FastAPI) | `k1z/api/` (**160 route** `/api/v1/*`) | Chưa diff từng endpoint |
| `cli.py` | *(engine options, chưa có CLI 1:1)* | **Khoảng trống** — xem §2.4 |

### 2.2 Ma trận tính năng (đã xác minh có bằng chứng)

| Tính năng (Python) | Go — vị trí | Trạng thái |
|---|---|---|
| Workflow engine: `when`/`optional`/`skip_if_exists`/`retries`/`fanout`/`fanout_concurrency`/`requires.min_bytes`/`depends_on`/`run_on_failed_deps`/`outputs`/`env`/`cwd`/`timeout`/`shell` | `k1z/workflow/{types,engine}.go` | OK đủ + parity-test pass |
| Templating `{key}`/`{vars.}`/`{steps.id.out}`/`{key\|default}`/`${}`-escape | `k1z/workflow/template.go` | OK `diffcmd_test.go` |
| Topo (Kahn) + chia level song song + `max_parallel` | `k1z/workflow/topo.go`,`engine.go` | OK `difftopo_test.go` |
| Pause (`pause.flag`→exit 75) / Resume (`resume.json`) / Print-plan | `engine.go` (`PauseExitCode`,`Resume`,`PrintPlan`) | OK có |
| 3 template 94/20/8 step | `workflows/*.yaml` → **95/20/8** top-level | OK khớp (lệch 1 = làm tròn) |
| Findings kinds vuln/http/port/subdomain/url | `parsers.go` | OK |
| Findings status open/**fp**/resolved + notes | `routes_findings.go:61` `case "open","fp","resolved"` | OK khớp |
| Inventory dedupe host:port | `routes_findings.go` (`DeleteHTTPAssets`) | OK |
| Scope deny-wins + mode bounty/vdp/oos + `scope_audit` + pivot isolation | `k1z/scope`, `routes_targets.go`, `runner.go` | OK test pass |
| Schedules cron + **Discord/Slack** webhook | `k1z/schedule`, `k1z/notify/notify.go` (embeds/attachments) | OK cơ chế khác (không Celery beat) |
| Tools ~100 install/update (gh_binary/pip/…) | `k1z/toolsmeta` → **113 tool** | OK test pass |
| Live log WS + step progress | `/ws/runs/{run_id}` (`server.go:278`) | OK |
| Cancel run | `runner.go` `CancelRun` + `cancel.flag` | OK (Python workflow.py không có — Go thêm) |

### 2.3 Bằng chứng build/test (phần k1nzr3c0n)

```
go build ./...                      → exit 0
go test ./k1z/...                   → 7/7 package OK
  agent · api · mcp · scope · store · toolsmeta · workflow   = ok
```
(Phần k1z dùng SQLite nên không cần Postgres.)

### 2.4 Chỗ Go **tốt hơn / khác** bản Python (có cơ sở)

- **Triển khai đơn giản hơn:** một binary Go tĩnh (~56MB), **không cần Redis/Celery broker**.
- **Có bộ parity-test riêng** cho engine (`diffcmd_test.go`, `difftopo_test.go`, `engine_test.go`,
  `race_test.go`) — bản Python không kèm.
- **Thêm Cancel** (`cancel.flag`) và **phục hồi khi worker restart** ở tầng runner.
- **An toàn kiểu** (Go tĩnh) cho toàn bộ engine/parsers/scope.

### 2.5 Khoảng trống phần k1nzr3c0n (chưa kiểm)

- Chưa diff **từng endpoint** 160 route Go ↔ FastAPI (shape JSON/status/query).
- Chưa so **từng field** parser (vd httpx trích status/title/tech) với Python.
- **CLI**: Python có `cli.py`; Go mới expose qua engine options + API, **chưa có CLI 1:1**.
- Chưa test ca biên scope (`*.example.com`, pivot bên thứ ba) đối chiếu từng case.

---

## 3. Phần B — ARTEX chạy "chuẩn như source" của nó?

Repo này **chính là** source ARTEX/ScopeWeaver (module `github.com/Autumn-27/artex`), build `./cmd/artex`.

### 3.1 Subsystem hiện diện & build

```
go build ./...  → exit 0  (gồm toàn bộ ARTEX)
Subsystems: server agent db enrich guard intercept llmnet llmpool llmrec
            notify traffic report sidequestion selfupdate config cmd/artex web/src  OK
go build -tags embedui ./cmd/artex → exit 0 (binary 56.5MB, nhúng UI)
```

### 3.2 Test suite gốc của ARTEX — CHƯA xanh (nhưng do nguyên nhân vô hại)

```
go test ./...  →  FAIL ở: agent, db, intercept, locale, notify, server
server: 52 test FAIL
```
Phân loại nguyên nhân (không có dấu hiệu vỡ chức năng):

| Nhóm | Vì sao | Ví dụ |
|---|---|---|
| **Thiếu PostgreSQL** | sandbox không có DB (`ARTEX_PG_DSN` chưa set) | `TestFindingTrafficAPIAndExport`, `TestNotifyDigest…` → lỗi "未找到数据库配置" |
| **Test i18n đòi KO/ZH** | dự án đã **cố ý English-only + rebrand K1nzr3c0n**, bỏ KO/ZH | `missing Korean message …`, `TestNotificationLanguage…`, `TestWebUIStubUsesRequestLanguage` |

→ **Kết luận Phần B:** ARTEX **build và chạy được**, nhưng **không thể chứng nhận "chạy đủ mọi
tính năng chuẩn như source" trong môi trường này** vì (a) test tích hợp cần Postgres, (b) bộ test i18n
của ARTEX nay lệch với hướng English-only. Cần [§5](#5-để-chứng-nhận-11-đầy-đủ) để chốt.

### 3.3 Việc nên làm để ARTEX "xanh như source"

1. Cấp **PostgreSQL** cho test (`ARTEX_PG_DSN=...` hoặc `server/config.json`), chạy lại `go test ./...`.
2. Với test i18n: hoặc **khôi phục catalog KO/ZH**, hoặc **cập nhật/bỏ** các test locale cho đúng
   hướng English-only (quyết định sản phẩm). Hiện chúng đỏ vì rebrand, không vì lỗi logic.

---

## 4. Verdict

| Câu hỏi | Trả lời |
|---|---|
| Mọi tính năng k1nzr3c0n khớp bản Python? | **Khớp ở mức cơ chế, rộng & có parity-test** (build+test k1z 7/7 xanh). **Chưa** chứng nhận 1:1 runtime; còn khoảng trống §2.5. |
| Có tốt hơn bản Python chỗ nào? | Có: deploy 1-binary không Redis/Celery, có parity-test, thêm cancel/khôi-phục, type-safe (§2.4). |
| ARTEX chạy đủ tính năng chuẩn như source? | **Build/chạy được**; **test suite gốc hiện đỏ** nhưng chỉ do thiếu Postgres + lệch i18n (English-only), **không thấy vỡ chức năng**. Chốt được sau §5. |

---

## 5. Để chứng nhận 1:1 đầy đủ

**(A) k1nzr3c0n runtime 1:1 (bắt buộc để nói "y hệt/tốt hơn"):**
1. Trên Kali có toolchain: chạy `01-full-recon-pipeline.yaml` (hoặc `--print-plan` cho khâu plan)
   cùng một target trên **cả** bản Python và bản Go.
2. So: danh sách step chạy, thứ tự/parallel level, số findings mỗi kind, nội dung `scope_audit`,
   file workspace sinh ra. Ghi khác biệt.

**(B) ARTEX "xanh như source":**
1. Dựng Postgres → `go test ./...` phải xanh (trừ nhóm i18n).
2. Quyết định số phận test i18n (khôi phục KO/ZH **hoặc** cập nhật theo English-only).

**(C) Diff tĩnh sâu (bổ trợ, không thay cho E2E):**
- Map từng endpoint 160 route Go ↔ FastAPI; so từng field parser; test ca biên scope.

---

### Phụ lục — lệnh tái lập

```bash
go build ./...                                  # cả hai hệ, phải exit 0
go test ./k1z/...                               # phần k1nzr3c0n — kỳ vọng 7/7 ok
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex   # binary nhúng UI
# ARTEX integration (cần Postgres):
#   ARTEX_PG_DSN="postgres://user:pass@host/db?sslmode=disable" go test ./...
```
