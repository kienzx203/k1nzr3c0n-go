# K1nzr3c0n — Hướng dẫn cài đặt & sử dụng

> Nền tảng recon/pentest tự động: **ARTEX/ScopeWeaver** (engine LLM tự hành, PostgreSQL)
> + **Workflow Runner k1nzr3c0n** (chạy workflow YAML bằng ~100 tool, SQLite). Một binary Go
> duy nhất, UI web nhúng sẵn. Chỉ dùng cho mục tiêu **được phép kiểm thử**.

---

## Mục lục
1. [Yêu cầu](#1-yêu-cầu)
2. [Cài đặt](#2-cài-đặt)
3. [Cấu hình](#3-cấu-hình)
4. [Chạy & đăng nhập lần đầu](#4-chạy--đăng-nhập-lần-đầu)
5. [Hướng dẫn từng chức năng](#5-hướng-dẫn-từng-chức-năng)
6. [Skills (nạp thêm tri thức)](#6-skills)
7. [Cập nhật & build lại](#7-cập-nhật--build-lại)
8. [Xử lý sự cố](#8-xử-lý-sự-cố)
9. [Bảo mật](#9-bảo-mật)
10. [Scripts tiện ích](#10-scripts-tiện-ích)
11. [Bổ sung xử lý sự cố](#11-bổ-sung-xử-lý-sự-cố)

---

## 1. Yêu cầu
- **Kali Linux** (hoặc Debian/Ubuntu) bare-metal/VM.
- **PostgreSQL** (bắt buộc cho ARTEX core).
- **Go** (build từ source) + bộ tool recon (subfinder, httpx, nuclei, naabu, katana… — cài qua trang *Tool versions*).
- RAM ≥ 4GB khuyến nghị (recon song song).

---

## 2. Cài đặt

### 2.1 PostgreSQL (một lần)
```bash
sudo apt-get install -y postgresql
sudo -u postgres psql -c "CREATE USER artex WITH PASSWORD 'CHANGE_ME';"
sudo -u postgres psql -c "CREATE DATABASE artex OWNER artex;"
```
Schema tự tạo/cập nhật mỗi lần khởi động (idempotent).
> Nếu `CREATE DATABASE` lỗi collation (glibc mismatch): chạy
> `sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION"` rồi tạo lại.

### 2.2 Lấy source & build (chỉ cần Go — UI đã nhúng sẵn)
```bash
git clone https://github.com/kienzx203/k1nzr3c0n-go /opt/k1nzr3c0n-src
cd /opt/k1nzr3c0n-src
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex
```
> Lỗi build kiểu `config has no field …` = **cache hỏng**, không phải source: `go clean -cache` rồi build lại.
> KHÔNG chạy `bash build.sh` nếu không hiểu — nó rebuild lại UI và có thể ghi đè bản dist tốt.

### 2.3 Thư mục chạy (base dir) — QUAN TRỌNG
Service đọc **skills / workflows / wordlists / data** theo biến `K1NZR3C0N_BASE` (mặc định = thư mục đang chạy). Hãy dựng một base dir cố định và đặt binary + dữ liệu ở đó:
```bash
sudo mkdir -p /opt/k1nzr3c0n
sudo cp /opt/k1nzr3c0n-src/k1nzr3c0n /opt/k1nzr3c0n/
sudo cp -r /opt/k1nzr3c0n-src/{workflows,wordlists,skills} /opt/k1nzr3c0n/
```
> **Ghi nhớ:** mọi dữ liệu runtime (skills, workflows, runs) nằm ở `<base>/…`. Checkout git
> (`-src`) chỉ để build — đừng nhầm hai nơi (xem [§8](#8-xử-lý-sự-cố)).

### 2.4 Chạy như systemd service
`/etc/systemd/system/k1nzr3c0n-go.service`:
```ini
[Unit]
Description=K1nzr3c0n
After=postgresql.service network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/k1nzr3c0n
Environment=K1NZR3C0N_BASE=/opt/k1nzr3c0n
Environment=ARTEX_PG_DSN=postgres://artex:CHANGE_ME@127.0.0.1:5432/artex?sslmode=disable
ExecStart=/opt/k1nzr3c0n/k1nzr3c0n -addr :8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now k1nzr3c0n-go
```

---

## 3. Cấu hình
- **Database:** biến `ARTEX_PG_DSN`, hoặc `config.json` cạnh binary:
  ```json
  { "database": { "host":"127.0.0.1","port":5432,"user":"artex","password":"CHANGE_ME","dbname":"artex","sslmode":"disable" },
    "skill_dir": "/opt/k1nzr3c0n/skills" }
  ```
- **LLM key:** `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` (hoặc nhập trong UI → *LLM*). Hỗ trợ Ollama/GLM local.
- **Cờ dòng lệnh:** `-addr :8000` (cổng, mặc định `:8787`), `-data <dir>` (SQLite runner), `-proxy 127.0.0.1:8788` (proxy ghi traffic; để trống để tắt).

---

## 4. Chạy & đăng nhập lần đầu
1. Mở `http://<IP>:8000/`.
2. Lần đầu → trang **/setup**: đặt mật khẩu admin.
3. Sau đó **/login** bằng mật khẩu đó. (Token lưu ở localStorage `artex_token`.)

---

## 5. Hướng dẫn từng chức năng

UI chia 3 nhóm ở sidebar: **Features**, **System**, **Workflow Runner**.

### 5A. Workflow Runner (lõi recon k1nzr3c0n)
Luồng chuẩn: **Targets → (chọn Workflow) → Runs → xem Run detail → Schedules/Inventory**.

- **Targets** — đăng ký mục tiêu + phạm vi (scope). Mỗi target có `mode`: `bounty` / `vdp` / `oos`, và danh sách scope (`example.com` = mọi sub; `*.example.com` = 1 cấp). Scope theo nguyên tắc **deny-wins** (chặn thắng) + ghi `scope_audit`. Click 1 target để xem chi tiết: lịch sử run, findings, audit, asset mới.
- **Workflows** — danh sách workflow YAML (nạp nóng, không cần restart). Click 1 workflow → mở **canvas editor** (kéo-thả DAG, React Flow) để xem/sửa bước. Nút **New workflow** tạo mới. 4 template có sẵn: 01 full-recon (+vuln scan, ~95 bước), 02 full-recon-artex (recon-only, ~91 bước), 03 js-secrets (~20), 04 param-discovery (~8).
- **Runs** — khởi chạy & theo dõi. Tạo run mới (chọn workflow + target + vars). Click 1 run → **Run detail**: tab **Logs** (WebSocket live), **Findings**, **Screenshots**, **Files**, **Report**, kèm tiến độ từng bước. Có thể **Pause / Resume / Cancel**.
- **Schedules** — recon liên tục theo cron. *+ New Schedule*: đặt Name, Target, Workflow, biểu thức cron 5 trường (có preset), var overrides, bật cảnh báo webhook khi có asset mới. Nút **Run now / Edit / Enable-Disable / Delete**.
- **Inventory** — gom asset HTTP qua nhiều run, dedupe theo `host:port`.
- **Tool versions** — cài/cập nhật ~113 tool (gh_binary/pip…), xem bản cài vs mới nhất.
- **API Keys** — khai báo key cho các dịch vụ recon (subfinder providers, chaos…).
- **Terminal** — terminal web (PTY) trên server, chạy login shell thật của bạn (zsh/bash). Mở nhiều tab, theo theme sáng/tối của app.
- **Upload** — tải lên wordlist / workflow YAML (kéo-thả).

### 5B. Features
- **Dashboard** — tổng quan số liệu (runs, findings, assets).
- **Chat** — trợ lý AI (agent có tên: *Auto*, *Penetration testing*). Streaming, đính kèm file, @mention asset/finding/task, dừng sinh, todolist, duyệt approval ngay trong chat.
- **Tasks** — engine **tự hành** (planner → worker, two-graph, findings). Tạo task + mục tiêu → chạy; xem graph/coverage/activity live; hỏi-người (side-question), hint cho planner, retest finding.
- **Findings** — quản lý phát hiện: kind `vuln/http/port/subdomain/url`, trạng thái `open / fp / resolved`, notes, tags; xem chi tiết + retest.
- **Traffic** — lưu lượng HTTP ghi qua proxy (`:8788`).
- **Tool executions** / **LLM recordings** — nhật ký lệnh tool & lời gọi LLM.
- **Assets** / **Asset sync** — kho asset + đồng bộ ScopeSentry.
- **Workspace** — file/thư mục làm việc.

### 5C. System
- **LLM** — cấu hình provider/model (Anthropic/OpenAI/Ollama/GLM), xem usage/quota, toggle local-only.
- **Agent** — chỉnh prompt/model/budget cho từng role (planner, worker, retester…) và chat agents.
- **MCP** — kết nối MCP server (tool ngoài).
- **Skill** — thư viện skill (agentskills.io). Xem cây file, thống kê gọi skill, *New skill*, *Upload archive* (xem [§6](#6-skills)).
- **Tool** — custom tool cho agent (command/script/http với JSON-Schema params).
- **Notifications** — webhook Discord/Slack cho run-complete / asset mới / finding critical.
- **Interception rules / Asset blocking / Approval records** — luật chặn/duyệt hành động agent.
- **Logs / System settings** — log hệ thống & cấu hình (self-update + rollback).

---

## 6. Skills
Skill = thư mục `<base>/skills/<tên>/SKILL.md` (frontmatter `name` + `description` + nội dung markdown). Agent dùng qua tool `load_skill`; trang **Skill** liệt kê tự động (đọc **runtime**, không cần restart).

**Thêm skill — 2 cách:**
1. **Copy thư mục** vào đúng base dir service đang đọc:
   ```bash
   cp -r hacktricks payloads-all-the-things /opt/k1nzr3c0n/skills/
   ```
   Rồi F5 trang Skill.
2. **Upload archive** (UI): trang Skill → *Upload archive* → chọn `.zip`/`.tar.gz` (gốc zip phải chứa `<tên>/SKILL.md`). Handler giải nén thẳng vào `<base>/skills` nên luôn đúng chỗ.

> Skill lớn (vd mirror HackTricks/PayloadsAllTheThings) chứa **token mẫu** trong tài liệu →
> GitHub push-protection chặn nếu commit .md. Vì vậy chúng **không nằm trong git**; phân phối
> bằng copy thư mục hoặc file `.zip` rồi Upload archive.

---

## 7. Cập nhật & build lại
```bash
cd /opt/k1nzr3c0n-src && git pull
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex
sudo cp k1nzr3c0n /opt/k1nzr3c0n/ && sudo systemctl restart k1nzr3c0n-go
```
**Nếu sửa giao diện** (`web/src`): UI phục vụ từ bản build nhúng `server/webui/dist`, nên phải
rebuild FE trước: đồng bộ `web/src` đã đổi sang môi trường có `node_modules` →
`node node_modules/next/dist/bin/next build` → copy `out/` vào `server/webui/dist/` → rồi build Go
như trên. (Chỉ sửa backend Go thì bỏ qua bước này.)

---

## 8. Xử lý sự cố

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| **Sửa UI mà không thấy đổi** | App phục vụ `server/webui/dist` prebuilt. Phải rebuild FE ([§7](#7-cập-nhật--build-lại)) + restart + hard-refresh (Ctrl+Shift+R). |
| **Skill không hiện trên trang Skill** | Service đọc `<base>/skills`, KHÁC checkout git `-src`. Copy folder vào **đúng** `<base>/skills` (vd `/opt/k1nzr3c0n/skills`), rồi F5. Xác nhận base: `systemctl show k1nzr3c0n-go -p WorkingDirectory -p Environment`. |
| **Terminal: `cd: HOME not set`** | Đã fix (PTY set HOME/USER/SHELL/PATH). Cần chạy binary mới. |
| **Terminal không thấy tool đã cài (opencode…)** | Terminal chạy **login shell thật** của bạn (zsh) để source `~/.zshrc`. Nếu tool cài ở `~/.opencode/bin`, bảo đảm dir đó có trong PATH của login shell (hoặc `ln -s ~/.opencode/bin/opencode /usr/local/bin/`). |
| **Schedules/Targets trắng trang** | Đã fix (lỗi port `useSearchParams` react-router→Next). Cần bản UI mới (rebuild FE). |
| **Push bị chặn "secrets"** | Skill mirror chứa token mẫu → GitHub push-protection. Các skill lớn đã được gitignore; phân phối qua copy/zip, không qua git. |
| **`CREATE DATABASE` lỗi collation** | `ALTER DATABASE template1 REFRESH COLLATION VERSION` rồi tạo lại DB. |
| **`/api/*` trả 401** | ARTEX core cần token đăng nhập (JWT). `/api/v1/*` (runner) mở khi chưa đặt API token. |

---

## 9. Bảo mật
- **`/api/v1/*` (runner) MỞ khi chưa đặt API token** → nếu máy chủ truy cập được từ ngoài, hãy **bind `127.0.0.1`** hoặc đặt API token, và đặt sau VPN/tường lửa.
- Chỉ scan mục tiêu **được phép**. Scope deny-wins + `scope_audit` giúp tránh quét ngoài phạm vi.
- Giữ LLM key/API key trong biến môi trường hoặc UI, không commit vào git.

---

---

## 10. Scripts tiện ích

Có sẵn trong `scripts/`. ARTEX `/api/*` **cần token đăng nhập**; lấy token bằng 1 trong 2:
- Trình duyệt (đang đăng nhập) → F12 → Console → `localStorage.getItem('artex_token')`.
- Hoặc để script tự login bằng mật khẩu. **Tên đăng nhập của ARTEX là `ARTEX`** (không phải `admin`); mật khẩu là cái bạn đặt ở `/setup`.

### 10.1 Thêm API keys recon hàng loạt — `scripts/add-api-keys.sh`
Nạp key cho các provider (Shodan, Censys, FOFA, Chaos, SecurityTrails, Netlas, LeakIX, CriminalIP, IntelX, DNSDumpster, WhoisXML, URLScan, CertSpotter, BeVigil, VirusTotal, GitHub, Google CSE/CX) vào DB qua `PUT /api/v1/keys/{provider}`.
```bash
cp scripts/api-keys.env.example scripts/api-keys.env   # rồi điền key thật (file này đã GITIGNORE)
BASE_URL=http://192.168.52.103:8000 ./scripts/add-api-keys.sh
```
> `scripts/api-keys.env` **không bao giờ commit** (chứa secret). Censys nhập dạng `API_ID` + `API_SECRET` (script tự ghép `ID:SECRET`). Kiểm tra: `curl -s $BASE_URL/api/v1/keys/stats`.

### 10.2 Tạo Task templates chuyên gia — `scripts/add-task-templates.sh`
Tạo sẵn **3 template** cho engine tự hành (Tasks), mỗi cái là playbook của senior operator: Cả 3 đều NHÚNG sẵn khối recon endpoint sâu (passive history + crawl + JavaScript/source-maps + API + param + brute-force) trong phần recon của chúng.
- **Bug Bounty** — tư duy threat-model, recon broad→deep, attack surface xếp ROI (IDOR/SSRF/authn/injection/client-side/infra) + kỹ thuật từng lớp, chuẩn validate CVSS/PoC.
- **Penetration Test** — PTES + OWASP WSTG, enum từng protocol, exploit có kiểm soát, post-ex AD/BloodHound, RoE + approvals.
- **Red Team** — objective-driven, MITRE ATT&CK kill chain, OPSEC/LOTL, detection-gap output.

```bash
# token nhanh:
BASE_URL=http://192.168.52.103:8000 ARTEX_TOKEN='<token>' ./scripts/add-task-templates.sh
# hoặc mật khẩu (username ARTEX mặc định):
BASE_URL=http://192.168.52.103:8000 ARTEX_PASSWORD='mật_khẩu' ./scripts/add-task-templates.sh
```
Thấy `ok ...` → mở **Tasks → New task → Task template** (hoặc *Manage templates*) chọn template → chỉ cần điền **Target** + đặt **asset block/allow rules** đúng scope → **Create**. (Advanced khuyến nghị: coverage ON cho bounty/pentest/recon, OFF cho red team; Dispatch first intent OFF.)

> Lưu ý: endpoint template của UI Tasks là `POST /api/task-templates` (ARTEX, cần token) — KHÁC `/api/v1/task-templates` (backend k1z runner). Nếu "No templates yet" sau khi chạy, gần như chắc chắn do sai endpoint hoặc thiếu token.

---

## 11. Bổ sung xử lý sự cố

| Triệu chứng | Xử lý |
|---|---|
| **Tasks: "No templates yet"** dù đã chạy script | Script phải trỏ `POST /api/task-templates` (ARTEX) + có token. Dùng `scripts/add-task-templates.sh` bản mới. |
| **`error: no token`** khi chạy seeder | Đặt `ARTEX_TOKEN=` (từ `localStorage.artex_token`) hoặc `ARTEX_PASSWORD=` (login username **ARTEX**). |
| **HTTP 401/403** khi tạo template/key | Token/mật khẩu sai hoặc hết hạn, hoặc sai username (phải là `ARTEX`). Lấy token mới. |
| **Script lỗi `syntax error near <<<`** | File dính **git conflict markers** (`<<<<<<< ======= >>>>>>>`). Trên server: `git merge --abort 2>/dev/null; git fetch origin; git reset --hard origin/main`. |
| **Truyền biến môi trường không ăn** | Đặt biến **trước** lệnh: `ARTEX_PASSWORD='...' bash ./script.sh` (KHÔNG phải tham số sau script). |

> Bảo mật: đừng dán mật khẩu/token/API key dạng plaintext ra nơi công khai; nếu lỡ lộ, **đổi mật khẩu** (`/setup` lại hoặc System settings) và **rotate** các key liên quan.

*Tài liệu này mô tả hệ thống tại thời điểm viết; kiểm tra lại tên file/cờ nếu bản build của bạn mới hơn.*
