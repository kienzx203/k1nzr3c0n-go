# k1nzr3c0n — Hướng dẫn sử dụng chi tiết

> ⚠️ **Chỉ dùng hợp pháp.** Đây là công cụ tấn công. Chỉ chạy trên tài sản bạn
> **sở hữu** hoặc **được phép bằng văn bản**. Giữ đúng phạm vi (scope) và luật.

Mục lục: [Cài đặt](#1-cài-đặt) · [Đăng nhập & giao diện](#2-đăng-nhập--giao-diện) ·
[Cấu hình LLM](#3-cấu-hình-llm) · [Claude Pro/Max](#4-claude-promax-subscription) ·
[Chạy Workflow recon](#5-chạy-workflow-recon) · [Xem Graph](#6-xem-graph) ·
[Task Agent](#7-task-agent-chat--tasks) · [Findings & Traffic](#8-findings--traffic) ·
[Cập nhật/Deploy](#9-cập-nhậtdeploy) · [Xử lý sự cố](#10-xử-lý-sự-cố).

---

## 1. Cài đặt

### Tự động (Kali) — khuyến nghị
```bash
# clone sẵn rồi chạy từ trong repo:
sudo bash scripts/install-kali.sh
# hoặc để script tự clone:
sudo REPO_URL=https://github.com/<bạn>/<repo>.git bash scripts/install-kali.sh
```
Script sẽ cài: Go 1.26, Node, PostgreSQL, bộ tool recon (nuclei/httpx/subfinder/
nmap…), tạo DB, dựng service systemd `k1nzr3c0n-go` (cổng `:8000`), build FE+BE,
và hỏi đặt mật khẩu admin.

Biến môi trường tuỳ chỉnh: `PORT`, `PG_USER/PG_PASS/PG_DB`, `ADMIN_USER`,
`SKIP_TOOLS=1` (bỏ cài tool), `SKIP_CLAUDE=1` (bỏ cài claude CLI).

### Thủ công
Xem mục **Manual build** trong [README](../README.md). Tóm tắt:
```bash
cd web && npm install && npm run build:static && cd ..
rm -rf server/webui/dist && cp -r web/out server/webui/dist
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex
ARTEX_PG_DSN='postgres://artex:artex@127.0.0.1:5432/artex?sslmode=disable' ./k1nzr3c0n -addr :8000
```

---

## 2. Đăng nhập & giao diện

Mở `http://<ip-server>:8000/` → đăng nhập user **ARTEX** + mật khẩu đã đặt.

Sidebar:
- **Features**: Dashboard, Chat (agent), Tasks, Findings, Traffic, Tool executions,
  LLM recordings, Assets, Asset sync, Workspace.
- **Workflow Runner**: Runs, Graph, Workflows.
- **System**: LLM, Agent, MCP, Skill, Tool, Notifications, Interception rules,
  Approval records, Logs, System settings.

---

## 3. Cấu hình LLM

Vào **System → LLM**. Mỗi card là một "profile" (nhà cung cấp + model + rate limit).
Ngôi sao ⭐ = profile đang active (mọi agent dùng nó mặc định).

- **New**: tạo profile cho provider thường (Anthropic / OpenAI / OpenAI-Responses /
  Ollama) — điền Format, Model, Base URL, API key.
- **Rotation settings**: bật pool/failover — khi profile chính lỗi/hết quota, tự
  xoay sang profile khác theo priority.
- **Set active** / **⭐**: chọn profile đang dùng. Xóa bằng nút 🗑 (xóa được cả
  profile đang active — hệ thống tự chuyển active sang cái khác; chỉ từ chối khi
  là profile cuối cùng).
- **Test connection**: gọi thử 1 request để kiểm tra profile chạy được.

---

## 4. Claude Pro/Max (subscription)

Dùng **gói Claude Pro/Max** thay cho API key trả tiền, bằng cách tái sử dụng token
mà **Claude Code CLI** đã có trên server.

**Bước 1 — login Claude Code trên server:**
```bash
sudo claude            # đăng nhập 1 lần; ghi /root/.claude/.credentials.json
```
(User chạy service là `root` nên dùng `sudo`. Nếu khác, đặt `CLAUDE_CONFIG_DIR`.)

**Bước 2 — tạo profile:** UI → **LLM → nút "Claude Pro/Max"** (cạnh Rotation settings):
- **Seed all models**: tạo 1 profile cho mỗi model hỗ trợ
  (`claude-opus-4-8`, `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5`,
  `claude-fable-5-1`, `claude-sonnet-4-5`, `claude-haiku-4-5`).
- **Add a model**: gõ tên model bất kỳ (kể cả model mới ra) rồi **Add**.

**Bước 3 — chọn active** profile Claude muốn dùng (vd `claude-opus-4-8`).

Token đọc **trực tiếp từ file login của server mỗi lần gọi** và **tự gia hạn**;
khi deploy cũng tự seed (`deploy.sh`, cần `ARTEX_PASSWORD`). Task agent dùng
profile claude-sub bình thường như mọi provider khác.

> ⚠️ Dùng gói subscription ngoài Claude Code vi phạm ToS của Anthropic và có thể
> bị khoá tài khoản. Đây là tính năng tự chọn, người vận hành tự chịu trách nhiệm.

---

## 5. Chạy Workflow recon

Vào **Workflow Runner → Runs → New run**:

1. **Target**: domain gốc, vd `example.com` (target chưa đăng ký sẽ tự tạo).
2. **Workflow**: chọn pipeline:
   - `02-full-recon-artex.yaml` — **mặc định, nhanh**: discovery chủ động (resolve
     → httpx → ports → nuclei) không passive. *(khuyến nghị để bắt đầu)*
   - `01-full-recon-pipeline.yaml` — đầy đủ/nặng (gồm passive sources, ASN, hoán vị
     subdomain…). Cần API keys passive (xem dưới).
   - `03-js-secrets-recon.yaml` — crawl JS, moi secret.
   - `04-param-discovery.yaml` — dò tham số.
   - `05-scan-hosts.yaml` — quét sâu 1 tập host + **VHOST matrix** (thử mọi tên
     không resolve × mọi IP qua Host header).
3. (Tuỳ chọn) `target_hosts` / `subdomains_list`: giới hạn tập host.
4. **Start** → theo dõi tiến trình, log từng bước realtime.

**API keys passive** (cho workflow 01): `cp scripts/api-keys.env.example
scripts/api-keys.env`, điền key, rồi deploy lại (tự nạp qua `/api/v1/keys`).
**Không commit** file này (đã gitignore).

Kết quả mọi tool được parse vào **DB** và **graph** tự động.

---

## 6. Xem Graph

**Workflow Runner → Graph** → chọn target → mở viewer graph2 (tab mới):
toàn bộ quan hệ domain ↔ subdomain ↔ IP ↔ ASN/subnet ↔ port ↔ URL ↔ param ↔
finding ↔ cert/dns/secret/bucket. Có Inspector, filter, path, export.

Agent cũng tra cứu graph này (per-target và per-run) khi phân tích.

---

## 7. Task Agent (Chat & Tasks)

- **Chat**: hội thoại với agent. Chọn agent (Auto / Red Team…) và model ở dưới ô
  nhập. Agent tự dùng tool (quản lý/chạy workflow, đọc log/graph/findings, chạy
  lệnh có kiểm soát, tạo/sửa skill & custom tool, MCP).
- **Tasks**: giao task mục tiêu rõ ràng (vd "pentest `example.com`"); agent tự
  lập kế hoạch, chạy recon/exploit, **verify** (tái hiện độc lập trước khi báo),
  **hunt** (tìm cái workflow bỏ sót), rồi ghi finding.
- Dùng template **Red Team** để có quy trình recon-driven + VHOST matrix sẵn.

---

## 8. Findings & Traffic

- **Findings**: kho lỗ hổng tập trung; mở từng finding xem chi tiết, bằng chứng,
  traffic liên quan, retest.
- **Traffic**: proxy ghi lại HTTP (mặc định `127.0.0.1:8788`); lọc/inspect request.
- **Tool executions / LLM recordings**: log chạy tool và log gọi LLM để truy vết.

---

## 9. Cập nhật/Deploy

Trên server (từ `/opt/k1nzr3c0n-src`):
```bash
sudo bash scripts/deploy.sh                      # full: FE + backend + assets + restart + seed
SKIP_FE=1 sudo bash scripts/deploy.sh            # nhanh: chỉ backend (không build lại FE)
SKIP_FE=1 ARTEX_PASSWORD='<mật khẩu>' sudo -E bash scripts/deploy.sh   # + seed Claude profiles
RESEED=1 ARTEX_PASSWORD='<mật khẩu>' sudo -E bash scripts/deploy.sh    # + nạp lại task template
```
> Lưu ý: nếu sửa **frontend**, phải build lại FE rồi commit `server/webui/dist`
> (repo track dist để go:embed). SKIP_FE chỉ dùng khi dist đã mới.

Quản lý service:
```bash
systemctl status k1nzr3c0n-go
journalctl -u k1nzr3c0n-go -f        # xem log realtime
systemctl restart k1nzr3c0n-go
```

---

## 10. Xử lý sự cố

| Triệu chứng | Nguyên nhân & cách xử lý |
| --- | --- |
| **Chat báo `401 OAuth access token has been revoked`** | Token Claude bị thu hồi (CLI refresh/login lại làm xoay vòng grant). Chạy lại `sudo claude` trên server để làm mới `/root/.claude/.credentials.json`; app đọc token sống nên tự cập nhật. Nếu grant bị thu hồi hẳn → `claude` login lại từ đầu. (Cũng là rủi ro ToS.) |
| **Model 5.x lỗi `thinking.type.disabled not supported`** | Đã xử lý tự động (runtime bỏ `thinking` cho model Claude 5). Nếu vẫn gặp, cập nhật binary mới nhất. |
| **Không tạo được profile claude-sub / `/seed` báo không có creds** | `claude` chưa login trên server, hoặc login bằng user khác user chạy service. Chạy `sudo claude`, hoặc đặt `CLAUDE_CONFIG_DIR` trỏ tới thư mục chứa `.credentials.json`. |
| **Xóa profile không được** | Chỉ không xóa được khi đó là **profile duy nhất**. Profile đang active vẫn xóa được (tự chuyển active sang cái khác). |
| **Workflow bước đỏ ngay khi render** | Lỗi template: dấu `{N}` (vd `{3}` trong regex) bị hiểu là biến. Dùng dạng `[0-9]{1,3}\.[0-9]...`, `[0-9][0-9][0-9]`, hoặc `curl -I` thay cho `%{http_code}`. |
| **Service không start** | `journalctl -u k1nzr3c0n-go -n 60` — thường do PostgreSQL chưa sẵn sàng hoặc `ARTEX_PG_DSN` sai. |
| **Workflow passive không ra kết quả** | Thiếu API key: `cp scripts/api-keys.env.example scripts/api-keys.env`, điền, deploy lại. |

---

### An toàn / Pháp lý
Chỉ test tài sản được phép. Giữ đúng scope. Không đưa tên mục tiêu thật vào code/commit
(dùng placeholder như `example.com`). Tôn trọng license của các tool/skill đi kèm.
