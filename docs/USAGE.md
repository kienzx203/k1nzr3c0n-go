# k1nzr3c0n — Hướng dẫn sử dụng đầy đủ (ALL chức năng)

> ⚠️ **Chỉ dùng hợp pháp.** Đây là công cụ tấn công. Chỉ chạy trên tài sản bạn
> **sở hữu** hoặc **được phép bằng văn bản**. Giữ đúng phạm vi (scope) và luật.
> Không đưa tên mục tiêu thật vào code/commit — dùng placeholder (`example.com`).

**Mục lục**
1. [Cài đặt](#1-cài-đặt) · 2. [Đăng nhập](#2-đăng-nhập) ·
3. [Cấu hình LLM & Claude Pro/Max](#3-cấu-hình-llm--claude-promax) ·
4. [Toàn bộ chức năng theo menu](#4-toàn-bộ-chức-năng-theo-menu) ·
5. [Quy trình điển hình (end-to-end)](#5-quy-trình-điển-hình-end-to-end) ·
6. [Cập nhật / Deploy](#6-cập-nhật--deploy) · 7. [Xử lý sự cố](#7-xử-lý-sự-cố).

---

## 1. Cài đặt

### All-in-one (Kali) — khuyến nghị
```bash
# từ trong repo đã clone:
sudo bash scripts/install-kali.sh
# hoặc để script tự clone:
sudo REPO_URL=https://github.com/<bạn>/<repo>.git bash scripts/install-kali.sh
```
Cài: Go 1.26, Node, PostgreSQL (tạo role+db), bộ tool recon (nuclei/httpx/subfinder/
dnsx/naabu/katana/ffuf/nmap/SecLists), (tuỳ chọn) claude CLI; dựng service systemd
`k1nzr3c0n-go` cổng `:8000`; build backend (dùng frontend đã nhúng sẵn); hỏi đặt
mật khẩu admin. Idempotent — chạy lại an toàn.

Tuỳ chỉnh: `PORT`, `PG_USER/PG_PASS/PG_DB`, `ADMIN_USER/ADMIN_PASS`,
`SKIP_TOOLS=1`, `SKIP_CLAUDE=1`, `GO_VERSION`.

### Thủ công
```bash
cd web && npm install && npm run build:static && cd ..
rm -rf server/webui/dist && cp -r web/out server/webui/dist
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex
ARTEX_PG_DSN='postgres://artex:artex@127.0.0.1:5432/artex?sslmode=disable' ./k1nzr3c0n -addr :8000
```

---

## 2. Đăng nhập

Mở `http://<ip-server>:8000/` → user **ARTEX** + mật khẩu đã đặt. Lần đầu nếu chưa
có mật khẩu, trang sẽ yêu cầu khởi tạo (hoặc installer đã làm qua `/api/auth/init`).

---

## 3. Cấu hình LLM & Claude Pro/Max

**System → LLM.** Mỗi card là 1 *profile* (provider + model + rate limit). ⭐ = active.

- **New** — tạo profile cho provider thường: **Anthropic / OpenAI / OpenAI-Responses /
  Ollama**. Điền Format, Model (nút 🔄 lấy danh sách model), Base URL, API key,
  (tuỳ chọn) Proxy, Custom session header, rate limit, context window, thinking.
- **Rotation settings** — bật *pool/failover*: khi profile chính lỗi/hết quota, tự
  xoay sang profile khác theo *priority*; có circuit-breaker (tạm loại profile đang
  lỗi) và *bind fallback* (ghim theo task).
- **Set active / ⭐** — chọn profile dùng mặc định. **Test connection** — gọi thử.
- **Xóa 🗑** — xóa được cả profile đang active (tự chuyển active sang cái khác);
  chỉ từ chối khi là profile **cuối cùng**.

### Claude Pro/Max (dùng gói subscription, không cần API key)
1. **Login Claude Code trên server:** `sudo claude` (ghi `/root/.claude/.credentials.json`).
2. **LLM → nút "Claude Pro/Max"** (cạnh Rotation settings):
   - **Seed all models**: tạo profile cho mọi model hỗ trợ (opus-4-8, opus/sonnet/
     haiku-5-5, fable-5-1, sonnet/haiku-4-5).
   - **Add a model**: gõ tên model bất kỳ (kể cả model mới) → Add.
3. **Set active** profile Claude muốn dùng. Token đọc **trực tiếp từ file login**
   mỗi lần gọi và **tự gia hạn**; deploy cũng tự seed (`deploy.sh` + `ARTEX_PASSWORD`).
   Task agent dùng claude-sub bình thường như mọi provider.

> ⚠️ Dùng subscription ngoài Claude Code vi phạm ToS Anthropic, có thể bị khoá tài khoản.

---

## 4. Toàn bộ chức năng theo menu

### Features
- **Dashboard** — tổng quan: token tiêu thụ, số task/finding, dòng hoạt động gần đây.
- **Chat** — hội thoại trực tiếp với **agent**. Chọn agent (Auto / Red Team…) và
  model ở dưới ô nhập. Dùng `@` để tham chiếu record (target/finding/run). Agent tự
  dùng tool: quản lý/chạy workflow, đọc log/graph/findings/DB, chạy lệnh có kiểm
  soát, tạo/sửa skill & custom tool, gọi MCP.
- **Tasks** — giao *task* mục tiêu rõ ràng (vd "pentest `example.com`"). Agent tự
  lập kế hoạch → recon/exploit → **verify** (tái hiện độc lập trước khi báo) →
  **hunt** (tìm cái workflow bỏ sót) → ghi finding. Mỗi task có template (vd
  **Red Team** = recon-driven + VHOST matrix), có thể gán nhiều LLM profile.
- **Findings** — kho lỗ hổng tập trung: mức độ, mô tả, bằng chứng, traffic liên
  quan, **retest** (chạy lại để xác nhận còn/đã vá).
- **Traffic** — proxy ghi HTTP (mặc định `127.0.0.1:8788`): lọc, inspect
  request/response, bind traffic vào finding làm bằng chứng.
- **Tool executions** — log mọi lần chạy tool (lệnh, rc, thời gian, output).
- **LLM recordings** — log từng lần gọi LLM (prompt/parameters/response) để truy vết & debug.
- **Assets** — kho tài sản (domain/host/IP/URL…) gom từ recon.
- **Asset sync** — đồng bộ/cập nhật tài sản.
- **Workspace** — không gian làm việc per-engagement (file, ghi chú, sản phẩm).

### Workflow Runner
- **Runs** — danh sách & tạo *run* recon. **New run**: chọn **Target** (domain gốc;
  target chưa đăng ký tự tạo), chọn **Workflow**, tuỳ chọn `target_hosts`/
  `subdomains_list` để giới hạn host, rồi **Start**. Theo dõi log từng bước realtime;
  run có thể **resume**. Kết quả tool được parse vào **DB + graph** tự động.
- **Graph** — chọn target → mở **graph2 viewer** (tab mới): toàn bộ quan hệ
  domain ↔ subdomain ↔ IP ↔ ASN/subnet ↔ port ↔ URL ↔ param ↔ finding ↔
  cert/dns/secret/bucket. Có Inspector, filter, path, centrality, export.
- **Workflows** — xem/quản lý pipeline (file `workflows/*.yaml`):
  | File | Dùng khi |
  |---|---|
  | `02-full-recon-artex.yaml` | **Mặc định, nhanh** — discovery chủ động (resolve→httpx→ports→nuclei), không passive. |
  | `01-full-recon-pipeline.yaml` | Đầy đủ/nặng — gồm passive sources, ASN, hoán vị subdomain (cần API keys passive). |
  | `03-js-secrets-recon.yaml` | Crawl JS, moi secret. |
  | `04-param-discovery.yaml` | Dò tham số. |
  | `05-scan-hosts.yaml` | Quét sâu 1 tập host + **VHOST matrix** (mọi tên không resolve × mọi IP qua Host header). |

### System
- **LLM** — xem [mục 3](#3-cấu-hình-llm--claude-promax).
- **Agent** — cấu hình agent (prompt hệ thống, catalog tool/skill, biến).
- **MCP** — khai báo **MCP server** (nguồn tool ngoài) cho agent gọi.
- **Skill** — thư viện kỹ năng tấn công (AD, cloud, k8s escape, API recon, red-team,
  AI security…) agent nạp theo nhu cầu; có thể bật/tắt, thêm/sửa.
- **Tool** — quản lý custom tool (định nghĩa lệnh + schema) cho agent.
- **Notifications** — thông báo sự kiện (task xong, finding mới…).
- **Interception rules** — luật chặn/duyệt hành động của agent (an toàn/kiểm soát).
- **Approval records** — nhật ký các hành động cần người duyệt.
- **Logs** — log hệ thống.
- **System settings** — cấu hình chung, đổi mật khẩu, tuỳ chọn vận hành.

---

## 5. Quy trình điển hình (end-to-end)

1. **LLM**: tạo/kích hoạt 1 profile (Claude Pro/Max hoặc provider khác).
2. **Workflow Runner → Runs → New run**: target `example.com`, workflow
   `02-full-recon-artex.yaml` → Start. Đợi recon xong.
3. **Graph**: mở graph target để xem toàn cảnh bề mặt tấn công.
4. **Tasks** (hoặc **Chat**): giao task "pentest `example.com`" — agent đọc
   graph/findings, chạy thêm, verify & ghi **Findings**.
5. **Findings/Traffic**: xem lỗ hổng + bằng chứng; retest khi cần.
6. (Nặng hơn) chạy `01` với API keys passive, `05-scan-hosts` cho VHOST matrix.

---

## 6. Cập nhật / Deploy

Trên server (`/opt/k1nzr3c0n-src`):
```bash
sudo bash scripts/deploy.sh                     # full: FE + backend + assets + restart + seed
SKIP_FE=1 sudo bash scripts/deploy.sh           # nhanh: chỉ backend (dùng FE đã nhúng)
SKIP_FE=1 ARTEX_PASSWORD='<mật khẩu>' sudo -E bash scripts/deploy.sh   # + seed Claude profiles
RESEED=1 ARTEX_PASSWORD='<mật khẩu>' sudo -E bash scripts/deploy.sh    # + nạp lại task template
```
> Nếu **sửa frontend** (`web/`): phải build lại FE rồi commit `server/webui/dist`
> (repo track dist để `go:embed`). SKIP_FE chỉ dùng khi dist đã mới.

Service:
```bash
systemctl status k1nzr3c0n-go
journalctl -u k1nzr3c0n-go -f
systemctl restart k1nzr3c0n-go
```

**API keys passive** (cho workflow 01): `cp scripts/api-keys.env.example
scripts/api-keys.env`, điền, deploy lại (tự nạp qua `/api/v1/keys`). **Không commit** file này.

---

## 7. Xử lý sự cố

| Triệu chứng | Xử lý |
|---|---|
| **Chat báo `401 OAuth access token has been revoked`** | Token Claude bị thu hồi (CLI refresh/login lại xoay vòng grant). Chạy `sudo claude` trên server để làm mới `/root/.claude/.credentials.json`; app đọc token sống nên tự cập nhật. Nếu thu hồi hẳn → `claude` login lại. (Cũng là rủi ro ToS.) |
| **Model 5.x lỗi `thinking.type.disabled not supported`** | Đã xử lý tự động (bỏ `thinking` cho Claude 5). Nếu còn → cập nhật binary mới nhất. |
| **Không tạo được claude-sub / `/seed` báo không có creds** | `claude` chưa login trên server, hoặc khác user chạy service. `sudo claude`, hoặc đặt `CLAUDE_CONFIG_DIR`. |
| **Xóa profile không được** | Chỉ không xóa được profile **duy nhất**. Profile active vẫn xóa được (tự chuyển active). |
| **Workflow bước đỏ ngay khi render** | Lỗi template: `{N}` (vd `{3}` trong regex) bị hiểu là biến. Dùng `[0-9]{1,3}\.…` (có dấu phẩy), `[0-9][0-9][0-9]`, hoặc `curl -I` thay `%{http_code}`. |
| **Service không start** | `journalctl -u k1nzr3c0n-go -n 60` — thường PostgreSQL chưa sẵn sàng hoặc `ARTEX_PG_DSN` sai. |
| **Workflow passive không ra kết quả** | Thiếu API key: cấu hình `scripts/api-keys.env` rồi deploy lại. |
| **FE không đổi sau deploy** | Quên rebuild+commit `server/webui/dist`, hoặc deploy SKIP_FE với dist cũ. |

---

### An toàn / Pháp lý
Chỉ test tài sản được phép. Giữ đúng scope. Không commit tên mục tiêu thật
(dùng `example.com`). Tôn trọng license của mọi tool/skill đi kèm.
