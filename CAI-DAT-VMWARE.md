# Cài đặt K1nzr3c0n từ đầu trên VMware (Kali Linux)

> Hướng dẫn cài sạch trên một VM mới. Lệnh copy-paste được. Chạy với `root` (hoặc `sudo`).
> Hai nửa: **ARTEX** (engine tự hành, PostgreSQL) + **Workflow Runner k1nzr3c0n** (recon, SQLite) — một binary.

---

## 0. Tạo VM trên VMware
- **OS:** Kali Linux (khuyến nghị — có sẵn ~100 tool recon). Ubuntu/Debian cũng được nhưng phải tự cài tool.
- **Tài nguyên:** ≥ **4 vCPU · 8GB RAM · 60GB disk** (recon song song + Postgres + build).
- **Network:** NAT hoặc Bridged. Công cụ "NAT-safe" nên NAT ổn. Ghi lại **IP VM**: `ip a` (vd `192.168.x.x`).
- Cập nhật hệ thống:
```bash
sudo apt-get update && sudo apt-get -y upgrade
```

---

## 1. Gói phụ thuộc hệ thống
```bash
sudo apt-get install -y git build-essential postgresql curl ca-certificates chromium
```
> `chromium` cho bước chụp screenshot (gowitness). `postgresql` bắt buộc cho ARTEX. **Không cần Redis.**

### Go (≥ 1.23 — tự nâng toolchain lên 1.26 theo go.mod)
Kali apt thường có Go cũ. Cài bản mới từ go.dev:
```bash
cd /tmp
curl -LO https://go.dev/dl/go1.23.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' | sudo tee /etc/profile.d/go.sh
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
go version    # go1.23.x — lần build đầu sẽ tự tải toolchain 1.26 theo go.mod
```

### Node.js 20+ (cho build giao diện — Next 16 / React 19)
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node -v   # v20.x
```

---

## 2. PostgreSQL
```bash
sudo systemctl enable --now postgresql
sudo -u postgres psql -c "CREATE USER artex WITH PASSWORD 'ĐỔI_MẬT_KHẨU_NÀY';"
sudo -u postgres psql -c "CREATE DATABASE artex OWNER artex;"
```
> Nếu `CREATE DATABASE` báo **collation version mismatch** (glibc mới):
> ```bash
> sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION"
> sudo -u postgres psql -c "CREATE DATABASE artex OWNER artex;"
> ```
Schema tự tạo khi chạy lần đầu (idempotent).

---

## 3. Lấy mã nguồn & build

```bash
sudo git clone https://github.com/kienzx203/k1nzr3c0n-go /opt/k1nzr3c0n-src
cd /opt/k1nzr3c0n-src
```

### 3a. Build giao diện (web → server/webui/dist)
```bash
cd web
npm ci                 # hoặc: npm install  (lần đầu, hơi lâu)
npm run build:static   # tạo web/out/
ls out/index.html      # PHẢI tồn tại trước khi qua bước sau
cd ..
rm -rf server/webui/dist && cp -r web/out server/webui/dist
```

### 3b. Build backend (Go, nhúng UI)
```bash
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex
./k1nzr3c0n -h   # kiểm binary chạy (in help)
```
> Lần đầu Go tự tải toolchain 1.26 + vendored deps — chờ vài phút. Lỗi `config has no field…` = cache hỏng: `go clean -cache` rồi build lại.

---

## 4. Bố trí thư mục chạy (base dir) — QUAN TRỌNG
Service đọc **skills/workflows/wordlists/data** theo `K1NZR3C0N_BASE`. Dựng base dir cố định:
```bash
sudo mkdir -p /opt/k1nzr3c0n
sudo cp k1nzr3c0n /opt/k1nzr3c0n/
sudo cp -r workflows wordlists skills /opt/k1nzr3c0n/
```
> Checkout git (`-src`) chỉ để build; dữ liệu runtime nằm ở `/opt/k1nzr3c0n`. Đừng nhầm hai nơi.

---

## 5. Chạy bằng systemd
Tạo `/etc/systemd/system/k1nzr3c0n-go.service`:
```ini
[Unit]
Description=K1nzr3c0n
After=postgresql.service network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/k1nzr3c0n
Environment=K1NZR3C0N_BASE=/opt/k1nzr3c0n
Environment=ARTEX_PG_DSN=postgres://artex:ĐỔI_MẬT_KHẨU_NÀY@127.0.0.1:5432/artex?sslmode=disable
Environment=RECON_API_BASE=http://127.0.0.1:8000
# Bật tự-triage (tùy chọn, tốn LLM): Environment=AUTO_TRIAGE_ENABLED=1
ExecStart=/opt/k1nzr3c0n/k1nzr3c0n -addr :8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now k1nzr3c0n-go
sudo systemctl status k1nzr3c0n-go --no-pager   # phải "active (running)"
journalctl -u k1nzr3c0n-go -f                    # xem log nếu lỗi
```

---

## 6. Chạy lần đầu (setup / login)
1. Mở trình duyệt: **`http://<IP-VM>:8000/`**
2. Lần đầu → **/setup**: đặt **mật khẩu admin**.
3. **/login**: tên đăng nhập là **`ARTEX`** + mật khẩu vừa đặt.

---

## 7. Cấu hình BẮT BUỘC để dùng được

### 7a. ⭐ LLM profile (BẮT BUỘC — nếu thiếu, mọi Task/Chat/agent "nằm im")
**System → LLM** → thêm profile (Anthropic / OpenAI / Ollama / GLM) + **API key** → **đặt active**.
> Đây là lỗi hay gặp nhất: tạo Task nhưng "không làm gì" = chưa có LLM profile hoạt động.

### 7b. Cài bộ tool recon
**Workflow Runner → Tool versions** → cài subfinder/httpx/nuclei/naabu/katana… (hoặc từng cái). Kali có sẵn nhiều tool.

### 7c. API keys cho recon (script)
```bash
cd /opt/k1nzr3c0n-src
cp scripts/api-keys.env.example scripts/api-keys.env   # điền key thật (file này gitignored)
BASE_URL=http://127.0.0.1:8000 ./scripts/add-api-keys.sh
```

### 7d. Task templates chuyên gia (bounty / pentest / redteam)
```bash
BASE_URL=http://127.0.0.1:8000 ARTEX_PASSWORD='mật_khẩu_admin' ./scripts/add-task-templates.sh
# (username đăng nhập là ARTEX, script tự dùng)
```

### 7e. Skills nâng cao (tùy chọn — hacktricks / payloads, không trong git)
Nếu có 2 thư mục skill đó: copy vào base dir rồi F5 trang Skill:
```bash
cp -r hacktricks payloads-all-the-things /opt/k1nzr3c0n/skills/
```

---

## 8. Tích hợp ARTEX ↔ Workflow Runner (đã có sẵn)
- **Send to Agent** (A): Run Detail có nút 🚀 → tạo Task tự hành từ bề mặt recon.
- Agent có tool `recon_findings`/`recon_assets` (B) và `run_workflow`/`run_status` (C).
- **Auto-triage** (D): bật `AUTO_TRIAGE_ENABLED=1` (systemd) + bật *alert new assets* trên một Schedule → re-scan có asset mới sẽ tự spawn Task. (Mặc định OFF để tránh tốn LLM.)

---

## 9. Bảo mật
- **`/api/v1` MỞ khi chưa đặt token** → nếu VM truy cập được từ ngoài, giữ sau firewall/VPN; hoặc đổi `-addr 127.0.0.1:8000` (chỉ localhost) rồi SSH-tunnel.
- Chỉ scan mục tiêu **được phép**. Dùng **Targets** (scope deny-wins) để giới hạn.
- Không commit `scripts/api-keys.env`; rotate key nếu lộ.

---

## 10. Cập nhật về sau
```bash
cd /opt/k1nzr3c0n-src && git pull
cd web && npm run build:static && ls out/index.html
cd .. && rm -rf server/webui/dist && cp -r web/out server/webui/dist
ARTEX_SKIP_FRONTEND=1 go build -tags embedui -o k1nzr3c0n ./cmd/artex
sudo systemctl stop k1nzr3c0n-go && sudo cp k1nzr3c0n /opt/k1nzr3c0n/ && sudo systemctl start k1nzr3c0n-go
```
> Sửa chỉ backend Go → bỏ qua bước `web`. Sửa UI → phải build lại `web`. Sau deploy hard-refresh trình duyệt (Ctrl+Shift+R).

---

## 11. Xử lý sự cố (gom các lỗi hay gặp)

| Triệu chứng | Xử lý |
|---|---|
| **Task tạo xong "không làm gì"** | Chưa có **LLM profile** active (System → LLM) — nguyên nhân #1. |
| Service không lên | `journalctl -u k1nzr3c0n-go -f`; thường do DSN Postgres sai hoặc port bận. |
| `CREATE DATABASE` lỗi collation | `ALTER DATABASE template1 REFRESH COLLATION VERSION` rồi tạo lại. |
| Build FE `Module not found` / type error | Đã fix sẵn trong repo (locale vendor + turbopack + ignoreBuildErrors) — chỉ cần `git pull` bản mới. |
| `cp: cannot stat 'out'` | `npm run build:static` lỗi → sửa lỗi đó trước; ĐỪNG `rm -rf dist` tới khi `ls out/index.html` OK. |
| `Text file busy` khi cp binary | `systemctl stop k1nzr3c0n-go` trước khi `cp`. |
| Sửa UI mà không thấy đổi | Phải rebuild `web` → copy vào `dist` → build Go → restart → hard-refresh. |
| Skill không hiện | Copy folder vào **`$K1NZR3C0N_BASE/skills`** (vd `/opt/k1nzr3c0n/skills`), không phải checkout `-src`. |
| Terminal `cd: HOME not set` / tool không thấy | Đã fix (PTY set env + dùng login shell thật). Cần binary mới. |
| `/api/*` 401 | ARTEX cần đăng nhập (username **ARTEX**). `/api/v1/*` runner mở sẵn. |

---

*Build FE cần Node 20+; backend cần Go ≥1.23 (tự nâng 1.26). Không cần Redis. Dữ liệu runtime ở `$K1NZR3C0N_BASE`.*
