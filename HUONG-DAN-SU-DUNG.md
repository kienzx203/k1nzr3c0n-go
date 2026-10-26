# Hướng dẫn sử dụng chuẩn — luồng recon → pentest tự hành

> Quy trình vận hành từ A→Z trên K1nzr3c0n. Đăng nhập username **ARTEX** + mật khẩu admin.
> Hai nửa: **Workflow Runner** (recon, mục "Workflow Runner" ở sidebar) + **ARTEX** (agent tự hành: Tasks/Agent/Chat).

---

## PHẦN A — Chuẩn bị 1 lần (bắt buộc, làm đúng thứ tự)

### A1. ⭐ LLM profile (THIẾU = mọi task/agent nằm im)
**System → LLM** → **+ Add profile** → chọn provider (Anthropic/OpenAI/GLM/Ollama…) + nhập **API key** → **Set active**.
> Đây là lỗi hay gặp #1: tạo task mà "không làm gì" = chưa có LLM profile active.

### A2. Cài bộ tool recon
**Workflow Runner → Tool versions** → cài subfinder, httpx, nuclei, naabu, katana, gau, ffuf… (Kali có sẵn nhiều; cái nào thiếu thì cài).

### A3. API keys cho recon (tùy chọn nhưng nên có)
**Workflow Runner → API Keys** → nhập key Shodan/Censys/SecurityTrails/GitHub… (tự inject vào subfinder + `$ENV` khi chạy workflow). Hoặc dùng script:
```bash
cd /opt/k1nzr3c0n-src
BASE_URL=http://127.0.0.1:8000 ./scripts/add-api-keys.sh   # điền key thật vào scripts/api-keys.env trước
```

### A4. Skill nâng cao (tùy chọn)
Copy skill vào base dir rồi **System → Agent → <agent> → bật skill** (agent_visibility):
```bash
sudo cp -r skills/recon-first-pentest skills/api-recon skills/scopesentry /opt/k1nzr3c0n/skills/
# hacktricks / payloads-all-the-things: copy nếu có (không trong git)
```

### A5. Template chuyên gia (1 lần)
```bash
BASE_URL=http://127.0.0.1:8000 ARTEX_PASSWORD='mật_khẩu' bash scripts/add-task-templates.sh
# → tạo template "Offensive Security" (tự chọn mode Bounty/Pentest/RedTeam + luồng workflow)
```

---

## PHẦN B — Chạy 1 engagement (luồng chính, lặp lại mỗi mục tiêu)

### B1. ⭐ Đăng ký Target (BẮT BUỘC — thiếu thì workflow không chạy)
**Workflow Runner → Targets → + Register Target**:
- **Name:** domain, vd `example.com`
- **Scope:** `*.example.com` và `example.com` (deny-wins: ngoài scope bị chặn)
- **Mode:** `bounty` / `vdp` / `oos`

Hoặc API:
```bash
curl -sS -X POST http://127.0.0.1:8000/api/v1/targets -H 'Content-Type: application/json' \
  -d '{"name":"example.com","scope":["*.example.com","example.com"],"mode":"bounty"}'
```

### B2. Tạo Task tự hành (CÁCH KHUYẾN NGHỊ — deterministic)
**Tasks → New task**:
1. **Template:** chọn **Offensive Security** (goal + playbook tự điền).
2. Sửa **Goal** cho rõ mục tiêu, có chứa domain (vd "Find in-scope high-severity bugs on example.com").
3. Mở phần nâng cao → tick **☑ 🔭 Recon-first**:
   - **Recon target:** `example.com` (bỏ trống = tự tách từ goal).
   - **Workflow:** **All workflows (all)** (chạy full-recon + JS/secrets + param) hoặc chọn 1 cái.
4. (Tùy chọn) chọn **LLM profile** riêng cho task.
5. **Create**.

→ Server **tự chạy recon workflow trước** (full option, trừ pivot scan + PTR /24 hàng xóm), chờ xong, **nạp brief**, rồi agent **pentest** dựa trên kết quả.

### B3. Theo dõi
Mở Task vừa tạo → tab **Session/Overview**. Activity chạy theo thứ tự:
```
⏳ Recon-first: preparing recon on example.com…
⏳ Recon-first: 01-full-recon-pipeline.yaml (run …) is running…
✅ Recon done (N/M workflows) — brief loaded, starting pentest.
→ (agent bắt đầu triage + khai thác)
```
- **Workflow Runner → Runs:** xem run recon thật (steps, log).
- Tab **Findings** (trong task) + mục **Findings** (toàn cục): lỗ hổng tìm được.
- Tab **Exploration paths / Broadcast / Test assets:** diễn tiến agent.

### B4. Report & Retest (tự động / thủ công)
- **Report writer** (agent): tự kích hoạt khi có finding → viết Markdown report (xem tab **Report** của task / mục Findings).
- **Finding retest** (agent): mở chi tiết 1 finding → nút phúc tra → đọc evidence gốc, kết luận độc lập.

---

## PHẦN C — Các cách chạy recon (hiểu để chọn)

| Cách | Khi nào | Hành vi |
|---|---|---|
| **B. Recon-first (server)** ⭐ | Mặc định, chắc chắn nhất | Server tự `run_workflow` trước khi agent chạy → agent LUÔN có brief. Không phụ thuộc LLM. |
| **Agent tự gọi** (template/skill) | Giữa task phát hiện bề mặt mới | Agent gọi `list_workflows` → tự chọn → `run_workflow` (mặc định CHỜ + trả brief). Chạy `wait=false` để song song. |
| **Send to Agent** | Có sẵn 1 Run recon đã xong | Mở **Runs → run đó → 🚀 Send to Agent** → tạo task pentest từ brief của run. |
| **Thủ công** | Chỉ muốn recon | **Targets → run** hoặc **Runs → New run** chọn workflow. |

---

## PHẦN D — Liên tục (tùy chọn): Schedule + Auto-triage
- **Workflow Runner → Schedules:** đặt lịch re-scan target, bật **Alert new assets**.
- Bật biến môi trường `AUTO_TRIAGE_ENABLED=1` (systemd): khi re-scan thấy **asset mới** → tự spawn 1 Task pentest cho phần mới. (Mặc định TẮT để không tốn LLM bất ngờ.)

---

## PHẦN E — Lỗi hay gặp
| Triệu chứng | Xử lý |
|---|---|
| Task "không làm gì" | Chưa có **LLM profile active** (A1). |
| Activity báo *"target … is not registered"* | Chưa đăng ký Target/scope (B1). |
| Không thấy workflow chạy khi tick Recon-first | Target chưa đăng ký, HOẶC chưa deploy bản có Recon-first. |
| Trang Targets/Keys không load lúc đang run | Đã fix (SQLite concurrency) — cần deploy commit `2bc2c3a`. |
| Agent không gọi được skill | Chưa bật trong **System → Agent → agent_visibility**. |
| Giao diện còn tiếng cũ sau deploy | **Ctrl+Shift+R** (hard-refresh). |

---

## Tóm tắt 1 dòng
**A (LLM + tool + key + template, 1 lần)** → **B1 đăng ký Target** → **B2 New task + Offensive Security + 🔭 Recon-first = All workflows** → theo dõi Findings/Report. Luôn ở trong scope.
