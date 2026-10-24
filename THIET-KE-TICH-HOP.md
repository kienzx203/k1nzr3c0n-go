# Thiết kế tích hợp ARTEX ↔ Workflow Runner (A · B · C · D)

> Mục tiêu: nối **Workflow Runner** (recon tất định, rẻ, rộng — SQLite/k1z) với **ARTEX**
> (suy luận tự hành, sâu, đắt — PostgreSQL) thành một vòng khép kín:
> *recon nuôi exploit, exploit điều phối recon, giám sát liên tục tự triage.*

---

## 0. Bối cảnh & ràng buộc (phải tôn trọng khi thiết kế)

| Ràng buộc | Hệ quả thiết kế |
|---|---|
| **2 database** — Workflow Runner dùng **SQLite** (`k1z`), ARTEX dùng **PostgreSQL** | Không chia sẻ bảng. Tích hợp ở **tầng service/API trong cùng 1 binary**, qua một lớp **Bridge** mỏng. |
| **Auth khác nhau** — ARTEX `/api/*` cần **JWT**; k1z `/api/v1/*` **mở** khi chưa đặt token | Gọi chéo trong tiến trình (in-process) hoặc dùng **service token** nội bộ, không phụ thuộc JWT của người dùng. |
| **Scope deny-wins** là chốt an toàn pháp lý | Mọi task/recon sinh tự động PHẢI mang theo scope của Target (dạng ARTEX `interceptRules` allow/deny). |
| **LLM tốn tiền** | Phần tự động (D) phải có **rate-limit + ngưỡng severity** để chặn bùng chi phí. |

### Lớp Bridge (nền tảng chung cho A/B/C/D)
Một package mới `k1z/bridge` (hoặc `server/bridge`) cung cấp:
- `CompileReconBrief(target|runID) → ReconBrief` — gom findings/hosts/ports/endpoints/tech/
  ST-intel/screenshots từ store k1z thành một cấu trúc + bản markdown tóm tắt.
- `CreateArtexTask(input) → taskID` — gọi **in-process** vào service tạo task của ARTEX
  (không qua HTTP/JWT), gắn scope + provenance `source_run_id`.
- `LaunchWorkflowRun(target, workflow, vars) → runID` và `RunStatus(runID)` — bọc runner k1z.
Bridge là nơi DUY NHẤT biết cả hai phía → tránh rải code chéo DB khắp nơi.

---

## A. Handoff: Run/Target → ARTEX Task  ⭐ (ưu tiên 1)

**Ý tưởng:** từ một Run đã recon xong, bấm 1 nút để spawn một Task ARTEX đã nạp sẵn toàn
bộ bề mặt tấn công → agent khỏi quét lại, vào thẳng khai thác.

**Luồng:**
```
Run Detail ──"🚀 Send to Agent"──▶ POST /api/v1/runs/{id}/handoff
                                        │ (bridge)
                                        ├─ CompileReconBrief(runID)
                                        │     hosts, ports, http+tech, endpoints/params,
                                        │     nuclei vulns, ST-intel, screenshots, scope
                                        ├─ CreateArtexTask({
                                        │     goal: "Triage & exploit <target>",
                                        │     description: <brief markdown>,
                                        │     interceptRules: <allow scope của target>,
                                        │     coverageEnabled: true, seedFirstIntent: false,
                                        │     source_run_id: id })
                                        └─▶ { task_id }
Frontend ──▶ điều hướng /function/tasks/detail?id=<task_id>
```

**Hợp đồng API (mới):**
- `GET  /api/v1/runs/{id}/recon-brief` → `{ target, scope, hosts[], ports[], services[], endpoints[], vulns[], markdown }` (chỉ biên dịch, không tạo task — dùng để preview).
- `POST /api/v1/runs/{id}/handoff` body `{ goal?, extra_note?, coverage?, seed_first_intent? }` → `{ task_id }`.
- Tùy chọn: `POST /api/v1/targets/{name}/handoff` (gom **tất cả** run của target, không chỉ 1 run).

**ReconBrief (ví dụ markdown nhồi vào `description`):**
```
# Recon surface — example.com (run 26dce7…, workflow 01-full-recon)
SCOPE (deny-wins): example.com, *.example.com   | mode: bounty
## Live hosts (httpx) — 42
  api.example.com [200, nginx, React]  admin.example.com [403]  …
## Open ports (naabu) — 7 hosts
  10.0.0.5: 22,80,443,8080  …
## Endpoints/params (katana+JS) — 318
  /api/v1/users?id=  /admin/export  /graphql  …
## Vulns (nuclei) — 3 (1 high, 2 medium)
  [high] CVE-2024-xxxx on api.example.com  …
## ST-intel: 1,730 subdomains, 12 SSL certs, WHOIS …
OBJECTIVE: validate & exploit the above WITHOUT re-scanning; prioritize auth/IDOR/SSRF.
```

**UI:** nút trên **Run Detail** (header, cạnh Report) + **Target detail**. Có dialog nhỏ cho
chọn goal preset (bounty/pentest/redteam — tái dùng template §task-templates) + coverage.

**Vì sao ưu tiên:** dùng `createTask` **đã có**, chủ yếu bridge + frontend, **không migrate DB**,
và là đường ống giá trị nhất (broad recon → focused exploitation).

---

## B. Agent đọc recon theo yêu cầu (tool cho ARTEX worker)

**Ý tưởng:** giữa một Task, worker ARTEX tự kéo dữ liệu recon đã có thay vì chạy lại tool.

**Cơ chế:** thêm **native tool** vào registry tool của ARTEX agent (`server/` agent tools),
thực thi bằng cách gọi **in-process** vào bridge/store k1z (không HTTP). Bộ tool:

| Tool | Tham số | Trả về |
|---|---|---|
| `recon_findings` | `target, kind?, severity?, limit?` | findings vuln/http/port/subdomain/url |
| `recon_hosts` | `target` | live hosts + status/title/tech/CDN |
| `recon_endpoints` | `target, with_params?` | URL/endpoint/param từ crawl+JS |
| `recon_st_intel` | `target, section` | subdomains/DNS/WHOIS/SSL |
| `recon_screenshot` | `target|host` | path ảnh (agent có thể mở/mô tả) |

**Thiết kế:** các tool chỉ **đọc**, tôn trọng scope (chỉ trả dữ liệu trong scope của task).
Phơi cho worker qua tool-visibility của agent-config (bật/tắt per-role). Đây là **đệm hoàn hảo
cho A**: task nạp brief tĩnh lúc tạo, rồi B cho agent đào sâu động.

**Thay thế nhẹ hơn (MVP):** khai báo bằng **Custom Tool kind=http** sẵn có trỏ tới
`http://127.0.0.1:<port>/api/v1/...` — không cần code Go, seed 1 lần. Nhược: phải bật k1z API.

---

## C. Agent chạy workflow (`run_workflow`) — recon do agent điều phối

**Ý tưởng:** chiều ngược của A — agent tự quyết "cần recon gì" rồi chạy workflow.

**Cơ chế:** tool bất đồng bộ (vì workflow chạy lâu):

| Tool | Hành vi |
|---|---|
| `run_workflow` | `{target, workflow, vars}` → `LaunchWorkflowRun` → trả `run_id` **ngay** (không chờ) |
| `run_status` | `{run_id}` → `{status, steps_done/total, findings_count}` để agent poll |
| (sau khi xong) | agent gọi `recon_findings`/`recon_hosts` (§B) để lấy kết quả |

**Scope safety (bắt buộc):** `run_workflow` CHỈ chạy được trên **target đã đăng ký & trong
scope của task** (deny-wins). Agent không thể nhắm target tùy ý. Thêm allowlist workflow
(vd chỉ cho các workflow "an toàn/nhẹ" khi agent tự chạy).

**Lưu ý chi phí/ồn:** nên có workflow "quick-recon" nhẹ cho agent, và giới hạn số run/task.

---

## D. Continuous diff → auto-spawn Task (giám sát liên tục)

**Ý tưởng:** Schedule re-scan target theo cron; khi bề mặt **thay đổi** (asset/endpoint/vuln
MỚI so với lần trước) → tự tạo Task ARTEX scope đúng phần **delta** để triage ngay.

**Cơ chế:** hook sau mỗi scheduled run (k1z `schedule` + `runner` đã có
`ListNewAssetsByRun`/new-assets diff):
```
scheduled run xong ──▶ computeDelta(run, prevRun)   // asset/endpoint/vuln mới
   if delta không rỗng AND schedule.auto_triage:
       brief = CompileReconBrief(delta-only)
       if maxSeverity(delta) >= schedule.min_severity AND dưới rate-limit:
           CreateArtexTask({ goal:"Triage bề mặt mới của <target>",
                             description: brief, interceptRules: scope,
                             source_run_id, source_schedule_id })
           notify (Discord/Slack): "N asset/vuln mới → Task <id> đã spawn"
```

**Cấu hình (per-schedule, thêm vào form Schedule):**
- `auto_triage: bool` — bật tự spawn Task khi có bề mặt mới.
- `min_severity` — chỉ spawn nếu delta có vuln >= mức này (hoặc "any new asset").
- `max_tasks_per_day` — trần chi phí.

**Giá trị:** biến hệ thống thành **continuous recon → autonomous triage** — đúng mơ ước bug-bounty/ASM.

---

## Xuyên suốt (áp cho cả A/B/C/D)

- **Scope:** mọi task/recon tự sinh mang `interceptRules` = scope của Target (allow in-scope,
  deny phần còn lại). Bridge dịch Target scope → ARTEX rules một chỗ.
- **Auth nội bộ:** bridge gọi ARTEX task-create **in-process** (không JWT). Nếu buộc qua HTTP,
  dùng **service token** riêng, không phải token người dùng.
- **Provenance (2 chiều):** Task lưu `source_run_id`/`source_schedule_id`; Run Detail hiện
  "Tasks sinh từ run này"; Task Detail hiện "Recon nguồn: run X". Cross-link UI.
- **Chi phí:** chỉ D là tự động → rate-limit + ngưỡng. A/B/C do người/agent chủ động.
- **Findings hợp nhất (đích xa, hậu A–D):** view Findings gộp cả 2 nguồn với badge
  nguồn + dedup — cần lớp đọc chéo 2 DB (bridge mở rộng).

---

## Lộ trình triển khai (phase)

| Phase | Nội dung | Phụ thuộc | Rủi ro |
|---|---|---|---|
| **1** | Lớp **Bridge** + `CompileReconBrief` + `CreateArtexTask` (in-process) + provenance cột `source_run_id` | — | Thấp |
| **2** | **A**: `/recon-brief` + `/handoff` + nút "Send to Agent" (Run & Target) | Phase 1 | Thấp (FE + 2 endpoint) |
| **3** | **B**: bộ tool `recon_*` cho worker ARTEX (native, in-process) | Phase 1 | TB (đụng registry tool ARTEX) |
| **4** | **C**: `run_workflow`/`run_status` + allowlist scope/workflow | Phase 1,3 | TB (an toàn scope) |
| **5** | **D**: hook scheduled-run + cấu hình auto_triage + rate-limit + notify | Phase 1,2 | TB (chi phí) |

**Khuyến nghị:** làm Phase 1→2 trước (A), có ngay giá trị lớn nhất; rồi B (đệm cho A); C/D sau.

---

*Thiết kế ở mức kiến trúc + hợp đồng API. Endpoint/field đánh dấu "(mới)" là đề xuất, chưa có trong code.*
