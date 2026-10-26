# Thiết kế: Luồng "Recon-First" — tạo task → tự recon → đọc kết quả → pentest sâu

> Mở rộng tích hợp A/B/C/D. Quyết định đã chốt:
> - **Kích hoạt:** OPT-IN qua checkbox "Recon-first" lúc tạo task (hoặc gắn sẵn vào template bounty/pentest). KHÔNG bật cho mọi task.
> - **Cơ chế:** CẢ HAI tầng — (1) **server mở màn** tự chạy workflow → nạp recon-brief vào task (deterministic); (2) **skill** để agent tự re-recon giữa chừng khi phát hiện bề mặt mới.

---

## 1. Vấn đề hiện tại

Agent đã có sẵn tool B/C/D (`recon_findings`, `recon_assets`, `run_workflow`, `run_status`), nhưng **không có gì đảm bảo** agent recon-trước: planner/LLM tự quyết có gọi `run_workflow` hay không → không "tự động", không chắc chắn, và tốn 1 vòng LLM chỉ để nó "nghĩ ra" là nên recon.

Mục tiêu: khi bật Recon-first, trình tự **recon → đọc → pentest** chạy **chắc chắn, đúng thứ tự**, rẻ LLM (server lo phần recon cơ học), và agent vẫn **chủ động re-recon** được khi cần.

---

## 2. Kiến trúc tổng thể

```
POST /api/tasks {recon_first:true, recon_target, recon_workflow}
        │
        ▼
  createTask()
        │  recon_first? ──No──► launchTask()  (luồng chuẩn như cũ)
        │
       Yes
        ▼
  launchTaskReconFirst(t, req)         ← server/recon_first.go (MỚI)
    1. resolve target (recon_target | tách domain từ goal/description)
    2. scope guard: target đã đăng ký? ──Chưa──► warn + fallback launchTask()
    3. seed root asset, emit "⏳ recon-first: đang chạy <workflow> trên <target>"
    4. beginTaskOperation  (giữ slot, CHƯA chạy engine)
        │
        ▼  (goroutine — không chặn HTTP response)
    5. POST /api/v1/runs {workflow,target}  → run_id          (tool C path)
    6. poll GET /api/v1/runs/{run_id}  mỗi 15s tới completed/failed/paused (cap 45')
    7. GET /api/v1/runs/{run_id}/recon-brief  → markdown brief (flow A)
    8. seedIntentText(t, brief + hướng dẫn pentest)   ← nạp recon vào frontier
    9. emit "✅ recon xong: N asset / M vuln — bắt đầu pentest"
   10. admitTask(t,"bootstrap")  → engine.Run chạy pentest VỚI recon đã có sẵn
        │
        └─ mọi lỗi (resolve/scope/run/timeout) ⇒ emit cảnh báo + fallback launchTask()
           (task KHÔNG BAO GIỜ bị kẹt — luôn có đường chạy)
        ▼
  Planner/Worker chạy, trong tay đã có recon-brief.
  Khi phát hiện bề mặt mới / cần quét lại ⇒ agent gọi Skill "recon-first-pentest"
  → playbook ép đúng loop recon_findings → (run_workflow nếu thiếu) → pentest.
```

Hai điểm tái dùng nguyên vẹn: **flow C** (`POST /api/v1/runs`, scope-guard `targetExists`) và **flow A** (`GET /runs/{id}/recon-brief`, `handleReconBrief`). Phần mới chỉ là chất keo server-side + 1 skill.

---

## 3. TẦNG 1 — Server mở màn (deterministic)

### 3.1 `createTaskReq` — thêm 3 field (`server/server.go:1447`)

```go
ReconFirst    *bool  `json:"recon_first,omitempty"`    // bật auto-recon mở màn; nil/false=luồng chuẩn
ReconTarget   string `json:"recon_target,omitempty"`   // target recon; rỗng=tách domain từ goal/description
ReconWorkflow string `json:"recon_workflow,omitempty"` // file workflow; rỗng=01-full-recon-pipeline.yaml
```

### 3.2 `createTask()` — rẽ nhánh (`server/server.go:1535`)

Thay dòng `s.launchTask(...)` cuối hàm bằng:

```go
if req.ReconFirst != nil && *req.ReconFirst {
    s.launchTaskReconFirst(t, req)   // async; tự fallback launchTask nếu không recon được
} else {
    s.launchTask(t, req.Description+" "+req.Goal,
        req.SeedFirstIntent != nil && *req.SeedFirstIntent)
}
```

### 3.3 `server/recon_first.go` (FILE MỚI)

```go
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	defaultReconWorkflow = "01-full-recon-pipeline.yaml"
	reconFirstMaxWait    = 45 * time.Minute // trần chờ recon; quá thì fallback
	reconPollEvery       = 15 * time.Second
)

// domainRe: tách host/domain đầu tiên trông hợp lệ từ text (đủ dùng cho goal/description).
var domainRe = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b`)

func extractTargetDomain(ss ...string) string {
	for _, s := range ss {
		// bỏ scheme/path nếu người dùng dán URL
		s = strings.TrimSpace(s)
		if m := domainRe.FindString(s); m != "" {
			return strings.ToLower(m)
		}
	}
	return ""
}

// launchTaskReconFirst: chạy recon workflow TRƯỚC, nạp brief vào task, rồi mới
// khởi động engine pentest. Mọi nhánh lỗi đều fallback về launchTask để task
// không bao giờ bị kẹt. Bất đồng bộ — HTTP trả về ngay.
func (s *Server) launchTaskReconFirst(t *Task, req createTaskReq) {
	seedText := req.Description + " " + req.Goal

	target := strings.ToLower(strings.TrimSpace(req.ReconTarget))
	if target == "" {
		target = extractTargetDomain(req.Goal, req.Description)
	}
	workflow := strings.TrimSpace(req.ReconWorkflow)
	if workflow == "" {
		workflow = defaultReconWorkflow
	}

	// Không tách được target → không biết recon cái gì → chạy chuẩn.
	if target == "" {
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "Recon-first: không xác định được target từ goal/mô tả — chạy luồng chuẩn."})
		s.launchTask(t, seedText, false)
		return
	}

	// Scope guard (giống tool run_workflow): chỉ recon target đã đăng ký deny-wins.
	ctx0, cancel0 := context.WithTimeout(s.ctx, 10*time.Second)
	registered := targetExists(ctx0, target)
	cancel0()
	if !registered {
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("Recon-first: target %q chưa đăng ký scope (Targets) — bỏ auto-recon, chạy luồng chuẩn. Đăng ký scope rồi thử lại để bật recon.", target)})
		s.launchTask(t, seedText, false)
		return
	}

	// Giữ slot nhưng CHƯA chạy engine; seed root asset để task có ngữ cảnh.
	if !s.engine.beginTaskOperation(t.ID) {
		return
	}
	s.seed(t, seedText)
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("⏳ Recon-first: chạy workflow %s trên %s…", workflow, target)})

	go func() {
		defer s.engine.decInflight(t.ID)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[recon-first] task %s panic: %v — fallback", t.ID, r)
				s.admitFallback(t, seedText)
			}
		}()

		ctx, cancel := context.WithTimeout(s.ctx, reconFirstMaxWait)
		defer cancel()

		runID, err := s.reconStartRun(ctx, target, workflow)
		if err != nil {
			s.reconAbort(t, seedText, "khởi động workflow thất bại: "+err.Error())
			return
		}
		if err := s.reconWaitDone(ctx, runID); err != nil {
			s.reconAbort(t, seedText, "chờ workflow: "+err.Error())
			return
		}
		brief, err := s.reconFetchBrief(ctx, runID)
		if err != nil || strings.TrimSpace(brief) == "" {
			s.reconAbort(t, seedText, "lấy recon-brief thất bại")
			return
		}

		// Nạp recon-brief làm intent đầu tiên của pentest.
		intent := brief + "\n\n---\nOBJECTIVE: Dựa HOÀN TOÀN vào bề mặt recon ở trên, " +
			"ưu tiên auth/IDOR/SSRF/injection trên các host sống. Xác minh nhanh bằng PoC tối thiểu. " +
			"Giữ STRICT in-scope (deny-wins), không DoS. Cần chi tiết thì gọi recon_findings/recon_assets; " +
			"nếu phát hiện bề mặt mới hãy gọi skill recon-first-pentest."
		s.seedIntentText(t, intent)
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "✅ Recon xong — nạp brief, bắt đầu pentest."})

		if _, err := s.admitTask(t, "bootstrap"); err != nil {
			log.Printf("[recon-first] task %s admit lỗi: %v", t.ID, err)
		}
	}()
}

// admitFallback/reconAbort: về luồng chuẩn (task vẫn chạy, chỉ là không có recon mở màn).
func (s *Server) admitFallback(t *Task, seedText string) {
	if _, err := s.admitTask(t, "bootstrap"); err != nil {
		log.Printf("[recon-first] task %s fallback admit lỗi: %v", t.ID, err)
	}
}
func (s *Server) reconAbort(t *Task, seedText, why string) {
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: "⚠️ Recon-first bỏ qua (" + why + ") — chạy luồng chuẩn."})
	s.admitFallback(t, seedText)
}

// ── HTTP helper tới k1z API cục bộ (ReconAPIBase set ở main) ───────────────
func (s *Server) reconJSON(ctx context.Context, method, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, ReconAPIBase+path, body)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, nil
}

func (s *Server) reconStartRun(ctx context.Context, target, workflow string) (string, error) {
	body, _ := json.Marshal(map[string]any{"workflow": workflow, "target": target})
	data, code, err := s.reconJSON(ctx, "POST", "/api/v1/runs", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(data)))
	}
	var r struct {
		ID    string `json:"id"`
		RunID string `json:"run_id"`
	}
	_ = json.Unmarshal(data, &r)
	if r.ID == "" {
		r.ID = r.RunID
	}
	if r.ID == "" {
		return "", fmt.Errorf("không có run id trong phản hồi")
	}
	return r.ID, nil
}

func (s *Server) reconWaitDone(ctx context.Context, runID string) error {
	tick := time.NewTicker(reconPollEvery)
	defer tick.Stop()
	for {
		data, code, err := s.reconJSON(ctx, "GET", "/api/v1/runs/"+runID, nil)
		if err == nil && code < 300 {
			var r struct{ Status string `json:"status"` }
			_ = json.Unmarshal(data, &r)
			switch strings.ToLower(r.Status) {
			case "completed", "done", "finished", "success":
				return nil
			case "failed", "error", "paused", "cancelled", "canceled":
				return fmt.Errorf("run kết thúc với status=%s", r.Status)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("quá thời gian chờ recon (%s)", reconFirstMaxWait)
		case <-tick.C:
		}
	}
}

func (s *Server) reconFetchBrief(ctx context.Context, runID string) (string, error) {
	data, code, err := s.reconJSON(ctx, "GET", "/api/v1/runs/"+runID+"/recon-brief", nil)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("HTTP %d", code)
	}
	// recon-brief trả markdown (text) hoặc {brief:"..."} — nhận cả hai.
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		var r struct{ Brief string `json:"brief"` }
		if json.Unmarshal(data, &r) == nil && r.Brief != "" {
			return r.Brief, nil
		}
	}
	return string(data), nil
}
```

> ⚠️ **Cần xác nhận khi implement:** (a) `POST /api/v1/runs` trả field id tên gì (`id`/`run_id`) và (b) `recon-brief` trả markdown thuần hay JSON — đọc `routes_bridge.go`/`routes_runs.go` để khớp. Hai helper trên đã nhận cả hai dạng để an toàn.

### 3.4 `seedIntentText` — biến thể của `seedFirstIntent` (`server/server.go:1741`)

Tách phần ghi intent ra để nạp nội dung tùy ý (recon-brief), giữ `seedFirstIntent` gọi lại nó:

```go
func (s *Server) seedFirstIntent(t *Task) {
	s.seedIntentText(t, fmt.Sprintf("完成任务目标：%s（任务：%s）", t.Goal, t.Description))
}

func (s *Server) seedIntentText(t *Task, summary string) {
	id, err := t.Store.AddIntent(map[string]any{"summary": summary}, 8, nil, "seed")
	if err != nil {
		log.Printf("[seed] task %s: 下发种子意图失败: %v", t.ID, err)
		return
	}
	if origin, _ := t.Store.OriginFactID(); origin > 0 {
		_ = t.Store.Link(origin, db.RelDerivedFrom, id)
	}
	log.Printf("[seed] task %s: 已下发种子意图 #%d", t.ID, id)
}
```

---

## 4. TẦNG 2 — Skill `recon-first-pentest` (agent tự re-recon giữa chừng)

File mới `skills/recon-first-pentest/SKILL.md`. Agent gọi khi: (a) task KHÔNG bật server recon-first nhưng cần recon; (b) giữa pentest phát hiện host/subdomain/param mới và muốn quét sâu rồi tấn công.

```markdown
---
name: recon-first-pentest
description: Dùng khi cần khảo sát bề mặt recon TRƯỚC rồi mới pentest, hoặc khi giữa chừng phát hiện host/subdomain/tham số mới và muốn quét lại rồi tấn công dựa trên kết quả.
---

# Recon-First Pentest (recon → đọc → tấn công có mục tiêu)

Quy trình BẮT BUỘC theo thứ tự. Không bịa bề mặt; luôn đọc kết quả thật từ Workflow Runner.

## Phase 1 — Tái dùng recon đã có (KHÔNG quét lại nếu đã có)
1. `recon_findings(target=<domain>)` và `recon_assets(target=<domain>)` để xem bề mặt ĐÃ map.
2. Nếu đã đủ (có host sống + port + url/param) → bỏ qua Phase 2, sang Phase 3.

## Phase 2 — Quét bù CHỈ KHI thiếu
3. Thiếu bề mặt → `run_workflow(target=<domain đã đăng ký>, workflow="01-full-recon-pipeline.yaml")`.
   - Chỉ chạy được với target ĐÃ đăng ký scope (deny-wins). Chưa đăng ký → dừng, báo operator.
4. `run_status(run_id)` lặp lại tới khi completed/failed/paused.
5. Đọc lại bằng `recon_findings` / `recon_assets`.

## Phase 3 — Pentest có mục tiêu (dựa trên kết quả, không quét mù)
6. Xếp ưu tiên host sống theo: tech lộ/version cũ > panel đăng nhập/admin > API/param nhiều > status 200 có nội dung.
7. Mỗi mục tiêu, bám lớp lỗi theo thứ tự tác động: authn/authz & IDOR → SSRF → injection (SQLi/cmd/template) → upload → secrets lộ trong JS.
8. Xác minh bằng PoC TỐI THIỂU, không phá hoại, không DoS. Giữ STRICT in-scope.
9. Phát hiện subdomain/host/param MỚI trong lúc tấn công → quay lại Phase 1 cho bề mặt mới đó (vòng lặp hẹp), không quét lại toàn bộ.

## Ranh giới
- Chỉ target đã đăng ký scope. Nghi ngờ phạm vi → hỏi operator, không tự mở rộng.
- Ưu tiên bằng chứng tái lập được hơn số lượng; mỗi finding phải có bước tái hiện.
```

### Gắn skill cho agent
- Skill nằm trong `$K1NZR3C0N_BASE/skills/recon-first-pentest/` (copy khi deploy, như các skill khác).
- Để worker agent "thấy" skill: thêm vào **agent_visibility** của agent pentest (UI: System → Agents → chọn agent → bật skill), hoặc seed mặc định khi khởi tạo agent. `wireAgentAugment` (assembly.go) sẽ tự nạp vào Skill meta-tool.
- Không cần `mcps:` vì skill chỉ dùng tool B/C đã có sẵn trong engine.

---

## 5. TẦNG 3 — Frontend + Template

### 5.1 Checkbox lúc tạo task (`web/src/app/(main)/function/tasks/page.tsx`)
- Thêm state `const [reconFirst, setReconFirst] = React.useState(false)` + ô input `reconTarget` (optional).
- Checkbox đặt cạnh `seedFirstIntent` (đã có ~dòng 3417): "🔭 Recon-first — tự chạy workflow recon trước rồi mới pentest (chỉ target đã đăng ký scope)".
- `createTask()` body thêm: `recon_first: reconFirst, recon_target: reconTarget || undefined`.

### 5.2 `api.ts` `createTask` (`web/src/lib/api.ts:238`)
```ts
reconFirst?: boolean;
reconTarget?: string;
// trong body:
recon_first: input.reconFirst ?? false,
recon_target: input.reconTarget,
```

### 5.3 Template mặc định bật sẵn (`scripts/add-task-templates.sh`)
- Template **Bug Bounty** / **Pentest**: thêm `"recon_first": true` vào payload prefill (nếu schema template cho phép field tùy ý; nếu không, thêm cột/field `recon_first` vào bảng task_templates + DTO). → chọn template là tự tick sẵn.
- Template **Red Team / CTF**: để `false` (không muốn full-recon mở màn).

---

## 6. An toàn / Edge case (đã xử trong thiết kế)

| Tình huống | Hành vi |
|---|---|
| Không tách được target | emit cảnh báo → luồng chuẩn (không kẹt) |
| Target chưa đăng ký scope | KHÔNG tự tạo scope (an toàn) → cảnh báo + luồng chuẩn |
| Workflow lỗi/timeout (cap 45') | emit cảnh báo → luồng chuẩn |
| recon-brief rỗng/lỗi | emit cảnh báo → luồng chuẩn |
| panic trong goroutine | recover → fallback admit |
| Không có LLM profile active | task vẫn vào FIFO như thường; recon vẫn chạy (recon không cần LLM), pentest chờ profile |
| Lạm dụng tốn quét | opt-in; mặc định tắt; chỉ target đã đăng ký |

Nguyên tắc xuyên suốt: **recon-first chỉ là lớp mở màn thêm; mọi nhánh hỏng đều rơi về luồng tạo-task chuẩn hiện có.** Không đụng cơ chế concurrency/admit — chỉ hoãn thời điểm `admitTask`.

---

## 7. Danh sách file đụng tới + thứ tự implement

1. `server/recon_first.go` **(mới)** — toàn bộ TẦNG 1.
2. `server/server.go` — thêm 3 field vào `createTaskReq`; rẽ nhánh trong `createTask`; refactor `seedFirstIntent` → `seedIntentText`.
3. `skills/recon-first-pentest/SKILL.md` **(mới)** — TẦNG 2; copy vào base dir khi deploy.
4. `web/src/lib/api.ts` + `web/src/app/(main)/function/tasks/page.tsx` — checkbox + field.
5. `scripts/add-task-templates.sh` — bật `recon_first` cho template bounty/pentest (có thể cần field template).
6. Build: `go build -tags embedui` + `go vet`; FE `npm run build:static`.

**Ước lượng:** TẦNG 1+ seedIntentText ~150 dòng Go; skill ~1 file md; FE ~20 dòng. Rủi ro thấp (additive, có fallback). Cần xác nhận 2 chi tiết API ở §3.3 khi code.


---

## 8. TRẠNG THÁI IMPLEMENT (đã code)

✅ **Đã làm (build + vet xanh):**
- `server/recon_first.go` (mới) — toàn bộ TẦNG 1: `launchTaskReconFirst`, resolve target (regex domain), scope-guard `targetExists`, poll `run_status`, lấy `recon-brief` (đọc đúng JSON key `markdown`), seed intent, fallback mọi nhánh lỗi. Status thành công khớp `"completed"` (fail/`cancelled`/`paused`/`timeout` = dừng).
- `server/server.go` — thêm 3 field `recon_first`/`recon_target`/`recon_workflow` vào `createTaskReq`; rẽ nhánh trong `createTask`; tách `seedFirstIntent` → `seedIntentText(t, summary)`.
- `skills/recon-first-pentest/SKILL.md` (mới) — TẦNG 2.
- FE: `web/src/lib/api.ts` (+ `reconFirst`/`reconTarget`) và trang tạo task `page.tsx` (state + checkbox 🔭 Recon-first + ô target + reset).

⏳ **Bước deploy (không phải code):**
- Copy `skills/recon-first-pentest/` vào `$K1NZR3C0N_BASE/skills/` và bật skill cho agent pentest trong **System → Agents → agent_visibility** để agent dùng được giữa chừng.
- Rebuild FE + go build + restart như CAI-DAT-VMWARE.md §10.

🔜 **Để sau (tùy chọn):** gắn `recon_first` mặc định vào **task template** — hiện template KHÔNG mang field hành vi nào (kể cả `seed_first_intent`), nên cần thêm cột DB + DTO + prefill; checkbox đã đủ cho opt-in nên chưa làm.
