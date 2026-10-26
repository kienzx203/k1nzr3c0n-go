package server

// Recon-first task launch: when a task opts in (recon_first), run a recon
// WORKFLOW first, compile the run's recon-brief, seed it as the task's first
// intent, and only THEN start the pentest engine — so the worker begins with the
// mapped surface in hand instead of guessing to re-scan. Deterministic and cheap
// on LLM (the mechanical recon is done server-side). Every failure branch falls
// back to the normal launchTask path so a task is never stranded.
//
// Reuses integration C (POST /api/v1/runs, scope-guarded by targetExists) and
// integration A (GET /api/v1/runs/{id}/recon-brief) over the mounted k1z API.

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
	reconFirstMaxWait    = 45 * time.Minute // cap on waiting for recon; then fall back
	reconPollEvery       = 15 * time.Second
)

// domainRe extracts the first plausible host/domain from free text (good enough
// for pulling a target out of a goal/description).
var domainRe = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b`)

func extractTargetDomain(ss ...string) string {
	for _, s := range ss {
		if m := domainRe.FindString(strings.TrimSpace(s)); m != "" {
			return strings.ToLower(m)
		}
	}
	return ""
}

// launchTaskReconFirst runs a recon workflow first, seeds the brief, then starts
// the engine. Asynchronous — the HTTP handler returns immediately. Any failure
// (no target, out-of-scope, workflow error, timeout, empty brief, panic) emits a
// visible notice and falls back to the standard launchTask path.
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

	if target == "" {
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "Recon-first: không xác định được target từ goal/mô tả — chạy luồng chuẩn."})
		s.launchTask(t, seedText, false)
		return
	}

	// Scope guard (same rule as the run_workflow tool): only recon a REGISTERED
	// target so the scan stays inside a defined deny-wins scope.
	ctx0, cancel0 := context.WithTimeout(s.ctx, 10*time.Second)
	registered := targetExists(ctx0, target)
	cancel0()
	if !registered {
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("Recon-first: target %q chưa đăng ký scope (Targets) — bỏ auto-recon, chạy luồng chuẩn. Đăng ký scope rồi thử lại.", target)})
		s.launchTask(t, seedText, false)
		return
	}

	// Hold a task operation slot but DON'T start the engine yet; seed the root
	// asset so the task has context while recon runs.
	if !s.engine.beginTaskOperation(t.ID) {
		return
	}
	s.seed(t, seedText)
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("⏳ Recon-first: chạy workflow %s trên %s…", workflow, target)})

	go func() {
		defer s.engine.decInflight(t.ID)
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[recon-first] task %s panic: %v — fallback", t.ID, rec)
				s.reconFallbackAdmit(t)
			}
		}()

		ctx, cancel := context.WithTimeout(s.ctx, reconFirstMaxWait)
		defer cancel()

		runID, err := s.reconStartRun(ctx, target, workflow)
		if err != nil {
			s.reconAbort(t, "khởi động workflow thất bại: "+err.Error())
			return
		}
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("Recon-first: run %s đang chạy, chờ hoàn tất…", runID)})

		if err := s.reconWaitDone(ctx, runID); err != nil {
			s.reconAbort(t, "chờ workflow: "+err.Error())
			return
		}
		brief, err := s.reconFetchBrief(ctx, runID)
		if err != nil || strings.TrimSpace(brief) == "" {
			s.reconAbort(t, "lấy recon-brief thất bại")
			return
		}

		intent := brief + "\n\n---\nOBJECTIVE: Dựa HOÀN TOÀN vào bề mặt recon ở trên, " +
			"ưu tiên broken access control/IDOR, SSRF, auth/JWT/OAuth, injection (SQLi/SSTI/command), file upload trên các host sống. " +
			"Xác minh bằng PoC tối thiểu, không phá hoại, không DoS. Giữ STRICT in-scope (deny-wins). " +
			"Cần chi tiết thì gọi recon_findings/recon_assets; phát hiện bề mặt mới thì gọi skill recon-first-pentest."
		s.seedIntentText(t, intent)
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "✅ Recon xong — đã nạp brief, bắt đầu pentest."})

		if _, err := s.admitTask(t, "bootstrap"); err != nil {
			log.Printf("[recon-first] task %s admit lỗi: %v", t.ID, err)
		}
	}()
}

// reconFallbackAdmit starts the engine for a task whose recon-first pre-step bailed
// out after the operation slot was already taken (so launchTask's own
// beginTaskOperation is not reused). Mirrors launchTask's tail.
func (s *Server) reconFallbackAdmit(t *Task) {
	if _, err := s.admitTask(t, "bootstrap"); err != nil {
		log.Printf("[recon-first] task %s fallback admit lỗi: %v", t.ID, err)
	}
}

func (s *Server) reconAbort(t *Task, why string) {
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: "⚠️ Recon-first bỏ qua (" + why + ") — chạy luồng chuẩn."})
	s.reconFallbackAdmit(t)
}

// ── HTTP helpers against the local k1z API (ReconAPIBase set from main) ───────

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
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.ID == "" {
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
			var r struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(data, &r)
			switch strings.ToLower(r.Status) {
			case "completed", "done", "finished", "success":
				return nil
			case "failed", "error", "paused", "cancelled", "canceled", "timeout":
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

// reconFetchBrief reads GET /runs/{id}/recon-brief. The k1z handler returns JSON
// with a "markdown" field (handleReconBrief); accept a raw-markdown body too.
func (s *Server) reconFetchBrief(ctx context.Context, runID string) (string, error) {
	data, code, err := s.reconJSON(ctx, "GET", "/api/v1/runs/"+runID+"/recon-brief", nil)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("HTTP %d", code)
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		var r struct {
			Markdown string `json:"markdown"`
		}
		if json.Unmarshal(data, &r) == nil && strings.TrimSpace(r.Markdown) != "" {
			return r.Markdown, nil
		}
	}
	return string(data), nil
}
