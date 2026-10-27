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
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// pendingPushBack maps a recon run id -> task id for runs an agent launched via
// run_workflow but may NOT consume inline (wait=false, or a run slower than the
// blocking cap). When such a run finishes, OnReconRunFinished seeds its brief back
// into the originating task, so a slow run is never silently skipped.
var pendingPushBack sync.Map // runID string -> taskID string

func registerPushBack(runID, taskID string) {
	if runID != "" && taskID != "" && taskID != "0" {
		pendingPushBack.Store(runID, taskID)
	}
}

// OnReconRunFinished is wired to the k1z runner's RunFinishedHook, which fires on
// every terminal outcome (completed, failed, cancelled). If the finished run was
// registered for push-back, fetch its recon brief and seed it back into the task
// that launched it (reviving a terminal task), so results that landed after the
// agent moved on — even partial results from a failed run — are acted on instead
// of lost. No-ops when the run wasn't registered or produced no brief.
func (s *Server) OnReconRunFinished(runID string) {
	defer func() { _ = recover() }()
	v, ok := pendingPushBack.LoadAndDelete(runID)
	if !ok {
		return
	}
	taskID, _ := v.(string)
	t, ok := s.m.Task(taskID)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	data, code, err := s.reconJSON(ctx, "GET", "/api/v1/runs/"+url.PathEscape(runID)+"/recon-brief", nil)
	if err != nil || code >= 300 {
		return
	}
	brief := reconBriefMarkdown(data)
	if strings.TrimSpace(brief) == "" {
		return
	}
	s.seedIntentText(t, "Recon run "+runID+" completed — its results arrived AFTER the earlier recon call:\n\n"+brief+
		"\n\nReview and act on any uncovered surface from this run; do not skip it.")
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: "📥 Recon run " + runID + " completed — results pushed back into the task."})
	s.reviveTask(t)
}

const (
	defaultReconWorkflow = "01-full-recon-pipeline.yaml"
	reconFirstMaxWait    = 90 * time.Minute // total cap across all recon workflows; then fall back
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
	workflowSpec := strings.TrimSpace(req.ReconWorkflow) // "" (default), a name, "a,b", or "all"

	if target == "" {
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "Recon-first: could not determine a target from the goal/description — running the standard flow."})
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
			Summary: fmt.Sprintf("Recon-first: target %q is not registered (Targets) — skipping auto-recon, running the standard flow. Register a scope and try again.", target)})
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
		Summary: fmt.Sprintf("⏳ Recon-first: preparing recon on %s…", target)})

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

		workflows := s.resolveReconWorkflows(ctx, workflowSpec)
		var briefs []string
		for _, wf := range workflows {
			runID, err := s.reconStartRun(ctx, target, wf, maxWorkflowVars(ctx, wf)) // full options (minus opted-out pivots)
			if err != nil {
				s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
					Summary: fmt.Sprintf("⚠️ Recon-first: workflow %s could not start (%s) — skipping.", wf, err.Error())})
				continue
			}
			s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("⏳ Recon-first: %s (run %s) is running…", wf, runID)})
			if err := s.reconWaitDone(ctx, runID); err != nil {
				s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
					Summary: fmt.Sprintf("⚠️ Recon-first: %s — %s", wf, err.Error())})
				if ctx.Err() != nil {
					break
				}
				continue
			}
			if b, err := s.reconFetchBrief(ctx, runID); err == nil && strings.TrimSpace(b) != "" {
				briefs = append(briefs, fmt.Sprintf("## Recon workflow: %s (run %s)\n\n%s", wf, runID, strings.TrimSpace(b)))
			}
			if ctx.Err() != nil {
				break
			}
		}

		if len(briefs) == 0 {
			s.reconAbort(t, "no recon workflow completed")
			return
		}

		intent := strings.Join(briefs, "\n\n---\n\n") + "\n\n---\nOBJECTIVE: Base your work ENTIRELY on the recon surface above. " +
			"Prioritize broken access control/IDOR, SSRF, auth/JWT/OAuth, injection (SQLi/SSTI/command) and file upload on the live hosts. " +
			"Validate with a minimal non-destructive PoC; no DoS. Stay STRICT in-scope (deny-wins). " +
			"For details call recon_findings/recon_assets; when you find new surface, call list_workflows to pick a fitting workflow, or the recon-first-pentest skill."
		s.seedIntentText(t, intent)
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("✅ Recon done (%d/%d workflows) — brief loaded, starting pentest.", len(briefs), len(workflows))})

		if _, err := s.admitTask(t, "bootstrap"); err != nil {
			log.Printf("[recon-first] task %s admit error: %v", t.ID, err)
		}
	}()
}

// resolveReconWorkflows turns the recon_workflow spec into a concrete list:
// "all" → every available workflow; a comma-separated list → those names; empty →
// the default single pipeline.
func (s *Server) resolveReconWorkflows(ctx context.Context, spec string) []string {
	spec = strings.TrimSpace(spec)
	if strings.EqualFold(spec, "all") {
		if all := s.reconListWorkflows(ctx); len(all) > 0 {
			return all
		}
		return []string{defaultReconWorkflow}
	}
	if spec == "" {
		return []string{defaultReconWorkflow}
	}
	var out []string
	for _, p := range strings.Split(spec, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{defaultReconWorkflow}
	}
	return out
}

// reconListWorkflows returns the available workflow file names from the Runner.
func (s *Server) reconListWorkflows(ctx context.Context) []string {
	data, code, err := s.reconJSON(ctx, "GET", "/api/v1/workflows", nil)
	if err != nil || code >= 300 {
		return nil
	}
	var names []string
	_ = json.Unmarshal(data, &names)
	return names
}

// reconFallbackAdmit starts the engine for a task whose recon-first pre-step bailed
// out after the operation slot was already taken (so launchTask's own
// beginTaskOperation is not reused). Mirrors launchTask's tail.
func (s *Server) reconFallbackAdmit(t *Task) {
	if _, err := s.admitTask(t, "bootstrap"); err != nil {
		log.Printf("[recon-first] task %s fallback admit error: %v", t.ID, err)
	}
}

func (s *Server) reconAbort(t *Task, why string) {
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: "⚠️ Recon-first skipped (" + why + ") — running the standard flow."})
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

func (s *Server) reconStartRun(ctx context.Context, target, workflow string, vars []string) (string, error) {
	payload := map[string]any{"workflow": workflow, "target": target}
	if len(vars) > 0 {
		payload["vars"] = vars
	}
	body, _ := json.Marshal(payload)
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
		return "", fmt.Errorf("no run id in the response")
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
				return fmt.Errorf("run ended with status=%s", r.Status)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("recon wait timed out (%s)", reconFirstMaxWait)
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
