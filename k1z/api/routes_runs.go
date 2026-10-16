package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/k1z/runner"
	"github.com/Autumn-27/artex/k1z/scope"
	"github.com/Autumn-27/artex/k1z/store"
)

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"auth_required": s.tokenEnabled()})
}

func (s *Server) tokenEnabled() bool { return len(token()) > 0 }

func (s *Server) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Workflow        string   `json:"workflow"`
		Target          string   `json:"target"`
		Out             *string  `json:"out"`
		Vars            []string `json:"vars"`
		Resume          bool     `json:"resume"`
		ContinueOnError bool     `json:"continue_on_error"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	vars, err := parseVarItems(body.Vars)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	in := runner.LaunchInput{
		Workflow:        body.Workflow,
		Target:          body.Target,
		Vars:            vars,
		Resume:          body.Resume,
		ContinueOnError: body.ContinueOnError,
	}
	if body.Out != nil {
		in.Out = *body.Out
	}
	run, err := s.Runner.Launch(in)
	if err != nil {
		switch e := err.(type) {
		case *runner.ScopeError:
			writeDetail(w, 403, e.Error())
		case *runner.NotFoundError:
			writeDetail(w, 404, e.Error())
		default:
			writeDetail(w, 400, err.Error())
		}
		return
	}
	writeJSON(w, 201, runToDict(run))
}

func parseVarItems(items []string) (map[string]string, error) {
	m := map[string]string{}
	for _, it := range items {
		if it == "" {
			continue
		}
		k, v, _ := strings.Cut(it, "=")
		if k == "" {
			return nil, errVarItem
		}
		m[k] = v
	}
	return m, nil
}

var errVarItem = &varError{}

type varError struct{}

func (*varError) Error() string { return "invalid vars entry" }

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 50)
	if limit > 200 {
		limit = 200
	}
	offset := atoiDefault(q.Get("offset"), 0)
	runs, total, err := s.St.ListRuns(store.RunFilter{
		Status: q.Get("status"), Workflow: q.Get("workflow"),
		Limit: limit, Offset: offset,
	})
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	items := []*runJSON{}
	for _, run := range runs {
		items = append(items, runToDict(run))
	}
	writeJSON(w, 200, map[string]any{"total": total, "items": items})
}

func (s *Server) handleRunStats(w http.ResponseWriter, r *http.Request) {
	byStatus, _ := s.St.CountRunsByStatus()
	findings, _ := s.St.RunStats()
	recent, _, _ := s.St.ListRuns(store.RunFilter{Limit: 8})
	items := []*runJSON{}
	for _, run := range recent {
		items = append(items, runToDict(run))
	}
	writeJSON(w, 200, map[string]any{
		"total": sumMap(byStatus),
		"by_status": map[string]int{
			"queued": byStatus["queued"], "running": byStatus["running"],
			"completed": byStatus["completed"], "failed": byStatus["failed"],
		},
		"findings": map[string]any{
			"total":       findings.FindingsTotal,
			"open_vulns":  findings.OpenVulns,
			"by_severity": findings.BySeverity,
		},
		"recent": items,
	})
}

func sumMap(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func (s *Server) getRunOr404(w http.ResponseWriter, runID string) *store.Run {
	run, err := s.St.GetRun(runID)
	if err == store.ErrNotFound {
		writeDetail(w, 404, "Run not found")
		return nil
	}
	if err != nil {
		writeDetail(w, 500, err.Error())
		return nil
	}
	return run
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	totalLogs, _ := s.St.CountLogs(run.ID)
	_, findingsCount, _ := s.St.ListFindings(store.FindingFilter{RunID: run.ID, Limit: 1})
	writeJSON(w, 200, struct {
		*runJSON
		TotalLogs     int `json:"total_logs"`
		FindingsCount int `json:"findings_count"`
	}{runToDict(run), totalLogs, findingsCount})
}

func (s *Server) handleDeleteRun(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	if err := s.St.DeleteRun(runID); err == store.ErrNotFound {
		writeDetail(w, 404, "Run not found")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) handleRunLogs(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	q := r.URL.Query()
	offset := atoiDefault(q.Get("offset"), 0)
	limit := atoiDefault(q.Get("limit"), 500)
	if limit > 2000 {
		limit = 2000
	}
	items, total, err := s.St.ListLogs(run.ID, offset, limit)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []string{}
	}
	writeJSON(w, 200, map[string]any{
		"total": total, "offset": offset, "limit": limit, "items": items,
	})
}

func (s *Server) handleRunCancel(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	if run.Status != "queued" && run.Status != "running" {
		writeDetail(w, 400, "Cannot cancel run with status: "+run.Status)
		return
	}
	if run.Workspace != "" {
		_ = os.MkdirAll(run.Workspace, 0o755)
		_ = os.WriteFile(filepath.Join(run.Workspace, "cancel.flag"), []byte{}, 0o644)
	}
	s.Runner.CancelRun(run.ID)
	_ = s.St.UpdateRunStatus(run.ID, "cancelled", map[string]any{
		"finished_at": store.SqlNow(),
	})
	run, _ = s.St.GetRun(run.ID)
	writeJSON(w, 200, runToDict(run))
}

func (s *Server) handleRunPause(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	if run.Status != "running" {
		writeDetail(w, 400, "Cannot pause run with status: "+run.Status)
		return
	}
	if run.Workspace == "" {
		writeDetail(w, 400, "Run has no workspace")
		return
	}
	_ = os.WriteFile(filepath.Join(run.Workspace, "pause.flag"), []byte{}, 0o644)
	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"message": "Pause requested — run will stop after the current step completes.",
	})
}

func (s *Server) handleRunPauseCancel(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	if run.Status != "running" {
		writeDetail(w, 400, "Run is not running (status: "+run.Status+")")
		return
	}
	if run.Workspace == "" {
		writeDetail(w, 400, "Run has no workspace")
		return
	}
	_ = os.Remove(filepath.Join(run.Workspace, "pause.flag"))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleRunResume(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	if run.Status != "paused" && run.Status != "failed" {
		writeDetail(w, 400, "Cannot resume run with status: "+run.Status)
		return
	}
	if run.Workspace == "" {
		writeDetail(w, 400, "Run has no workspace")
		return
	}
	_ = os.Remove(filepath.Join(run.Workspace, "pause.flag"))
	// reset non-terminal steps to pending
	var steps []map[string]any
	_ = json.Unmarshal([]byte(run.StepsJSON), &steps)
	for _, st := range steps {
		switch st["status"] {
		case "paused", "failed", "running":
			st["status"] = "pending"
		}
	}
	b, _ := json.Marshal(steps)
	_ = s.St.SetRunStepsJSON(run.ID, string(b))
	_ = s.St.UpdateRunStatus(run.ID, "running", map[string]any{
		"resume": true, "finished_at": nil, "paused_at": nil, "steps_json": string(b),
	})
	s.Runner.Enqueue(run.ID)
	run, _ = s.St.GetRun(run.ID)
	writeJSON(w, 200, runToDict(run))
}

func (s *Server) handleRunNewAssets(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	items, err := s.St.ListNewAssetsByRun(run.ID)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []newAssetJSON{}
	for _, n := range items {
		out = append(out, newAssetToDict(n))
	}
	writeJSON(w, 200, map[string]any{"total": len(out), "items": out})
}

func (s *Server) handleRunReparse(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	go func() {
		_ = reparseRunner(s, run)
	}()
	writeJSON(w, 202, map[string]any{"task_id": newUUID(), "run_id": run.ID})
}

func (s *Server) handleRunFindings(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 200)
	offset := atoiDefault(q.Get("offset"), 0)
	items, total, err := s.St.ListRunFindings(run.ID, store.FindingFilter{
		Kind: q.Get("kind"), Severity: q.Get("severity"), Status: q.Get("status"),
		Limit: limit, Offset: offset,
	})
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []*findingJSON{}
	for _, f := range items {
		out = append(out, findingToDict(f))
	}
	writeJSON(w, 200, map[string]any{"total": total, "offset": offset, "limit": limit, "items": out})
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = randRead(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return formatUUID(b)
}

func formatUUID(b []byte) string {
	return strings.ToLower(strings.Join([]string{
		hexB(b[0:4]), hexB(b[4:6]), hexB(b[6:8]), hexB(b[8:10]), hexB(b[10:16]),
	}, "-"))
}

var _ = scope.Normalize
var _ = time.Now
