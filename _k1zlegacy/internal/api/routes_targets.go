package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k1nzr3c0n/internal/config"
	"k1nzr3c0n/internal/runner"
	"k1nzr3c0n/internal/scope"
	"k1nzr3c0n/internal/store"
)

var _ = time.Now

// ── scope check ──────────────────────────────────────────────────────────────

func (s *Server) handleScopeCheck(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	var coveredBy map[string]any
	reason := "unregistered — no scope defined"
	inScope := false
	denied := false
	if t := scope.Covering(s.St, host); t != nil {
		coveredBy = map[string]any{"name": t.Name, "mode": t.Mode}
		if t.Mode == "oos" {
			denied = true
			reason = "marked out-of-scope"
		} else {
			inScope = true
			reason = "covered by " + t.Name
		}
	}
	writeJSON(w, 200, map[string]any{
		"host": host, "covered_by": coveredBy, "in_scope": inScope,
		"denied": denied, "reason": reason,
	})
}

// ── targets ──────────────────────────────────────────────────────────────────

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.St.ListTargets()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	items := []map[string]any{}
	for _, t := range targets {
		sum, _ := s.St.TargetSummary(t.Name)
		items = append(items, targetWithSummary(t, sum))
	}
	writeJSON(w, 200, map[string]any{"total": len(items), "items": items})
}

func targetWithSummary(t *store.Target, sum store.TargetSummary) map[string]any {
	var lastRunAt any
	if sum.LastRunAt != nil {
		lastRunAt = iso(*sum.LastRunAt)
	}
	return map[string]any{
		"name": t.Name, "scope": rawOr(t.ScopeJSON, "[]"), "mode": t.Mode,
		"notes": t.Notes, "created_at": iso(t.CreatedAt), "updated_at": iso(t.UpdatedAt),
		"total_runs": sum.TotalRuns, "last_run_id": sum.LastRunID,
		"last_run_at": lastRunAt, "last_status": sum.LastStatus,
		"open_vulns": sum.OpenVulns, "by_severity": sum.BySeverity,
	}
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string   `json:"name"`
		Scope []string `json:"scope"`
		Mode  *string  `json:"mode"`
		Notes *string  `json:"notes"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	name := strings.ToLower(strings.TrimSpace(body.Name))
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, " ") {
		writeDetail(w, 400, "Invalid target name (expected a domain)")
		return
	}
	mode := "bounty"
	if body.Mode != nil {
		mode = *body.Mode
	}
	switch mode {
	case "bounty", "vdp", "oos":
	default:
		writeDetail(w, 400, "mode must be one of: bounty, vdp, oos")
		return
	}
	if _, err := s.St.GetTarget(name); err == nil {
		writeDetail(w, 409, "Target already exists: "+name)
		return
	}
	scopeJSON := "[]"
	if body.Scope != nil {
		b, _ := json.Marshal(body.Scope)
		scopeJSON = string(b)
	}
	t := &store.Target{Name: name, ScopeJSON: scopeJSON, Mode: mode, Notes: body.Notes}
	if err := s.St.CreateTarget(t); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, targetToDict(t))
}

func (s *Server) getTargetOr404(w http.ResponseWriter, name string) *store.Target {
	t, err := s.St.GetTarget(strings.ToLower(name))
	if err == store.ErrNotFound {
		writeDetail(w, 404, "Target not found")
		return nil
	}
	if err != nil {
		writeDetail(w, 500, err.Error())
		return nil
	}
	return t
}

func (s *Server) handleGetTarget(w http.ResponseWriter, r *http.Request) {
	t := s.getTargetOr404(w, r.PathValue("name"))
	if t == nil {
		return
	}
	sum, _ := s.St.TargetSummary(t.Name)
	m := targetWithSummary(t, sum)
	runs, _, _ := s.St.ListRuns(store.RunFilter{Limit: 1000})
	var recent []*runJSON
	count := 0
	for _, run := range runs {
		if run.Target == t.Name {
			recent = append(recent, runToDict(run))
			count++
			if count == 10 {
				break
			}
		}
	}
	if recent == nil {
		recent = []*runJSON{}
	}
	m["recent_runs"] = recent
	writeJSON(w, 200, m)
}

func (s *Server) handlePatchTarget(w http.ResponseWriter, r *http.Request) {
	t := s.getTargetOr404(w, r.PathValue("name"))
	if t == nil {
		return
	}
	var body struct {
		Scope *[]string `json:"scope"`
		Mode  *string   `json:"mode"`
		Notes *string   `json:"notes"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if body.Mode != nil {
		switch *body.Mode {
		case "bounty", "vdp", "oos":
			t.Mode = *body.Mode
		default:
			writeDetail(w, 400, "mode must be one of: bounty, vdp, oos")
			return
		}
	}
	if body.Scope != nil {
		b, _ := json.Marshal(*body.Scope)
		t.ScopeJSON = string(b)
	}
	if body.Notes != nil {
		t.Notes = body.Notes
	}
	if err := s.St.UpdateTarget(t); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, targetToDict(t))
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	if err := s.St.DeleteTarget(name); err == store.ErrNotFound {
		writeDetail(w, 404, "Target not found")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) handleTargetAudit(w http.ResponseWriter, r *http.Request) {
	t := s.getTargetOr404(w, r.PathValue("name"))
	if t == nil {
		return
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 100)
	rows, err := s.St.ListScopeAudit(t.Name, limit)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	items := []map[string]any{}
	for _, a := range rows {
		items = append(items, map[string]any{
			"id": a.ID, "action": a.Action, "result": a.Result,
			"detail": a.Detail, "ts": iso(a.TS),
		})
	}
	writeJSON(w, 200, map[string]any{"total": len(items), "items": items})
}

func (s *Server) handleTargetNewAssets(w http.ResponseWriter, r *http.Request) {
	t := s.getTargetOr404(w, r.PathValue("name"))
	if t == nil {
		return
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 100)
	items, err := s.St.ListNewAssetsByTarget(t.Name, limit)
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

// ── schedules ────────────────────────────────────────────────────────────────

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := s.St.ListSchedules()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []*scheduleJSON{}
	for _, sc := range items {
		out = append(out, scheduleToDict(sc))
	}
	writeJSON(w, 200, map[string]any{"total": len(out), "items": out})
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name           string            `json:"name"`
		Workflow       string            `json:"workflow"`
		Target         string            `json:"target"`
		CronExpr       string            `json:"cron_expr"`
		Vars           map[string]string `json:"vars"`
		Enabled        *bool             `json:"enabled"`
		AlertNewAssets *bool             `json:"alert_new_assets"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	enabled, alert := true, true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if body.AlertNewAssets != nil {
		alert = *body.AlertNewAssets
	}
	if _, err := os.Stat(filepath.Join(config.WorkflowsDir(), body.Workflow)); err != nil {
		writeDetail(w, 404, "Workflow not found: "+body.Workflow)
		return
	}
	if !cronValid(body.CronExpr) {
		writeDetail(w, 400, "Invalid cron expression: '"+body.CronExpr+"' (expected 5 fields, local time)")
		return
	}
	varsJSON := "{}"
	if body.Vars != nil {
		b, _ := json.Marshal(body.Vars)
		varsJSON = string(b)
	}
	sc := &store.Schedule{
		Name: body.Name, Workflow: body.Workflow, Target: body.Target,
		CronExpr: body.CronExpr, VarsJSON: varsJSON,
		Enabled: enabled, AlertNewAssets: alert,
	}
	if enabled {
		if next := cronNext(body.CronExpr); !next.IsZero() {
			sc.NextRunAt = next
		}
	}
	if err := s.St.CreateSchedule(sc); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, scheduleToDict(sc))
}

func (s *Server) getScheduleOr404(w http.ResponseWriter, id string) *store.Schedule {
	n, err := parseID(id)
	if err != nil {
		writeDetail(w, 404, "Schedule not found")
		return nil
	}
	sc, err := s.St.GetSchedule(n)
	if err == store.ErrNotFound {
		writeDetail(w, 404, "Schedule not found")
		return nil
	}
	if err != nil {
		writeDetail(w, 500, err.Error())
		return nil
	}
	return sc
}

func (s *Server) handleGetSchedule(w http.ResponseWriter, r *http.Request) {
	sc := s.getScheduleOr404(w, r.PathValue("id"))
	if sc == nil {
		return
	}
	writeJSON(w, 200, scheduleToDict(sc))
}

func (s *Server) handlePatchSchedule(w http.ResponseWriter, r *http.Request) {
	sc := s.getScheduleOr404(w, r.PathValue("id"))
	if sc == nil {
		return
	}
	var body struct {
		Name           *string           `json:"name"`
		CronExpr       *string           `json:"cron_expr"`
		Vars           map[string]string `json:"vars"`
		Enabled        *bool             `json:"enabled"`
		AlertNewAssets *bool             `json:"alert_new_assets"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if body.Name != nil {
		sc.Name = *body.Name
	}
	if body.CronExpr != nil {
		if !cronValid(*body.CronExpr) {
			writeDetail(w, 400, "Invalid cron expression: '"+*body.CronExpr+"' (expected 5 fields, local time)")
			return
		}
		sc.CronExpr = *body.CronExpr
	}
	if body.Vars != nil {
		b, _ := json.Marshal(body.Vars)
		sc.VarsJSON = string(b)
	}
	if body.Enabled != nil {
		sc.Enabled = *body.Enabled
	}
	if body.AlertNewAssets != nil {
		sc.AlertNewAssets = *body.AlertNewAssets
	}
	sc.NextRunAt = time.Time{}
	if sc.Enabled {
		if next := cronNext(sc.CronExpr); !next.IsZero() {
			sc.NextRunAt = next
		}
	}
	if err := s.St.UpdateSchedule(sc); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, scheduleToDict(sc))
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	sc := s.getScheduleOr404(w, r.PathValue("id"))
	if sc == nil {
		return
	}
	if err := s.St.DeleteSchedule(sc.ID); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	w.WriteHeader(204)
}

func (s *Server) handleTriggerSchedule(w http.ResponseWriter, r *http.Request) {
	sc := s.getScheduleOr404(w, r.PathValue("id"))
	if sc == nil {
		return
	}
	vars := map[string]string{}
	_ = json.Unmarshal([]byte(sc.VarsJSON), &vars)
	run, err := s.Runner.LaunchScheduleRun(&runner.ScheduleSpec{
		Workflow: sc.Workflow, Target: sc.Target,
	}, vars)
	if err != nil {
		writeDetail(w, 404, err.Error())
		return
	}
	sc.LastRunID = &run.ID
	t := store.NowUTC()
	sc.LastRunAt = t
	_ = s.St.UpdateSchedule(sc)
	writeJSON(w, 200, map[string]any{"run_id": run.ID, "schedule": scheduleToDict(sc)})
}
