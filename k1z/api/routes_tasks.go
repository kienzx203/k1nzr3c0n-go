package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/Autumn-27/artex/k1z/bus"
	"github.com/Autumn-27/artex/k1z/store"
)

// rawJSON returns a payload string as embeddable JSON (object/array), or a JSON
// string literal when it isn't valid JSON.
func rawJSON(s string) json.RawMessage {
	if s == "" {
		return json.RawMessage("{}")
	}
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	b, _ := json.Marshal(s)
	return json.RawMessage(b)
}

func jsonUnmarshalStr(s string, v any) error {
	if s == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), v)
}

func jsonStrAPI(s string) string { b, _ := json.Marshal(s); return string(b) }

// ── helpers ──────────────────────────────────────────────────────────────────

func pathInt(r *http.Request, key string) int64 {
	n, _ := strconv.ParseInt(r.PathValue(key), 10, 64)
	return n
}

func (s *Server) taskDTO(t *store.Task) map[string]any {
	running := s.Explore != nil && s.Explore.IsRunning(t.ID)
	m := map[string]any{
		"id": t.ID, "name": t.Name, "goal": t.Goal, "description": t.Description,
		"exploration_id": t.ExplorationID, "status": t.Status, "paused": t.Paused,
		"running": running, "company_id": t.CompanyID, "max_workers": t.MaxWorkers,
		"timeout_seconds": t.TimeoutSeconds, "coverage_enabled": t.CoverageEnabled,
		"llm_profile_id": t.LLMProfileID, "active_llm_profile_id": t.ActiveLLMProfileID,
		"created_at": iso(t.CreatedAt), "updated_at": iso(t.UpdatedAt),
	}
	if !t.CompletedAt.IsZero() {
		m["completed_at"] = iso(t.CompletedAt)
	}
	return m
}

func (s *Server) explCounts(explID int64) map[string]int {
	c := map[string]int{}
	for _, k := range []string{store.NodeIntent, store.NodeFact, store.NodeFinding, store.NodeHint} {
		ns, _ := s.St.ListNodes(explID, k)
		c[k+"s"] = len(ns)
	}
	open, _ := s.St.CountOpenIntents(explID)
	c["open_intents"] = open
	return c
}

// ── CRUD + control ───────────────────────────────────────────────────────────

func (s *Server) handleTaskList(w http.ResponseWriter, r *http.Request) {
	archived := r.URL.Query().Get("archived") == "1"
	tasks, err := s.St.ListTasksFiltered(r.URL.Query().Get("status"), archived)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for i := range tasks {
		d := s.taskDTO(&tasks[i])
		d["counts"] = s.explCounts(tasks[i].ExplorationID)
		d["category_id"] = s.St.TaskCategoryID(tasks[i].ID)
		out = append(out, d)
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

// ── categories ───────────────────────────────────────────────────────────────

func (s *Server) handleCategoryList(w http.ResponseWriter, r *http.Request) {
	cats, _ := s.St.ListCategories()
	out := []map[string]any{}
	for _, c := range cats {
		out = append(out, map[string]any{"id": c.ID, "name": c.Name, "color": c.Color})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) handleCategoryCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string `json:"name"`
		Color string `json:"color"`
	}
	if err := readJSON(r, &body); err != nil || body.Name == "" {
		writeDetail(w, 422, "name is required")
		return
	}
	c, err := s.St.CreateCategory(body.Name, body.Color)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": c.ID, "name": c.Name, "color": c.Color})
}

func (s *Server) handleCategoryDelete(w http.ResponseWriter, r *http.Request) {
	_ = s.St.DeleteCategory(pathInt(r, "id"))
	writeJSON(w, 200, map[string]any{"deleted": true})
}

func (s *Server) handleTaskSetCategory(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CategoryID int64 `json:"category_id"`
	}
	_ = readJSON(r, &body)
	if err := s.St.SetTaskCategory(pathInt(r, "id"), body.CategoryID); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ── templates ────────────────────────────────────────────────────────────────

func (s *Server) handleTemplateList(w http.ResponseWriter, r *http.Request) {
	ts, _ := s.St.ListTemplates()
	out := []map[string]any{}
	for _, t := range ts {
		out = append(out, map[string]any{"id": t.ID, "name": t.Name, "goal": t.Goal,
			"description": t.Description, "max_workers": t.MaxWorkers})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) handleTemplateCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Goal        string `json:"goal"`
		Description string `json:"description"`
		MaxWorkers  int    `json:"max_workers"`
	}
	if err := readJSON(r, &body); err != nil || body.Name == "" || body.Goal == "" {
		writeDetail(w, 422, "name and goal are required")
		return
	}
	t := &store.TaskTemplate{Name: body.Name, Goal: body.Goal, Description: body.Description, MaxWorkers: body.MaxWorkers}
	if err := s.St.CreateTemplate(t); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": t.ID})
}

func (s *Server) handleTemplateDelete(w http.ResponseWriter, r *http.Request) {
	_ = s.St.DeleteTemplate(pathInt(r, "id"))
	writeJSON(w, 200, map[string]any{"deleted": true})
}

// handleTemplateLaunch creates (and optionally starts) a task from a template.
func (s *Server) handleTemplateLaunch(w http.ResponseWriter, r *http.Request) {
	tpl, err := s.St.GetTemplate(pathInt(r, "id"))
	if err != nil {
		writeDetail(w, 404, "template not found")
		return
	}
	var body struct {
		Autostart bool `json:"autostart"`
	}
	_ = readJSON(r, &body)
	t := &store.Task{Name: tpl.Name, Goal: tpl.Goal, Description: tpl.Description,
		MaxWorkers: tpl.MaxWorkers, CoverageEnabled: true}
	if err := s.St.CreateTask(t); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	if body.Autostart && s.Explore != nil {
		if e := s.Explore.StartTask(t.ID); e != nil {
			writeJSON(w, 201, map[string]any{"id": t.ID, "start_error": e.Error()})
			return
		}
	}
	writeJSON(w, 201, s.taskDTO(t))
}

// ── archive / restore ────────────────────────────────────────────────────────

func (s *Server) handleTaskArchive(w http.ResponseWriter, r *http.Request) {
	id := pathInt(r, "id")
	if s.Explore != nil {
		s.Explore.StopTask(id)
	}
	if err := s.St.ArchiveTask(id); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"archived": true})
}

func (s *Server) handleTaskRestore(w http.ResponseWriter, r *http.Request) {
	if err := s.St.RestoreTask(pathInt(r, "id")); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"restored": true})
}

func (s *Server) handleTaskCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name           string   `json:"name"`
		Goal           string   `json:"goal"`
		Description    string   `json:"description"`
		CompanyID      int64    `json:"company_id"`
		LLMProfileID   int64    `json:"llm_profile_id"`
		MaxWorkers     int      `json:"max_workers"`
		TimeoutSeconds int      `json:"timeout_seconds"`
		Scope          []string `json:"scope"`
		Autostart      bool     `json:"autostart"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if body.Goal == "" {
		writeDetail(w, 422, "goal is required")
		return
	}
	t := &store.Task{
		Name: body.Name, Goal: body.Goal, Description: body.Description,
		CompanyID: body.CompanyID, LLMProfileID: body.LLMProfileID,
		MaxWorkers: body.MaxWorkers, TimeoutSeconds: body.TimeoutSeconds,
		CoverageEnabled: true,
	}
	if err := s.St.CreateTask(t); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	if body.Autostart && s.Explore != nil {
		if err := s.Explore.StartTask(t.ID); err != nil {
			writeJSON(w, 201, map[string]any{"id": t.ID, "start_error": err.Error()})
			return
		}
	}
	writeJSON(w, 201, s.taskDTO(t))
}

func (s *Server) handleTaskGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.St.GetTask(pathInt(r, "id"))
	if err != nil {
		writeDetail(w, 404, "task not found")
		return
	}
	expl, _ := s.St.GetExploration(t.ExplorationID)
	d := s.taskDTO(t)
	d["counts"] = s.explCounts(t.ExplorationID)
	d["todolist"] = s.todolistFor(t.ExplorationID)
	d["category_id"] = s.St.TaskCategoryID(t.ID)
	if !t.ArchivedAt.IsZero() {
		d["archived_at"] = iso(t.ArchivedAt)
	}
	if expl != nil {
		d["exploration_status"] = expl.Status
	}
	writeJSON(w, 200, d)
}

func (s *Server) todolistFor(explID int64) string {
	digs, _ := s.St.ListNodes(explID, store.NodeDigest)
	for _, dg := range digs {
		var p map[string]any
		_ = jsonUnmarshalStr(dg.Payload, &p)
		if t, ok := p["todolist"].(string); ok {
			return t
		}
	}
	return ""
}

func (s *Server) handleTaskDelete(w http.ResponseWriter, r *http.Request) {
	id := pathInt(r, "id")
	if s.Explore != nil {
		s.Explore.StopTask(id)
	}
	if err := s.St.DeleteTask(id); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) handleTaskStart(w http.ResponseWriter, r *http.Request) {
	if s.Explore == nil {
		writeDetail(w, 503, "exploration engine unavailable")
		return
	}
	if err := s.Explore.StartTask(pathInt(r, "id")); err != nil {
		writeDetail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"status": "running"})
}

func (s *Server) handleTaskPause(w http.ResponseWriter, r *http.Request) {
	if s.Explore != nil {
		s.Explore.PauseTask(pathInt(r, "id"))
	}
	writeJSON(w, 200, map[string]any{"status": "paused"})
}

func (s *Server) handleTaskStop(w http.ResponseWriter, r *http.Request) {
	if s.Explore != nil {
		s.Explore.StopTask(pathInt(r, "id"))
	}
	writeJSON(w, 200, map[string]any{"status": "stopped"})
}

// ── graph / activity / coverage ──────────────────────────────────────────────

func (s *Server) handleTaskGraph(w http.ResponseWriter, r *http.Request) {
	t, err := s.St.GetTask(pathInt(r, "id"))
	if err != nil {
		writeDetail(w, 404, "task not found")
		return
	}
	nodes, _ := s.St.ListNodes(t.ExplorationID, "")
	edges, _ := s.St.ListEdges(t.ExplorationID)
	nout := []map[string]any{}
	for _, n := range nodes {
		nout = append(nout, map[string]any{
			"id": n.ID, "kind": n.Kind, "state": n.State, "priority": n.Priority,
			"payload": rawJSON(n.Payload), "origin": n.Origin, "owner": n.Owner,
			"created_at": iso(n.CreatedAt),
		})
	}
	eout := []map[string]any{}
	for _, e := range edges {
		eout = append(eout, map[string]any{"src": e.SrcID, "dst": e.DstID, "rel": e.Rel})
	}
	writeJSON(w, 200, map[string]any{"nodes": nout, "edges": eout})
}

func (s *Server) handleTaskActivity(w http.ResponseWriter, r *http.Request) {
	t, err := s.St.GetTask(pathInt(r, "id"))
	if err != nil {
		writeDetail(w, 404, "task not found")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	nodeID, _ := strconv.ParseInt(r.URL.Query().Get("node_id"), 10, 64)
	acts, _ := s.St.ListActivity(t.ExplorationID, nodeID, limit)
	out := []map[string]any{}
	for _, a := range acts {
		out = append(out, map[string]any{
			"id": a.ID, "node_id": a.NodeID, "worker": a.Worker, "kind": a.Kind,
			"tool": a.Tool, "is_error": a.IsError, "summary": a.Summary, "detail": a.Detail,
			"created_at": iso(a.CreatedAt),
		})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) handleTaskCoverage(w http.ResponseWriter, r *http.Request) {
	t, err := s.St.GetTask(pathInt(r, "id"))
	if err != nil {
		writeDetail(w, 404, "task not found")
		return
	}
	covered := map[int64]bool{}
	ids, _ := s.St.CoveredAssetIDs(t.ExplorationID)
	for _, id := range ids {
		covered[id] = true
	}
	f := store.GraphAssetFilter{}
	if t.CompanyID > 0 {
		f.CompanyID = t.CompanyID
	}
	assets, _ := s.St.ListAssetsGraph(f)
	out := []map[string]any{}
	testedN := 0
	for _, a := range assets {
		if covered[a.ID] {
			testedN++
		}
		out = append(out, map[string]any{"id": a.ID, "type": a.Type, "value": a.Value, "tested": covered[a.ID]})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out), "tested": testedN})
}

// ── retests ──────────────────────────────────────────────────────────────────

func (s *Server) handleRetestList(w http.ResponseWriter, r *http.Request) {
	fid := pathInt(r, "finding_id")
	rs, _ := s.St.ListRetests(fid)
	out := []map[string]any{}
	for _, rt := range rs {
		out = append(out, map[string]any{
			"id": rt.ID, "finding_id": rt.FindingID, "status": rt.Status,
			"conclusion": rt.Conclusion, "fix_version": rt.FixVersion, "conditions": rt.Conditions,
			"notes": rt.Notes, "evidence": rt.Evidence, "created_at": iso(rt.CreatedAt),
		})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) handleRetestStart(w http.ResponseWriter, r *http.Request) {
	fid := pathInt(r, "finding_id")
	f, err := s.St.GetFinding(fid)
	if err != nil {
		writeDetail(w, 404, "finding not found")
		return
	}
	var body struct {
		FixVersion string `json:"fix_version"`
		Conditions string `json:"conditions"`
		Notes      string `json:"notes"`
	}
	_ = readJSON(r, &body)
	rt := &store.FindingRetest{FindingID: fid, Status: "running",
		FixVersion: body.FixVersion, Conditions: body.Conditions, Notes: body.Notes}
	if err := s.St.CreateRetest(rt); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	// Spin up a dedicated retest task (the `retester` agent) when the engine is up.
	if s.Explore != nil {
		host := ""
		if f.Host != "" {
			host = f.Host
		}
		goal := "Retest vulnerability #" + strconv.FormatInt(fid, 10)
		if f.Title != nil {
			goal += ": " + *f.Title
		}
		if host != "" {
			goal += " on " + host
		}
		goal += ". Confirm whether it is still reproducible (reproducible / fixed / cannot_confirm)."
		t := &store.Task{Name: "retest", Goal: goal, Description: body.Notes, CoverageEnabled: false, MaxWorkers: 1}
		if err := s.St.CreateTask(t); err == nil {
			rt.TaskID = t.ID
			_ = s.Explore.StartTask(t.ID)
		}
	}
	writeJSON(w, 201, map[string]any{"id": rt.ID, "status": rt.Status, "task_id": rt.TaskID})
}

// ── agent role configs ───────────────────────────────────────────────────────

func (s *Server) handleAgentConfigList(w http.ResponseWriter, r *http.Request) {
	cfgs, _ := s.St.ListAgentConfigs()
	out := []map[string]any{}
	for _, c := range cfgs {
		out = append(out, map[string]any{
			"id": c.ID, "role": c.Role, "name": c.Name, "prompt": c.Prompt,
			"description": c.Description, "kind": c.Kind,
			"llm_profile_id": c.LLMProfileID, "max_steps": c.MaxSteps,
			"tools": c.Tools, "enabled": c.Enabled, "updated_at": iso(c.UpdatedAt),
		})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) handleAgentConfigUpdate(w http.ResponseWriter, r *http.Request) {
	role := r.PathValue("role")
	var body struct {
		Prompt       string `json:"prompt"`
		LLMProfileID int64  `json:"llm_profile_id"`
		MaxSteps     int    `json:"max_steps"`
		Tools        string `json:"tools"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if err := s.St.UpdateAgentConfig(role, body.Prompt, body.LLMProfileID, body.MaxSteps, body.Tools, enabled); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"role": role, "updated": true})
}

// ── side-questions (human-in-the-loop) ───────────────────────────────────────

func sideQDTO(q store.SideQuestion) map[string]any {
	return map[string]any{
		"id": q.ID, "exploration_id": q.ExplorationID, "node_id": q.NodeID,
		"worker": q.Worker, "question": q.Question, "answer": q.Answer,
		"status": q.Status, "created_at": iso(q.CreatedAt),
	}
}

func (s *Server) handleTaskQuestions(w http.ResponseWriter, r *http.Request) {
	t, err := s.St.GetTask(pathInt(r, "id"))
	if err != nil {
		writeDetail(w, 404, "task not found")
		return
	}
	qs, _ := s.St.ListSideQuestions(t.ExplorationID, false)
	out := []map[string]any{}
	for _, q := range qs {
		out = append(out, sideQDTO(q))
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) handleQuestionsPending(w http.ResponseWriter, r *http.Request) {
	qs, _ := s.St.ListPendingSideQuestions()
	out := []map[string]any{}
	for _, q := range qs {
		out = append(out, sideQDTO(q))
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) handleQuestionAnswer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Answer string `json:"answer"`
	}
	_ = readJSON(r, &body)
	if body.Answer == "" {
		writeDetail(w, 422, "answer is required")
		return
	}
	if err := s.St.AnswerSideQuestion(pathInt(r, "qid"), body.Answer); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"answered": true})
}

func (s *Server) handleQuestionSkip(w http.ResponseWriter, r *http.Request) {
	_ = s.St.SkipSideQuestion(pathInt(r, "qid"))
	writeJSON(w, 200, map[string]any{"skipped": true})
}

// handleTaskMessage injects operator guidance (mainagent chat-in-task).
func (s *Server) handleTaskMessage(w http.ResponseWriter, r *http.Request) {
	t, err := s.St.GetTask(pathInt(r, "id"))
	if err != nil {
		writeDetail(w, 404, "task not found")
		return
	}
	var body struct {
		Text string `json:"text"`
	}
	if err := readJSON(r, &body); err != nil || body.Text == "" {
		writeDetail(w, 422, "text is required")
		return
	}
	var id int64
	if s.Explore != nil {
		id, _ = s.Explore.AddHint(t.ExplorationID, body.Text)
	} else {
		n := &store.ExplorationNode{ExplorationID: t.ExplorationID, Kind: store.NodeHint,
			State: "active", Payload: `{"text":` + jsonStrAPI(body.Text) + `}`, Origin: "operator"}
		_ = s.St.CreateNode(n)
		id = n.ID
	}
	writeJSON(w, 201, map[string]any{"id": id, "accepted": true})
}

// ── live stream ──────────────────────────────────────────────────────────────

func (s *Server) handleTaskStream(w http.ResponseWriter, r *http.Request) {
	t, err := s.St.GetTask(pathInt(r, "id"))
	if err != nil {
		writeDetail(w, 404, "task not found")
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	topic := "task-" + strconv.FormatInt(t.ExplorationID, 10)
	ch, cancel := s.Bus.Subscribe(topic)
	defer cancel()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			ctx, c := context.WithTimeout(r.Context(), 10*time.Second)
			err := conn.Write(ctx, websocket.MessageText, mustJSON(msg))
			c()
			if err != nil {
				return
			}
		}
	}
}

var _ = bus.Message{}
