package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"k1nzr3c0n/internal/agent"
	"k1nzr3c0n/internal/store"
)

func maskKey(k string) string {
	if len(k) > 8 {
		return k[:4] + strings.Repeat("*", len(k)-8) + k[len(k)-4:]
	}
	return "****"
}

// ── llm profiles ─────────────────────────────────────────────────────────────

func (s *Server) handleLLMList(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.St.ListLLMProfiles()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for _, p := range profiles {
		out = append(out, map[string]any{
			"id": p.ID, "name": p.Name, "base_url": p.BaseURL,
			"api_key_masked": maskKey(p.APIKey), "model": p.Model,
			"temperature": p.Temperature, "created_at": iso(p.CreatedAt),
		})
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleLLMCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string  `json:"name"`
		BaseURL     string  `json:"base_url"`
		APIKey      string  `json:"api_key"`
		Model       string  `json:"model"`
		Temperature float64 `json:"temperature"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if body.Name == "" || body.BaseURL == "" || body.APIKey == "" || body.Model == "" {
		writeDetail(w, 422, "name, base_url, api_key, model are required")
		return
	}
	if body.Temperature == 0 {
		body.Temperature = 0.2
	}
	p := &store.LLMProfile{Name: body.Name, BaseURL: strings.TrimSuffix(body.BaseURL, "/"),
		APIKey: body.APIKey, Model: body.Model, Temperature: body.Temperature}
	if err := s.St.CreateLLMProfile(p); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": p.ID, "name": p.Name, "upserted": p.ID > 0})
}

func (s *Server) handleLLMDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := parseID(r.PathValue("id"))
	if err := s.St.DeleteLLMProfile(id); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	w.WriteHeader(204)
}

// ── conversations + chat ─────────────────────────────────────────────────────

func (s *Server) handleConvList(w http.ResponseWriter, r *http.Request) {
	convs, err := s.St.ListConversations()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for _, c := range convs {
		out = append(out, map[string]any{"id": c.ID, "title": c.Title, "updated_at": iso(c.UpdatedAt)})
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleConvMessages(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeDetail(w, 404, "Conversation not found")
		return
	}
	msgs, err := s.St.ListChatMessages(id)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for _, m := range msgs {
		if m.Role == "tool" {
			continue // internal plumbing — UI shows user/assistant + tool names
		}
		entry := map[string]any{"role": m.Role, "content": m.Content, "created_at": iso(m.CreatedAt)}
		if m.ToolCalls != "" && m.ToolCalls != "[]" {
			entry["tool_calls"] = m.ToolCalls
		}
		out = append(out, entry)
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleConvDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := parseID(r.PathValue("id"))
	_ = s.St.DeleteConversation(id)
	w.WriteHeader(204)
}

// handleAgentChat runs one agent turn: POST {message, conversation_id?, profile_id?}
func (s *Server) handleAgentChat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Message        string `json:"message"`
		ConversationID *int64 `json:"conversation_id"`
		ProfileID      *int64 `json:"profile_id"`
	}
	if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.Message) == "" {
		writeDetail(w, 422, "message is required")
		return
	}

	// resolve profile: explicit → first → 503
	profiles, _ := s.St.ListLLMProfiles()
	if len(profiles) == 0 {
		writeDetail(w, 503, "No LLM profile configured — create one at /api/v1/llm first")
		return
	}
	prof := profiles[0]
	if body.ProfileID != nil {
		if p, err := s.St.GetLLMProfile(*body.ProfileID); err == nil {
			prof = *p
		}
	}

	convID := int64(0)
	if body.ConversationID != nil {
		convID = *body.ConversationID
	} else {
		title := body.Message
		if len(title) > 40 {
			title = title[:40]
		}
		conv, err := s.St.CreateConversation(title, "recon-agent")
		if err != nil {
			writeDetail(w, 500, err.Error())
			return
		}
		convID = conv.ID
	}

	client := agent.NewClient(prof.BaseURL, prof.APIKey, prof.Model, prof.Temperature)
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
	defer cancel()
	res, err := agent.RunTurnMCP(ctx, s.St, s.Runner, client, convID, body.Message, agent.LoopConfig{})
	if err != nil {
		writeDetail(w, 502, "agent error: "+err.Error())
		return
	}
	_ = s.St.InsertLLMUsage(prof.ID, convID,
		res.UsageTotals.PromptTokens, res.UsageTotals.CompletionTokens, res.UsageTotals.TotalTokens)
	writeJSON(w, 200, map[string]any{
		"conversation_id": convID,
		"reply":           res.Reply,
		"tool_calls":      res.ToolCalls,
		"rounds":          res.Rounds,
		"tokens":          res.UsageTotals,
	})
}

func (s *Server) handleLLMUsage(w http.ResponseWriter, r *http.Request) {
	u, err := s.St.LLMUsageTotals()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, u)
}

// ── companies + asset graph ──────────────────────────────────────────────────

func (s *Server) handleCompanyList(w http.ResponseWriter, r *http.Request) {
	comps, err := s.St.ListCompanies()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for _, c := range comps {
		assets, _ := s.St.ListAssetsGraph(store.GraphAssetFilter{CompanyID: c.ID, Limit: 5000})
		byType := map[string]int{}
		for _, a := range assets {
			byType[a.Type]++
		}
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "notes": c.Notes, "asset_count": len(assets), "by_type": byType,
		})
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleCompanyCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string  `json:"name"`
		Notes *string `json:"notes"`
	}
	if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.Name) == "" {
		writeDetail(w, 422, "name is required")
		return
	}
	c, err := s.St.UpsertCompany(strings.TrimSpace(body.Name), body.Notes)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": c.ID, "name": c.Name})
}

func (s *Server) handleGraphAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	companyID := int64(0)
	if v := q.Get("company_id"); v != "" {
		companyID, _ = parseID(v)
	}
	assets, err := s.St.ListAssetsGraph(store.GraphAssetFilter{
		CompanyID: companyID, Type: q.Get("type"), Q: q.Get("q"),
	})
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for _, a := range assets {
		out = append(out, map[string]any{
			"id": a.ID, "company_id": a.CompanyID, "type": a.Type, "value": a.Value,
			"meta": json.RawMessage(orEmpty(a.Meta, "{}")), "source": a.Source, "created_at": iso(a.CreatedAt),
		})
	}
	writeJSON(w, 200, map[string]any{"total": len(out), "items": out})
}

func (s *Server) handleGraphAssetCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type      string `json:"type"`
		Value     string `json:"value"`
		Meta      string `json:"meta"`
		CompanyID *int64 `json:"company_id"`
	}
	if err := readJSON(r, &body); err != nil || body.Type == "" || body.Value == "" {
		writeDetail(w, 422, "type and value are required")
		return
	}
	a := &store.Asset{Type: body.Type, Value: body.Value, Meta: body.Meta, CompanyID: body.CompanyID, Source: "manual"}
	if a.Meta == "" {
		a.Meta = "{}"
	}
	if err := s.St.UpsertAsset(a); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	s.St.EnrichAssetDNS(*a)
	writeJSON(w, 201, map[string]any{"id": a.ID})
}

func (s *Server) handleGraphAssetDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := parseID(r.PathValue("id"))
	_ = s.St.DeleteAsset(id)
	w.WriteHeader(204)
}

// ── traffic ──────────────────────────────────────────────────────────────────

func (s *Server) handleTrafficList(w http.ResponseWriter, r *http.Request) {
	items, err := s.St.ListTraffic(r.URL.Query().Get("host"), atoiDefault(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for _, t := range items {
		out = append(out, map[string]any{
			"id": t.ID, "run_id": t.RunID, "host": t.Host, "method": t.Method, "path": t.Path,
			"status_code": t.StatusCode, "finding_id": t.FindingID, "created_at": iso(t.CreatedAt),
		})
	}
	writeJSON(w, 200, map[string]any{"total": len(out), "items": out})
}

func (s *Server) handleTrafficGet(w http.ResponseWriter, r *http.Request) {
	id, _ := parseID(r.PathValue("id"))
	t, err := s.St.GetTraffic(id)
	if err == store.ErrNotFound {
		writeDetail(w, 404, "Traffic not found")
		return
	}
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": t.ID, "host": t.Host, "method": t.Method, "path": t.Path,
		"status_code": t.StatusCode, "request": t.Request, "response": t.Response,
		"finding_id": t.FindingID, "created_at": iso(t.CreatedAt),
	})
}

func (s *Server) handleTrafficBind(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TrafficID int64 `json:"traffic_id"`
		FindingID int64 `json:"finding_id"`
	}
	if err := readJSON(r, &body); err != nil || body.TrafficID == 0 || body.FindingID == 0 {
		writeDetail(w, 422, "traffic_id and finding_id are required")
		return
	}
	if err := s.St.BindTrafficEvidence(body.TrafficID, body.FindingID); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"bound": true})
}

// ── capture control ──────────────────────────────────────────────────────────

func (s *Server) handleCaptureStatus(w http.ResponseWriter, r *http.Request) {
	if s.Cap == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "available": false})
		return
	}
	writeJSON(w, 200, map[string]any{
		"enabled": s.Cap.Enabled(), "available": true, "addr": captureAddr(),
		"ca_cert": "/ca/ca-cert.pem (under base dir)",
	})
}

func (s *Server) handleCaptureToggle(w http.ResponseWriter, r *http.Request) {
	if s.Cap == nil {
		writeDetail(w, 503, "capture proxy unavailable")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if err := s.Cap.SetEnabled(body.Enabled); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": body.Enabled, "addr": captureAddr()})
}

func (s *Server) handleRulesList(w http.ResponseWriter, r *http.Request) {
	rules, err := s.St.ListTrafficRules()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rules)
}

func (s *Server) handleRulesCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pattern string `json:"pattern"`
		Action  string `json:"action"`
	}
	if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.Pattern) == "" {
		writeDetail(w, 422, "pattern is required")
		return
	}
	if err := s.St.CreateTrafficRule(strings.TrimSpace(body.Pattern), body.Action); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (s *Server) handleRulesDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := parseID(r.PathValue("id"))
	_ = s.St.DeleteTrafficRule(id)
	w.WriteHeader(204)
}

// ── MCP servers ──────────────────────────────────────────────────────────────

func (s *Server) handleMCPList(w http.ResponseWriter, r *http.Request) {
	items, err := s.St.ListMCP()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) handleMCPCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string   `json:"name"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
		Enabled *bool    `json:"enabled"`
	}
	if err := readJSON(r, &body); err != nil || body.Name == "" || body.Command == "" {
		writeDetail(w, 422, "name and command are required")
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	id, err := s.St.CreateMCP(store.MCPServer{Name: body.Name, Command: body.Command, Args: body.Args, Enabled: enabled})
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

func (s *Server) handleMCPDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := parseID(r.PathValue("id"))
	_ = s.St.DeleteMCP(id)
	w.WriteHeader(204)
}

// ── pending approvals ────────────────────────────────────────────────────────

func (s *Server) handleApprovalsList(w http.ResponseWriter, r *http.Request) {
	only := r.URL.Query().Get("pending") == "1"
	items, err := s.St.ListPendingApprovals(only)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) handleApprovalDecide(w http.ResponseWriter, r *http.Request) {
	id, _ := parseID(r.PathValue("id"))
	var body struct {
		Decision string `json:"decision"`
	}
	if err := readJSON(r, &body); err != nil || (body.Decision != "approve" && body.Decision != "deny") {
		writeDetail(w, 422, "decision must be approve|deny")
		return
	}
	if err := s.St.SetApprovalDecision(id, body.Decision); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "decision": body.Decision})
}

// ── side question: ask about a run without touching it ───────────────────────

func (s *Server) handleSideQuestion(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RunID    string `json:"run_id"`
		Question string `json:"question"`
	}
	if err := readJSON(r, &body); err != nil || body.RunID == "" || body.Question == "" {
		writeDetail(w, 422, "run_id and question are required")
		return
	}
	profiles, _ := s.St.ListLLMProfiles()
	if len(profiles) == 0 {
		writeDetail(w, 503, "No LLM profile configured")
		return
	}
	prof := profiles[0]
	run, err := s.St.GetRun(body.RunID)
	if err != nil {
		writeDetail(w, 404, "Run not found")
		return
	}
	items, _, _ := s.St.ListRunFindings(run.ID, store.FindingFilter{Limit: 100})
	logs, _, _ := s.St.ListLogs(run.ID, 0, 80)

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	client := agent.NewClient(prof.BaseURL, prof.APIKey, prof.Model, prof.Temperature)

	var findingsTxt strings.Builder
	for _, f := range items {
		sev := "info"
		if f.Severity != nil {
			sev = *f.Severity
		}
		findingsTxt.WriteString(fmt.Sprintf("- [%s] %s %s %s\n", f.Kind, sev, f.Host, deref(f.TemplateID)))
	}
	prompt := fmt.Sprintf("Run %s (workflow %s, target %s, status %s).\nFindings (top 100):\n%s\nRecent logs (tail):\n%s\n\nQuestion: %s",
		run.ID, run.Workflow, run.Target, run.Status, findingsTxt.String(), strings.Join(logs, "\n"), body.Question)
	turn, _, err := client.ChatCompletion(ctx, []agent.Message{{Role: "user", Content: prompt}}, nil)
	if err != nil {
		writeDetail(w, 502, "LLM error: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"answer": turn.Content})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// handleAutopilot runs an autonomous engagement (multi-phase agent loop).
func (s *Server) handleAutopilot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Goal      string `json:"goal"`
		MaxSteps  int    `json:"max_steps"`
		ProfileID *int64 `json:"profile_id"`
	}
	if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.Goal) == "" {
		writeDetail(w, 422, "goal is required")
		return
	}
	profiles, _ := s.St.ListLLMProfiles()
	if len(profiles) == 0 {
		writeDetail(w, 503, "No LLM profile configured")
		return
	}
	prof := profiles[0]
	if body.ProfileID != nil {
		if p, err := s.St.GetLLMProfile(*body.ProfileID); err == nil {
			prof = *p
		}
	}
	client := agent.NewClient(prof.BaseURL, prof.APIKey, prof.Model, prof.Temperature)
	// NOTE: detached context — the handler returns immediately (202) and the
	// loop must outlive the request; a request-scoped ctx would cancel it.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
		defer cancel()
		res, err := agent.RunAutopilot(ctx, s.St, s.Runner, client, body.Goal, body.MaxSteps)
		if err != nil {
			log.Printf("[autopilot] finished with error: %v", err)
			_ = res
		}
	}()
	writeJSON(w, 202, map[string]any{"status": "started", "goal": body.Goal})
}

func (s *Server) handleAgentRulesList(w http.ResponseWriter, r *http.Request) {
	items, err := s.St.ListAgentRules()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) handleAgentRulesCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ToolPattern  string `json:"tool_pattern"`
		InputPattern string `json:"input_pattern"`
		Action       string `json:"action"`
	}
	if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.ToolPattern) == "" {
		writeDetail(w, 422, "tool_pattern is required")
		return
	}
	if err := s.St.CreateAgentRule(strings.TrimSpace(body.ToolPattern), body.InputPattern, body.Action); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (s *Server) handleAgentRulesDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := parseID(r.PathValue("id"))
	_ = s.St.DeleteAgentRule(id)
	w.WriteHeader(204)
}

func (s *Server) handleAgentAudit(w http.ResponseWriter, r *http.Request) {
	items, err := s.St.ListAgentAudit(atoiDefault(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) handleUntestedAssets(w http.ResponseWriter, r *http.Request) {
	items, err := s.St.UntestedAssets(200)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"total": len(items), "items": items})
}

func captureAddr() string {
	if v := os.Getenv("K1NZR3C0N_PROXY_ADDR"); v != "" {
		return v
	}
	return "127.0.0.1:8083"
}
