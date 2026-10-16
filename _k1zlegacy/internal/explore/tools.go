// Package explore is the ScopeWeaver/ARTEX-style autonomous exploration engine
// ported onto k1nzr3c0n. It runs goal-driven Tasks over the two-graph model:
// a planner (the only intent generator) reads the exploration graph and emits
// intents; N workers each claim ONE intent, run real tools traced by the
// recording proxy, and write facts/findings/assets back into both graphs.
//
// This is additive — it reuses k1nzr3c0n's agent.Client (LLM), runner, store
// and bus without changing the existing workflow runner.
package explore

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"k1nzr3c0n/internal/agent"
	"k1nzr3c0n/internal/store"
)

// toolExec dispatches one tool call; stop=true ends the agent loop.
type toolExec func(call agent.FunctionCall) (result string, stop bool)

// ── shared JSON arg helpers ──────────────────────────────────────────────────

func argStr(args map[string]any, k string) string {
	if v, ok := args[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}
func argInt(args map[string]any, k string) int {
	if v, ok := args[k]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}
func argStrList(args map[string]any, k string) []string {
	var out []string
	if v, ok := args[k]; ok {
		if arr, ok := v.([]any); ok {
			for _, e := range arr {
				if s, ok := e.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}
func parseArgs(raw string) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &m)
	return m
}

func td(name, desc string, params map[string]any) agent.ToolDef {
	return agent.ToolDef{Type: "function", Function: agent.FunctionSpec{Name: name, Description: desc, Parameters: params}}
}
func obj(props map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required}
}
func pStr(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func pInt(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }
func pArr(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

// ── planner tools ────────────────────────────────────────────────────────────

func plannerTools() []agent.ToolDef {
	return []agent.ToolDef{
		td("graph_overview", "Read the current exploration state: goal, counts of intents/facts/findings, open intents, recent facts, and the shared todolist.", obj(map[string]any{})),
		td("list_assets", "List in-scope assets for this task with coverage (whether each has been probed).", obj(map[string]any{})),
		td("submit_intent", "Queue ONE new exploration direction (intent) for a worker. Only submit a direction that is genuinely new and whose prerequisites are satisfied.", obj(map[string]any{
			"description": pStr("What the worker should investigate, concretely."),
			"priority":    pInt("0-100; higher runs first."),
			"assets":      pArr("Asset values this intent targets (host/url/ip), optional."),
		}, "description")),
		td("update_todolist", "Record/replace the shared multi-round attack-chain todolist (markdown). Persists across planner wakes.", obj(map[string]any{"todolist": pStr("Markdown checklist of the serial exploitation chain.")}, "todolist")),
		td("mark_goal_met", "Declare the goal achieved and finish the task.", obj(map[string]any{"reason": pStr("Why the goal is met.")})),
		td("finish", "Stop planning this round (no new direction). If the frontier is also empty the task completes.", obj(map[string]any{"reason": pStr("Why there is nothing to send.")})),
	}
}

// plannerState is returned by graph_overview.
func (m *Manager) plannerOverview(explID int64, goal string) string {
	intents, _ := m.st.ListNodes(explID, store.NodeIntent)
	facts, _ := m.st.ListNodes(explID, store.NodeFact)
	findings, _ := m.st.ListNodes(explID, store.NodeFinding)
	var open int
	for _, n := range intents {
		if n.State == store.IntentOpen || n.State == store.IntentRunning {
			open++
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "GOAL: %s\n", goal)
	fmt.Fprintf(&sb, "intents=%d (open/running=%d)  facts=%d  findings=%d\n", len(intents), open, len(facts), len(findings))
	sb.WriteString("\nRECENT FACTS:\n")
	n := 0
	for i := len(facts) - 1; i >= 0 && n < 12; i-- {
		var p map[string]any
		_ = json.Unmarshal([]byte(facts[i].Payload), &p)
		fmt.Fprintf(&sb, "- [%d] %s\n", facts[i].ID, truncate(argStr(p, "summary"), 160))
		n++
	}
	// human guidance injected via the mainagent chat (hint nodes)
	hints, _ := m.st.ListNodes(explID, store.NodeHint)
	var active []store.ExplorationNode
	for _, h := range hints {
		if h.State == "active" {
			active = append(active, h)
		}
	}
	if len(active) > 0 {
		sb.WriteString("\nOPERATOR GUIDANCE (follow this):\n")
		for _, h := range active {
			var p map[string]any
			_ = json.Unmarshal([]byte(h.Payload), &p)
			fmt.Fprintf(&sb, "- %s\n", truncate(argStr(p, "text"), 240))
		}
	}
	sb.WriteString("\nTODOLIST:\n")
	sb.WriteString(m.getTodolist(explID))
	return sb.String()
}

// AddHint records operator guidance (mainagent chat) as an active hint node the
// planner reads on its next wake.
func (m *Manager) AddHint(explID int64, text string) (int64, error) {
	n := &store.ExplorationNode{ExplorationID: explID, Kind: store.NodeHint, State: "active",
		Payload: `{"text":` + jsonStr(text) + `}`, Origin: "operator"}
	if err := m.st.CreateNode(n); err != nil {
		return 0, err
	}
	m.emit(explID, "guidance", map[string]any{"id": n.ID, "text": text})
	return n.ID, nil
}

// getTodolist reads the shared todolist stored in a digest node.
func (m *Manager) getTodolist(explID int64) string {
	digs, _ := m.st.ListNodes(explID, store.NodeDigest)
	for _, d := range digs {
		var p map[string]any
		_ = json.Unmarshal([]byte(d.Payload), &p)
		if t := argStr(p, "todolist"); t != "" {
			return t
		}
	}
	return "(empty)"
}

func (m *Manager) setTodolist(explID int64, md string) {
	digs, _ := m.st.ListNodes(explID, store.NodeDigest)
	payload := `{"todolist":` + jsonStr(md) + `}`
	if len(digs) > 0 {
		_ = m.st.SetNodePayload(digs[0].ID, payload)
		return
	}
	_ = m.st.CreateNode(&store.ExplorationNode{ExplorationID: explID, Kind: store.NodeDigest, State: "active", Payload: payload, Origin: "planner"})
}

// ── worker tools ─────────────────────────────────────────────────────────────

func workerTools() []agent.ToolDef {
	return []agent.ToolDef{
		td("run_bash", "Run a shell command (Kali recon tools, curl, etc.). HTTP(S) is routed through the recording proxy and captured as evidence. Keep commands bounded.", obj(map[string]any{"command": pStr("The shell command.")}, "command")),
		td("record_fact", "Record a confirmed observation (a fact) derived from this intent.", obj(map[string]any{
			"summary": pStr("One-line fact."),
			"detail":  pStr("Supporting detail/output."),
			"asset":   pStr("Related asset value (host/url/ip), optional."),
		}, "summary")),
		td("record_finding", "Record a security finding (vulnerability) proven by this intent.", obj(map[string]any{
			"title":    pStr("Finding title."),
			"severity": pStr("critical|high|medium|low|info."),
			"host":     pStr("Affected host or URL."),
			"evidence": pStr("Evidence / reproduction."),
		}, "title", "severity", "host")),
		td("add_asset", "Add a discovered asset to the shared asset graph (and anchor it to this intent).", obj(map[string]any{
			"type":  pStr("domain|subdomain|ip|port|site|endpoint."),
			"value": pStr("The asset value."),
		}, "type", "value")),
		td("ask_human", "Ask the human operator a question and WAIT for their answer (human-in-the-loop). Use only when you genuinely need a decision, credential, or scope clarification you cannot determine yourself.", obj(map[string]any{"question": pStr("The question for the operator.")}, "question")),
		td("search_worker_traces", "Keyword-search OTHER workers' execution steps in this task (your own steps are excluded). Returns hits with their intent_id.", obj(map[string]any{"query": pStr("Keyword(s).")}, "query")),
		td("get_worker_trace", "Fetch the full steps of one intent (by intent_id) for detailed exchange.", obj(map[string]any{"intent_id": pInt("The intent node id."), "limit": pInt("Max steps (default 20).")}, "intent_id")),
		td("done", "Finish this intent. Call when the direction is exhausted or its facts are recorded.", obj(map[string]any{"summary": pStr("What you concluded.")}, "summary")),
	}
}

// workerExec builds the executor for one claimed intent.
func (m *Manager) workerExec(ctx context.Context, explID, intentID int64, worker string, companyID int64) toolExec {
	return func(call agent.FunctionCall) (string, bool) {
		a := parseArgs(call.Arguments)
		switch call.Name {
		case "run_bash":
			cmd := argStr(a, "command")
			out, isErr := m.runBash(ctx, cmd)
			_ = m.st.AppendActivity(&store.Activity{ExplorationID: explID, NodeID: intentID, Worker: worker,
				Kind: "tool", Tool: "bash", IsError: isErr, Summary: truncate(cmd, 200), Detail: out})
			m.emit(explID, "step", map[string]any{"intent": intentID, "tool": "bash", "command": truncate(cmd, 200)})
			return out, false
		case "record_fact":
			summary, detail := argStr(a, "summary"), argStr(a, "detail")
			fid := m.recordFact(explID, intentID, summary, detail, argStr(a, "asset"), companyID)
			m.emit(explID, "fact", map[string]any{"id": fid, "summary": summary})
			return fmt.Sprintf("fact #%d recorded", fid), false
		case "record_finding":
			id := m.recordFinding(explID, intentID, a, companyID)
			m.emit(explID, "finding", map[string]any{"id": id, "title": argStr(a, "title"), "severity": argStr(a, "severity")})
			return fmt.Sprintf("finding #%d recorded", id), false
		case "add_asset":
			aid := m.addAsset(intentID, argStr(a, "type"), argStr(a, "value"), companyID)
			return fmt.Sprintf("asset #%d added & anchored", aid), false
		case "ask_human":
			q := argStr(a, "question")
			qid, _ := m.st.CreateSideQuestion(explID, intentID, worker, q)
			_ = m.st.AppendActivity(&store.Activity{ExplorationID: explID, NodeID: intentID, Worker: worker,
				Kind: "question", Summary: truncate(q, 300)})
			m.emit(explID, "question", map[string]any{"id": qid, "intent": intentID, "question": q})
			ans := m.waitForAnswer(ctx, qid)
			_ = m.st.AppendActivity(&store.Activity{ExplorationID: explID, NodeID: intentID, Worker: worker,
				Kind: "answer", Summary: truncate(ans, 300)})
			m.emit(explID, "answer", map[string]any{"id": qid, "answer": ans})
			return "Human answered: " + ans, false
		case "search_worker_traces":
			hits, _ := m.st.SearchActivity(explID, intentID, argStr(a, "query"), 20)
			return formatTraceHits(hits), false
		case "get_worker_trace":
			limit := argInt(a, "limit")
			if limit <= 0 {
				limit = 20
			}
			steps, _ := m.st.ListActivity(explID, int64(argInt(a, "intent_id")), limit)
			return formatTraceSteps(steps), false
		case "done":
			_ = m.st.SetNodeState(intentID, store.IntentDone, "")
			_ = m.st.AppendActivity(&store.Activity{ExplorationID: explID, NodeID: intentID, Worker: worker,
				Kind: "summary", Summary: truncate(argStr(a, "summary"), 400)})
			return "intent done", true
		}
		return "unknown tool: " + call.Name, false
	}
}

// ── worker write-back helpers ────────────────────────────────────────────────

func (m *Manager) recordFact(explID, intentID int64, summary, detail, asset string, companyID int64) int64 {
	n := &store.ExplorationNode{ExplorationID: explID, Kind: store.NodeFact, State: "confirmed",
		Payload: `{"summary":` + jsonStr(summary) + `,"detail":` + jsonStr(detail) + `}`, Origin: "worker"}
	_ = m.st.CreateNode(n)
	_ = m.st.AddEdge(explID, intentID, n.ID, store.RelYields)
	if asset != "" {
		if aid := m.anchorAssetValue(n.ID, asset, companyID); aid > 0 {
			_ = m.st.AddAnchor(intentID, aid)
		}
	}
	return n.ID
}

func (m *Manager) recordFinding(explID, intentID int64, a map[string]any, companyID int64) int64 {
	title, sev, host, ev := argStr(a, "title"), strings.ToLower(argStr(a, "severity")), argStr(a, "host"), argStr(a, "evidence")
	// exploration finding node
	n := &store.ExplorationNode{ExplorationID: explID, Kind: store.NodeFinding, State: "confirmed",
		Payload: `{"title":` + jsonStr(title) + `,"severity":` + jsonStr(sev) + `,"host":` + jsonStr(host) + `,"evidence":` + jsonStr(ev) + `}`, Origin: "worker"}
	_ = m.st.CreateNode(n)
	_ = m.st.AddEdge(explID, intentID, n.ID, store.RelProves)
	// bridge into the existing findings table so it shows on the Findings page
	sevP, nameP, evP, descP := sev, title, ev, "Discovered by autonomous task exploration."
	f := &store.Finding{RunID: fmt.Sprintf("task-%d", explID), Kind: "vuln", Severity: &sevP,
		Host: host, Name: &nameP, Title: &nameP, Evidence: &evP, Description: &descP, Status: "open"}
	_ = m.st.InsertFinding(f)
	if host != "" {
		if aid := m.anchorAssetValue(n.ID, host, companyID); aid > 0 {
			_ = m.st.AddAnchor(intentID, aid)
		}
	}
	return n.ID
}

func (m *Manager) addAsset(intentID int64, typ, value string, companyID int64) int64 {
	aid := m.anchorAssetValue(intentID, value, companyID)
	if typ != "" && aid == 0 {
		aid, _ = m.upsertAsset(typ, value, companyID)
		if aid > 0 {
			_ = m.st.AddAnchor(intentID, aid)
		}
	}
	return aid
}

// anchorAssetValue resolves an asset by value (guessing type), upserts if needed,
// and returns its id (does not create the anchor edge itself for facts/findings —
// callers anchor the intent).
func (m *Manager) anchorAssetValue(nodeID int64, value string, companyID int64) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	typ := guessAssetType(value)
	aid, _ := m.upsertAsset(typ, value, companyID)
	if aid > 0 {
		_ = m.st.AddAnchor(nodeID, aid)
	}
	return aid
}

func (m *Manager) upsertAsset(typ, value string, companyID int64) (int64, error) {
	a := &store.Asset{Type: typ, Value: strings.TrimSpace(value), Source: "task", Meta: "{}"}
	if companyID > 0 {
		a.CompanyID = &companyID
	}
	return m.st.UpsertAssetGetID(a)
}

func guessAssetType(v string) string {
	switch {
	case strings.HasPrefix(v, "http://"), strings.HasPrefix(v, "https://"):
		return "endpoint"
	case strings.Count(v, ".") == 3 && !strings.ContainsAny(v, "abcdefghijklmnopqrstuvwxyz"):
		return "ip"
	case strings.Contains(v, ":"):
		return "port"
	case strings.Count(v, ".") >= 2:
		return "subdomain"
	default:
		return "domain"
	}
}

// ── bash through the recording proxy ─────────────────────────────────────────

func (m *Manager) runBash(ctx context.Context, command string) (string, bool) {
	if strings.TrimSpace(command) == "" {
		return "(empty command)", true
	}
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	c := exec.CommandContext(cctx, "bash", "-lc", command)
	c.Env = append([]string{}, osEnviron()...)
	if m.proxyAddr != "" {
		p := m.proxyAddr
		if !strings.HasPrefix(p, "http") {
			p = "http://" + p
		}
		c.Env = append(c.Env, "HTTP_PROXY="+p, "HTTPS_PROXY="+p, "http_proxy="+p, "https_proxy="+p)
	}
	out, err := c.CombinedOutput()
	s := string(out)
	if len(s) > 8000 {
		s = s[:8000] + "\n…(truncated)"
	}
	if cctx.Err() == context.DeadlineExceeded {
		return s + "\n(command timed out after 120s)", true
	}
	return s, err != nil
}

// ── formatting ───────────────────────────────────────────────────────────────

func formatTraceHits(hits []store.Activity) string {
	if len(hits) == 0 {
		return "(no matching steps from other workers)"
	}
	var sb strings.Builder
	for _, h := range hits {
		fmt.Fprintf(&sb, "[intent %d · %s] %s\n", h.NodeID, h.Tool, truncate(h.Summary, 160))
	}
	return sb.String()
}

func formatTraceSteps(steps []store.Activity) string {
	if len(steps) == 0 {
		return "(no steps)"
	}
	var sb strings.Builder
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		fmt.Fprintf(&sb, "• %s: %s\n%s\n", s.Tool, truncate(s.Summary, 160), truncate(s.Detail, 600))
	}
	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// normDesc normalizes an intent description for dedup (lowercase, collapsed spaces).
func normDesc(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
func jsonUnmarshal(s string, v any) error {
	if s == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), v)
}
