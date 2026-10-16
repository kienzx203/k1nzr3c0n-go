package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"k1nzr3c0n/internal/mcp"
	"k1nzr3c0n/internal/runner"
	"k1nzr3c0n/internal/store"
)

// MCPRegistry holds live MCP connections for one chat turn.
type MCPRegistry struct {
	servers map[string]*mcp.Server // by registered name
}

// ConnectEnabled spawns every enabled MCP server from the DB.
func ConnectEnabled(ctx context.Context, st *store.Store) *MCPRegistry {
	r := &MCPRegistry{servers: map[string]*mcp.Server{}}
	cfgs, err := st.ListMCP()
	if err != nil {
		return r
	}
	for _, c := range cfgs {
		if !c.Enabled {
			continue
		}
		srv, err := mcp.Connect(ctx, c.Name, c.Command, c.Args)
		if err != nil {
			continue // unreachable server never blocks chat
		}
		r.servers[c.Name] = srv
	}
	return r
}

// Close terminates all connections.
func (r *MCPRegistry) Close() {
	for _, s := range r.servers {
		s.Close()
	}
}

// ExtraTools renders every MCP tool in the OpenAI tools format, named
// mcp_<server>_<tool>.
func (r *MCPRegistry) ExtraTools() []ToolDef {
	var out []ToolDef
	for name, srv := range r.servers {
		for _, t := range srv.Tools() {
			schema := t.InputSchema
			if schema == nil {
				schema = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			out = append(out, ToolDef{Type: "function", Function: FunctionSpec{
				Name:        fmt.Sprintf("mcp_%s_%s", sanitizeName(name), sanitizeName(t.Name)),
				Description: fmt.Sprintf("[MCP %s] %s", name, t.Description),
				Parameters:  schema,
			}})
		}
	}
	return out
}

func sanitizeName(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "-", "_")
}

// ExecMCP dispatches an mcp_<server>_<tool> call. Server name is matched
// longest-first so names containing underscores resolve correctly.
func (r *MCPRegistry) ExecMCP(ctx context.Context, call FunctionCall) string {
	if !strings.HasPrefix(call.Name, "mcp_") {
		return `{"error":"not an mcp tool"}`
	}
	rest := strings.TrimPrefix(call.Name, "mcp_")
	for name, srv := range r.servers {
		prefix := sanitizeName(name) + "_"
		if strings.HasPrefix(rest, prefix) {
			tool := strings.TrimPrefix(rest, prefix)
			var args map[string]any
			_ = json.Unmarshal([]byte(call.Arguments), &args)
			out, err := srv.CallTool(ctx, tool, args)
			if err != nil {
				b, _ := json.Marshal(map[string]any{"error": err.Error()})
				return string(b)
			}
			b, _ := json.Marshal(map[string]any{"output": out})
			return string(b)
		}
	}
	return `{"error":"unknown mcp server/tool: ` + call.Name + `"}`
}

// RunTurnMCP is RunTurn with dynamic MCP tools merged in.
func RunTurnMCP(ctx context.Context, st *store.Store, r *runner.Runner, c *Client,
	convID int64, userMsg string, cfg LoopConfig) (*LoopResult, error) {
	_ = c // primary; failover handled inside the round loop

	reg := ConnectEnabled(ctx, st)
	defer reg.Close()

	if cfg.MaxToolRounds <= 0 {
		cfg.MaxToolRounds = 24
	}
	if err := st.InsertChatMessage(&store.ChatMessage{ConversationID: convID, Role: "user", Content: userMsg}); err != nil {
		return nil, err
	}
	history, err := st.ListChatMessages(convID)
	if err != nil {
		return nil, err
	}
	msgs := compactedMessages(ctx, c, cfg.sysPrompt(), history)

	res := &LoopResult{}
	baseTools := Tools()
	mcpTools := reg.ExtraTools()
	all := append(append([]ToolDef{}, baseTools...), mcpTools...)

	chat := func() (*Turn, *Usage, error) {
		turn, usage, err := c.ChatCompletion(ctx, msgs, all)
		if err == nil || !retryable(err) {
			return turn, usage, err
		}
		// primary failed retryably → try other configured profiles
		if others := stFailoverProfiles(st, c); len(others) > 0 {
			if t2, u2, _, err2 := ChatWithFailover(ctx, others, msgs, all); err2 == nil {
				return t2, u2, nil
			}
		}
		return turn, usage, err
	}

	for round := 0; round < cfg.MaxToolRounds; round++ {
		turn, usage, err := chat()
		if err != nil {
			return res, err
		}
		res.Rounds = round + 1
		res.UsageTotals.PromptTokens += usage.PromptTokens
		res.UsageTotals.CompletionTokens += usage.CompletionTokens
		res.UsageTotals.TotalTokens += usage.TotalTokens

		if !turn.HasToolCalls() {
			res.Reply = turn.Content
			_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: convID, Role: "assistant", Content: turn.Content})
			return res, nil
		}
		tcb, _ := json.Marshal(turn.ToolCalls)
		_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: convID, Role: "assistant", Content: turn.Content, ToolCalls: string(tcb)})
		msgs = append(msgs, Message{Role: "assistant", Content: turn.Content, ToolCalls: turn.ToolCalls})

		for _, tc := range turn.ToolCalls {
			var out string
			allow, denyMsg := GateCheck(st, tc.Function.Name, tc.Function.Arguments)
			if !allow {
				out = `{"blocked": true, "error": ` + jsonString(denyMsg) + `}`
				Audit(st, tc.Function.Name, tc.Function.Arguments, out, true)
			} else if strings.HasPrefix(tc.Function.Name, "mcp_") {
				out = safeMCP(ctx, reg, tc.Function)
				Audit(st, tc.Function.Name, tc.Function.Arguments, out, false)
			} else {
				out = safeExec(st, r, tc.Function)
				Audit(st, tc.Function.Name, tc.Function.Arguments, out, false)
			}
			res.ToolCalls = append(res.ToolCalls, tc.Function.Name)
			_ = st.InsertChatMessage(&store.ChatMessage{
				ConversationID: convID, Role: "tool", Content: out, ToolCallID: tc.ID,
			})
			msgs = append(msgs, Message{Role: "tool", Content: out, ToolCallID: tc.ID})
		}
	}
	res.Reply = "Reached the tool-call round limit — please continue with a more specific question."
	_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: convID, Role: "assistant", Content: res.Reply})
	return res, nil
}

func safeMCP(ctx context.Context, reg *MCPRegistry, fc FunctionCall) (out string) {
	defer func() {
		if rec := recover(); rec != nil {
			out = `{"error":"mcp tool crashed"}`
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return reg.ExecMCP(cctx, fc)
}

// compactedMessages builds the LLM context. When the history is long
// (> 60 messages), older turns are summarized by the model itself into one
// digest note (ScopeWeaver compaction concept, pragmatic form) so multi-hour
// conversations stay inside the context window.
func compactedMessages(ctx context.Context, c *Client, system string, history []store.ChatMessage) []Message {
	const keepRecent = 24
	const compactThreshold = 60

	build := func(msgs []store.ChatMessage) []Message {
		out := []Message{{Role: "system", Content: system}}
		for _, m := range msgs {
			switch m.Role {
			case "user", "assistant":
				mm := Message{Role: m.Role, Content: m.Content}
				if m.ToolCalls != "" && m.ToolCalls != "[]" {
					_ = json.Unmarshal([]byte(m.ToolCalls), &mm.ToolCalls)
				}
				out = append(out, mm)
			case "tool":
				out = append(out, Message{Role: "tool", Content: m.Content, ToolCallID: m.ToolCallID})
			}
		}
		return out
	}

	if len(history) <= compactThreshold {
		return build(history)
	}
	old, recent := history[:len(history)-keepRecent], history[len(history)-keepRecent:]

	var sb strings.Builder
	sb.WriteString("Summarize this earlier conversation compactly (key decisions, tools called with outcomes, targets, findings). Keep facts; drop fluff. Reply with the summary only:\n")
	for _, m := range old {
		role := m.Role
		content := m.Content
		if len(content) > 400 {
			content = content[:400] + "…"
		}
		sb.WriteString(role + ": " + content + "\n")
	}
	sumCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	turn, _, err := c.ChatCompletion(sumCtx, []Message{
		{Role: "system", Content: "You compress pentest-operation chat logs."},
		{Role: "user", Content: sb.String()},
	}, nil)
	digest := "(earlier history unavailable)"
	if err == nil && strings.TrimSpace(turn.Content) != "" {
		digest = turn.Content
	}
	compacted := []store.ChatMessage{{
		Role:    "user",
		Content: "[CONTEXT DIGEST — summary of earlier turns]\n" + digest,
	}}
	return build(append(compacted, recent...))
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// stFailoverProfiles lists OTHER configured profiles (primary excluded).
func stFailoverProfiles(st *store.Store, primary *Client) []ProfileRef {
	rows, err := st.ListLLMProfiles()
	if err != nil {
		return nil
	}
	var out []ProfileRef
	for _, p := range rows {
		if p.BaseURL == primary.BaseURL && p.Model == primary.Model {
			continue
		}
		out = append(out, ProfileRef{ID: p.ID, BaseURL: p.BaseURL, APIKey: p.APIKey, Model: p.Model, Temp: p.Temperature})
	}
	return out
}
