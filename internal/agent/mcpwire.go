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
	msgs := []Message{{Role: "system", Content: SystemPrompt}}
	for _, m := range history {
		switch m.Role {
		case "user", "assistant":
			mm := Message{Role: m.Role, Content: m.Content}
			if m.ToolCalls != "" && m.ToolCalls != "[]" {
				_ = json.Unmarshal([]byte(m.ToolCalls), &mm.ToolCalls)
			}
			msgs = append(msgs, mm)
		case "tool":
			msgs = append(msgs, Message{Role: "tool", Content: m.Content, ToolCallID: m.ToolCallID})
		}
	}

	res := &LoopResult{}
	baseTools := Tools()
	mcpTools := reg.ExtraTools()
	all := append(append([]ToolDef{}, baseTools...), mcpTools...)

	for round := 0; round < cfg.MaxToolRounds; round++ {
		turn, usage, err := c.ChatCompletion(ctx, msgs, all)
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
			if strings.HasPrefix(tc.Function.Name, "mcp_") {
				out = safeMCP(ctx, reg, tc.Function)
			} else {
				out = safeExec(st, r, tc.Function)
			}
			res.ToolCalls = append(res.ToolCalls, tc.Function.Name)
			_ = st.InsertChatMessage(&store.ChatMessage{
				ConversationID: convID, Role: "tool", Content: out, ToolCallID: tc.ID,
			})
			msgs = append(msgs, Message{Role: "tool", Content: out, ToolCallID: tc.ID})
		}
	}
	res.Reply = "Đạt giới hạn vòng gọi tool — hãy tiếp tục với câu hỏi cụ thể hơn."
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
