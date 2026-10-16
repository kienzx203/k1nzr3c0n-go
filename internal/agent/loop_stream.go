package agent

import (
	"context"
	"encoding/json"
	"strings"

	"k1nzr3c0n/internal/runner"
	"k1nzr3c0n/internal/store"
)

// StreamEmit delivers one streaming event to the caller (SSE transport).
type StreamEmit func(event string, payload map[string]any)

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RunTurnMCPStream is RunTurnMCP with token-by-token streaming. It emits:
//
//	"delta" {content}   — a fragment of the assistant's text as it arrives
//	"tool"  {name}      — a tool is about to execute
//	"tool_result" {name, output_preview}
//
// The tool-calling loop, persistence and MCP wiring are identical to
// RunTurnMCP, so behavior matches the non-streaming path.
func RunTurnMCPStream(ctx context.Context, st *store.Store, r *runner.Runner, c *Client,
	convID int64, userMsg string, cfg LoopConfig, emit StreamEmit) (*LoopResult, error) {

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
	all := append(append([]ToolDef{}, Tools()...), reg.ExtraTools()...)
	all = append(all, CustomToolDefs(st)...)

	for round := 0; round < cfg.MaxToolRounds; round++ {
		turn, usage, err := c.ChatCompletionStream(ctx, msgs, all, func(frag string) {
			if emit != nil {
				emit("delta", map[string]any{"content": frag})
			}
		})
		if err != nil {
			return res, err
		}
		res.Rounds = round + 1
		if usage != nil {
			res.UsageTotals.PromptTokens += usage.PromptTokens
			res.UsageTotals.CompletionTokens += usage.CompletionTokens
			res.UsageTotals.TotalTokens += usage.TotalTokens
		}

		if !turn.HasToolCalls() {
			res.Reply = turn.Content
			_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: convID, Role: "assistant", Content: turn.Content})
			return res, nil
		}
		tcb, _ := json.Marshal(turn.ToolCalls)
		_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: convID, Role: "assistant", Content: turn.Content, ToolCalls: string(tcb)})
		msgs = append(msgs, Message{Role: "assistant", Content: turn.Content, ToolCalls: turn.ToolCalls})

		for _, tc := range turn.ToolCalls {
			if emit != nil {
				emit("tool", map[string]any{"name": tc.Function.Name, "args": truncateStr(tc.Function.Arguments, 400)})
			}
			var out string
			allow, denyMsg := GateCheck(st, tc.Function.Name, tc.Function.Arguments)
			if !allow {
				out = `{"blocked": true, "error": ` + jsonString(denyMsg) + `}`
				Audit(st, tc.Function.Name, tc.Function.Arguments, out, true)
			} else if strings.HasPrefix(tc.Function.Name, "mcp_") {
				out = safeMCP(ctx, reg, tc.Function)
				Audit(st, tc.Function.Name, tc.Function.Arguments, out, false)
			} else if IsCustomTool(st, tc.Function.Name) {
				out = ExecCustomTool(st, tc.Function)
				Audit(st, tc.Function.Name, tc.Function.Arguments, out, false)
			} else {
				out = safeExec(st, r, tc.Function)
				Audit(st, tc.Function.Name, tc.Function.Arguments, out, false)
			}
			res.ToolCalls = append(res.ToolCalls, tc.Function.Name)
			if emit != nil {
				emit("tool_result", map[string]any{"name": tc.Function.Name, "output": truncateStr(out, 600)})
			}
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
