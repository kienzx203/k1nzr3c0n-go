package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Autumn-27/artex/k1z/runner"
	"github.com/Autumn-27/artex/k1z/store"
)

// baseDir mirrors config.BaseDir without an import cycle.
func baseDir() string {
	b := os.Getenv("K1NZR3C0N_BASE")
	if b == "" {
		b = "."
	}
	if abs, err := filepath.Abs(b); err == nil {
		return abs
	}
	return b
}

// LoopConfig controls one chat turn.
type LoopConfig struct {
	MaxToolRounds int    // safety cap on tool-call rounds (default 16)
	SystemPrompt  string // overrides the default system prompt (per chat agent)
}

// sysPrompt returns the configured override or the package default.
func (c LoopConfig) sysPrompt() string {
	if c.SystemPrompt != "" {
		return c.SystemPrompt
	}
	return SystemPrompt
}

// LoopResult is the outcome of one user turn.
type LoopResult struct {
	Reply       string
	Rounds      int
	ToolCalls   []string // names executed, in order
	UsageTotals Usage
}

// RunTurn executes one user message: persists it, then loops
// (completion → tool execution → tool results) until the model produces a
// plain reply or hits the round cap. The full exchange is persisted so the
// conversation resumes with history.
func RunTurn(ctx context.Context, st *store.Store, r *runner.Runner, c *Client,
	convID int64, userMsg string, cfg LoopConfig) (*LoopResult, error) {

	if cfg.MaxToolRounds <= 0 {
		cfg.MaxToolRounds = 16
	}
	if err := st.InsertChatMessage(&store.ChatMessage{ConversationID: convID, Role: "user", Content: userMsg}); err != nil {
		return nil, err
	}
	// build message list from history (system + persisted turns)
	history, err := st.ListChatMessages(convID)
	if err != nil {
		return nil, err
	}
	msgs := []Message{{Role: "system", Content: cfg.sysPrompt()}}
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
	tools := Tools()
	for round := 0; round < cfg.MaxToolRounds; round++ {
		turn, usage, err := c.ChatCompletion(ctx, msgs, tools)
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
		// persist the assistant tool-call turn
		tcb, _ := json.Marshal(turn.ToolCalls)
		_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: convID, Role: "assistant", Content: turn.Content, ToolCalls: string(tcb)})
		msgs = append(msgs, Message{Role: "assistant", Content: turn.Content, ToolCalls: turn.ToolCalls})

		for _, tc := range turn.ToolCalls {
			out := safeExec(st, r, tc.Function)
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

// safeExec never lets a tool panic kill the server.
func safeExec(st *store.Store, r *runner.Runner, fc FunctionCall) (out string) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[agent] tool %s panicked: %v", fc.Name, rec)
			out = fmt.Sprintf(`{"error":"tool %s crashed"}`, fc.Name)
		}
	}()
	return Exec(st, r, fc)
}
