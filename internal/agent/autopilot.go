package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"k1nzr3c0n/internal/runner"
	"k1nzr3c0n/internal/store"
)

// Autopilot drives an engagement autonomously through role phases
// (ScopeWeaver's planner → worker → reviewer discipline in one loop):
// for each phase the model answers with strict JSON, the loop executes the
// decided action, then re-evaluates until the goal is met or budgets die.

const autopilotSystem = `You are the autonomous engagement orchestrator. You drive the recon through PHASES, replying with STRICT JSON only (no prose):

{"phase":"plan","action":"launch_run","workflow":"01-full-recon-pipeline.yaml","target":"example.com","reason":"...","done":false}
{"phase":"execute","action":"wait_run","run_id":"...","reason":"...","done":false}
{"phase":"analyze","action":"triage","finding_id":1,"status":"fp","reason":"...","done":false}
{"phase":"analyze","action":"report","summary":"...","done":true}

Rules:
- phase order: plan → execute (wait for runs) → analyze → plan… (iterate)
- available actions: create_target, launch_run, wait_run (poll a run), cancel_run, triage (finding_id+status), ingest_assets, report (finish with summary), done:true
- wait_run: reply immediately with the current status from the last tool result; if still running and nothing else useful to do, action wait_run again (the driver sleeps between steps)
- stay in scope; never launch workflows for unregistered targets
- when the goal is met (or no further action helps), reply {"phase":"analyze","action":"report","summary":"...","done":true}`

type autopilotStep struct {
	Phase     string `json:"phase"`
	Action    string `json:"action"`
	Workflow  string `json:"workflow"`
	Target    string `json:"target"`
	RunID     string `json:"run_id"`
	Reason    string `json:"reason"`
	FindingID int64  `json:"finding_id"`
	Status    string `json:"status"`
	Summary   string `json:"summary"`
	Done      bool   `json:"done"`
}

// AutopilotResult reports one autonomous engagement run.
type AutopilotResult struct {
	ConversationID int64    `json:"conversation_id"`
	Steps          []string `json:"steps"`
	Summary        string   `json:"summary"`
	Rounds         int      `json:"rounds"`
	Usage          Usage    `json:"tokens"`
}

// RunAutopilot executes the autonomous loop. maxSteps bounds iterations
// (default 40); each step is one LLM round + action execution.
func RunAutopilot(ctx context.Context, st *store.Store, r *runner.Runner, c *Client,
	goal string, maxSteps int) (*AutopilotResult, error) {

	if maxSteps <= 0 {
		maxSteps = 40
	}
	conv, err := st.CreateConversation("autopilot: "+goal, "autopilot")
	if err != nil {
		return nil, err
	}
	res := &AutopilotResult{ConversationID: conv.ID}
	_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: conv.ID, Role: "user",
		Content: "GOAL: " + goal + "\n\nDrive the engagement autonomously. Start now."})

	msgs := []Message{
		{Role: "system", Content: autopilotSystem},
		{Role: "user", Content: "GOAL: " + goal},
	}
	tools := Tools()

	for step := 0; step < maxSteps; step++ {
		turn, usage, err := c.ChatCompletion(ctx, msgs, tools)
		if err != nil {
			return res, fmt.Errorf("round %d: %w", step, err)
		}
		res.Rounds++
		res.Usage.PromptTokens += usage.PromptTokens
		res.Usage.CompletionTokens += usage.CompletionTokens
		res.Usage.TotalTokens += usage.TotalTokens

		content := strings.TrimSpace(turn.Content)
		// strip markdown fences if the model wraps JSON
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(content, "```")

		var dec autopilotStep
		if jerr := json.Unmarshal([]byte(content), &dec); jerr != nil {
			// nudge back to strict JSON
			msgs = append(msgs, Message{Role: "assistant", Content: turn.Content},
				Message{Role: "user", Content: "Invalid JSON. Reply with STRICT JSON per the system prompt."})
			continue
		}
		res.Steps = append(res.Steps, fmt.Sprintf("%s:%s %s", dec.Phase, dec.Action, dec.Reason))
		_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: conv.ID, Role: "assistant",
			Content: fmt.Sprintf("[%s] %s — %s", dec.Phase, dec.Action, dec.Reason)})

		if dec.Done || dec.Action == "report" {
			res.Summary = dec.Summary
			_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: conv.ID, Role: "assistant",
				Content: "AUTUPILOT DONE: " + dec.Summary})
			return res, nil
		}

		out := execAutopilotAction(ctx, st, r, dec)
		msgs = append(msgs, Message{Role: "assistant", Content: turn.Content},
			Message{Role: "user", Content: "TOOL RESULT: " + out})
		_ = st.InsertChatMessage(&store.ChatMessage{ConversationID: conv.ID, Role: "tool", Content: out})

		// waiting? sleep so a running scan progresses between rounds
		if dec.Action == "wait_run" {
			select {
			case <-ctx.Done():
				return res, ctx.Err()
			case <-time.After(20 * time.Second):
			}
		}
	}
	res.Summary = "Đạt giới hạn bước autopilot."
	return res, nil
}

func execAutopilotAction(ctx context.Context, st *store.Store, r *runner.Runner, dec autopilotStep) string {
	switch dec.Action {
	case "create_target":
		return Exec(st, r, FunctionCall{Name: "create_target", Arguments: mustJSON(map[string]any{
			"name": dec.Target, "mode": "bounty"})})
	case "launch_run":
		args := map[string]any{"workflow": dec.Workflow, "target": dec.Target}
		return Exec(st, r, FunctionCall{Name: "launch_run", Arguments: mustJSON(args)})
	case "wait_run":
		return Exec(st, r, FunctionCall{Name: "get_run_status", Arguments: mustJSON(map[string]any{"run_id": dec.RunID})})
	case "cancel_run":
		return Exec(st, r, FunctionCall{Name: "cancel_run", Arguments: mustJSON(map[string]any{"run_id": dec.RunID})})
	case "triage":
		return Exec(st, r, FunctionCall{Name: "patch_finding", Arguments: mustJSON(map[string]any{
			"finding_id": dec.FindingID, "status": dec.Status})})
	case "ingest_assets":
		return Exec(st, r, FunctionCall{Name: "list_findings", Arguments: mustJSON(map[string]any{"limit": 50})})
	}
	return `{"error":"unknown action ` + dec.Action + `"}`
}

func mustJSON(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}
