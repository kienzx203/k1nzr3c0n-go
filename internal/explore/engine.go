package explore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"k1nzr3c0n/internal/agent"
	"k1nzr3c0n/internal/bus"
	"k1nzr3c0n/internal/store"
)

// Manager owns the lifecycle of running tasks (the engine). It is created once
// and shared; StartTask spawns one exploration loop goroutine per task.
type Manager struct {
	st        *store.Store
	bus       *bus.Bus
	proxyAddr string

	mu      sync.Mutex
	running map[int64]context.CancelFunc
}

func NewManager(st *store.Store, b *bus.Bus, proxyAddr string) *Manager {
	return &Manager{st: st, bus: b, proxyAddr: proxyAddr, running: map[int64]context.CancelFunc{}}
}

func osEnviron() []string { return os.Environ() }

// IsRunning reports whether a task's loop goroutine is active.
func (m *Manager) IsRunning(taskID int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.running[taskID]
	return ok
}

// StartTask resolves an LLM profile and launches the exploration loop.
func (m *Manager) StartTask(taskID int64) error {
	m.mu.Lock()
	if _, ok := m.running[taskID]; ok {
		m.mu.Unlock()
		return errors.New("task already running")
	}
	m.mu.Unlock()

	task, err := m.st.GetTask(taskID)
	if err != nil {
		return err
	}
	client, profID, err := m.resolveClient(task)
	if err != nil {
		return err
	}
	_ = m.st.SetTaskActiveLLM(taskID, profID)
	_ = m.st.SetTaskPaused(taskID, false)

	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.running[taskID] = cancel
	m.mu.Unlock()
	go m.run(ctx, taskID, client)
	return nil
}

// PauseTask / StopTask both cancel the loop; status differs.
func (m *Manager) PauseTask(taskID int64) {
	m.stop(taskID)
	_ = m.st.SetTaskPaused(taskID, true)
	_ = m.st.SetTaskStatus(taskID, "paused")
}
func (m *Manager) StopTask(taskID int64) {
	m.stop(taskID)
	_ = m.st.SetTaskStatus(taskID, "failed")
}
func (m *Manager) stop(taskID int64) {
	m.mu.Lock()
	if cancel, ok := m.running[taskID]; ok {
		cancel()
		delete(m.running, taskID)
	}
	m.mu.Unlock()
}

// agentFor applies the per-role agent_config override (prompt / LLM / budget)
// on top of the task's fallback client and built-in defaults.
func (m *Manager) agentFor(role string, fallback *agent.Client, defaultSys string, defaultSteps int) (*agent.Client, string, int) {
	client, sys, steps := fallback, defaultSys, defaultSteps
	if cfg, err := m.st.GetAgentConfig(role); err == nil && cfg != nil {
		if cfg.Prompt != "" {
			sys = cfg.Prompt
		}
		if cfg.MaxSteps > 0 {
			steps = cfg.MaxSteps
		}
		if cfg.LLMProfileID > 0 {
			if p, e := m.st.GetLLMProfile(cfg.LLMProfileID); e == nil {
				client = agent.NewClient(p.BaseURL, p.APIKey, p.Model, p.Temperature)
			}
		}
	}
	return client, sys, steps
}

// waitForAnswer blocks until a side-question is answered/skipped, ctx is done,
// or a 20-minute cap elapses. Returns the human's answer (or a sentinel).
func (m *Manager) waitForAnswer(ctx context.Context, qid int64) string {
	deadline := time.Now().Add(20 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return "(task stopped before the human answered)"
		case <-time.After(2 * time.Second):
		}
		if time.Now().After(deadline) {
			_ = m.st.SkipSideQuestion(qid)
			return "(no answer within 20 minutes — proceed with your best judgment)"
		}
		q, err := m.st.GetSideQuestion(qid)
		if err != nil {
			return "(question lookup failed — proceed)"
		}
		switch q.Status {
		case "answered":
			return q.Answer
		case "skipped":
			return "(human skipped — proceed with your best judgment)"
		}
	}
}

func (m *Manager) resolveClient(task *store.Task) (*agent.Client, int64, error) {
	tryIDs := []int64{task.ActiveLLMProfileID, task.LLMProfileID}
	for _, id := range tryIDs {
		if id == 0 {
			continue
		}
		if p, err := m.st.GetLLMProfile(id); err == nil {
			return agent.NewClient(p.BaseURL, p.APIKey, p.Model, p.Temperature), p.ID, nil
		}
	}
	profiles, err := m.st.ListLLMProfiles()
	if err != nil || len(profiles) == 0 {
		return nil, 0, errors.New("no LLM profile configured")
	}
	p := profiles[0]
	return agent.NewClient(p.BaseURL, p.APIKey, p.Model, p.Temperature), p.ID, nil
}

// ── the exploration loop ─────────────────────────────────────────────────────

const maxRounds = 40

func (m *Manager) run(ctx context.Context, taskID int64, client *agent.Client) {
	defer func() {
		m.mu.Lock()
		delete(m.running, taskID)
		m.mu.Unlock()
	}()

	task, err := m.st.GetTask(taskID)
	if err != nil {
		return
	}
	_ = m.st.SetTaskStatus(taskID, "running")
	_ = m.st.SetExplorationStatus(task.ExplorationID, "open")
	m.emit(task.ExplorationID, "status", map[string]any{"status": "running"})

	var deadline time.Time
	if task.TimeoutSeconds > 0 {
		deadline = time.Now().Add(time.Duration(task.TimeoutSeconds) * time.Second)
	}

	for round := 0; round < maxRounds; round++ {
		if ctx.Err() != nil {
			return
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			_ = m.st.SetTaskStatus(taskID, "timeout")
			_ = m.st.SetExplorationStatus(task.ExplorationID, "failed")
			m.emit(task.ExplorationID, "status", map[string]any{"status": "timeout"})
			return
		}
		// re-check pause
		if t, _ := m.st.GetTask(taskID); t != nil && t.Paused {
			return
		}

		emitted, goalMet := m.plannerTurn(ctx, task, client)
		if ctx.Err() != nil {
			return
		}
		if goalMet {
			_ = m.st.SetTaskStatus(taskID, "done")
			_ = m.st.SetExplorationStatus(task.ExplorationID, "achieved")
			m.emit(task.ExplorationID, "status", map[string]any{"status": "done", "reason": "goal met"})
			return
		}

		m.drainFrontier(ctx, task, client)

		open, _ := m.st.CountOpenIntents(task.ExplorationID)
		if emitted == 0 && open == 0 {
			_ = m.st.SetTaskStatus(taskID, "done")
			_ = m.st.SetExplorationStatus(task.ExplorationID, "achieved")
			m.emit(task.ExplorationID, "status", map[string]any{"status": "done", "reason": "frontier exhausted"})
			return
		}
	}
	// round budget reached
	_ = m.st.SetTaskStatus(taskID, "done")
	m.emit(task.ExplorationID, "status", map[string]any{"status": "done", "reason": "round budget reached"})
}

// ── planner ──────────────────────────────────────────────────────────────────

const plannerSystem = `You are the PLANNER of an autonomous penetration-testing task.
You are the ONLY component that creates intents (exploration directions). Read the
current exploration graph and the shared todolist, then decide the next step(s).

Rules:
- Maintain a serial attack chain in the todolist (find entry → credentials → lateral → escalate).
  Record it once with update_todolist, then release intents step by step across rounds.
- Each round, submit ONLY intents whose prerequisites are already satisfied by existing facts.
  Do NOT lay out the whole chain in one round. Often the right move is to submit 0 and finish.
- Never repeat a direction that already has a fact or a running/open intent.
- When the goal is proven by the findings/facts, call mark_goal_met.
- When there is no genuinely new direction this round, call finish.
Be concise and decisive. Use graph_overview and list_assets before submitting.`

func (m *Manager) plannerTurn(ctx context.Context, task *store.Task, client *agent.Client) (emitted int, goalMet bool) {
	goalNode := m.goalNodeID(task.ExplorationID)
	exec := func(call agent.FunctionCall) (string, bool) {
		a := parseArgs(call.Arguments)
		switch call.Name {
		case "graph_overview":
			return m.plannerOverview(task.ExplorationID, task.Goal), false
		case "list_assets":
			return m.assetsCoverage(task), false
		case "submit_intent":
			desc := argStr(a, "description")
			if desc == "" {
				return "error: description required", false
			}
			n := &store.ExplorationNode{ExplorationID: task.ExplorationID, Kind: store.NodeIntent,
				State: store.IntentOpen, Priority: argInt(a, "priority"), Origin: "planner",
				Payload: `{"description":` + jsonStr(desc) + `}`}
			_ = m.st.CreateNode(n)
			if goalNode > 0 {
				_ = m.st.AddEdge(task.ExplorationID, goalNode, n.ID, store.RelSpawns)
			}
			for _, av := range argStrList(a, "assets") {
				_ = m.anchorAssetValue(n.ID, av, task.CompanyID)
			}
			emitted++
			m.emit(task.ExplorationID, "intent", map[string]any{"id": n.ID, "description": desc})
			return fmt.Sprintf("intent #%d queued", n.ID), false
		case "update_todolist":
			m.setTodolist(task.ExplorationID, argStr(a, "todolist"))
			return "todolist updated", false
		case "mark_goal_met":
			if goalNode > 0 {
				_ = m.st.SetNodeState(goalNode, "met", argStr(a, "reason"))
			}
			goalMet = true
			return "goal marked met", true
		case "finish":
			return "planning finished for this round", true
		}
		return "unknown tool: " + call.Name, false
	}
	user := "Exploration state:\n\n" + m.plannerOverview(task.ExplorationID, task.Goal) +
		"\n\nDecide the next step(s). Submit intents only for ready directions, or finish."
	pClient, pSys, pSteps := m.agentFor("planner", client, plannerSystem, 14)
	_, _, _ = m.runAgent(ctx, pClient, pSys, user, plannerTools(), exec, pSteps)
	return emitted, goalMet
}

func (m *Manager) goalNodeID(explID int64) int64 {
	goals, _ := m.st.ListNodes(explID, store.NodeGoal)
	if len(goals) > 0 {
		return goals[0].ID
	}
	return 0
}

// assetsCoverage lists company assets and whether each has been probed this task.
func (m *Manager) assetsCoverage(task *store.Task) string {
	covered := map[int64]bool{}
	ids, _ := m.st.CoveredAssetIDs(task.ExplorationID)
	for _, id := range ids {
		covered[id] = true
	}
	f := store.GraphAssetFilter{}
	if task.CompanyID > 0 {
		f.CompanyID = task.CompanyID
	}
	assets, _ := m.st.ListAssetsGraph(f)
	if len(assets) == 0 {
		return "(no assets in scope yet — discover some with a worker)"
	}
	var sb []byte
	for _, a := range assets {
		mark := "untested"
		if covered[a.ID] {
			mark = "TESTED"
		}
		sb = append(sb, fmt.Sprintf("- [%s] %s (%s)\n", mark, a.Value, a.Type)...)
	}
	return string(sb)
}

// ── workers ──────────────────────────────────────────────────────────────────

const workerSystem = `You are a WORKER on an autonomous penetration-testing task.
You have claimed ONE intent and must pursue only that direction, then stop.

Do:
- Run real recon tools with run_bash (subfinder, httpx, nuclei, ffuf, curl, nmap…).
  HTTP is captured as evidence automatically.
- Before heavy work, use search_worker_traces to reuse what other workers already found.
- Record confirmed observations with record_fact, new assets with add_asset,
  and vulnerabilities with record_finding.
- When the direction is exhausted or its facts are recorded, call done with a summary.
Stay strictly within your intent. Keep commands bounded and safe. Do not wander to other directions.`

const retesterSystem = `You are a VULNERABILITY RETESTER on an autonomous task.
You have claimed ONE intent whose purpose is to re-verify a previously reported
vulnerability. Reproduce the original issue with real tools (run_bash / HTTP).

Conclude exactly one of:
- "reproducible" — the vulnerability still triggers (record a finding with evidence),
- "fixed" — it no longer triggers (record a fact stating it is fixed),
- "cannot_confirm" — inconclusive (record a fact explaining why).
Record your evidence, then call done with the conclusion. Stay within this intent.`

func (m *Manager) drainFrontier(ctx context.Context, task *store.Task, client *agent.Client) {
	var wg sync.WaitGroup
	workers := task.MaxWorkers
	if workers <= 0 {
		workers = 3
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(wi int) {
			defer wg.Done()
			worker := fmt.Sprintf("worker-%d", wi+1)
			for {
				if ctx.Err() != nil {
					return
				}
				if t, _ := m.st.GetTask(task.ID); t != nil && t.Paused {
					return
				}
				intent, err := m.st.ClaimNextIntent(task.ExplorationID, worker)
				if errors.Is(err, store.ErrNotFound) || err != nil {
					return
				}
				m.executeIntent(ctx, task, client, intent, worker)
			}
		}(i)
	}
	wg.Wait()
}

func (m *Manager) executeIntent(ctx context.Context, task *store.Task, client *agent.Client, intent *store.ExplorationNode, worker string) {
	var p map[string]any
	_ = jsonUnmarshal(intent.Payload, &p)
	desc := argStr(p, "description")
	m.emit(task.ExplorationID, "claim", map[string]any{"intent": intent.ID, "worker": worker, "description": desc})

	// anchored-asset context
	assetIDs, _ := m.st.ListAnchorsForNode(intent.ID)
	ctxLines := fmt.Sprintf("GOAL: %s\nYOUR INTENT (#%d): %s\n", task.Goal, intent.ID, desc)
	if len(assetIDs) > 0 {
		ctxLines += fmt.Sprintf("Anchored to %d asset(s).\n", len(assetIDs))
	}
	user := ctxLines + "\nPursue this intent now. Use tools; record facts/findings; call done when finished."

	exec := m.workerExec(ctx, task.ExplorationID, intent.ID, worker, task.CompanyID)
	// retest tasks run their workers under the dedicated "retester" agent role
	role, baseSys := "worker", workerSystem
	if task.Name == "retest" {
		role, baseSys = "retester", retesterSystem
	}
	wClient, wSys, wSteps := m.agentFor(role, client, baseSys, 18)
	_, _, err := m.runAgent(ctx, wClient, wSys, user, workerTools(), exec, wSteps)

	// if the worker never called done, close the intent as exhausted
	if n, e := m.st.GetNode(intent.ID); e == nil && n.State == store.IntentRunning {
		reason := ""
		if err != nil {
			reason = err.Error()
		}
		_ = m.st.SetNodeState(intent.ID, store.IntentExhausted, reason)
	}
	m.emit(task.ExplorationID, "intent-done", map[string]any{"intent": intent.ID})
}

// ── generic agent loop ───────────────────────────────────────────────────────

func (m *Manager) runAgent(ctx context.Context, client *agent.Client, sys, user string,
	tools []agent.ToolDef, exec toolExec, maxSteps int) (string, *agent.Usage, error) {
	msgs := []agent.Message{{Role: "system", Content: sys}, {Role: "user", Content: user}}
	var total agent.Usage
	for step := 0; step < maxSteps; step++ {
		if ctx.Err() != nil {
			return "", &total, ctx.Err()
		}
		turn, usage, err := client.ChatCompletion(ctx, msgs, tools)
		if err != nil {
			return "", &total, err
		}
		if usage != nil {
			total.PromptTokens += usage.PromptTokens
			total.CompletionTokens += usage.CompletionTokens
			total.TotalTokens += usage.TotalTokens
		}
		msgs = append(msgs, agent.Message{Role: "assistant", Content: turn.Content, ToolCalls: turn.ToolCalls})
		if !turn.HasToolCalls() {
			return turn.Content, &total, nil
		}
		stop := false
		for _, tc := range turn.ToolCalls {
			res, s := exec(tc.Function)
			msgs = append(msgs, agent.Message{Role: "tool", ToolCallID: tc.ID, Content: truncate(res, 6000)})
			if s {
				stop = true
			}
		}
		if stop {
			return "", &total, nil
		}
	}
	return "", &total, nil
}

// ── events ───────────────────────────────────────────────────────────────────

func (m *Manager) emit(explID int64, kind string, data map[string]any) {
	if m.bus == nil {
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["event"] = kind
	b, _ := jsonMarshal(data)
	m.bus.Publish(fmt.Sprintf("task-%d", explID), bus.Message{Type: "log", Message: string(b)})
}
