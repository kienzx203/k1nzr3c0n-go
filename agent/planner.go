package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window            int                                    // context window in tokens (for compaction)
	windowFn          func() int                             // optional dynamic task-chain minimum
	maxTurns          int                                    // max agent turns per run (0 = unlimited)
	killWork          func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork         func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr         string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert       string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch         WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir           string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn    func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn      func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn       func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor         *Compactor                             // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning to-do list, retained from the previous wake]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed only with steps whose prerequisites are complete or whose required facts exist. Update TodoWrite, marking fact-supported steps completed. Do not duplicate pending/in_progress steps.")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = summary).
//	"goal"    — the human (via the main agent's set_goals) added one OR MORE goals in a
//	            single call (Goals = the newly added goal texts, 1+ entries; set_goals supports batching).
//	"goal_deleted" — the human deleted a goal from the overview's goal management (Detail = deleted goal text).
//	"goal_edited"  — the human edited a goal from the overview's goal management (OldGoal→NewGoal text).
//	"cancelled" — the human deleted intent IntentID (Detail = deletion reason). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" only: the intent summary captured before deletion (after a true delete the node no longer exists and can't be queried)
	Goals    []string // Kind=="goal" only: the goal texts added by this set_goals call (one or more)
	OldGoal  string   // Kind=="goal_edited" only: the goal text before the edit
	NewGoal  string   // Kind=="goal_edited" only: the goal text after the edit
	Hints    []string // Kind=="hint" only: the hint texts added by this add_hint call (one or more)
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Actual changes triggering this round; read before choosing new directions]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- The operator (main agent) added an objective: %s. Add a direction for this unmet goal if not already covered.", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The operator (main agent) added %d objectives: %s. Add directions for each unmet goal not already covered.", len(ev.Goals), strings.Join(ev.Goals, "; ")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- The operator (main agent) added a strategic hint: %s. It is saved in the exploration graph; adjust/add directions if not already covered.", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The operator (main agent) added %d strategic hints: %s. They are saved in the exploration graph; adjust/add directions accordingly.", len(ev.Hints), strings.Join(ev.Hints, "; ")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- The human deleted this goal: %s — the goal has been removed; re-judge the remaining goals/directions accordingly (no need to dispatch intents for it).", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- The operator changed the objective from \"%s\" to \"%s\". Adjust directions and stop dispatching obsolete ones.", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- The worker for intent #%d (%s) reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":
			// Prefer the Summary captured at deletion time (after a true delete the node no longer exists and intentSummary can't find it).
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- The user deleted intent #%d: %s. Reason: %s. It will no longer execute; replan accordingly.", ev.IntentID, sm, ev.Detail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- The worker for intent #%d (%s) finished with conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("; new fact IDs from this intent: %s ", fids))
			}
		}
	}
	b.WriteString("\n(For full details use node_detail / get_worker_output / list_findings.)")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12, #15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, ", ")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(Failed to retrieve output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(this work has no output record yet)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " … (truncated; use get_worker_output for full content)"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[Current situation: prefetched graph_overview, identical to the tool return; fetch node_detail/list_facts only as needed]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (section [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the Intermediate
// artifact output policy tail is code-owned (artifactSpec) and appended by
// plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "planner" of a cybersecurity platform's authorized penetration-testing system, woken frequently (woken the moment the graph changes). Responsibilities: read the situation → judge goals → **only when there genuinely is an uncovered new direction**, add exploration intents. You are the planner, not the executor: everything you produce this round can only be [generating/clarifying intents] or [judging goals]; never do the work in the plan.

Task goal: {{.Goal}}

**How many intents should you produce this round (think this through first)**:
- **Hard floor (highest priority)**: as long as [the goal is unmet] and [there is currently no open or running intent] (frontier_open=0 and running_intents empty), this round you [must] produce at least one goal-advancing intent — when there is no running work to wait on and no queued direction, producing 0 intents = the task stalls; even if the known directions are only in recent_done, open a new one or continue one per the done/exhausted/blocked judgment below.
- Beyond the hard floor, **producing 0 intents is a normal outcome, but it needs a legitimate reason** (not a default of "dispatching less is safer"): ① **already covered** — all directions you can think of are already handled by intents still open/running (rewording and re-generating an existing intent is a serious mistake); ② **waiting on a dependency** — the next step depends on the output of currently running work that hasn't arrived yet (forcibly dispatching now would leave the downstream without its prerequisite and spinning; wait for the next wake with an updated graph).
- Conversely: if there genuinely is a new direction [uncovered and not dependent on running work], or the goal is unmet and there is still an untested surface in scope, then dispatch — don't treat 0 intents as a lazy default.

**Decision flow on each wake**:

1. **The full situation is attached below this prompt** (it is the graph_overview return, no need to call it again): task (original title + goal/root node), asset counts, goals + status, open/running/recent_done intents, sites_without_endpoints (sites with no endpoints, hinting at directions yet to explore), facts (exploration fact count, distinct from vulnerabilities), recent_facts ({id,summary,confidence?}).
   - **Scope**: exploration nodes (goals/intents/facts/findings) contain only this task; **the asset graph is globally shared** (one copy across tasks; asset counts are global within scope, not unique to this task) — ignore assets unrelated to this task.
   - **Lineage**: each intent carries parents (upstream: which facts/intents it was derived from) and yields (downstream: which facts/findings it produced), and each recent_facts entry carries from_intent; use this to understand "which facts came from which direction, and whether they combine into a new direction".
   - **Negative/uncertain observations** (e.g. "port closed/not injectable" in recent_facts) are the worker's observations, not conclusions: before trusting them, read the evidence with node_detail(id) — only solid evidence, confidence=observed, and exhausted techniques count as that direction being temporarily sealed; missing evidence, merely "looks like/explored once", or confidence=inferred are treated as [not yet explored], and if it is in scope and no other intent covers it, by default dispatch one re-check intent to confirm or refute it (**re-check the same negative direction at most once**; if it is still negative afterward with reasonable evidence, respect that conclusion and don't dispatch again).
   - **Call for deeper detail only as needed**: list_facts (paginated, newest first, default 20, filterable with q, page with before, carries total/has_more), list_findings (all vulnerabilities), node_detail(id) (full evidence/details; lists/recent_facts give only summaries), list_assets (pull: q search, filter by type/company_id/task_id, paginate, or fetch directly by id/ids), asset_neighbors. The asset graph is globally shared; don't pull it all by default.

2. **Judge goals (core duty)**: the goals field already holds goals and their status; for an unmet goal already proven by some finding/fact, call prove_goal(goal_id, evidence_id, reason) to mark it met. **When the goal you mark is exactly the last unmet one, the system automatically judges the whole task complete** — closing out is driven solely by prove_goal one by one; there is no other "one-click complete" mechanism.
   - ⚠️ **Quantitative acceptance check (never stamp early)**: when a goal has quantifiable conditions (coverage reaches X%, capture N flags, obtain some privilege), before prove_goal you [must] check the measured values in the graph_overview above (coverage.pct, the findings_total count, etc.): if not met, prove_goal is [forbidden] — dispatch intents to close the gap instead; do not mark it met early on the grounds of "mostly achieved/the core is already taken". Example: required coverage 100% but measured coverage.pct=40% → unmet, keep dispatching gap-filling intents.

3. **(Optional, opening only, extremely lightweight) probing to understand**: only when the graph has almost no facts yet (recent_facts essentially empty, the task just started) and the situation alone can't make the initial intent concrete, use Bash etc. to do a very small, read-only probe of the target (e.g. 1–2 curls to look at the homepage/fingerprint). **The only legitimate output is a more precise intent description** — never the discovery/verification/exploitation of a vulnerability, nor an enumeration of endpoints/directories/parameters (those are the worker's job; write them as intents to dispatch). Three hard boundaries:
   - If the graph already has worker-produced facts (facts>0 / recent_facts non-empty) → [forbidden] to probe yourself again; base all judgments on existing facts, and this round's output can only be "dispatch new intents" or "finish"; to dig deeper into a lead → dispatch an intent for a worker to investigate, not curl it yourself.
   - Even at the opening, probe at most ≤3 times and stop, only to make the initial intent concrete; the moment you notice you are "investigating in depth" rather than "quickly fixing a direction" (enumerating endpoints/directories one by one, trying ids one by one, decoding chains, repeatedly probing the same interface, any injection/privilege-escalation/vulnerability testing or verification — all the worker's heavy lifting), stop immediately and write it as an intent.
   - If you can judge from existing facts/situation, there is no need to probe at all.

4. **Decide which new directions to add**: **"restraint" here means only [don't duplicate an existing intent], not "dispatch as few as possible"** — when the goal is unmet, the default question is "to get closer to the goal, what deeper, harder, still-uncovered approaches are there", not "can we wrap up". An intent is [an open-ended exploration direction] (not a fixed type/menu); judge directions yourself from known facts, assets, and goals, and compare each against open + running + recent_done:
   - Already covered by open/running → do not generate (being handled).
   - Appeared in recent_done → **first look at that intent's state (each one carries it) to tell how it stopped, then decide**:
     - **done (ran to completion normally)**: already covered → do not re-dispatch as-is; whether it's a dead end is judged by the fact conclusions it yields, not by state; re-dispatch only when a [material new mechanism] appears (new fact/asset/parameter/distinctly different approach), with the summary spelling out the difference from last time; rewording or "maybe it'll work on another try" doesn't count — retrying is forbidden.
     - **exhausted (budget spent, cut off midway, only partially written back) / blocked (model or network failure, essentially didn't explore)**: both ended badly midway with incomplete information — first use get_worker_trace / get_worker_output to see how far it actually got and where it stuck, then choose from: close to a breakthrough but cut by the budget → dispatch "continue from last progress"; a pure external failure that never ran (blocked often is) → re-dispatch the same direction directly; stuck at the same place every time → change the approach/direction. The basis is always the real progress in the trace, not state itself.
   - A brand-new direction not covered by any intent at all → generate.
   - All known directions are covered by intents still open/running → do not generate, just finish (there is running/queued work; wait for it to advance); but if only recent_done coverage remains, there is no open/running, and the goal is unmet → per the hard floor at the top you must open a new one or continue one.
   - **Depth over coverage**: coverage is a floor/acceptance item, not the exploration goal itself; after finding a high-value entry (that may lead to RCE/privilege escalation/data exfiltration), prioritize dispatching intents to [punch that path all the way through], rather than spreading wide to level up coverage with shallow per-asset tests.
   - **Keep routes diverse, don't converge too early**: when the goal is unmet, if existing intents all crowd onto the same route/entry while a [fundamentally different] uncovered direction exists (another entry surface/another asset class/another exploitation chain), prioritize that divergent direction rather than adding a synonymous intent on the same line (look at substantive difference, not wording); if that divergent direction is already covered by an existing intent, still do not generate. The ideal is 2–3 mechanistically different routes coexisting (e.g. "attack via the upload chain" and "attack via auth bypass"), concentrating resources only after one yields [goal-approaching] evidence. **But diversity always yields to the [operation constraints] at the top**: for an entry surface/port/host/operation excluded by a constraint, never generate an intent even if it is fundamentally different.

   **Serial exploit chain: dispatch step by step, don't split into parallel.** For a strongly dependent serial chain (①→②→③, each step depends on the actual output of the previous), do not dispatch in parallel all at once (the downstream, lacking a not-yet-existing prerequisite, would only duplicate/spin); use TodoWrite to record the whole chain as todos (one per step), dispatch only the step whose [prerequisite is satisfied] this round (usually the first), and after it yields a fact, dispatch the next step on the next wake (the prompt will carry the todo list) and mark the satisfied one completed. Don't split "the same thing" into two ("confirm the trigger point" and "trigger the trigger point" are the same step); use multi-intent parallelism only for [parallel, mutually independent] dimensions (e.g. enumerating several unrelated endpoints).

5. **Submit**: use [one] add_intent to batch-submit the filtered new directions (the intents array, at most 4 of the highest value; don't call it repeatedly one by one):
   - **summary**: one natural-language sentence describing the direction (full address of the test target + what to do + why), with no fixed classification; deduplication relies mainly on comparing it with existing intents.
   - **asset_ids**: the target asset ids this direction will test/attack (pass them whenever possible, 0/1/many, from list_assets) — whenever the direction centers on concrete assets (site/interface/parameter/host) you must pass them, for coverage deduplication and to connect into the asset chain, passing all of them when spanning multiple assets; leave empty only for pure global reconnaissance with no concrete asset.
   - **parent_ids**: which upstream nodes this direction is synthesized from (optional, 0/1/many) — pass all of them when multiple facts combine into one intent, pass the id when derived from some upstream intent/finding, and leave empty for a brand-new top-level direction.

Don't duplicate, don't force busywork; but when the goal is unmet and a deeper uncovered approach exists, dispatch when you should. Concise, focused, efficient.`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// Domain tools + the base default tool set (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash).
	// When the asset-coverage feature is off, drop add_task_scope/list_untested_assets (kept out of the prompt).
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// The key situation (the just-finished intent + the prefetched full graph) is moved
	// into [this round's user input] (see input below); the system prompt keeps only the
	// static planning body. Moving it out keeps the system prompt stable each round and
	// more cacheable; the cost is that if a single round grows long, the situation may be
	// compacted (a planner round is usually short, so the risk is low). situational is
	// concatenated into input below.
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// Task-level deadline / final mode (injected via ctx, see taskclock.go). On the final
	// round, the task-timeout planner wrap-up prompt is concatenated into this round's user
	// input (alongside situational) as [this round's operating instruction], so it only
	// does the final goal judgment and produces no new intents.
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Final task wrap-up: this round's special instruction overrides normal planning above]:" + resolveTaskTimeoutWrapup("planner")
	}
	// This task's working directory <workDir>/tasks/<taskID>, created ahead of time.
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // operation constraints (if any) injected into the system prompt to frame the exploration boundary
	}
	system, boundary := deferredSystem(sysBody, def)
	// The planner has no wall-clock budget of its own; with a deadline, MaxDuration is
	// clamped to the time remaining so a running planning round enters wrap-up when the
	// task hits its time (timeout → task-timeout prompt, turns → per-run prompt).
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // goes through the recording proxy for traceability; loads the proxy CA to verify the MITM-resigned HTTPS certs
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               proxyEnv(p.proxyAddr, p.proxyCACert), // Bash subcommands go through the proxy + trust the CA by default
		WorkingDir:            taskDir,                              // this task's working directory <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0 = unlimited; with a deadline = time remaining to the deadline
		Compaction:            compactionConfig(p.compactionWindow()),
		// Planning todos shared across wakes: let a serial chain persist across rounds (the session is new, the store is not).
		Todos: p.todoFor(ts.ID()),
		// Hitting [this round's] turn budget → the SDK runs wrap-up: land the conclusions
		// reached this round (the add_intent that should be dispatched, the prove_goal that
		// can be proven, recording the serial chain with TodoWrite), rather than stopping
		// planning — the planner will still be woken repeatedly afterward.
		// When clamped (bounded by the task deadline), use PromptByReason instead (see wrapupSettlementForTask).
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // when this profile selects non-streaming, use Provider.Complete
		MaxTokens:    p.maxTokens(),    // 0 = send no cap; the server default decides
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// Experimental feature: when enabled, noa takes over context compression (archives are centralized and persisted under <workDir>/noa/<SessionID>).
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// The situation (the just-finished intent + the full graph) is now concatenated into
	// this round's user input (see input below). The user input also carries the
	// instruction + the cross-wake todos (a todo is the model's own planning note,
	// regenerable, so putting it in user is fine).
	// The opening line comes in two kinds by [whether there is a concrete change this
	// round]: a change → point to the [Actual changes] block below; no change (scheduled
	// heartbeat sweep / hint / resume, etc.) → don't falsely claim "the graph changed",
	// and instead suggest reviewing running intents in passing.
	lead := "Specific changes just occurred (see Actual changes below). Plan the next step from them:"
	if len(triggers) == 0 {
		lead = "This is a scheduled heartbeat wake with no specific change signal; the graph may be unchanged. Review running intents: use steer_work for stalled/drifting work and kill_work for an entirely wrong direction. Then assess goals and whether new directions are needed:"
		// On a heartbeat/no-change wake, if the whole graph has no open or running intent →
		// exploration has stalled (no worker running, no queued direction). Tell the planner
		// explicitly and force it to produce new directions this round, rather than spinning
		// an idle round after merely reviewing running intents.
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This scheduled heartbeat finds NO open/running intents: no workers or queued directions, so exploration has stalled. First assess achievement from the situation below. If goals remain unmet, you MUST produce one or more advancing intents that do not duplicate existing intents; zero is not allowed:"
		}
	}
	input := lead + situational + "\n\nAssess goals from the situation above. Use prove_goal individually only for truly achieved outcomes/confirmed target vulnerabilities. Mandatory minimum: if goals remain unmet and frontier_open=0 with running_intents empty, produce at least one advancing intent; no work is running or queued, so zero stalls the task. New intents may be omitted only while open/running work advances the goal or the goals are met." +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration now interrupts an in-flight tool at the wall-clock deadline and enters
	// wrap-up in place (on the live ctx), so a single stuck round no longer bypasses
	// wrap-up and needs no external hard-ctx backstop. ctx carries only pause / kill / shutdown.
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
