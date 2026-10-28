// Package runner executes runs: it replaces Celery worker + beat with an
// in-process worker pool and wires engine events into the DB, the live bus,
// findings parsers, and webhooks.
package runner

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/k1z/bus"
	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/notify"
	"github.com/Autumn-27/artex/k1z/parsers"
	"github.com/Autumn-27/artex/k1z/scope"
	"github.com/Autumn-27/artex/k1z/store"
	"github.com/Autumn-27/artex/k1z/workflow"
)

// incrementalParseSteps mirrors tasks.py _INCREMENTAL_PARSE_STEPS: steps whose
// completion triggers a mid-run findings re-parse (vuln steps deliberately
// excluded so critical alerts only fire after vuln scans ran).
var incrementalParseSteps = map[string]bool{
	"httpx": true, "httpx_probe": true, "screenshot": true,
	"pivot_httpx_probe": true, "st_pivot_screenshot": true, "naabu_topscan": true,
}

// ── provider metadata (ported from tasks.py) ─────────────────────────────────

var subfinderKeyMap = map[string]string{"zoomeye": "zoomeyeapi"}
var subfinderSkip = map[string]bool{
	"criminalip": true, "google_cse": true, "google_cx": true, "hunter": true,
	"greynoise": true, "binaryedge": true, "fullhunt": true, "quake": true,
}
var uncoverProviders = map[string]string{
	"shodan": "shodan", "chaos": "chaos", "censys": "censys", "fofa": "fofa",
	"quake": "quake", "zoomeye": "zoomeye", "netlas": "netlas",
	"binaryedge": "binaryedge", "hunter": "hunter", "criminalip": "criminalip",
	"onyphe": "onyphe", "driftnet": "driftnet", "greynoise": "greynoise",
}
var providerEnvMap = map[string][]string{
	"shodan":         {"SHODAN_API_KEY"},
	"securitytrails": {"SECURITYTRAILS_KEY"},
	"virustotal":     {"VIRUSTOTAL_KEY"},
	"bevigil":        {"BEVIGIL_KEY"},
	"fofa":           {"FOFA_KEY"},
	"chaos":          {"CHAOS_API_KEY"},
	"github":         {"GITHUB_TOKEN"},
	"zoomeye":        {"ZOOMEYE_API_KEY"},
	"binaryedge":     {"BINARYEDGE_API_KEY"},
	"netlas":         {"NETLAS_API_KEY"},
	"fullhunt":       {"FULLHUNT_API_KEY"},
	"leakix":         {"LEAKIX_API_KEY"},
	"c99":            {"C99_API_KEY"},
	"intelx":         {"INTELX_API_KEY"},
	"hackertarget":   {"HACKERTARGET_API_KEY"},
	"dnsdumpster":    {"DNSDUMPSTER_API_KEY"},
	"whoisxmlapi":    {"WHOISXMLAPI_API_KEY"},
	"urlscan":        {"URLSCAN_API_KEY"},
	"certspotter":    {"CERTSPOTTER_API_KEY", "CERTSPOTTER_KEY"},
	"google_cse":     {"GOOGLE_CSE_KEY"},
	"google_cx":      {"GOOGLE_CX"},
	"qwen":           {"DASHSCOPE_API_KEY"},
	"hunter":         {"HUNTER_API_KEY"},
	"criminalip":     {"CRIMINALIP_API_KEY"},
	"greynoise":      {"GREYNOISE_API_KEY"},
	"censys":         {"CENSYS_API_ID", "CENSYS_API_SECRET"},
}

// ── runner ───────────────────────────────────────────────────────────────────

type Runner struct {
	St    *store.Store
	Bus   *bus.Bus
	Limit time.Duration

	// ProxyEnv returns the recording-proxy env overlay for a run when
	// capture is enabled (set by main; nil = capture off).
	ProxyEnv func(runID string) map[string]string

	queue   chan string
	engines map[string]*engineHandle
	mu      sync.Mutex
	wg      sync.WaitGroup
}

type engineHandle struct {
	KillAll func()
}

func New(st *store.Store, b *bus.Bus) *Runner {
	return &Runner{
		St:      st,
		Bus:     b,
		Limit:   time.Duration(config.TaskTimeLimit()) * time.Second,
		queue:   make(chan string, 1024),
		engines: map[string]*engineHandle{},
	}
}

// Start launches the worker pool and recovers orphaned runs.
func (r *Runner) Start(workers int) {
	r.RecoverOrphans()
	for i := 0; i < workers; i++ {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for runID := range r.queue {
				r.ExecuteRun(runID)
			}
		}()
	}
}

func (r *Runner) Stop() {
	close(r.queue)
	r.wg.Wait()
}

// Enqueue adds a queued run to the work queue.
func (r *Runner) Enqueue(runID string) {
	select {
	case r.queue <- runID:
	default:
		log.Printf("[runner] queue full; dropping %s", runID)
	}
}

// LaunchScheduleRun launches a run for a schedule trigger (scope gate skipped)
// and returns it, or a NotFoundError when the workflow file is gone.
func (r *Runner) LaunchScheduleRun(sc *ScheduleSpec, vars map[string]string) (*store.Run, error) {
	wfPath := filepath.Join(config.WorkflowsDir(), sc.Workflow)
	if _, err := os.Stat(wfPath); err != nil {
		return nil, &NotFoundError{Msg: "Workflow not found: " + sc.Workflow}
	}
	return r.Launch(LaunchInput{
		Workflow:       sc.Workflow,
		Target:         sc.Target,
		Vars:           vars,
		SkipScopeCheck: true,
	})
}

// ScheduleSpec carries the fields LaunchScheduleRun needs.
type ScheduleSpec struct {
	Workflow string
	Target   string
}

// RecoverOrphans fails runs stuck in 'running' from a previous process life.
func (r *Runner) RecoverOrphans() {
	runs, err := r.St.ActiveRuns()
	if err != nil {
		return
	}
	for _, run := range runs {
		if run.Status != "running" {
			continue // queued runs still execute (Python: broker keeps them)
		}
		msg := "Interrupted by a worker restart — no process was left running this scan. Use Resume to continue from the last completed step."
		_ = r.St.UpdateRunStatus(run.ID, "failed", map[string]any{
			"error_message": msg, "finished_at": store.SqlNow(),
		})
		r.flipSteps(run.ID, "running", "failed")
		r.Bus.Publish(run.ID, bus.Message{Type: "done", Status: "failed", Error: msg})
		log.Printf("[runner] recovered orphaned run %s", run.ID)
	}
}

// ── launch ───────────────────────────────────────────────────────────────────

type LaunchInput struct {
	Workflow        string
	Target          string
	Out             string
	Vars            map[string]string
	Resume          bool
	ContinueOnError bool
	SkipScopeCheck  bool
}

// Launch validates scope + workflow, pre-renders steps_json, creates the run
// row, and enqueues it. Returns the new run or an error mirroring the Python
// HTTP error semantics ("Out of scope: ...", "Invalid workflow path", ...).
func (r *Runner) Launch(in LaunchInput) (*store.Run, error) {
	if !in.SkipScopeCheck {
		if ok, reason := scope.CheckTargetScope(r.St, in.Target); !ok {
			return nil, &ScopeError{Reason: reason}
		}
	}
	wfPath := filepath.Join(config.WorkflowsDir(), in.Workflow)
	if filepath.Clean(wfPath) != filepath.Clean(safeJoin(config.WorkflowsDir(), in.Workflow)) {
		return nil, fmt.Errorf("Invalid workflow path")
	}
	if _, err := os.Stat(wfPath); err != nil {
		return nil, &NotFoundError{Msg: "Workflow not found: " + in.Workflow}
	}
	wf, err := workflow.Load(wfPath)
	if err != nil {
		return nil, fmt.Errorf("Workflow validation failed: %v", err)
	}

	// workspace
	timestamp := time.Now().Format("20060102-150405")
	ws := filepath.Join(config.RunsDir(), workflow.SafeTarget(in.Target), timestamp)
	if in.Out != "" {
		abs := safeJoin(config.RunsDir(), in.Out)
		if filepath.Clean(abs) != filepath.Clean(in.Out) && !strings.HasPrefix(abs, config.RunsDir()) {
			return nil, fmt.Errorf("Invalid output path")
		}
		ws = abs
	}
	vars := workflow.VarsMerge(wf.Vars, in.Vars)
	varsJSON, _ := json.Marshal(vars)

	stepsJSON := prerenderSteps(wf, in.Target, ws, timestamp)

	runID := newRunID()
	run := &store.Run{
		ID:              runID,
		Workflow:        in.Workflow,
		Target:          in.Target,
		Status:          "queued",
		Workspace:       ws,
		VarsJSON:        string(varsJSON),
		ContinueOnError: in.ContinueOnError,
		Resume:          in.Resume,
		StepsJSON:       stepsJSON,
	}
	if err := r.St.CreateRun(run); err != nil {
		return nil, err
	}
	r.Enqueue(runID)
	return run, nil
}

func safeJoin(base, rel string) string {
	clean := filepath.Clean(filepath.Join(base, rel))
	if !strings.HasPrefix(clean, filepath.Clean(base)) {
		return base
	}
	return clean
}

// prerenderSteps builds the UI steps list with rendered commands. The
// target/workspace/timestamp are supplied by the caller (real values).
func prerenderSteps(wf *workflow.Workflow, target, ws, timestamp string) string {
	ctx := map[string]any{
		"target": target, "workspace": ws, "timestamp": timestamp,
		"steps": map[string]any{}, "status": map[string]any{},
	}
	vars := map[string]any{}
	for k, v := range wf.Vars {
		vars[k] = v
		ctx[k] = v
	}
	ctx["vars"] = vars

	type entry struct {
		ID     string          `json:"id"`
		Status string          `json:"status"`
		Name   string          `json:"name"`
		Cmd    string          `json:"cmd,omitempty"`
		Fanout json.RawMessage `json:"fanout,omitempty"`
	}
	var list []entry
	for _, st := range wf.Steps {
		e := entry{ID: st.ID, Status: "pending", Name: st.Name}
		if st.Run != nil {
			if cmd, err := workflow.RenderTemplate(*st.Run, ctx, true); err == nil {
				e.Cmd = cmd
			} else {
				e.Cmd = *st.Run
			}
		} else if len(st.Fanout) > 0 {
			type fc struct {
				ID  string `json:"id"`
				Cmd string `json:"cmd"`
			}
			var children []fc
			for _, c := range st.Fanout {
				cmd, err := workflow.RenderTemplate(c.Run, ctx, true)
				if err != nil {
					cmd = c.Run
				}
				children = append(children, fc{ID: c.ID, Cmd: cmd})
			}
			b, _ := json.Marshal(children)
			e.Fanout = b
		}
		list = append(list, e)
	}
	b, _ := json.Marshal(list)
	return string(b)
}

// ── execution ────────────────────────────────────────────────────────────────

// ScopeError signals an out-of-scope target (HTTP 403 upstream).
type ScopeError struct{ Reason string }

func (e *ScopeError) Error() string { return "Out of scope: " + e.Reason }

// NotFoundError signals a 404 upstream.
type NotFoundError struct{ Msg string }

func (e *NotFoundError) Error() string { return e.Msg }

// runEvents wires engine output into steps_json updates, the bus, and the DB.
type runEvents struct {
	r         *Runner
	run       *store.Run
	steps     []map[string]any
	mu        sync.Mutex
	logBuf    []string
	lastFlush time.Time
	started   time.Time
}

func (e *runEvents) flush(force bool) {
	e.mu.Lock()
	buf := e.logBuf
	e.logBuf = nil
	e.lastFlush = time.Now()
	e.mu.Unlock()
	if len(buf) > 0 || force {
		_ = e.r.St.InsertLogs(e.run.ID, buf)
	}
}

func (e *runEvents) publishLog(line string) {
	e.r.Bus.Publish(e.run.ID, bus.Message{Type: "log", Message: line})
	e.mu.Lock()
	e.logBuf = append(e.logBuf, line)
	shouldFlush := len(e.logBuf) >= 20 || (!e.lastFlush.IsZero() && time.Since(e.lastFlush) >= time.Second)
	e.mu.Unlock()
	if shouldFlush {
		e.flush(false)
	}
}

func (e *runEvents) Info(msg string) { e.publishLog("[+] " + msg) }
func (e *runEvents) Warn(msg string) { e.publishLog("[!] " + msg) }

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// cleanLine strips ANSI codes and collapses progress bars: split on \r and
// keep only the LAST non-empty segment (Python parity).
func cleanLine(line string) string {
	line = ansiRe.ReplaceAllString(line, "")
	if strings.Contains(line, "\r") {
		var last string
		for _, seg := range strings.Split(line, "\r") {
			if strings.TrimSpace(seg) != "" {
				last = seg
			}
		}
		line = last
	}
	return line
}

func (e *runEvents) Line(label, line string) {
	e.publishLog("[" + label + "] " + cleanLine(line))
}

func (e *runEvents) setStepStatus(id, status string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.steps {
		if s["id"] == id {
			if cur, _ := s["status"].(string); cur == "ok" && status == "skipped" {
				continue // never downgrade ok → skipped (resume guard)
			}
			s["status"] = status
			return
		}
	}
}

func (e *runEvents) persistSteps() {
	e.mu.Lock()
	b, _ := json.Marshal(e.steps)
	e.mu.Unlock()
	_ = e.r.St.SetRunStepsJSON(e.run.ID, string(b))
}

func (e *runEvents) publishSteps() {
	e.mu.Lock()
	b, _ := json.Marshal(e.steps)
	e.mu.Unlock()
	e.r.Bus.Publish(e.run.ID, bus.Message{Type: "step", Steps: b})
}

func (e *runEvents) StepStart(id string) {
	e.setStepStatus(id, "running")
	e.persistSteps()
	e.publishSteps()
}

func (e *runEvents) StepDone(id string) {
	e.setStepStatus(id, "ok")
	e.persistSteps()
	e.publishSteps()
	if incrementalParseSteps[id] {
		go rParse(e.r, e.run.ID)
	}
}

func (e *runEvents) StepFail(id string) {
	e.setStepStatus(id, "failed")
	e.persistSteps()
	e.publishSteps()
}

func (e *runEvents) StepSkip(id string) {
	e.setStepStatus(id, "skipped")
	e.persistSteps()
	e.publishSteps()
}

func (e *runEvents) StepTime(id string, ms int64) {
	e.mu.Lock()
	for _, s := range e.steps {
		if s["id"] == id {
			s["duration_ms"] = ms
		}
	}
	b, _ := json.Marshal(e.steps)
	e.mu.Unlock()
	_ = e.r.St.SetRunStepsJSON(e.run.ID, string(b))
}

func rParse(r *Runner, runID string) {
	run, err := r.St.GetRun(runID)
	if err != nil {
		return
	}
	_ = parsers.ParseWorkspace(r.St, run, r.Bus, false)
}

// flipSteps rewrites steps with from-status into to-status in steps_json.
func (r *Runner) flipSteps(runID, from, to string) {
	run, err := r.St.GetRun(runID)
	if err != nil {
		return
	}
	var steps []map[string]any
	if json.Unmarshal([]byte(run.StepsJSON), &steps) != nil {
		return
	}
	for _, s := range steps {
		if s["status"] == from {
			s["status"] = to
		}
	}
	b, _ := json.Marshal(steps)
	_ = r.St.SetRunStepsJSON(runID, string(b))
}

// CancelRun kills the engine for a running run and marks it cancelled.
func (r *Runner) CancelRun(runID string) {
	r.mu.Lock()
	h := r.engines[runID]
	delete(r.engines, runID)
	r.mu.Unlock()
	if h != nil {
		h.KillAll()
	}
	_ = os.WriteFile(filepath.Join(r.workspaceOf(runID), "cancel.flag"), []byte{}, 0o644)
}

func (r *Runner) workspaceOf(runID string) string {
	if run, err := r.St.GetRun(runID); err == nil {
		return run.Workspace
	}
	return ""
}

// ExecuteRun runs one run to completion (worker-pool body).
func (r *Runner) ExecuteRun(runID string) {
	run, err := r.St.GetRun(runID)
	if err != nil {
		return
	}
	// A queued run may have been cancelled before a worker picked it up —
	// never resurrect it (Python revokes the Celery task).
	if run.Status != "queued" && run.Status != "running" {
		return
	}
	// API-key injection (subfinder/uncover configs + env overlay + chaos var)
	keyEnv := r.injectAPIKeys(run)
	vars := map[string]string{}
	_ = json.Unmarshal([]byte(run.VarsJSON), &vars)
	if ck := keyEnv["CHAOS_API_KEY"]; ck != "" && vars["chaos_key"] == "" {
		vars["chaos_key"] = ck
		vb, _ := json.Marshal(vars)
		_ = r.St.UpdateRunStatus(runID, "running", map[string]any{"vars_json": string(vb)})
		run.VarsJSON = string(vb)
	}

	extra := map[string]any{"started_at": store.SqlNow()}
	if !run.StartedAt.IsZero() {
		extra["started_at"] = store.SqlTime(run.StartedAt) // preserve on resume
	}
	_ = r.St.UpdateRunStatus(runID, "running", extra)
	r.Bus.Publish(runID, bus.Message{Type: "status", Status: "running"})

	wfPath := filepath.Join(config.WorkflowsDir(), run.Workflow)
	wf, err := workflow.Load(wfPath)
	if err != nil {
		msg := fmt.Sprintf("Workflow load failed: %v", err)
		_ = r.finishRun(runID, "failed", &msg, nil)
		return
	}

	ev := &runEvents{r: r, run: run, started: time.Now()}
	_ = json.Unmarshal([]byte(run.StepsJSON), &ev.steps)
	if ev.steps == nil {
		ev.steps = []map[string]any{}
	}

	eng := &engineBridge{}
	r.mu.Lock()
	r.engines[runID] = &engineHandle{KillAll: func() { eng.cancel() }}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.engines, runID)
		r.mu.Unlock()
	}()

	// task time limit (Celery task_time_limit parity): kill the engine and
	// fail the run when the wall-clock budget is exhausted.
	if r.Limit > 0 {
		limiter := time.AfterFunc(r.Limit, func() {
			eng.timedOut.Store(true)
			eng.cancel()
			_ = os.WriteFile(filepath.Join(run.Workspace, "cancel.flag"), []byte{}, 0o644)
		})
		defer limiter.Stop()
	}

	envOverlay := keyEnv // per-run env (no process-global mutation)
	if r.ProxyEnv != nil {
		for k, v := range r.ProxyEnv(runID) {
			envOverlay[k] = v // capture proxy wins over keys (no overlap anyway)
		}
	}
	opts := workflow.Options{
		Target:          run.Target,
		Workspace:       run.Workspace,
		Vars:            vars,
		ContinueOnError: run.ContinueOnError,
		Resume:          run.Resume,
		EnvOverlay:      envOverlay,
	}
	_ = os.Remove(filepath.Join(run.Workspace, "pause.flag"))

	err = eng.run(wf, opts, ev)

	ev.flush(true)
	elapsed := time.Since(ev.started).Seconds()

	var statusErr error = err
	if eng.timedOut.Load() && err != nil {
		statusErr = &workflow.WorkflowError{Msg: "Run exceeded the task time limit (" + r.Limit.String() + ") and was terminated"}
	}
	// The cancel API flips the DB row to "cancelled" before the engine even
	// unwinds; any terminal error under that condition is a cancellation
	// (mirrors tasks.py re-fetching the run after kill).
	if statusErr != nil {
		if fresh, ferr := r.St.GetRun(runID); ferr == nil && fresh.Status == "cancelled" {
			statusErr = workflow.ErrCancelled
		}
	}

	switch {
	case statusErr == workflow.ErrPaused:
		rc := workflow.PauseExitCode
		_ = r.St.UpdateRunStatus(runID, "paused", map[string]any{
			"paused_at": store.SqlNow(), "finished_at": store.SqlNow(), "returncode": rc,
		})
		r.flipSteps(runID, "running", "paused")
		r.publishDone(runID, "paused", elapsed, &rc)
		go notify.RunFinished(r.St, run, "paused")
	case statusErr == workflow.ErrCancelled && !eng.timedOut.Load():
		_ = r.finishRun(runID, "cancelled", nil, nil)
		r.flipSteps(runID, "running", "cancelled")
		r.publishDone(runID, "cancelled", elapsed, nil)
		_ = parsers.ParseWorkspace(r.St, run, r.Bus, true) // partial results still parsed
		fireRunFinished(run.ID)
	case statusErr == nil:
		zero := 0
		_ = r.finishRun(runID, "completed", nil, &zero)
		r.flipSteps(runID, "running", "ok")
		r.publishDone(runID, "completed", elapsed, &zero)
		_ = parsers.ParseWorkspace(r.St, run, r.Bus, true)
		go notify.RunFinished(r.St, run, "completed")
		go r.maybeAutoTriage(run)
		fireRunFinished(run.ID) // push the brief back to the task that launched it (if registered)
	default:
		msg := statusErr.Error()
		if we, ok := statusErr.(*workflow.WorkflowError); ok {
			msg = we.Msg
		}
		rc := 2
		_ = r.finishRun(runID, "failed", &msg, &rc)
		r.flipSteps(runID, "running", "failed")
		r.publishDone(runID, "failed", elapsed, &rc)
		_ = parsers.ParseWorkspace(r.St, run, r.Bus, true)
		go notify.RunFinished(r.St, run, "failed")
		fireRunFinished(run.ID) // partial findings from a failed run must still reach the task
	}
}

// fireRunFinished invokes the push-back hook (if wired) off the hot path. Called
// from every terminal branch — completed, cancelled, failed — so a run whose
// results arrived after the agent moved on is pushed back regardless of outcome.
func fireRunFinished(runID string) {
	if RunFinishedHook != nil {
		go RunFinishedHook(runID)
	}
}

func (r *Runner) finishRun(runID, status string, errMsg *string, rc *int) error {
	extra := map[string]any{"finished_at": store.SqlNow()}
	if errMsg != nil {
		extra["error_message"] = *errMsg
	}
	if rc != nil {
		extra["returncode"] = *rc
	}
	return r.St.UpdateRunStatus(runID, status, extra)
}

func (r *Runner) publishDone(runID, status string, elapsed float64, rc *int) {
	round := float64(int(elapsed*10)) / 10
	steps := "[]"
	if run, err := r.St.GetRun(runID); err == nil {
		steps = run.StepsJSON
	}
	r.Bus.Publish(runID, bus.Message{
		Type: "done", Status: status, Steps: json.RawMessage(steps),
		ElapsedS: &round, Returncode: rc,
	})
}

// engineBridge carries a cancel signal into the workflow engine.
type engineBridge struct {
	cancelFn func()
	timedOut atomic.Bool
}

func (b *engineBridge) cancel() {
	if b.cancelFn != nil {
		b.cancelFn()
	}
}

func (b *engineBridge) run(wf *workflow.Workflow, opts workflow.Options, ev workflow.Events) error {
	// The engine reads cancel.flag itself; KillAll flips an engine-level flag.
	// We get that by running with a cancellable wrapper: engine exposes KillAll
	// via a small adapter — simplest is to run RunWorkflow with the events and
	// wrap the engine instance. RunWorkflow hides the engine, so we recreate
	// the handle through a package-level hook.
	return workflow.RunWorkflowWithHandle(wf, opts, ev, func(h workflow.Handle) {
		b.cancelFn = h.KillAll
	})
}

// injectAPIKeys writes provider configs and returns the env overlay.
func (r *Runner) injectAPIKeys(run *store.Run) map[string]string {
	keys, _ := r.St.ListKeys()
	keyMap := map[string]string{}
	for _, k := range keys {
		keyMap[k.Provider] = k.Value
	}
	writeSubfinderConfig(keyMap)
	writeUncoverConfig(keyMap)
	env := map[string]string{}
	for provider, value := range keyMap {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		for i, envVar := range providerEnvMap[provider] {
			if provider == "censys" {
				id, secret, _ := strings.Cut(value, ":")
				env["CENSYS_API_ID"] = id
				env["CENSYS_API_SECRET"] = secret
				break
			}
			_ = i
			env[envVar] = value
		}
	}
	return env
}

func writeSubfinderConfig(keyMap map[string]string) {
	cfg := map[string][]string{}
	for p, v := range keyMap {
		if subfinderSkip[p] {
			continue
		}
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		key := p
		if k, ok := subfinderKeyMap[p]; ok {
			key = k
		}
		if p == "intelx" && !strings.Contains(v, ":") {
			v = "2.intelx.io:" + v
		}
		cfg[key] = []string{v}
	}
	writeProviderYAML(filepath.Join(homeDir(), ".config", "subfinder", "provider-config.yaml"), cfg)
}

func writeUncoverConfig(keyMap map[string]string) {
	cfg := map[string][]string{}
	for provider, uncoverKey := range uncoverProviders {
		if v := strings.TrimSpace(keyMap[provider]); v != "" {
			cfg[uncoverKey] = []string{v}
		}
	}
	writeProviderYAML(filepath.Join(homeDir(), ".config", "uncover", "provider-config.yaml"), cfg)
}

func writeProviderYAML(path string, cfg map[string][]string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	var b strings.Builder
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		b.WriteString(k + ":\n")
		for _, v := range cfg[k] {
			b.WriteString("  - " + v + "\n")
		}
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}

func homeDir() string {
	// subfinder/uncover and the workflow's setup/uncover steps read ~/.config
	// (hardcoded /root when run as root). Fall back to /root — NOT "." — so the
	// provider configs we write land where those tools actually read them, even
	// if $HOME is unset. (boot.go also sets $HOME process-wide as the primary fix.)
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "/root"
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

var runIDCounter int64

func newRunID() string {
	// uuid4().hex[:12] equivalent: random hex
	b := make([]byte, 6)
	if _, err := crand.Read(b); err != nil {
		return fmt.Sprintf("%012x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
