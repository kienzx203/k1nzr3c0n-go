package workflow

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Events receives engine output. The server runner implements it to update
// steps_json, stream logs, and persist them; the CLI prints the exact Python
// format (including ##K1Z markers) so downstream parsing is unchanged.
type Events interface {
	Info(msg string) // "[+] msg"
	Warn(msg string) // "[!] msg"
	Line(label, line string)
	StepStart(id string)
	StepDone(id string)
	StepFail(id string)
	StepSkip(id string)
	StepTime(id string, ms int64)
}

// NoopEvents discards everything.
type NoopEvents struct{}

func (NoopEvents) Info(string)            {}
func (NoopEvents) Warn(string)            {}
func (NoopEvents) Line(_, _ string)       {}
func (NoopEvents) StepStart(string)       {}
func (NoopEvents) StepDone(string)        {}
func (NoopEvents) StepFail(string)        {}
func (NoopEvents) StepSkip(string)        {}
func (NoopEvents) StepTime(string, int64) {}

// Options controls one run_workflow invocation.
type Options struct {
	Target          string
	Workspace       string
	Vars            map[string]string // merged (defaults + overrides)
	ContinueOnError bool
	Resume          bool
	PrintPlan       bool
	MaxParallel     int // from workflow; override via Options if > 0

	// EnvOverlay layers per-run environment variables (API keys) over the
	// inherited environment WITHOUT mutating the process env — safe for
	// concurrent runs in one process.
	EnvOverlay map[string]string
}

// ── resume.json ──────────────────────────────────────────────────────────────

type resumeEntry struct {
	Status    string            `json:"status"`
	Outputs   map[string]string `json:"outputs"`
	Skipped   bool              `json:"skipped"`
	UpdatedAt string            `json:"updated_at"`
	Message   *string           `json:"message"`
}

type resumeFile struct {
	Steps map[string]*resumeEntry `json:"steps"`
}

// ── engine ───────────────────────────────────────────────────────────────────

type engine struct {
	opt       Options
	wf        *Workflow
	ev        Events
	workspace string

	ctxMu  sync.Mutex
	ctx    map[string]any
	status map[string]string

	resumeMu sync.Mutex
	resume   *resumeFile

	procsMu sync.Mutex
	procs   map[string]*exec.Cmd

	cancelled   atomic.Bool
	pauseSeen   atomic.Bool
	toolMissing atomic.Bool
}

// Handle exposes control over a running workflow (cancel support for hosts).
type Handle struct {
	KillAll func()
}

// RunWorkflowWithHandle runs the workflow and passes the engine handle to onReady
// before execution begins, so the host can cancel it (API cancel path).
func RunWorkflowWithHandle(wf *Workflow, opt Options, ev Events, onReady func(Handle)) error {
	if opt.Resume && opt.Workspace == "" {
		return werrf("--resume requires --out pointing at an existing workspace")
	}
	if opt.MaxParallel > 0 {
		wf.MaxParallel = opt.MaxParallel
	}
	if opt.Workspace == "" {
		ts := time.Now().Format("20060102-150405")
		opt.Workspace = filepath.Join("runs", SafeTarget(opt.Target), ts)
	}
	ws, err := filepath.Abs(opt.Workspace)
	if err != nil {
		ws = opt.Workspace
	}
	if err := os.MkdirAll(ws, 0o755); err != nil {
		return werrf("create workspace: %v", err)
	}
	e := &engine{
		opt:       opt,
		wf:        wf,
		ev:        ev,
		workspace: ws,
		procs:     map[string]*exec.Cmd{},
	}
	if onReady != nil {
		onReady(Handle{KillAll: e.KillAll})
	}
	return e.run()
}

// RunWorkflow executes the whole workflow. Returns nil, ErrPaused,
// ErrCancelled, or a *WorkflowError.
func RunWorkflow(wf *Workflow, opt Options, ev Events) error {
	return RunWorkflowWithHandle(wf, opt, ev, nil)
}

func (e *engine) run() error {
	wf, opt, ev, ws := e.wf, e.opt, e.ev, e.workspace
	vars := map[string]any{}
	for k, v := range opt.Vars {
		vars[k] = v
	}
	e.ctx = map[string]any{
		"target":    opt.Target,
		"workspace": ws,
		"timestamp": time.Now().Format("20060102-150405"),
		"steps":     map[string]any{},
		"status":    map[string]any{},
	}
	for k, v := range vars { // flattened access
		e.ctx[k] = v
	}
	e.ctx["vars"] = vars
	e.status = map[string]string{}
	e.resume = &resumeFile{Steps: map[string]*resumeEntry{}}
	if opt.Resume {
		e.loadResume()
	}

	levels, err := ExecutionLevels(wf.Steps)
	if err != nil {
		return err
	}
	startedAt := time.Now()

	for _, level := range levels {
		var failed []string
		if len(level) == 1 {
			st := level[0]
			if err := e.executeStep(st); err != nil {
				return err
			}
			if e.statusOf(st.ID) == "failed" {
				if !opt.ContinueOnError {
					return werrf("Step failed: '%s'", st.ID)
				}
				failed = append(failed, st.ID)
			}
		} else {
			ids := make([]string, len(level))
			for i, s := range level {
				ids[i] = s.ID
			}
			if wf.MaxParallel > 0 && len(level) > wf.MaxParallel {
				ev.Info(fmt.Sprintf("Parallel (%d) — max %d concurrent: %s", len(level), wf.MaxParallel, strings.Join(ids, ", ")))
			} else {
				ev.Info(fmt.Sprintf("Parallel (%d): %s", len(level), strings.Join(ids, ", ")))
			}
			workers := len(level)
			if wf.MaxParallel > 0 && wf.MaxParallel < workers {
				workers = wf.MaxParallel
			}
			sem := make(chan struct{}, workers)
			var wg sync.WaitGroup
			var fmu sync.Mutex
			for _, st := range level {
				wg.Add(1)
				go func(st *Step) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					defer func() {
						if r := recover(); r != nil {
							e.ev.Warn(fmt.Sprintf("Step '%s' crashed: %v", st.ID, r))
							e.setStatus(st.ID, "failed")
						}
					}()
					if err := e.executeStep(st); err != nil {
						e.ev.Warn(fmt.Sprintf("Step '%s' internal error: %v", st.ID, err))
						e.setStatus(st.ID, "failed")
					}
					if e.statusOf(st.ID) == "failed" {
						fmu.Lock()
						failed = append(failed, st.ID)
						fmu.Unlock()
					}
				}(st)
			}
			wg.Wait()
		}
		// pause is honored only after a level completes (Python checks
		// between levels, including after the final one)
		if !opt.PrintPlan {
			if flagExists(ws, "pause.flag") {
				e.pauseSeen.Store(true)
				ev.Info("[PAUSED] Pause flag detected — checkpointing. Use Resume to continue.")
				return ErrPaused
			}
			if e.cancelled.Load() || flagExists(ws, "cancel.flag") {
				e.cancelled.Store(true)
				return ErrCancelled
			}
		}
		if len(failed) > 0 && !opt.ContinueOnError {
			return werrf("Steps failed: %s", strings.Join(failed, ", "))
		}
		if e.cancelled.Load() {
			return ErrCancelled
		}
	}
	ev.Info(fmt.Sprintf("Workspace: %s", ws))
	ev.Info(fmt.Sprintf("Done in %.1fs.", time.Since(startedAt).Seconds()))
	return nil
}

// ── step execution ───────────────────────────────────────────────────────────

func (e *engine) setStatus(id, st string) {
	e.ctxMu.Lock()
	e.status[id] = st
	m := e.ctx["status"].(map[string]any)
	m[id] = st
	e.ctxMu.Unlock()
}

func (e *engine) setStepOutputs(id string, outputs map[string]string) {
	e.ctxMu.Lock()
	defer e.ctxMu.Unlock()
	steps := e.ctx["steps"].(map[string]any)
	container := steps
	for _, part := range strings.Split(id, ".") {
		next, ok := container[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			container[part] = next
		}
		container = next
	}
	for k, v := range outputs {
		container[k] = v
	}
}

func (e *engine) executeStep(st *Step) error {
	// 1. failed deps
	if !st.RunOnFailedDeps {
		var failedDeps []string
		for _, d := range st.DependsOn {
			if s := e.statusOf(d); s == "failed" || s == "skipped" {
				failedDeps = append(failedDeps, d)
			}
		}
		if len(failedDeps) > 0 {
			e.ev.Warn(fmt.Sprintf("Skipping '%s' (failed deps: %s)", st.ID, strings.Join(failedDeps, ", ")))
			e.setStatus(st.ID, "skipped")
			e.ev.StepSkip(st.ID)
			return nil
		}
	}
	// 2. when
	if st.When != nil && !EvalWhen(*st.When, e.snapshotCtx()) {
		e.ev.Info(fmt.Sprintf("Skipping '%s' (when condition is false: '%s')", st.ID, *st.When))
		e.setStatus(st.ID, "skipped")
		e.ev.StepSkip(st.ID)
		return nil
	}
	if st.Name != "" && st.Name != st.ID {
		e.ev.Info(fmt.Sprintf("Step: %s — %s", st.ID, st.Name))
	} else {
		e.ev.Info(fmt.Sprintf("Step: %s", st.ID))
	}
	e.ev.StepStart(st.ID)
	start := time.Now()

	var outputs map[string]string
	var runCmd string
	if st.Run != nil {
		rendered, err := RenderTemplate(*st.Run, e.snapshotCtx(), false)
		if err != nil {
			e.setStatus(st.ID, "failed")
			e.recordResume(st.ID, "failed", nil, false, strp(err.Error()))
			e.ev.StepFail(st.ID)
			return nil
		}
		runCmd = rendered
		outputs, err = e.renderOutputs(st.Outputs)
		if err != nil {
			e.setStatus(st.ID, "failed")
			e.recordResume(st.ID, "failed", nil, false, strp(err.Error()))
			e.ev.StepFail(st.ID)
			return nil
		}
	} else if st.Fanout != nil {
		outputs = map[string]string{}
	}

	// 6. resume / skip_if_exists short-circuit (never applies to fanout steps)
	if st.Fanout == nil && (e.resumeStepOK(st.ID) || st.SkipIfExists) {
		paths := st.Requires
		if len(paths) == 0 {
			for _, p := range outputs {
				paths = append(paths, Require{Path: p, MinBytes: 1}) // non-empty required
			}
		}
		if e.requirementsMet(paths) { // vacuously true when no paths (parity)
			if e.resumeStepOK(st.ID) {
				e.ev.Warn(fmt.Sprintf("Skipping '%s' (already completed)", st.ID))
			}
			e.setStepOutputs(st.ID, outputs)
			e.setStatus(st.ID, "ok")
			e.recordResume(st.ID, "ok", outputs, true, nil)
			e.ev.StepDone(st.ID)
			e.ev.StepTime(st.ID, msSince(start))
			return nil
		}
	}

	// 7. plan mode
	if e.opt.PrintPlan {
		if st.Run != nil {
			e.ev.Info(fmt.Sprintf("%s: %s", st.ID, runCmd))
		}
		for _, c := range st.Fanout {
			if cmd, err := RenderTemplate(c.Run, e.snapshotCtx(), true); err == nil {
				e.ev.Info(fmt.Sprintf("%s.%s: %s", st.ID, c.ID, cmd))
			}
		}
		e.setStatus(st.ID, "planned")
		e.ev.StepDone(st.ID)
		return nil
	}

	if st.Fanout != nil {
		switch e.executeFanout(st) {
		case "failed":
			e.setStatus(st.ID, "failed")
			e.recordResume(st.ID, "failed", outputs, false, strp("fanout child failed"))
			e.ev.StepFail(st.ID)
			e.ev.StepTime(st.ID, msSince(start))
			return nil
		case "skipped":
			e.setStatus(st.ID, "skipped")
			e.recordResume(st.ID, "skipped", nil, false, strp("all children skipped"))
			e.ev.StepSkip(st.ID)
			e.ev.StepTime(st.ID, msSince(start))
			return nil
		}
		e.setStatus(st.ID, "ok")
		e.recordResume(st.ID, "ok", outputs, false, nil)
		e.setStepOutputs(st.ID, outputs)
		e.ev.StepDone(st.ID)
		e.ev.StepTime(st.ID, msSince(start))
		return nil
	}
	var ok bool
	{
		// 9. record running
		e.recordResume(st.ID, "running", nil, false, nil)
		ok = e.runCommand(st.ID, runCmd, st.Shell, st.Timeout, st.Retries, st.Env, st.Cwd, "")
		e.setStepOutputs(st.ID, outputs)
		// 12. requires
		if ok && len(st.Requires) > 0 {
			if !e.requirementsMetQuiet(st.Requires) {
				ok = false
				e.ev.Warn(fmt.Sprintf("[%s] Required output(s) missing after success", st.ID))
			}
		}
	}
	// 13. optional downgrade
	if !ok && st.Optional {
		ok = true
		e.ev.Warn(fmt.Sprintf("Step '%s' failed but is optional, continuing.", st.ID))
	}
	if ok {
		e.setStatus(st.ID, "ok")
		e.recordResume(st.ID, "ok", outputs, false, nil)
		e.ev.StepDone(st.ID)
	} else {
		e.setStatus(st.ID, "failed")
		e.recordResume(st.ID, "failed", outputs, false, strp("exit non-zero"))
		e.ev.Warn(fmt.Sprintf("[%s] Step failed", st.ID))
		e.ev.StepFail(st.ID)
	}
	e.ev.StepTime(st.ID, msSince(start))
	return nil
}

// executeFanout returns the parent status: "ok" | "failed" | "skipped".
func (e *engine) executeFanout(st *Step) string {
	type task struct {
		child   *Child
		label   string
		run     string
		env     map[string]string
		cwd     *string
		timeout *Timeout
		outputs map[string]string
	}
	completed := 0
	resolveFailed := false
	var tasks []*task
	for _, c := range st.Fanout {
		label := st.ID + "." + c.ID
		if c.When != nil && !EvalWhen(*c.When, e.snapshotCtx()) {
			// B4: when-skipped children still publish outputs (Python parity)
			if outs, err := e.renderOutputs(c.Outputs); err == nil {
				e.setStepOutputs(label, outs)
			}
			e.ev.Info(fmt.Sprintf("Skipping %s (when condition false)", label))
			e.setStatus(label, "skipped")
			continue
		}
		outs, err := e.renderOutputs(c.Outputs)
		if err != nil {
			e.ev.Warn(fmt.Sprintf("[%s] %v", label, err))
			e.setStatus(label, "failed")
			e.recordResume(label, "failed", nil, false, strp(err.Error()))
			resolveFailed = true // B2: render errors fail the parent
			continue
		}
		if e.resumeStepOK(label) || c.SkipIfExists {
			paths := c.Requires
			if len(paths) == 0 {
				for _, p := range outs {
					paths = append(paths, Require{Path: p, MinBytes: 1})
				}
			}
			if e.requirementsMet(paths) {
				e.ev.Warn(fmt.Sprintf("Skipping %s (already completed)", label))
				e.setStepOutputs(label, outs)
				e.setStatus(label, "ok")
				e.recordResume(label, "ok", outs, true, nil)
				completed++
				continue
			}
		}
		run, err := RenderTemplate(c.Run, e.snapshotCtx(), false)
		if err != nil {
			e.ev.Warn(fmt.Sprintf("[%s] %v", label, err))
			e.setStatus(label, "failed")
			e.recordResume(label, "failed", nil, false, strp(err.Error()))
			resolveFailed = true
			continue
		}
		t := &task{child: c, label: label, run: run, env: c.Env, cwd: c.Cwd, outputs: outs}
		if c.Timeout != nil {
			t.timeout = c.Timeout
		} else {
			t.timeout = st.FanoutTimeoutDefault
		}
		tasks = append(tasks, t)
	}
	if len(tasks) == 0 {
		if resolveFailed {
			return "failed"
		}
		if completed > 0 {
			return "ok"
		}
		return "skipped" // B1: all children skipped → parent skips
	}
	for _, t := range tasks {
		e.recordResume(t.label, "running", nil, false, nil)
	}
	workers := st.FanoutConcurrency
	if workers <= 0 {
		workers = min(len(tasks), 4)
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var fmu sync.Mutex
	anyFailed := false
	for _, t := range tasks {
		wg.Add(1)
		go func(t *task) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok := e.runCommand(t.label, t.run, t.child.Shell, t.timeout, t.child.Retries, t.env, t.cwd, "")
			if ok && len(t.child.Requires) > 0 && !e.requirementsMetQuiet(t.child.Requires) {
				ok = false
			}
			if !ok && t.child.Optional {
				ok = true
				e.ev.Warn(fmt.Sprintf("[%s] failed but is optional, continuing.", t.label))
			}
			e.setStepOutputs(t.label, t.outputs)
			if ok {
				e.setStatus(t.label, "ok")
				e.recordResume(t.label, "ok", t.outputs, false, nil)
			} else {
				e.setStatus(t.label, "failed")
				e.recordResume(t.label, "failed", t.outputs, false, strp("exit non-zero"))
				fmu.Lock()
				anyFailed = true
				fmu.Unlock()
			}
		}(t)
	}
	wg.Wait()
	if anyFailed || resolveFailed {
		return "failed"
	}
	return "ok"
}

// ── command runner ───────────────────────────────────────────────────────────

// runCommand mirrors _run_command: process-group execution, line streaming,
// timeout kill (TERM→KILL), retries with 1s sleep, cancel-flag polling.
func (e *engine) runCommand(label, command string, useShell bool, timeout *Timeout, retries int, env map[string]string, cwd *string, stdin string) bool {
	attempts := retries + 1
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		e.ev.Info(fmt.Sprintf("[%s] (%d/%d) %s", label, attempt, attempts, command))
		if attempt > 1 {
			// the retry pause is visible in timing; banner above carries the count
		}
		if e.cancelled.Load() || flagExists(e.workspace, "cancel.flag") {
			e.cancelled.Store(true)
			return false
		}
		ok := e.runOnce(label, command, useShell, timeout, env, cwd, stdin)
		if ok {
			return true
		}
		if e.cancelled.Load() || e.toolMissing.Load() {
			return false // missing tools are not retried (Python parity)
		}
		if attempt < attempts {
			time.Sleep(time.Second)
		}
	}
	return false
}

func (e *engine) runOnce(label, command string, useShell bool, timeout *Timeout, stepEnv map[string]string, cwdT *string, stdin string) bool {
	start := time.Now()
	var cmd *exec.Cmd
	scriptPath := ""
	cleanup := func() {}
	defer cleanup()

	sysExec := func(name string, args ...string) {
		cmd = exec.Command(name, args...)
	}

	// resolve cwd
	cwd := e.workspace
	if cwdT != nil {
		rendered, err := RenderTemplate(*cwdT, e.snapshotCtx(), false)
		if err == nil && rendered != "" {
			if filepath.IsAbs(rendered) {
				cwd = rendered
			} else {
				cwd = filepath.Join(e.workspace, rendered)
			}
		}
	}
	_ = os.MkdirAll(cwd, 0o755)

	if useShell {
		trimmed := strings.TrimSpace(command)
		if strings.Contains(command, "\n") {
			f, err := os.CreateTemp("", "k1z_*.sh")
			if err != nil {
				e.ev.Warn(fmt.Sprintf("[%s] Failed to create temp script: %v", label, err))
				return false
			}
			scriptPath = f.Name()
			f.WriteString("#!/bin/bash\n" + command + "\n")
			f.Close()
			os.Chmod(scriptPath, 0o755)
			sysExec(scriptPath)
			cleanup = func() { os.Remove(scriptPath) }
		} else {
			sysExec("/bin/sh", "-c", trimmed)
		}
	} else {
		args, err := shlexSplit(command)
		if err != nil {
			e.ev.Warn(fmt.Sprintf("[%s] Cannot parse command: %v", label, err))
			return false
		}
		if len(args) == 0 {
			e.ev.Warn(fmt.Sprintf("[%s] Empty command", label))
			return false
		}
		if _, err := exec.LookPath(args[0]); err != nil {
			e.ev.Warn(fmt.Sprintf("[%s] Tool not found: %s", label, args[0]))
			e.toolMissing.Store(true)
			return false
		}
		sysExec(args[0], args[1:]...)
	}

	// environment: inherited + per-run overlay + step env
	envMap := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		envMap[k] = v
	}
	for k, v := range e.opt.EnvOverlay {
		envMap[k] = v // DB keys override env (single source of truth)
	}
	for k, tpl := range stepEnv {
		if rendered, err := RenderTemplate(tpl, e.snapshotCtx(), true); err == nil {
			envMap[k] = rendered
		} else {
			envMap[k] = tpl
		}
	}
	finalEnv := make([]string, 0, len(envMap))
	for k, v := range envMap {
		finalEnv = append(finalEnv, k+"="+v)
	}
	cmd.Env = finalEnv
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // own process group

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.ev.Warn(fmt.Sprintf("[%s] pipe: %v", label, err))
		return false
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		e.ev.Warn(fmt.Sprintf("[%s] Failed to start: %v", label, err))
		return false
	}
	e.registerProc(label, cmd)
	defer e.unregisterProc(label)

	var deadline time.Time
	if timeout != nil {
		deadline = start.Add(time.Duration(timeout.Seconds * float64(time.Second)))
	}

	lines := make(chan string, 256)
	readerDone := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(readerDone)
	}()

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	timedOut := false
	cancelled := false
readLoop:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break readLoop
			}
			e.ev.Line(label, line)
		case <-readerDone:
			// drain remaining
			for {
				select {
				case line := <-lines:
					e.ev.Line(label, line)
				default:
					break readLoop
				}
			}
		case <-tick.C:
			if !deadline.IsZero() && time.Now().After(deadline) {
				timedOut = true
				e.killProc(cmd)
				break readLoop
			}
			if e.cancelled.Load() || flagExists(e.workspace, "cancel.flag") {
				e.cancelled.Store(true)
				cancelled = true
				e.killProc(cmd)
				break readLoop
			}
		}
	}
	_ = stdout.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waitTimeout := time.NewTimer(10 * time.Second)
	var waitErr error
	select {
	case waitErr = <-done:
	case <-waitTimeout.C:
		e.killProc(cmd)
		waitErr = <-done
	}
	waitTimeout.Stop()

	elapsed := time.Since(start).Seconds()
	if cancelled {
		e.ev.Warn(fmt.Sprintf("[%s] Cancelled", label))
		return false
	}
	if timedOut {
		e.ev.Warn(fmt.Sprintf("[%s] Timed out after %.0fs", label, timeout.Seconds))
		return false
	}
	rc := 0
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			rc = -1
		}
	}
	if rc == 0 {
		e.ev.Info(fmt.Sprintf("[%s] Done (%.1fs)", label, elapsed))
		return true
	}
	e.ev.Warn(fmt.Sprintf("[%s] Exit code %d (%.1fs)", label, rc, elapsed))
	return false
}

func (e *engine) registerProc(label string, cmd *exec.Cmd) {
	e.procsMu.Lock()
	e.procs[label] = cmd
	e.procsMu.Unlock()
}

func (e *engine) unregisterProc(label string) {
	e.procsMu.Lock()
	delete(e.procs, label)
	e.procsMu.Unlock()
}

func (e *engine) killProc(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid := -cmd.Process.Pid
	if err := syscall.Kill(pgid, syscall.SIGTERM); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	// Wait up to 5s for the group to die; liveness via Signal(0) because
	// ProcessState is only set by Wait() (which the caller still owns).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if err := syscall.Kill(pgid, syscall.Signal(0)); err != nil {
			return // group leader gone
		}
	}
	if err := syscall.Kill(pgid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}

// KillAll terminates every running command (used by the API cancel path).
func (e *engine) KillAll() {
	e.cancelled.Store(true)
	e.procsMu.Lock()
	defer e.procsMu.Unlock()
	for _, cmd := range e.procs {
		e.killProc(cmd)
	}
}

// Cancelled reports whether the cancel flag was seen.
func (e *engine) Cancelled() bool { return e.cancelled.Load() }

// ── outputs / requires / resume helpers ──────────────────────────────────────

// snapshotCtx returns a deep-enough copy for lock-free template rendering:
// top-level scalars plus copied steps/status containers (nested step maps are
// written only under ctxMu before a level starts, so copying the containers
// here is race-free).
func (e *engine) snapshotCtx() map[string]any {
	e.ctxMu.Lock()
	defer e.ctxMu.Unlock()
	out := make(map[string]any, len(e.ctx))
	for k, v := range e.ctx {
		switch t := v.(type) {
		case map[string]any:
			cp := make(map[string]any, len(t))
			for k2, v2 := range t {
				cp[k2] = v2
			}
			out[k] = cp
		default:
			out[k] = v
		}
	}
	return out
}

// statusOf reads a step status under lock (parallel levels read siblings).
func (e *engine) statusOf(id string) string {
	e.ctxMu.Lock()
	defer e.ctxMu.Unlock()
	return e.status[id]
}

func (e *engine) renderOutputs(outs map[string]string) (map[string]string, error) {
	if outs == nil {
		return map[string]string{}, nil
	}
	rendered := map[string]string{}
	for k, tpl := range outs {
		v, err := RenderTemplate(tpl, e.snapshotCtx(), false)
		if err != nil {
			return nil, err
		}
		rendered[k] = v
	}
	return rendered, nil
}

func (e *engine) requirementsMet(reqs []Require) bool      { return e.checkRequires(reqs, false) }
func (e *engine) requirementsMetQuiet(reqs []Require) bool { return e.checkRequires(reqs, true) }

func (e *engine) checkRequires(reqs []Require, quiet bool) bool {
	for _, r := range reqs {
		path, err := RenderTemplate(r.Path, e.snapshotCtx(), false)
		if err != nil {
			return false
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(e.workspace, path)
		}
		fi, err := os.Stat(path)
		if err != nil {
			if !quiet {
				e.ev.Warn(fmt.Sprintf("Required path missing: %s", path))
			}
			return false
		}
		if fi.IsDir() {
			continue
		}
		if fi.Size() < r.MinBytes {
			if !quiet {
				e.ev.Warn(fmt.Sprintf("Required path too small (%d < %d): %s", fi.Size(), r.MinBytes, path))
			}
			return false
		}
	}
	return true
}

func (e *engine) resumeStepOK(id string) bool {
	if !e.opt.Resume {
		return false
	}
	e.resumeMu.Lock()
	defer e.resumeMu.Unlock()
	if ent, ok := e.resume.Steps[id]; ok {
		return ent.Status == "ok"
	}
	return false
}

func (e *engine) recordResume(id, status string, outputs map[string]string, skipped bool, msg *string) {
	if !e.opt.Resume {
		return // Python writes resume.json only with --resume
	}
	e.resumeMu.Lock()
	defer e.resumeMu.Unlock()
	ent, ok := e.resume.Steps[id]
	if !ok {
		ent = &resumeEntry{}
		e.resume.Steps[id] = ent
	}
	if status != "ok" || ent.Status != "running" || true {
		ent.Status = status
	}
	ent.Outputs = outputs
	ent.Skipped = skipped
	ent.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
	ent.Message = msg
	if outputs == nil {
		ent.Outputs = map[string]string{}
	}
	e.writeResume()
}

func (e *engine) loadResume() {
	data, err := os.ReadFile(filepath.Join(e.workspace, "resume.json"))
	if err != nil {
		return
	}
	var rf resumeFile
	if json.Unmarshal(data, &rf) == nil && rf.Steps != nil {
		e.resume = &rf
	}
}

func (e *engine) writeResume() {
	data, err := json.MarshalIndent(e.resume, "", "  ")
	if err != nil {
		return
	}
	tmp := filepath.Join(e.workspace, "resume.tmp")
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(e.workspace, "resume.json"))
	}
}

func flagExists(workspace, name string) bool {
	_, err := os.Stat(filepath.Join(workspace, name))
	return err == nil
}

func strp(s string) *string { return &s }

func msSince(t time.Time) int64 { return time.Since(t).Milliseconds() }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// shlexSplit is a POSIX-mode shlex replacement: handles single quotes, double
// quotes and backslash escapes outside quotes.
func shlexSplit(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	var hasToken bool
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if hasToken {
				args = append(args, cur.String())
				cur.Reset()
				hasToken = false
			}
			i++
		case c == '\\':
			if i+1 >= n {
				return nil, fmt.Errorf("No escaped character")
			}
			cur.WriteByte(s[i+1])
			hasToken = true
			i += 2
		case c == '\'':
			hasToken = true
			i++
			closed := false
			for i < n {
				if s[i] == '\'' {
					closed = true
					i++
					break
				}
				cur.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("No closing quotation")
			}
		case c == '"':
			hasToken = true
			i++
			closed := false
			for i < n {
				if s[i] == '"' {
					closed = true
					i++
					break
				}
				if s[i] == '\\' && i+1 < n && (s[i+1] == '"' || s[i+1] == '\\' || s[i+1] == '$' || s[i+1] == '`') {
					cur.WriteByte(s[i+1])
					i += 2
					continue
				}
				cur.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("No closing quotation")
			}
		default:
			cur.WriteByte(c)
			hasToken = true
			i++
		}
	}
	if hasToken {
		args = append(args, cur.String())
	}
	return args, nil
}

// FormatMS renders a millisecond count for the ##K1Z:TIME marker.
func FormatMS(ms int64) string { return strconv.FormatInt(ms, 10) }
