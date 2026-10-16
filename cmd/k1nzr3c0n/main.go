// k1nzr3c0n is a single-binary rewrite of the Python FastAPI+Celery stack:
// `serve` runs the API server + embedded worker pool + cron scheduler; the
// other subcommands mirror the Python CLI (run/validate/plan/list).
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"k1nzr3c0n/internal/agent"
	"k1nzr3c0n/internal/api"
	"k1nzr3c0n/internal/bus"
	"k1nzr3c0n/internal/capture"
	"k1nzr3c0n/internal/config"
	"k1nzr3c0n/internal/notify"
	"k1nzr3c0n/internal/runner"
	"k1nzr3c0n/internal/schedule"
	"k1nzr3c0n/internal/store"
	"k1nzr3c0n/internal/workflow"
)

func main() {
	if len(os.Args) < 2 {
		serve()
		return
	}
	switch os.Args[1] {
	case "serve":
		serve()
	case "run":
		cmdRun(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	case "plan":
		cmdPlan(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "version":
		fmt.Println("k1nzr3c0n-go 3.0.0")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (serve|run|validate|plan|list)\n", os.Args[1])
		os.Exit(2)
	}
}

func serve() {
	st, err := store.Open(config.DBPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "[x] open db:", err)
		os.Exit(1)
	}
	b := bus.New()
	r := runner.New(st, b)
	r.Start(config.WorkerConcurrency())

	// recording proxy (traffic capture) — nil-safe when CA generation fails
	cap, capErr := capture.New(st, config.BaseDir())
	if capErr != nil {
		fmt.Fprintln(os.Stderr, "[!] capture proxy unavailable:", capErr)
	}
	r.ProxyEnv = func(runID string) map[string]string {
		if cap == nil || !cap.Enabled() {
			return nil
		}
		addr := cap.Addr
		// run id rides in the proxy userinfo (Proxy-Authorization) so
		// concurrent runs tag their traffic correctly
		p := "http://" + runID + "@" + addr
		return map[string]string{
			"HTTP_PROXY":  p,
			"HTTPS_PROXY": p,
			"http_proxy":  p,
			"https_proxy": p,
			"NO_PROXY":    "localhost,127.0.0.1",
		}
	}

	agent.SeedAgentRules(st)
	notify.DBWebhookURL = func() string { return st.GetNotifySettings().WebhookURL }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	schedule.Start(ctx, st, r)

	srv := api.New(st, b, r)
	srv.Cap = cap
	addr := config.HTTPAddr()
	fmt.Printf("[+] k1nzr3c0n-go listening on %s (base=%s workers=%d)\n",
		addr, config.BaseDir(), config.WorkerConcurrency())
	if err := listenAndServe(addr, srv.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, "[x]", err)
		os.Exit(1)
	}
}

// ── CLI commands (parity with cli.py) ────────────────────────────────────────

func cmdRun(args []string) {
	fs := newFlagSet()
	wf := fsString(fs, "w", "workflow", "", "workflow YAML (required)")
	target := fsString(fs, "t", "target", "", "scan target (required)")
	out := fsString(fs, "o", "out", "", "output workspace")
	planOnly := fsBool(fs, "", "plan", false, "print commands only")
	cont := fsBool(fs, "", "continue-on-error", false, "keep running after failures")
	vars := fsVarList(fs, "vars", "KEY=VALUE overrides (repeatable)")
	resume := fsBool(fs, "", "resume", false, "resume previous run")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *wf == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: k1nzr3c0n run -w workflow.yaml -t target [--plan] [--vars k=v]")
		os.Exit(2)
	}
	w, err := workflow.Load(*wf)
	exitOnWorkflowError(err)
	overrides := map[string]string{}
	for _, kv := range *vars {
		m, err := workflow.ParseVarOverrides([]string{kv})
		exitOnWorkflowError(err)
		for k, v := range m {
			overrides[k] = v
		}
	}
	ev := &cliEvents{}
	err = workflow.RunWorkflow(w, workflow.Options{
		Target:          *target,
		Workspace:       *out,
		Vars:            workflow.VarsMerge(w.Vars, overrides),
		ContinueOnError: *cont,
		Resume:          *resume,
		PrintPlan:       *planOnly,
	}, ev)
	if err != nil {
		if werr, ok := err.(*workflow.WorkflowError); ok {
			if werr == workflow.ErrPaused {
				os.Exit(workflow.PauseExitCode)
			}
			fmt.Fprintln(os.Stderr, "[x]", werr.Msg)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "[x]", err)
		os.Exit(2)
	}
}

func cmdValidate(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: k1nzr3c0n validate workflow.yaml")
		os.Exit(2)
	}
	w, err := workflow.Load(args[0])
	exitOnWorkflowError(err)
	levels, err := workflow.ExecutionLevels(w.Steps)
	exitOnWorkflowError(err)
	fmt.Printf("[+] %s — OK (%d steps)\n", w.Name, len(w.Steps))
	var names []string
	for k := range w.Vars {
		names = append(names, k)
	}
	sort.Strings(names)
	fmt.Println("vars:", strings.Join(names, ", "))
	maxPar := 0
	for _, l := range levels {
		if len(l) > maxPar {
			maxPar = len(l)
		}
	}
	fmt.Printf("Levels: %d (max parallelism: %d)\n", len(levels), maxPar)
}

func cmdPlan(args []string) {
	fs := newFlagSet()
	wf := fsString(fs, "w", "workflow", "", "workflow YAML (required)")
	target := fsString(fs, "t", "target", "", "target (required)")
	vars := fsVarList(fs, "vars", "KEY=VALUE overrides")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *wf == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: k1nzr3c0n plan -w workflow.yaml -t target")
		os.Exit(2)
	}
	w, err := workflow.Load(*wf)
	exitOnWorkflowError(err)
	overrides := map[string]string{}
	for _, kv := range *vars {
		m, _ := workflow.ParseVarOverrides([]string{kv})
		for k, v := range m {
			overrides[k] = v
		}
	}
	merged := workflow.VarsMerge(w.Vars, overrides)
	fmt.Printf("[+] %s — plan for target %s\n", w.Name, *target)
	levels, _ := workflow.ExecutionLevels(w.Steps)
	for i, level := range levels {
		mode := "sequential"
		if len(level) > 1 {
			mode = fmt.Sprintf("%d parallel", len(level))
		}
		fmt.Printf("Level %d (%s)\n", i, mode)
		for _, st := range level {
			fmt.Printf("  %s: %s\n", st.ID, planRender(st, merged, *target))
		}
	}
}

func planRender(st *workflow.Step, vars map[string]string, target string) string {
	ctx := map[string]any{
		"target": target, "workspace": "<workspace>", "timestamp": "<timestamp>",
		"steps": map[string]any{}, "status": map[string]any{},
	}
	for k, v := range vars {
		ctx[k] = v
	}
	ctx["vars"] = toAnyMap(vars)
	if st.Run != nil {
		if cmd, err := workflow.RenderTemplate(*st.Run, ctx, true); err == nil {
			return cmd
		}
		return *st.Run
	}
	if len(st.Fanout) > 0 {
		return fmt.Sprintf("(fanout × %d)", len(st.Fanout))
	}
	return ""
}

func toAnyMap(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cmdList(args []string) {
	dir := "workflows"
	if len(args) > 1 && (args[0] == "-d" || args[0] == "--dir") {
		dir = args[1]
	}
	entries, err := filepath.Glob(filepath.Join(dir, "**", "*.yaml"))
	if err != nil || len(entries) == 0 {
		entries, _ = filepath.Glob(filepath.Join(dir, "*.yaml"))
	}
	if len(entries) == 0 {
		if _, err := os.Stat(dir); err != nil {
			fmt.Fprintln(os.Stderr, "[x] workflows dir not found:", dir)
			os.Exit(2)
		}
	}
	for _, e := range entries {
		if w, err := workflow.Load(e); err != nil {
			fmt.Printf("[!] %s: %v\n", e, err)
		} else {
			var names []string
			for k := range w.Vars {
				names = append(names, k)
			}
			sort.Strings(names)
			fmt.Printf("%s (%d steps)  vars: %s\n", e, len(w.Steps), strings.Join(names, ", "))
		}
	}
}

func exitOnWorkflowError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "[x]", err.Error())
	os.Exit(2)
}

// cliEvents prints the exact Python CLI format, including ##K1Z markers.
type cliEvents struct{}

func (cliEvents) Info(msg string)     { fmt.Println("[+] " + msg) }
func (cliEvents) Warn(msg string)     { fmt.Println("[!] " + msg) }
func (cliEvents) Line(l, s string)    { fmt.Printf("[%s] %s\n", l, s) }
func (cliEvents) StepStart(id string) { fmt.Printf("##K1Z:START:%s##\n", id) }
func (cliEvents) StepDone(id string)  { fmt.Printf("##K1Z:DONE:%s##\n", id) }
func (cliEvents) StepFail(id string)  { fmt.Printf("##K1Z:FAIL:%s##\n", id) }
func (cliEvents) StepSkip(id string)  { fmt.Printf("##K1Z:SKIP:%s##\n", id) }
func (cliEvents) StepTime(id string, ms int64) {
	fmt.Printf("##K1Z:TIME:%s:%d##\n", id, ms)
}
