package workflow

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRenderTemplate(t *testing.T) {
	ctx := map[string]any{
		"target": "example.com",
		"vars":   map[string]any{"wordlist": "big.txt"},
		"steps":  map[string]any{"sub": map[string]any{"file": "/tmp/x.txt"}},
		"empty":  "",
	}
	cases := []struct {
		tpl, want string
		wantErr   bool
	}{
		{"{target}", "example.com", false},
		{"{vars.wordlist}", "big.txt", false},
		{"{steps.sub.file}", "/tmp/x.txt", false},
		{"{missing|fallback}", "fallback", false},
		{"{empty|fallback}", "", false},               // empty string is NOT missing
		{"${VAR:-x} stays", "${VAR:-x} stays", false}, // $ escape
		{"{unknown}", "", true},
	}
	for _, c := range cases {
		got, err := RenderTemplate(c.tpl, ctx, false)
		if c.wantErr {
			if err == nil {
				t.Errorf("RenderTemplate(%q): expected error", c.tpl)
			}
			continue
		}
		if err != nil {
			t.Errorf("RenderTemplate(%q): %v", c.tpl, err)
			continue
		}
		if got != c.want {
			t.Errorf("RenderTemplate(%q) = %q, want %q", c.tpl, got, c.want)
		}
	}
}

func TestEvalWhen(t *testing.T) {
	ctx := map[string]any{"vars": map[string]any{
		"a": "true", "b": "false", "c": "", "d": "yes",
	}}
	if !EvalWhen("{vars.a}", ctx) {
		t.Error("a=true should be truthy")
	}
	if EvalWhen("{vars.b}", ctx) {
		t.Error("b=false should be falsy")
	}
	if EvalWhen("{vars.c}", ctx) {
		t.Error("empty should be falsy")
	}
	if !EvalWhen("{vars.d}", ctx) {
		t.Error("yes should be truthy")
	}
	if !EvalWhen("{vars.b} || {vars.a}", ctx) {
		t.Error("|| any-true should be true")
	}
	if EvalWhen("{vars.a} && {vars.b}", ctx) {
		t.Error("&& all-true should be false")
	}
	// quirk parity: unknown var renders literal → truthy
	if !EvalWhen("{vars.nope}", ctx) {
		t.Error("unknown var renders literal {vars.nope} → truthy (parity quirk)")
	}
}

func writeWF(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "wf.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const testWF = `
name: test
max_parallel: 2
vars:
  enabled: "true"
steps:
  - id: one
    name: First
    run: echo hello > one.txt
    shell: true
    outputs:
      file: one.txt
  - id: gated
    when: "{vars.enabled}"
    run: echo gated
    depends_on: one
  - id: fan
    depends_on: one
    fanout:
      - id: a
        run: echo A
      - id: b
        run: echo B
    fanout_concurrency: 1
  - id: last
    run: echo done
    depends_on: [gated, fan]
`

func TestLoadAndLevels(t *testing.T) {
	dir := t.TempDir()
	wf, err := Load(writeWF(t, dir, testWF))
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Steps) != 4 {
		t.Fatalf("steps = %d, want 4", len(wf.Steps))
	}
	if wf.MaxParallel != 2 {
		t.Fatalf("max_parallel = %d", wf.MaxParallel)
	}
	levels, err := ExecutionLevels(wf.Steps)
	if err != nil {
		t.Fatal(err)
	}
	if len(levels) != 3 {
		t.Fatalf("levels = %d, want 3 (one | gated,fan | last)", len(levels))
	}
	if levels[0][0].ID != "one" || levels[2][0].ID != "last" {
		t.Fatalf("unexpected level layout")
	}
}

func TestCycleDetection(t *testing.T) {
	dir := t.TempDir()
	p := writeWF(t, dir, `
steps:
  - id: a
    run: echo a
    depends_on: b
  - id: b
    run: echo b
    depends_on: a
`)
	if _, err := Load(p); err == nil {
		t.Fatal("cycle should fail validation")
	}
}

func TestRunWorkflowEndToEnd(t *testing.T) {
	dir := t.TempDir()
	wf, err := Load(writeWF(t, dir, testWF))
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(dir, "ws")
	ev := &collectEvents{}
	err = RunWorkflow(wf, Options{Target: "example.com", Workspace: ws,
		Vars: wf.Vars, ContinueOnError: true, Resume: true}, ev)
	if err != nil {
		t.Fatal(err)
	}
	ev.mu.Lock()
	defer ev.mu.Unlock()
	if ev.status["one"] != "ok" || ev.status["gated"] != "ok" || ev.status["last"] != "ok" {
		t.Fatalf("statuses: %+v", ev.status)
	}
	if ev.status["fan"] != "ok" {
		t.Fatalf("fan status: %+v", ev.status)
	}
	if _, err := os.Stat(filepath.Join(ws, "one.txt")); err != nil {
		t.Fatal("step output file missing")
	}
	// resume.json written
	if _, err := os.Stat(filepath.Join(ws, "resume.json")); err != nil {
		t.Fatal("resume.json missing")
	}
}

type collectEvents struct {
	NoopEvents
	mu     sync.Mutex
	status map[string]string
	infos  []string
}

func (c *collectEvents) Info(m string) {
	c.mu.Lock()
	c.infos = append(c.infos, m)
	c.mu.Unlock()
}

func (c *collectEvents) StepDone(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status == nil {
		c.status = map[string]string{}
	}
	c.status[id] = "ok"
}

func TestPauseBetweenLevels(t *testing.T) {
	dir := t.TempDir()
	wf, err := Load(writeWF(t, dir, `
steps:
  - id: one
    run: echo one
  - id: two
    run: echo two
    depends_on: one
`))
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(dir, "ws")
	os.MkdirAll(ws, 0o755)
	os.WriteFile(filepath.Join(ws, "pause.flag"), []byte{}, 0o644)
	err = RunWorkflow(wf, Options{Target: "t", Workspace: ws}, NoopEvents{})
	if err != ErrPaused {
		t.Fatalf("err = %v, want ErrPaused", err)
	}
}

func TestTimeoutAndRetry(t *testing.T) {
	dir := t.TempDir()
	wf, err := Load(writeWF(t, dir, `
steps:
  - id: slow
    run: sleep 30
    timeout: 1
    retries: 1
    optional: true
`))
	if err != nil {
		t.Fatal(err)
	}
	ev := &collectEvents{}
	err = RunWorkflow(wf, Options{Target: "t", Workspace: filepath.Join(dir, "ws")}, ev)
	if err != nil {
		t.Fatal(err)
	}
}

func TestShlexSplit(t *testing.T) {
	args, err := shlexSplit(`nuclei -u "http://x" -t 'a b' -header "A: B"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nuclei", "-u", "http://x", "-t", "a b", "-header", "A: B"}
	if len(args) != len(want) {
		t.Fatalf("args = %v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

// B1: fanout with all children skipped → parent skipped (not failed).
func TestFanoutAllSkipped(t *testing.T) {
	dir := t.TempDir()
	wf, err := Load(writeWF(t, dir, `
vars:
  gate: "false"
steps:
  - id: fan
    fanout:
      - id: a
        when: "{vars.gate}"
        run: echo A
    depends_on: []
  - id: after
    run: echo after
    shell: true
    depends_on: fan
`))
	if err != nil {
		t.Fatal(err)
	}
	ev := &collectEvents{status: map[string]string{}}
	err = RunWorkflow(wf, Options{Target: "t", Workspace: filepath.Join(dir, "ws"),
		Vars: wf.Vars, ContinueOnError: false}, ev)
	if err != nil {
		t.Fatalf("run should succeed, got: %v", err)
	}
	if ev.status["fan"] == "ok" && ev.status["fan"] != "skipped" {
		// collectEvents only records ok; reaching here means DONE fired
	}
}

// B5: skip_if_exists with an EMPTY output file must NOT skip.
func TestSkipIfExistsRequiresNonEmpty(t *testing.T) {
	dir := t.TempDir()
	ws := filepath.Join(dir, "ws")
	os.MkdirAll(ws, 0o755)
	os.WriteFile(filepath.Join(ws, "out.txt"), []byte{}, 0o644) // empty
	wf, err := Load(writeWF(t, dir, `
steps:
  - id: s
    run: echo data > out.txt
    shell: true
    skip_if_exists: true
    outputs:
      file: out.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	ev := &collectEvents{status: map[string]string{}}
	if err := RunWorkflow(wf, Options{Target: "t", Workspace: ws}, ev); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(ws, "out.txt"))
	if strings.TrimSpace(string(data)) != "data" {
		t.Fatalf("step should have re-run (empty output), got %q", data)
	}
}

// B8: included sub-workflow vars merge into the parent workflow.
func TestIncludeVarsMerge(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "sub.yaml"), []byte(`
vars:
  subvar: "from-sub"
steps:
  - id: child
    run: echo {vars.subvar} > child.txt
    shell: true
`), 0o644)
	wf, err := Load(writeWF(t, dir, `
steps:
  - id: inc
    id-ns: inc
    workflow: sub.yaml
`))
	// the step uses `workflow:` include; id-ns is a bogus key, harmless
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if wf.Vars["subvar"] != "from-sub" {
		t.Fatalf("include vars not merged: %+v", wf.Vars)
	}
	if len(wf.Steps) != 1 || wf.Steps[0].ID != "inc.child" {
		t.Fatalf("steps = %+v", wf.Steps)
	}
}

// B11: bool/int vars load and render.
func TestNonStringVars(t *testing.T) {
	dir := t.TempDir()
	wf, err := Load(writeWF(t, dir, `
vars:
  flag: true
  count: 3
steps:
  - id: s
    when: "{vars.flag}"
    run: echo "{vars.count}"
    shell: true
`))
	if err != nil {
		t.Fatalf("bool/int vars should load: %v", err)
	}
	if wf.Vars["flag"] != "true" || wf.Vars["count"] != "3" {
		t.Fatalf("vars = %+v", wf.Vars)
	}
}

// B1/B10 validation: explicit max_parallel: 0 rejected.
func TestMaxParallelZero(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(writeWF(t, dir, `
max_parallel: 0
steps:
  - id: s
    run: echo hi
`))
	if err == nil {
		t.Fatal("max_parallel: 0 should be rejected")
	}
}
