package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/k1z/runner"
	"github.com/Autumn-27/artex/k1z/store"
	"github.com/Autumn-27/artex/k1z/workflow"
)

// TestGetRunLogsTailWindow verifies get_run_logs returns the LAST N lines
// (A1 regression: wrong window + slice panic when total > limit).
func TestGetRunLogsTailWindow(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var lines []string
	for i := 1; i <= 3000; i++ {
		lines = append(lines, "line-"+pad(i))
	}
	if err := st.InsertLogs("r1", lines); err != nil {
		t.Fatal(err)
	}
	r := &runner.Runner{St: st}
	out := Exec(st, r, FunctionCall{Name: "get_run_logs", Arguments: `{"run_id":"r1","limit":5}`})
	var res struct {
		Total int      `json:"total"`
		Lines []string `json:"lines"`
	}
	if json.Unmarshal([]byte(out), &res) != nil {
		t.Fatalf("bad json: %s", out)
	}
	if res.Total != 3000 {
		t.Fatalf("total = %d", res.Total)
	}
	if len(res.Lines) != 5 {
		t.Fatalf("lines = %d, want 5", len(res.Lines))
	}
	if res.Lines[len(res.Lines)-1] != "line-3000" {
		t.Fatalf("last line = %q, want line-3000 (tail window broken)", res.Lines[len(res.Lines)-1])
	}
}

// TestWorkflowWithPercentPlaceholder documents template parity: %{x} is a
// placeholder error in BOTH engines (shipped workflows never use it).
func TestWorkflowWithPercentPlaceholder(t *testing.T) {
	dir := t.TempDir()
	wf := "steps:\n  - id: s\n    run: curl -w \"%{http_code}\"\n    shell: true\n"
	p := filepath.Join(dir, "wf.yaml")
	os.WriteFile(p, []byte(wf), 0o644)
	if _, err := workflow.Load(p); err != nil {
		t.Fatal(err)
	}
	// rendering must fail with the unknown-variable error
	w, _ := workflow.Load(p)
	_, rerr := workflow.RenderTemplate(*w.Steps[0].Run, map[string]any{"workspace": dir}, false)
	if rerr == nil || !strings.Contains(rerr.Error(), "Unknown template variable") {
		t.Fatalf("expected unknown-variable error, got %v", rerr)
	}
}

func pad(n int) string {
	s := ""
	for i := 0; i < 4-len(sprintN(n)); i++ {
		s += "0"
	}
	return s + sprintN(n)
}

func sprintN(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
