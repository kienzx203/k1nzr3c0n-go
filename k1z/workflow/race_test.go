package workflow

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestParallelLevelRace runs a workflow whose levels contain many parallel
// steps under the race detector — guards the ctx/status map fixes (R2/R3).
func TestParallelLevelRace(t *testing.T) {
	dir := t.TempDir()
	var steps string
	steps += "  - id: s0\n    run: echo 0\n    shell: true\n"
	for i := 1; i <= 20; i++ {
		steps += "  - id: p" + itoa(i) + "\n    run: echo " + itoa(i) + "\n    shell: true\n    depends_on: [s0]\n"
	}
	steps += "  - id: last\n    run: echo last\n    shell: true\n    depends_on: [p1, p5, p20]\n"
	wf, err := Load(writeWF(t, dir, "max_parallel: 8\nsteps:\n"+steps))
	if err != nil {
		t.Fatal(err)
	}
	ev := &raceEvents{}
	err = RunWorkflow(wf, Options{Target: "t", Workspace: filepath.Join(dir, "ws"),
		Vars: wf.Vars, ContinueOnError: true}, ev)
	if err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

type raceEvents struct {
	NoopEvents
	mu  sync.Mutex
	log []string
}

func (r *raceEvents) Info(m string) {
	r.mu.Lock()
	r.log = append(r.log, m)
	r.mu.Unlock()
}

func (r *raceEvents) Line(l, s string) {
	r.mu.Lock()
	r.log = append(r.log, l+s)
	r.mu.Unlock()
}

var _ = os.Getenv
