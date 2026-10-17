package agent

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadSkillsDir(t *testing.T) {
	// Resolve the repo root from this test file's location so the test is
	// hermetic — it passed only when `go test` happened to run from the repo
	// root (K1NZR3C0N_BASE="." → ./skills), and found 0 skills otherwise.
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	t.Setenv("K1NZR3C0N_BASE", repoRoot)
	skills := LoadSkillsDir()
	if len(skills) < 2 {
		t.Fatalf("expected >=2 skills, got %d", len(skills))
	}
	names := map[string]bool{}
	for _, s := range skills {
		names[s.Name] = true
		if s.Instructions == "" || s.Description == "" {
			t.Errorf("skill %s missing body/description", s.Name)
		}
	}
	if !names["api-recon"] || !names["scopesentry"] {
		t.Fatalf("missing expected skills: %v", names)
	}
}
