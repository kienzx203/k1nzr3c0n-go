package agent

import "testing"

func TestLoadSkillsDir(t *testing.T) {
	t.Setenv("K1NZR3C0N_BASE", "/mnt/c/Users/kin/Downloads/k1nzr3c0n-go")
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
	if !names["web-recon"] || !names["report-writing"] {
		t.Fatalf("missing expected skills: %v", names)
	}
}
