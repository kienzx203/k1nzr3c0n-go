package agent

import "testing"

func TestCamelToSnake(t *testing.T) {
	cases := map[string]string{
		"WebFetch": "web_fetch", "TodoWrite": "todo_write", "Bash": "bash",
		"LS": "ls", "bash": "bash", "run_workflow": "run_workflow",
	}
	for in, want := range cases {
		if got := camelToSnake(in); got != want {
			t.Errorf("camelToSnake(%q)=%q want %q", in, got, want)
		}
	}
}

func TestToolAliasNames(t *testing.T) {
	// CamelCase → lower/snake/UPPER (deduped, original dropped)
	got := toolAliasNames("WebFetch")
	want := map[string]bool{"webfetch": true, "web_fetch": true, "WEBFETCH": true}
	if len(got) != 3 {
		t.Fatalf("WebFetch aliases = %v (want 3)", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected alias %q", g)
		}
	}
	// already-lowercase name → no aliases (no drift to defend)
	if a := toolAliasNames("sleep"); a != nil {
		t.Errorf("sleep should yield no aliases, got %v", a)
	}
}
