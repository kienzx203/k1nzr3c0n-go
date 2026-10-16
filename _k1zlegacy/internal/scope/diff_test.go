package scope

import (
	"encoding/json"
	"os"
	"testing"
)

func TestScopeDifferential(t *testing.T) {
	if os.Getenv("K1Z_DIFF") == "" {
		t.Skip("set K1Z_DIFF=1")
	}
	data, err := os.ReadFile("/tmp/opencode/py_scope.json")
	if err != nil {
		t.Skip("no python results")
	}
	var cases []struct {
		Host     string   `json:"host"`
		Norm     string   `json:"norm"`
		Patterns []string `json:"patterns"`
		Match    bool     `json:"match"`
	}
	if json.Unmarshal(data, &cases) != nil {
		t.Fatal("bad json")
	}
	mismatch := 0
	for _, c := range cases {
		if got := Normalize(c.Host); got != c.Norm {
			t.Errorf("Normalize(%q) = %q, py = %q", c.Host, got, c.Norm)
			mismatch++
		}
		if got := Match(c.Host, c.Patterns); got != c.Match {
			t.Errorf("Match(%q, %v) = %v, py = %v", c.Host, c.Patterns, got, c.Match)
			mismatch++
		}
	}
	if mismatch == 0 {
		t.Logf("scope differential: %d/%d cases identical", len(cases)*2, len(cases)*2)
	}
}
