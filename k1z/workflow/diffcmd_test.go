package workflow

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestDumpDiffCases mirrors diff_template.py's cases for differential testing.
func TestDumpDiffCases(t *testing.T) {
	if os.Getenv("K1Z_DIFF") == "" {
		t.Skip("set K1Z_DIFF=1")
	}
	ctx := map[string]any{
		"target": "example.com", "empty": "", "num": "5",
		"vars":   map[string]any{"a": "1", "b": "", "f": "false", "t": "true"},
		"steps":  map[string]any{"s1": map[string]any{"file": "/x"}, "f": map[string]any{"c1": map[string]any{"out": "o"}}},
		"status": map[string]any{}, "workspace": "/ws", "dash": "v",
	}
	cases := []string{
		"{target}", "{vars.a}", "{steps.s1.file}", "{steps.f.c1.out}",
		"{empty|def}", "{vars.b|def}", "{missing|def}", "{missing}",
		"${VAR:-x}", "pre ${HOME} post", "{target|def}", "{num}",
		"{vars.a}{vars.b}", "no placeholders", "{target}{target}",
		"{ |def}", "{|}", "{a||b||c}", "{vars.missing}", "{target|}",
		"unicode: {target}-é", "{target}}", "{{target}}", "{}",
		"{TARGET}", "{vars.A}", "{steps.s1.nope}", "{steps.s1.file|def}",
	}
	type result struct {
		Case string  `json:"case"`
		Out  *string `json:"out"`
		Err  *string `json:"err"`
	}
	var results []result
	add := func(c string, out string, errStr string) {
		var o *string
		var e *string
		if errStr == "" {
			o = &out
		} else {
			e = &errStr
		}
		results = append(results, result{Case: c, Out: o, Err: e})
	}
	for _, c := range cases {
		out, err := RenderTemplate(c, ctx, false)
		if err != nil {
			add(c, "", err.Error())
		} else {
			add(c, out, "")
		}
	}
	for _, c := range []string{"{missing}", "{empty|d}", "{vars.b|d}"} {
		out, err := RenderTemplate(c, ctx, true)
		if err != nil {
			add("AM:"+c, "", err.Error())
		} else {
			add("AM:"+c, out, "")
		}
	}
	whens := []string{"{vars.t}", "{vars.f}", "{vars.b}", "{vars.a}", "0", "false", "no", "none", "NO", "False",
		"{vars.t} && {vars.a}", "{vars.f} && {vars.t}", "{vars.t} || {vars.f}", "{vars.f} || {vars.f}",
		"{vars.nope}", "", "yes", "TRUE", "  {vars.t}  ", "{vars.t}&&{vars.a}"}
	for _, w := range whens {
		v := EvalWhen(w, ctx)
		s := fmt.Sprint(v)
		results = append(results, result{Case: "WHEN:" + w, Out: &s, Err: nil})
	}
	b, _ := json.Marshal(results)
	os.WriteFile("/tmp/opencode/go_template_results.json", b, 0o644)
	t.Logf("go side: %d", len(results))
}
