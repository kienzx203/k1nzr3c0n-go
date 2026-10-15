package workflow

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ── YAML loading ─────────────────────────────────────────────────────────────

type rawWorkflow struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	MaxParallel *int             `yaml:"max_parallel"`
	Vars        map[string]any   `yaml:"vars"`
	Steps       []map[string]any `yaml:"steps"`
}

// stringifyVars converts YAML bool/int/float var values to strings like
// Python's implicit str() at render time ("true", "3", "2.5").
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func stringifyVars(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out[k] = t
		case bool:
			if t {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		case int:
			out[k] = strconv.Itoa(t)
		case float64:
			out[k] = strconv.FormatFloat(t, 'f', -1, 64)
		default:
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}

// Load parses + validates a workflow file, expanding includes.
func Load(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, werrf("read %s: %v", path, err)
	}
	var raw rawWorkflow
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, werrf("Invalid YAML: %v", err)
	}
	if len(raw.Steps) == 0 {
		return nil, werrf("Workflow must contain a non-empty 'steps' list.")
	}
	if raw.MaxParallel != nil && *raw.MaxParallel < 1 {
		return nil, werrf("'max_parallel' must be >= 1.")
	}
	baseDir := filepath.Dir(path)
	expanded, incVars, err := expandSteps(raw.Steps, baseDir, []string{path})
	if err != nil {
		return nil, err
	}
	// include sub-workflow vars merged parent-first (parent wins on conflict)
	vars := map[string]any{}
	for k, v := range incVars {
		vars[k] = v
	}
	for k, v := range raw.Vars {
		if _, exists := vars[k]; !exists {
			vars[k] = v
		}
	}
	steps, err := validateAll(expanded)
	if err != nil {
		return nil, err
	}
	return &Workflow{
		Name:        raw.Name,
		Description: raw.Description,
		MaxParallel: derefInt(raw.MaxParallel),
		Vars:        stringifyVars(vars),
		Steps:       steps,
	}, nil
}

// expandSteps recursively inlines `workflow:` include steps. The second
// return value accumulates vars contributed by included sub-workflows.
func expandSteps(rawSteps []map[string]any, baseDir string, stack []string) ([]map[string]any, map[string]any, error) {
	var out []map[string]any
	incVars := map[string]any{}
	for _, sm := range rawSteps {
		if incPath, ok := stringField(sm, "workflow"); ok && incPath != "" {
			if _, hasRun := sm["run"]; hasRun {
				return nil, nil, werrf("include step cannot combine 'workflow' with 'run'")
			}
			if _, hasFan := sm["fanout"]; hasFan {
				return nil, nil, werrf("include step cannot combine 'workflow' with 'fanout'")
			}
			id, _ := stringField(sm, "id")
			if id == "" {
				return nil, nil, werrf("include step requires an 'id'")
			}
			ns, hasNs := stringField(sm, "namespace")
			if !hasNs || ns == "" {
				ns = id
			}
			inc := incPath
			if !filepath.IsAbs(inc) {
				// try CWD first, then including file's dir
				if _, err := os.Stat(inc); err == nil {
					// keep as-is (relative to CWD)
				} else if _, err := os.Stat(filepath.Join(baseDir, inc)); err == nil {
					inc = filepath.Join(baseDir, inc)
				}
			}
			abs, err := filepath.Abs(inc)
			if err != nil {
				return nil, nil, werrf("resolve include %s: %v", incPath, err)
			}
			for _, p := range stack {
				if p == abs {
					return nil, nil, werrf("Workflow include cycle: %s", strings.Join(append(stack, abs), " → "))
				}
			}
			data, err := os.ReadFile(abs)
			if err != nil {
				return nil, nil, werrf("read include %s: %v", abs, err)
			}
			var sub rawWorkflow
			if err := yaml.Unmarshal(data, &sub); err != nil {
				return nil, nil, werrf("Invalid YAML in include %s: %v", abs, err)
			}
			if len(sub.Steps) == 0 {
				return nil, nil, werrf("include %s has no steps", abs)
			}
			// include-step vars overlay (extension; sub-workflow defaults are
			// merged into the workflow vars above)
			if pv, ok := sm["vars"].(map[string]any); ok {
				for k, v := range pv {
					incVars[k] = v
				}
			}
			child, subVars, err := expandSteps(sub.Steps, filepath.Dir(abs), append(stack, abs))
			if err != nil {
				return nil, nil, err
			}
			// child vars: sub-workflow defaults, then include-step overlay
			for k, v := range subVars {
				if _, exists := incVars[k]; !exists {
					incVars[k] = v
				}
			}
			for k, v := range sub.Vars {
				if _, exists := incVars[k]; !exists {
					incVars[k] = v
				}
			}
			// rewrite ids, deps, and {steps.<old>. references
			idMap := map[string]string{}
			var oldIDs []string
			for _, c := range child {
				cid, _ := stringField(c, "id")
				if cid == "" {
					continue
				}
				idMap[cid] = ns + "." + cid
				oldIDs = append(oldIDs, cid)
			}
			sort.Slice(oldIDs, func(i, j int) bool { return len(oldIDs[i]) > len(oldIDs[j]) })
			deps, _ := stringOrList(sm, "depends_on")
			for _, c := range child {
				cid, _ := stringField(c, "id")
				c["id"] = ns + "." + cid
				// map child deps through idMap; unmapped stay as-is (parent-level)
				cdeps, _ := stringOrList(c, "depends_on")
				var nd []string
				for _, d := range cdeps {
					if m, ok := idMap[d]; ok {
						nd = append(nd, m)
					} else {
						nd = append(nd, d)
					}
				}
				// include step's deps appended to every child
				nd = append(nd, deps...)
				if len(nd) > 0 {
					c["depends_on"] = nd
				}
				rewriteStepsRefs(c, oldIDs, idMap)
			}
			out = append(out, child...)
			continue
		}
		out = append(out, sm)
	}
	return out, incVars, nil
}

// rewriteStepsRefs replaces {steps.<old>. with {steps.<new>. in all string
// fields of a step map, longest old-id first.
func rewriteStepsRefs(sm map[string]any, oldIDs []string, idMap map[string]string) {
	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case string:
			s := t
			for _, old := range oldIDs {
				s = strings.ReplaceAll(s, "{steps."+old+".", "{steps."+idMap[old]+".")
			}
			return s
		case map[string]any:
			for k, vv := range t {
				t[k] = walk(vv)
			}
			return t
		case []any:
			for i, vv := range t {
				t[i] = walk(vv)
			}
			return t
		}
		return v
	}
	for k, v := range sm {
		sm[k] = walk(v)
	}
}

// ── validation / normalization ───────────────────────────────────────────────

func validateAll(rawSteps []map[string]any) ([]*Step, error) {
	seen := map[string]bool{}
	var steps []*Step
	for i, sm := range rawSteps {
		st, err := normalizeStep(sm, i)
		if err != nil {
			return nil, err
		}
		if seen[st.ID] {
			return nil, werrf("Duplicate step id: '%s'", st.ID)
		}
		seen[st.ID] = true
		steps = append(steps, st)
	}
	if _, err := TopologicalOrder(steps); err != nil {
		return nil, err
	}
	return steps, nil
}

func normalizeStep(sm map[string]any, index int) (*Step, error) {
	st := &Step{Index: index, FanoutConcurrency: 0}
	var ok bool
	st.ID, ok = stringField(sm, "id")
	if !ok || st.ID == "" {
		return nil, werrf("Step #%d is missing 'id'", index+1)
	}
	if v, ok := stringField(sm, "name"); ok {
		st.Name = v
	}
	deps, err := stringOrList(sm, "depends_on")
	if err != nil {
		return nil, werrf("Step '%s': %v", st.ID, err)
	}
	st.DependsOn = deps

	if v, ok := sm["run"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, werrf("Step '%s': 'run' must be a string", st.ID)
		}
		st.Run = &s
	}
	if v, ok := sm["when"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, werrf("Step '%s': 'when' must be a string", st.ID)
		}
		st.When = &s
	}
	if st.Run == nil && st.When == nil {
		if _, hasFan := sm["fanout"]; !hasFan {
			return nil, werrf("Step '%s' has neither 'run' nor 'fanout'", st.ID)
		}
	}
	st.Shell = boolField(sm, "shell")
	if t, err := parseTimeoutField(sm["timeout"]); err != nil {
		return nil, werrf("Step '%s': %v", st.ID, err)
	} else {
		st.Timeout = t
	}
	if v, ok := intField(sm, "retries"); ok {
		st.Retries = v
	} else if _, has := sm["retries"]; has {
		return nil, werrf("Step '%s': 'retries' must be an integer", st.ID)
	}
	var boolFields = []struct {
		key string
		dst *bool
	}{
		{"optional", &st.Optional},
		{"skip_if_exists", &st.SkipIfExists},
		{"run_on_failed_deps", &st.RunOnFailedDeps},
	}
	for _, bf := range boolFields {
		if v, has := sm[bf.key]; has {
			b, ok := v.(bool)
			if !ok {
				return nil, werrf("Step '%s': '%s' must be a boolean", st.ID, bf.key)
			}
			*bf.dst = b
		}
	}
	if m, ok := sm["outputs"].(map[string]any); ok {
		st.Outputs = map[string]string{}
		for k, v := range m {
			st.Outputs[k] = fmt.Sprintf("%v", v)
		}
	}
	reqs, err := normalizeRequires(sm["requires"])
	if err != nil {
		return nil, werrf("Step '%s': %v", st.ID, err)
	}
	st.Requires = reqs
	if m, ok := sm["env"].(map[string]any); ok {
		st.Env = map[string]string{}
		for k, v := range m {
			st.Env[k] = fmt.Sprintf("%v", v)
		}
	}
	if v, ok := stringField(sm, "cwd"); ok {
		st.Cwd = &v
	}
	if v, has := sm["fanout"]; has {
		list, ok := v.([]any)
		if !ok || len(list) == 0 {
			return nil, werrf("Step '%s': 'fanout' must be a non-empty list", st.ID)
		}
		if st.Run != nil {
			return nil, werrf("Step '%s' cannot have both 'run' and 'fanout'", st.ID)
		}
		childSeen := map[string]bool{}
		for ci, cm := range list {
			cmap, ok := cm.(map[string]any)
			if !ok {
				return nil, werrf("Step '%s': fanout child #%d must be a mapping", st.ID, ci+1)
			}
			child, err := normalizeChild(cmap, ci)
			if err != nil {
				return nil, werrf("Step '%s' fanout: %v", st.ID, err)
			}
			if childSeen[child.ID] {
				return nil, werrf("Step '%s': duplicate fanout child id '%s'", st.ID, child.ID)
			}
			childSeen[child.ID] = true
			st.Fanout = append(st.Fanout, child)
		}
	}
	if v, ok := intField(sm, "fanout_concurrency"); ok {
		if v < 1 {
			return nil, werrf("Step '%s': fanout_concurrency must be >= 1", st.ID)
		}
		st.FanoutConcurrency = v
	} else if _, has := sm["fanout_concurrency"]; has {
		return nil, werrf("Step '%s': fanout_concurrency must be an integer", st.ID)
	}
	if t, err := parseTimeoutField(sm["fanout_timeout_default"]); err != nil {
		return nil, werrf("Step '%s': %v", st.ID, err)
	} else {
		st.FanoutTimeoutDefault = t
	}
	return st, nil
}

func normalizeChild(cm map[string]any, index int) (*Child, error) {
	c := &Child{Index: index}
	var ok bool
	c.ID, ok = stringField(cm, "id")
	if !ok || c.ID == "" {
		return nil, werrf("child #%d is missing 'id'", index+1)
	}
	if _, has := cm["depends_on"]; has {
		return nil, werrf("child '%s' cannot have 'depends_on'", c.ID)
	}
	c.Run, ok = stringField(cm, "run")
	if !ok || c.Run == "" {
		return nil, werrf("child '%s' is missing 'run'", c.ID)
	}
	if v, ok := stringField(cm, "name"); ok {
		c.Name = v
	}
	if v, ok := stringField(cm, "when"); ok {
		c.When = &v
	}
	c.Shell = boolField(cm, "shell")
	if t, err := parseTimeoutField(cm["timeout"]); err != nil {
		return nil, err
	} else {
		c.Timeout = t
	}
	if v, ok := intField(cm, "retries"); ok {
		c.Retries = v
	}
	c.Optional = boolField(cm, "optional")
	c.SkipIfExists = boolField(cm, "skip_if_exists")
	if m, ok := cm["outputs"].(map[string]any); ok {
		c.Outputs = map[string]string{}
		for k, v := range m {
			c.Outputs[k] = fmt.Sprintf("%v", v)
		}
	}
	reqs, err := normalizeRequires(cm["requires"])
	if err != nil {
		return nil, err
	}
	c.Requires = reqs
	if m, ok := cm["env"].(map[string]any); ok {
		c.Env = map[string]string{}
		for k, v := range m {
			c.Env[k] = fmt.Sprintf("%v", v)
		}
	}
	if v, ok := stringField(cm, "cwd"); ok {
		c.Cwd = &v
	}
	return c, nil
}

func normalizeRequires(v any) ([]Require, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("'requires' must be a list")
	}
	var out []Require
	for _, item := range list {
		switch t := item.(type) {
		case string:
			out = append(out, Require{Path: t})
		case map[string]any:
			p, _ := stringField(t, "path")
			mb, _ := intField(t, "min_bytes")
			out = append(out, Require{Path: p, MinBytes: int64(mb)})
		default:
			return nil, fmt.Errorf("'requires' entries must be strings or {path, min_bytes}")
		}
	}
	return out, nil
}

func parseTimeoutField(v any) (*Timeout, error) {
	if v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case int:
		if t <= 0 {
			return nil, fmt.Errorf("timeout must be > 0")
		}
		return &Timeout{Seconds: float64(t)}, nil
	case float64:
		if t <= 0 {
			return nil, fmt.Errorf("timeout must be > 0")
		}
		return &Timeout{Seconds: t}, nil
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil, fmt.Errorf("timeout must be > 0")
		}
		mult := 1.0
		num := s
		switch s[len(s)-1] {
		case 's':
			num = s[:len(s)-1]
		case 'm':
			num = s[:len(s)-1]
			mult = 60
		case 'h':
			num = s[:len(s)-1]
			mult = 3600
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
		if err != nil || f <= 0 {
			return nil, fmt.Errorf("invalid timeout: %q", t)
		}
		return &Timeout{Seconds: f * mult}, nil
	}
	return nil, fmt.Errorf("timeout must be a number or Ns/Nm/Nh string")
}

// ── small YAML accessors ─────────────────────────────────────────────────────

func stringField(m map[string]any, key string) (string, bool) {
	v, has := m[key]
	if !has || v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case int, float64, bool:
		return fmt.Sprintf("%v", t), true
	}
	return "", false
}

func boolField(m map[string]any, key string) bool {
	v, has := m[key]
	if !has {
		return false
	}
	b, _ := v.(bool)
	return b
}

func intField(m map[string]any, key string) (int, bool) {
	v, has := m[key]
	if !has {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case float64:
		return int(t), true
	case string:
		if n, err := strconv.Atoi(t); err == nil {
			return n, true
		}
	}
	return 0, false
}

// stringOrList coerces a scalar or list value into []string.
func stringOrList(m map[string]any, key string) ([]string, error) {
	v, has := m[key]
	if !has || v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}, nil
	case []any:
		var out []string
		for _, item := range t {
			switch s := item.(type) {
			case string:
				out = append(out, s)
			case int, float64, bool:
				out = append(out, fmt.Sprintf("%v", s))
			default:
				return nil, fmt.Errorf("'%s' must contain only strings", key)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("'%s' must be a string or list of strings", key)
}
