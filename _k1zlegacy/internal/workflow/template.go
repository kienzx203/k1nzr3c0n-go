package workflow

import (
	"regexp"
	"strconv"
	"strings"
)

// placeholderRe matches {key} / {a.b} / {key|default}. Go RE2 has no lookbehind,
// so the caller must skip matches preceded by '$' (handled in RenderTemplate).
var placeholderRe = regexp.MustCompile(`\{([A-Za-z0-9_.|-]+)\}`)

// ResolveKey resolves a dotted key path like steps.httpx.file against a nested
// map context. Missing segments yield nil.
func ResolveKey(key string, ctx map[string]any) any {
	var current any = ctx
	for _, part := range strings.Split(key, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		v, has := m[part]
		if !has {
			return nil
		}
		current = v
	}
	return current
}

// RenderTemplate substitutes {key}, {a.b.c}, and {key|default} placeholders.
// A '$' immediately before '{' escapes the placeholder (left literal) so shell
// constructs like ${VAR:-x} pass through. Unknown keys are an error unless
// allowMissing, in which case the placeholder is left as-is.
func RenderTemplate(template string, ctx map[string]any, allowMissing bool) (string, error) {
	if !strings.Contains(template, "{") {
		return template, nil
	}
	var b strings.Builder
	last := 0
	for _, m := range placeholderRe.FindAllStringSubmatchIndex(template, -1) {
		start, end := m[0], m[1]
		// skip ${...} (shell escaping)
		if start > 0 && template[start-1] == '$' {
			continue
		}
		spec := template[m[2]:m[3]]
		key, def, hasDef := "", "", false
		if i := strings.Index(spec, "|"); i >= 0 {
			key, def, hasDef = spec[:i], spec[i+1:], true
		} else {
			key = spec
		}
		key = strings.TrimSpace(key)
		val := ResolveKey(key, ctx)
		if val == nil {
			if hasDef {
				b.WriteString(template[last:start])
				b.WriteString(def)
				last = end
				continue
			}
			if allowMissing {
				continue // leave placeholder literal
			}
			return "", werrf("Unknown template variable: '%s'", spec)
		}
		b.WriteString(template[last:start])
		b.WriteString(toStr(val))
		last = end
	}
	b.WriteString(template[last:])
	return b.String(), nil
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return ""
	}
}

// EvalWhen evaluates a `when:` expression: '||' = any truthy, '&&' = all
// truthy (default). Truthy mirrors Python: rendered lowercased value not in
// {”, '0', 'false', 'no', 'none'}.
func EvalWhen(expr string, ctx map[string]any) bool {
	check := func(part string) bool {
		rendered, err := RenderTemplate(strings.TrimSpace(part), ctx, true)
		if err != nil {
			return false
		}
		v := strings.ToLower(strings.TrimSpace(rendered))
		switch v {
		case "", "0", "false", "no", "none":
			return false
		}
		return true
	}
	if strings.Contains(expr, "||") {
		for _, part := range strings.Split(expr, "||") {
			if check(part) {
				return true
			}
		}
		return false
	}
	if strings.Contains(expr, "&&") {
		for _, part := range strings.Split(expr, "&&") {
			if !check(part) {
				return false
			}
		}
		return true
	}
	return check(expr)
}
