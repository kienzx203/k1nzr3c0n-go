// Package scope implements the deny-wins target registry check.
package scope

import (
	"encoding/json"
	"strings"

	"github.com/Autumn-27/artex/k1z/store"
)

// Normalize mirrors Python _normalize: strip scheme/path/port, lowercase,
// drop trailing dots.
func Normalize(host string) string {
	h := strings.TrimSpace(strings.ToLower(host))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.Index(h, "/"); i >= 0 {
		h = h[:i]
	}
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	return strings.TrimRight(h, ".")
}

// Match reports whether host matches one of the scope patterns.
//   - "example.com" matches example.com and any-depth subdomains
//   - "*.example.com" matches single-label subdomains only (not the apex)
func Match(host string, patterns []string) bool {
	h := Normalize(host)
	if h == "" {
		return false
	}
	for _, raw := range patterns {
		p := Normalize(raw)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			base := p[2:]
			suffix := "." + base
			if strings.HasSuffix(h, suffix) {
				label := strings.TrimSuffix(h, suffix)
				if label != "" && !strings.Contains(label, ".") {
					return true
				}
			}
		} else {
			if h == p || strings.HasSuffix(h, "."+p) {
				return true
			}
		}
	}
	return false
}

// Covering returns the first registered target whose patterns cover host.
func Covering(st *store.Store, host string) *store.Target {
	targets, err := st.ListTargets()
	if err != nil {
		return nil
	}
	for _, t := range targets {
		patterns := []string{t.Name}
		var extra []string
		if json.Unmarshal([]byte(t.ScopeJSON), &extra) == nil {
			patterns = append(patterns, extra...)
		}
		if Match(host, patterns) {
			return t
		}
	}
	return nil
}

// CheckTargetScope is the deny-wins gate at run creation. It writes an audit
// row for every decision.
func CheckTargetScope(st *store.Store, target string) (bool, string) {
	t := Normalize(target)
	audit := &store.ScopeAudit{Target: t, Action: "run_start", Result: "allowed"}
	covering := Covering(st, t)
	var detail string
	switch {
	case covering == nil:
		detail = "unregistered target — no scope defined"
	case covering.Mode == "oos":
		audit.Result = "denied"
		audit.Action = "blocked"
		detail = "target '" + covering.Name + "' is marked out-of-scope"
	default:
		detail = "covered by registered target '" + covering.Name + "' (mode=" + covering.Mode + ")"
	}
	d := detail
	audit.Detail = &d
	_ = st.InsertScopeAudit(audit)
	return audit.Result == "allowed", detail
}
