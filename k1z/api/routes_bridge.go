package api

// Bridge: Workflow Runner (recon) -> ARTEX (autonomous Task). This file compiles
// a run's recon surface into a structured brief + markdown summary, which the UI
// hands to ARTEX's createTask as the task description ("Send to Agent"). Pure
// k1z-side read; no cross-DB coupling.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/k1z/store"
)

func (s *Server) handleReconBrief(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	findings, _, err := s.St.ListFindings(store.FindingFilter{RunID: run.ID, Limit: 10000})
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}

	// scope from the target registry (deny-wins), if the target is registered
	var scope []string
	mode := ""
	if t, e := s.St.GetTarget(strings.ToLower(run.Target)); e == nil && t != nil {
		mode = t.Mode
		_ = json.Unmarshal([]byte(rawOr(t.ScopeJSON, "[]")), &scope)
	}

	var vulns, httpF, portF, subF, urlF []*store.Finding
	for _, f := range findings {
		switch f.Kind {
		case "vuln":
			vulns = append(vulns, f)
		case "http":
			httpF = append(httpF, f)
		case "port":
			portF = append(portF, f)
		case "subdomain":
			subF = append(subF, f)
		case "url":
			urlF = append(urlF, f)
		}
	}
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(vulns, func(i, j int) bool { return rank[rbSev(vulns[i].Severity)] < rank[rbSev(vulns[j].Severity)] })
	sevCount := map[string]int{}
	for _, f := range vulns {
		sevCount[rbSev(f.Severity)]++
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Recon surface — %s  (run %s, workflow %s)\n", run.Target, run.ID, run.Workflow)
	if len(scope) > 0 {
		fmt.Fprintf(&b, "SCOPE (deny-wins): %s  | mode: %s\n\n", strings.Join(scope, ", "), rbOr(mode, "—"))
	} else {
		fmt.Fprintf(&b, "SCOPE: %s and *.%s — register the target for a stricter deny-wins scope\n\n", run.Target, run.Target)
	}

	fmt.Fprintf(&b, "## Vulnerabilities — %d", len(vulns))
	if len(sevCount) > 0 {
		var parts []string
		for _, lv := range []string{"critical", "high", "medium", "low", "info"} {
			if sevCount[lv] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", sevCount[lv], lv))
			}
		}
		fmt.Fprintf(&b, " (%s)", strings.Join(parts, ", "))
	}
	b.WriteString("\n")
	for i, f := range vulns {
		if i >= 60 {
			fmt.Fprintf(&b, "  …+%d more\n", len(vulns)-60)
			break
		}
		fmt.Fprintf(&b, "  [%s] %s — %s%s\n", rbSev(f.Severity), rbOr(rbP(f.Name), rbOr(rbP(f.TemplateID), "finding")), f.Host, rbPre("  ", f.URL))
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Live HTTP hosts — %d\n", len(httpF))
	for i, f := range httpF {
		if i >= 120 {
			fmt.Fprintf(&b, "  …+%d more\n", len(httpF)-120)
			break
		}
		fmt.Fprintf(&b, "  %s [%s]%s%s\n", rbHostURL(f), rbStatus(f.StatusCode), rbPre("  ", f.Title), rbTech(f.Tech))
	}
	b.WriteString("\n")

	portByHost := map[string][]string{}
	order := []string{}
	for _, f := range portF {
		if f.Port != nil {
			if _, ok := portByHost[f.Host]; !ok {
				order = append(order, f.Host)
			}
			portByHost[f.Host] = append(portByHost[f.Host], fmt.Sprintf("%d", *f.Port))
		}
	}
	fmt.Fprintf(&b, "## Open ports — %d hosts\n", len(portByHost))
	for i, h := range order {
		if i >= 60 {
			fmt.Fprintf(&b, "  …+%d more hosts\n", len(order)-60)
			break
		}
		fmt.Fprintf(&b, "  %s: %s\n", h, strings.Join(portByHost[h], ","))
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Subdomains — %d\n", len(subF))
	rbSample(&b, subF, 60, func(f *store.Finding) string { return f.Host })
	b.WriteString("\n")

	fmt.Fprintf(&b, "## URLs / endpoints — %d\n", len(urlF))
	rbSample(&b, urlF, 80, func(f *store.Finding) string { return rbOr(rbP(f.URL), f.Host) })
	b.WriteString("\n")

	b.WriteString("OBJECTIVE: validate & exploit the surface above WITHOUT re-scanning. Prioritize broken access control / IDOR, SSRF, auth/JWT/OAuth flaws, injection (SQLi/SSTI/command), and file upload. Stay STRICTLY in scope (deny-wins); no DoS; prove impact with a minimal PoC.\n")

	writeJSON(w, 200, map[string]any{
		"run_id":   run.ID,
		"target":   run.Target,
		"workflow": run.Workflow,
		"scope":    scope,
		"mode":     mode,
		"counts": map[string]int{
			"vuln": len(vulns), "http": len(httpF), "port": len(portF),
			"subdomain": len(subF), "url": len(urlF),
		},
		"markdown": b.String(),
	})
}

// ── recon-brief helpers (rb*) ─────────────────────────────────────────────────

func rbP(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func rbSev(p *string) string {
	if p == nil || *p == "" {
		return "info"
	}
	return *p
}
func rbOr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
func rbPre(prefix string, p *string) string {
	if p == nil || *p == "" {
		return ""
	}
	return prefix + *p
}
func rbStatus(p *int) string {
	if p == nil {
		return "?"
	}
	return fmt.Sprintf("%d", *p)
}
func rbHostURL(f *store.Finding) string {
	if f.URL != nil && *f.URL != "" {
		return *f.URL
	}
	return f.Host
}
func rbTech(j string) string {
	var arr []string
	_ = json.Unmarshal([]byte(j), &arr)
	if len(arr) == 0 {
		return ""
	}
	return "  (" + strings.Join(arr, ", ") + ")"
}
func rbSample(b *strings.Builder, fs []*store.Finding, limit int, get func(*store.Finding) string) {
	seen := map[string]bool{}
	n := 0
	for _, f := range fs {
		v := get(f)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		if n >= limit {
			fmt.Fprintf(b, "  …+%d more\n", len(fs)-n)
			return
		}
		fmt.Fprintf(b, "  %s\n", v)
		n++
	}
}
