package runner

// Integration D: continuous recon -> auto-spawn an ARTEX triage Task. When a
// SCHEDULED re-scan finds NEW surface, and the feature is explicitly enabled, we
// compile a delta brief and hand it to ARTEX via AutoTriageHook (wired in main to
// the task manager). Default OFF (env gate) so it never spends LLM budget by
// surprise, and throttled per-target.

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/k1z/store"
)

// AutoTriageHook, when set, creates an autonomous Task from a recon delta. The
// signature is string-only so this package never imports ARTEX/Postgres.
var AutoTriageHook func(target, goal, brief string)

var (
	triageMu   sync.Mutex
	lastTriage = map[string]time.Time{}
)

func (r *Runner) maybeAutoTriage(run *store.Run) {
	defer func() { _ = recover() }() // never let triage break a finished run

	if AutoTriageHook == nil || os.Getenv("AUTO_TRIAGE_ENABLED") == "" {
		return
	}

	// only targets with an enabled schedule that opted into new-asset alerts
	scheds, _ := r.St.ListSchedules()
	opted := false
	for _, sc := range scheds {
		if sc.Enabled && sc.AlertNewAssets && strings.EqualFold(sc.Target, run.Target) {
			opted = true
			break
		}
	}
	if !opted {
		return
	}

	newAssets, _ := r.St.ListNewAssetsByRun(run.ID)
	if len(newAssets) == 0 {
		return
	}

	// throttle: at most one auto-triage per target per hour
	key := strings.ToLower(run.Target)
	triageMu.Lock()
	if t, ok := lastTriage[key]; ok && time.Since(t) < time.Hour {
		triageMu.Unlock()
		return
	}
	lastTriage[key] = time.Now()
	triageMu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "# Continuous recon — new surface on %s\n", run.Target)
	fmt.Fprintf(&b, "A scheduled re-scan (workflow %s, run %s) discovered %d NEW asset(s) vs prior runs.\n\n", run.Workflow, run.ID, len(newAssets))
	b.WriteString("## New assets\n")
	for i, a := range newAssets {
		if i >= 100 {
			fmt.Fprintf(&b, "  …+%d more\n", len(newAssets)-100)
			break
		}
		fmt.Fprintf(&b, "  %s\n", a.Host)
	}
	if vulns, _, _ := r.St.ListFindings(store.FindingFilter{RunID: run.ID, Kind: "vuln", Status: "open", Limit: 40}); len(vulns) > 0 {
		fmt.Fprintf(&b, "\n## Open vulns in this run — %d\n", len(vulns))
		for _, f := range vulns {
			sev := "info"
			if f.Severity != nil && *f.Severity != "" {
				sev = *f.Severity
			}
			name := ""
			if f.Name != nil {
				name = *f.Name
			}
			fmt.Fprintf(&b, "  [%s] %s — %s\n", sev, name, f.Host)
		}
	}
	b.WriteString("\nOBJECTIVE: triage ONLY the new/changed surface above. Validate quickly; prioritize auth/IDOR/SSRF on the new hosts. Stay STRICTLY in scope (deny-wins); no DoS. Use recon_findings for details.\n")

	goal := fmt.Sprintf("Triage %d new asset(s) found on %s by continuous recon.", len(newAssets), run.Target)
	AutoTriageHook(run.Target, goal, b.String())
}
