// Package report renders the run HTML report and platform markdown drafts.
package report

import (
	"fmt"
	"html"
	"strings"

	"k1nzr3c0n/internal/store"
)

var sevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// HTML renders the run report page.
func HTML(run *store.Run, findings []*store.Finding) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>k1nzr3c0n report ` + html.EscapeString(run.ID) + `</title>
<style>
body{font-family:ui-sans-serif,system-ui;background:#0b0e14;color:#d7dde8;margin:2rem}
h1,h2{color:#7ee2a8} table{border-collapse:collapse;width:100%;margin:1rem 0}
td,th{border:1px solid #232a3a;padding:.5rem .7rem;text-align:left;font-size:.9rem}
.critical{color:#f85149;font-weight:700}.high{color:#ff9142;font-weight:700}
.medium{color:#e3b341}.low{color:#8b949e}.info{color:#6e7681}
.meta{color:#8b949e;font-size:.9rem}
</style></head><body>`)
	b.WriteString("<h1>Recon report</h1>")
	b.WriteString(fmt.Sprintf("<p class='meta'>Run <code>%s</code> · target <b>%s</b> · workflow <code>%s</code> · status <b>%s</b></p>",
		html.EscapeString(run.ID), html.EscapeString(run.Target), html.EscapeString(run.Workflow), html.EscapeString(run.Status)))
	b.WriteString(fmt.Sprintf("<p class='meta'>%d findings</p>", len(findings)))
	b.WriteString("<h2>Findings</h2><table><tr><th>Severity</th><th>Kind</th><th>Host</th><th>Name / template</th><th>URL</th><th>Status</th></tr>")
	for _, f := range findings {
		sev := ""
		if f.Severity != nil {
			sev = *f.Severity
		}
		name := ""
		if f.TemplateID != nil {
			name = *f.TemplateID
		}
		if f.Name != nil && name == "" {
			name = *f.Name
		}
		url := ""
		if f.URL != nil {
			url = *f.URL
		}
		b.WriteString(fmt.Sprintf("<tr><td class='%s'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			html.EscapeString(sev), html.EscapeString(sev), html.EscapeString(f.Kind),
			html.EscapeString(f.Host), html.EscapeString(name), html.EscapeString(url), html.EscapeString(f.Status)))
	}
	b.WriteString("</table></body></html>")
	return b.String()
}

// Engagement renders a full-run + cross-run engagement summary (all open
// findings grouped by severity, asset counts).
func Engagement(target string, findings []*store.Finding, assetCount int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Engagement report — %s\n\n", target)
	fmt.Fprintf(&b, "Total open findings: **%d** · assets in graph: **%d**\n\n", len(findings), assetCount)
	bySev := map[string][]*store.Finding{}
	for _, f := range findings {
		sev := "info"
		if f.Severity != nil {
			sev = *f.Severity
		}
		bySev[sev] = append(bySev[sev], f)
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		group := bySev[sev]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s (%d)\n\n", strings.ToUpper(sev), len(group))
		for _, f := range group {
			name := f.Host
			if f.TemplateID != nil && *f.TemplateID != "" {
				name = *f.TemplateID + " — " + f.Host
			}
			fmt.Fprintf(&b, "- **%s** (run `%s`)", name, f.RunID)
			if f.URL != nil && *f.URL != "" {
				fmt.Fprintf(&b, " · %s", *f.URL)
			}
			if f.Notes != nil && *f.Notes != "" {
				fmt.Fprintf(&b, " · notes: %s", *f.Notes)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

type draftSection struct{ Header, Body string }

// Draft renders the per-vuln markdown drafts for a platform format.
func Draft(run *store.Run, openVulns []*store.Finding, format string) string {
	var headers []string
	switch format {
	case "bugcrowd":
		headers = []string{"## Description", "## Proof of Concept", "## Impact", "## Remediation"}
	case "markdown":
		headers = []string{"## Summary", "## Steps to Reproduce", "## Impact"}
	default: // hackerone
		headers = []string{"## Summary", "## Steps to Reproduce", "## Impact", "## Supporting Material/References"}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Draft submissions — %s\n\n", run.Target)
	if len(openVulns) == 0 {
		b.WriteString("No open vulnerability findings in this run.\n")
		return b.String()
	}
	for _, f := range openVulns {
		sev := "info"
		if f.Severity != nil {
			sev = *f.Severity
		}
		name := f.Host
		if f.TemplateID != nil && *f.TemplateID != "" {
			name = *f.TemplateID + " — " + f.Host
		}
		fmt.Fprintf(&b, "## [%s] %s\n\n", strings.ToUpper(sev), name)
		for i, h := range headers {
			fmt.Fprintf(&b, "%s\n\n", h)
			switch i {
			case 0:
				if f.Description != nil && *f.Description != "" {
					fmt.Fprintf(&b, "%s\n\n", *f.Description)
				} else {
					b.WriteString("_(describe the vulnerability)_\n\n")
				}
			case 1:
				if f.Evidence != nil && *f.Evidence != "" {
					fmt.Fprintf(&b, "```\n%s\n```\n\n", *f.Evidence)
				} else if f.URL != nil && *f.URL != "" {
					fmt.Fprintf(&b, "Affected URL: %s\n\n", *f.URL)
				} else {
					b.WriteString("_(reproduction steps)_\n\n")
				}
			case 2:
				b.WriteString("_(describe the business impact)_\n\n")
			default:
				b.WriteString("_(references, screenshots)_\n\n")
			}
		}
		b.WriteString("---\n\n")
	}
	return b.String()
}

// SortBySeverity orders findings critical → info, then host.
func SortBySeverity(fs []*store.Finding) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && lessFindings(fs[j], fs[j-1]); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func lessFindings(a, b *store.Finding) bool {
	sa, sb := "info", "info"
	if a.Severity != nil {
		sa = *a.Severity
	}
	if b.Severity != nil {
		sb = *b.Severity
	}
	if sevOrder[sa] != sevOrder[sb] {
		return sevOrder[sa] < sevOrder[sb]
	}
	return a.Host < b.Host
}
