// Package notify sends Discord/Slack webhooks (run completion, new assets,
// critical findings). Format auto-detects from the URL.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"k1nzr3c0n/internal/config"
	"k1nzr3c0n/internal/store"
)

type field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func send(payload map[string]any) {
	url := config.WebhookURL()
	if url == "" {
		return
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return
	}
	resp.Body.Close()
}

func isDiscord() bool { return strings.Contains(config.WebhookURL(), "discord.com") }

// RunFinished fires the run-completion webhook (title, fields, color).
func RunFinished(st *store.Store, run *store.Run, status string) {
	time.Sleep(10 * time.Second) // let parse_findings settle (countdown=10 parity)
	icon := "✅"
	color := "good"
	icolor := 0x3FB950
	if status != "completed" {
		icon = "❌"
		color = "danger"
		icolor = 0xF85149
	}
	_, totalFindings, _ := st.ListFindings(store.FindingFilter{RunID: run.ID, Limit: 1})
	duration := ""
	if !run.StartedAt.IsZero() && !run.FinishedAt.IsZero() {
		secs := run.FinishedAt.Sub(run.StartedAt).Seconds()
		if secs < 60 {
			duration = fmt.Sprintf("%.0fs", secs)
		} else {
			duration = (time.Duration(secs) * time.Second).Round(time.Second).String()
		}
	} else if !run.StartedAt.IsZero() {
		duration = time.Since(run.StartedAt).Round(time.Second).String()
	}
	title := fmt.Sprintf("%s k1nzr3c0n · %s", icon, strings.ToUpper(status))
	fields := []field{
		{"Target", fmt.Sprintf("**%s**", run.Target), true},
		{"Workflow", fmt.Sprintf("`%s`", run.Workflow), true},
		{"Duration", fmt.Sprintf("**%s**", duration), true},
		{"Findings", fmt.Sprintf("**%d**", totalFindings), true},
		{"Run ID", fmt.Sprintf("`%s`", run.ID), true},
	}
	desc := strings.Builder{}
	for _, f := range fields {
		desc.WriteString(fmt.Sprintf("**%s:** %s\n", f.Name, f.Value))
	}
	if isDiscord() {
		send(map[string]any{
			"embeds": []map[string]any{{
				"title":       title,
				"description": desc.String(),
				"color":       icolor,
				"footer":      map[string]string{"text": "k1nzr3c0n"},
			}},
		})
	} else {
		var slackFields []map[string]any
		for _, f := range fields {
			slackFields = append(slackFields, map[string]any{
				"title": f.Name, "value": f.Value, "short": f.Short,
			})
		}
		send(map[string]any{
			"username":    config.WebhookUsername(),
			"attachments": []map[string]any{{"title": title, "text": strings.ReplaceAll(desc.String(), "**", ""), "fields": slackFields, "color": color, "footer": "k1nzr3c0n"}},
		})
	}
}

// NewAssets fires the 🆕 alert (green) with up to 15 hosts.
func NewAssets(target, runID, workflow string, hosts []string) {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("**Target:** **%s**\n", target))
	b.WriteString(fmt.Sprintf("**Run:** `%s` (`%s`)\n", runID, workflow))
	shown := hosts
	if len(shown) > 15 {
		shown = shown[:15]
	}
	for _, h := range shown {
		b.WriteString(fmt.Sprintf("`%s`\n", h))
	}
	if len(hosts) > 15 {
		b.WriteString(fmt.Sprintf("… and %d more", len(hosts)-15))
	}
	title := fmt.Sprintf("🆕 k1nzr3c0n · %d NEW ASSETS", len(hosts))
	sendMessage(title, b.String(), true)
}

// CriticalFindings fires the 🚨 alert (red) with up to 8 rows.
func CriticalFindings(crit, high int, rows []string) {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("**%d critical · %d high**\n", crit, high))
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	sendMessage(fmt.Sprintf("🚨 k1nzr3c0n · CRITICAL/HIGH FINDINGS"), b.String(), false)
}

func sendMessage(title, body string, ok bool) {
	if isDiscord() {
		color := 0xF85149
		if ok {
			color = 0x3FB950
		}
		send(map[string]any{
			"embeds": []map[string]any{{
				"title":       title,
				"description": body,
				"color":       color,
				"footer":      map[string]string{"text": "k1nzr3c0n"},
			}},
		})
	} else {
		color := "danger"
		if ok {
			color = "good"
		}
		send(map[string]any{
			"username":    config.WebhookUsername(),
			"attachments": []map[string]any{{"title": title, "text": strings.ReplaceAll(body, "**", ""), "color": color, "footer": "k1nzr3c0n"}},
		})
	}
}
