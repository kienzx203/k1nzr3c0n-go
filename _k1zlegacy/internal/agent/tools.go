package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k1nzr3c0n/internal/runner"
	"k1nzr3c0n/internal/scope"
	"k1nzr3c0n/internal/store"
)

// SystemPrompt is the recon-agent persona, adapted from ScopeWeaver's
// independent pentest agent: it OPERATES the platform through tools instead
// of running commands itself.
const SystemPrompt = `You are the recon agent of an authorized penetration-testing platform (k1nzr3c0n). You operate the platform through TOOLS — you never run raw commands.

Operating discipline:
1. Start broad, then focus. For a new engagement: register the target (create_target with scope patterns), check what's already known (list_assets, list_findings), then launch the appropriate workflow (launch_run). The main pipeline "01-full-recon-pipeline.yaml" covers passive enum → DNS → ports → HTTP → crawl → vuln scan.
2. Monitor runs with get_run_status / get_run_logs (pass the run id). Long scans take minutes to hours — report progress, don't spam polls.
3. After completion, review findings (list_findings), ingest discovered hosts into the asset graph (insert_asset), and triage: mark false positives with patch_finding status="fp".
4. Only operate within the registered scope. Creating runs for out-of-scope targets will be refused (403). Respect that.
5. Bind captured HTTP evidence to findings (list_traffic + bind_evidence) when traffic proves a finding.
6. Report facts from actual tool returns — never invent results. Mark uncertainty explicitly.
7. Answer in the user's language. Be concise; summarize with hosts/counts, not raw dumps.

Workflow catalog: 01-full-recon-pipeline.yaml (full recon, ~95 steps), 02-js-secrets-recon.yaml (JS/secrets), 03-param-discovery.yaml (parameter discovery).`

// PentestSystemPrompt drives the standalone "Penetration testing" chat agent —
// an autonomous operator that plans, executes and validates through the platform.
const PentestSystemPrompt = `You are the autonomous Penetration Testing agent of an authorized platform (k1nzr3c0n). You independently handle an engagement end-to-end: reconnaissance, attack-surface discovery, exploitation, verification and wrap-up, through the platform's TOOLS.

Operating discipline:
1. Clarify scope first. Register/confirm the target (create_target with scope patterns) and respect it strictly — out-of-scope actions are refused (403).
2. For a goal-driven engagement, create an autonomous Task so the planner/worker engine explores the two-graph attack surface; monitor it and inject hints when useful.
3. For direct recon, launch the appropriate workflow (launch_run) and monitor it (get_run_status/get_run_logs).
4. Triage findings (list_findings, patch_finding), ingest assets (insert_asset), and bind HTTP evidence (list_traffic + bind_evidence) to proven findings.
5. Think adversarially: chain findings (entry → credentials → lateral → escalation). Verify before claiming — never invent results.
6. Answer in the user's language. Be concise; summarize with hosts/severities/counts.`

// ChatAgentPrompt returns the built-in system prompt for a chat agent key.
func ChatAgentPrompt(key string) string {
	switch key {
	case "pentest":
		return PentestSystemPrompt
	default: // "auto" and anything else → the platform assistant
		return SystemPrompt
	}
}

// Tools returns the tool catalog exposed to the LLM.
func Tools() []ToolDef {
	str := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	arr := func(desc string) map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
	}
	return []ToolDef{
		{Type: "function", Function: FunctionSpec{
			Name:        "list_skills",
			Description: "List available skill playbooks (procedural guidance packages).",
			Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "load_skill",
			Description: "Load one skill playbook and follow its instructions for the rest of this task.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"name": str("skill name from list_skills"),
			}, "required": []any{"name"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "list_workflows",
			Description: "List available workflow YAML files with step counts.",
			Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "create_target",
			Description: "Register a target with scope patterns and engagement mode. mode: bounty|vdp|oos. Scope patterns: 'example.com' covers all subdomains; '*.example.com' covers one-label subs.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"name":  str("primary domain, e.g. example.com"),
				"scope": arr("extra scope patterns"),
				"mode":  str("bounty | vdp | oos (default bounty)"),
			}, "required": []any{"name"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "scope_check",
			Description: "Check whether a host is in scope (deny-wins registry).",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"host": str("hostname to check"),
			}, "required": []any{"host"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "launch_run",
			Description: "Start a workflow run against a target. Returns run id + status. Optional vars override workflow defaults (e.g. nuclei_rl=50, run_screenshot=false).",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"workflow": str("workflow file name, e.g. 01-full-recon-pipeline.yaml"),
				"target":   str("scan target"),
				"vars":     map[string]any{"type": "object", "description": "optional var overrides (string values)"},
			}, "required": []any{"workflow", "target"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "get_run_status",
			Description: "Run status + per-step progress + findings count.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"run_id": str("run id from launch_run"),
			}, "required": []any{"run_id"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "get_run_logs",
			Description: "Tail run logs (default last 40 lines).",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"run_id": str("run id"),
				"limit":  map[string]any{"type": "integer", "description": "number of lines (default 40, max 200)"},
			}, "required": []any{"run_id"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "cancel_run",
			Description: "Cancel a queued/running run.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"run_id": str("run id"),
			}, "required": []any{"run_id"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "list_findings",
			Description: "Query findings. Filters optional. Returns structured intel (vuln/http/port/subdomain).",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"run_id":   str("filter by run"),
				"kind":     str("vuln|http|port|subdomain"),
				"severity": str("critical|high|medium|low|info"),
				"status":   str("open|fp|resolved"),
				"limit":    map[string]any{"type": "integer", "description": "default 50"},
			}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "patch_finding",
			Description: "Triage a finding: set status (open|fp|resolved) and/or notes.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"finding_id": map[string]any{"type": "integer"},
				"status":     str("open | fp | resolved"),
				"notes":      str("analyst notes"),
			}, "required": []any{"finding_id"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "list_assets",
			Description: "Query the asset graph (companies + assets: domain/subdomain/ip/port/site/endpoint).",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"q":    str("substring filter on value"),
				"type": str("domain|subdomain|ip|port|site|endpoint"),
			}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "list_untested_assets",
			Description: "Coverage: graph assets that have never appeared in any finding — the untested surface.",
			Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "insert_asset",
			Description: "Add an asset to the graph (idempotent by type+value).",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"type":  str("domain|subdomain|ip|port|site|endpoint"),
				"value": str("hostname / ip / url"),
				"meta":  str("optional JSON metadata: title, tech, status_code"),
			}, "required": []any{"type", "value"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "list_traffic",
			Description: "List captured HTTP traffic from the recording proxy (evidence for findings).",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"host": str("filter by host substring"),
			}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "bind_evidence",
			Description: "Bind a captured traffic pair to a finding as evidence.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"traffic_id": map[string]any{"type": "integer"},
				"finding_id": map[string]any{"type": "integer"},
			}, "required": []any{"traffic_id", "finding_id"}},
		}},
	}
}

// Exec dispatches one tool call against the platform. Returns a JSON string.
func Exec(st *store.Store, r *runner.Runner, call FunctionCall) string {
	var in map[string]any
	_ = json.Unmarshal([]byte(call.Arguments), &in)
	arg := func(k string) string {
		if v, ok := in[k].(string); ok {
			return v
		}
		return ""
	}
	argInt := func(k string, def int) int {
		if v, ok := in[k].(float64); ok {
			return int(v)
		}
		return def
	}
	fail := func(err error) string { b, _ := json.Marshal(map[string]any{"error": err.Error()}); return string(b) }
	okJSON := func(v any) string { b, _ := json.Marshal(v); return string(b) }

	switch call.Name {
	case "list_skills":
		var out []map[string]any
		for _, sk := range LoadSkillsDir() {
			out = append(out, map[string]any{"name": sk.Name, "description": sk.Description})
		}
		return okJSON(out)

	case "load_skill":
		want := arg("name")
		for _, sk := range LoadSkillsDir() {
			if sk.Name == want || strings.EqualFold(sk.Name, want) {
				st.InsertSkillUsage(sk.Name, "recon-agent", "", len(call.Arguments), true)
				return okJSON(map[string]any{"name": sk.Name, "instructions": sk.Instructions})
			}
		}
		st.InsertSkillUsage(want, "recon-agent", "", len(call.Arguments), false)
		return `{"error": "unknown skill ` + want + `"}`

	case "list_workflows":
		entries, err := os.ReadDir(workflowsDir())
		if err != nil {
			return fail(err)
		}
		var out []map[string]any
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
				out = append(out, map[string]any{"name": e.Name()})
			}
		}
		return okJSON(out)

	case "create_target":
		mode := arg("mode")
		if mode == "" {
			mode = "bounty"
		}
		var scopePat []string
		if arr, ok := in["scope"].([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					scopePat = append(scopePat, s)
				}
			}
		}
		t := &store.Target{Name: strings.ToLower(arg("name")), Mode: mode}
		if scopePat == nil {
			scopePat = []string{}
		}
		b, _ := json.Marshal(scopePat)
		t.ScopeJSON = string(b)
		if err := st.CreateTarget(t); err != nil {
			return fail(err)
		}
		return okJSON(map[string]any{"created": t.Name, "mode": mode, "scope": scopePat})

	case "scope_check":
		host := strings.ToLower(arg("host"))
		var coveredBy map[string]any
		reason := "unregistered — no scope defined"
		inScope, denied := false, false
		if t := scope.Covering(st, host); t != nil {
			coveredBy = map[string]any{"name": t.Name, "mode": t.Mode}
			if t.Mode == "oos" {
				denied = true
				reason = "marked out-of-scope"
			} else {
				inScope = true
				reason = "covered by " + t.Name
			}
		}
		return okJSON(map[string]any{"host": host, "in_scope": inScope, "denied": denied, "covered_by": coveredBy, "reason": reason})

	case "launch_run":
		vars := map[string]string{}
		if vm, ok := in["vars"].(map[string]any); ok {
			for k, v := range vm {
				vars[k] = fmt.Sprintf("%v", v)
			}
		}
		run, err := r.Launch(runner.LaunchInput{
			Workflow: arg("workflow"), Target: arg("target"), Vars: vars,
		})
		if err != nil {
			return fail(err)
		}
		return okJSON(map[string]any{"run_id": run.ID, "status": run.Status, "workflow": run.Workflow, "target": run.Target})

	case "get_run_status":
		run, err := st.GetRun(arg("run_id"))
		if err != nil {
			return fail(err)
		}
		totalLogs, _ := st.CountLogs(run.ID)
		_, findings, _ := st.ListFindings(store.FindingFilter{RunID: run.ID, Limit: 1})
		return okJSON(map[string]any{
			"run_id": run.ID, "status": run.Status, "workflow": run.Workflow, "target": run.Target,
			"steps": json.RawMessage(orDef(run.StepsJSON, "[]")), "total_logs": totalLogs, "findings": findings,
		})

	case "get_run_logs":
		limit := argInt("limit", 40)
		if limit > 200 {
			limit = 200
		}
		// fetch the LAST `limit` lines: probe total with an empty page first
		_, total, err := st.ListLogs(arg("run_id"), 0, 1)
		if err != nil {
			return fail(err)
		}
		offset := total - limit
		if offset < 0 {
			offset = 0
		}
		items, _, err := st.ListLogs(arg("run_id"), offset, limit)
		if err != nil {
			return fail(err)
		}
		return okJSON(map[string]any{"total": total, "lines": items})

	case "cancel_run":
		run, err := st.GetRun(arg("run_id"))
		if err != nil {
			return fail(err)
		}
		if run.Status == "queued" || run.Status == "running" {
			r.CancelRun(run.ID)
			_ = st.UpdateRunStatus(run.ID, "cancelled", map[string]any{"finished_at": store.SqlNow()})
		}
		return okJSON(map[string]any{"run_id": run.ID, "status": "cancelled"})

	case "list_findings":
		limit := argInt("limit", 50)
		items, total, err := st.ListFindings(store.FindingFilter{
			RunID: arg("run_id"), Kind: arg("kind"), Severity: arg("severity"), Status: arg("status"),
			Limit: limit,
		})
		if err != nil {
			return fail(err)
		}
		var out []map[string]any
		for _, f := range items {
			m := map[string]any{"id": f.ID, "kind": f.Kind, "host": f.Host, "status": f.Status}
			if f.Severity != nil {
				m["severity"] = *f.Severity
			}
			if f.Port != nil {
				m["port"] = *f.Port
			}
			if f.TemplateID != nil {
				m["template_id"] = *f.TemplateID
			}
			if f.URL != nil {
				m["url"] = *f.URL
			}
			if f.Title != nil {
				m["title"] = *f.Title
			}
			out = append(out, m)
		}
		return okJSON(map[string]any{"total": total, "items": out})

	case "patch_finding":
		var status, notes *string
		if s := arg("status"); s != "" {
			status = &s
		}
		if n := arg("notes"); n != "" {
			notes = &n
		}
		id := int64(argInt("finding_id", 0))
		if err := st.PatchFinding(id, status, notes, nil); err != nil {
			return fail(err)
		}
		return okJSON(map[string]any{"updated": id})

	case "list_assets":
		assets, err := st.ListAssetsGraph(store.GraphAssetFilter{Q: arg("q"), Type: arg("type")})
		if err != nil {
			return fail(err)
		}
		var out []map[string]any
		for _, a := range assets {
			out = append(out, map[string]any{"id": a.ID, "type": a.Type, "value": a.Value, "meta": json.RawMessage(orDef(a.Meta, "{}")), "source": a.Source})
		}
		return okJSON(map[string]any{"total": len(out), "items": out})

	case "list_untested_assets":
		un, err := st.UntestedAssets(50)
		if err != nil {
			return fail(err)
		}
		var out []map[string]any
		for _, a := range un {
			out = append(out, map[string]any{"type": a.Type, "value": a.Value})
		}
		return okJSON(map[string]any{"total": len(out), "items": out})

	case "insert_asset":
		meta := arg("meta")
		if meta == "" {
			meta = "{}"
		}
		a := store.Asset{Type: arg("type"), Value: arg("value"), Meta: meta, Source: "agent"}
		if err := st.UpsertAsset(&a); err != nil {
			return fail(err)
		}
		st.EnrichAssetDNS(a)
		return okJSON(map[string]any{"ok": true, "type": a.Type, "value": a.Value})

	case "list_traffic":
		items, err := st.ListTraffic(arg("host"), 50)
		if err != nil {
			return fail(err)
		}
		var out []map[string]any
		for _, t := range items {
			out = append(out, map[string]any{"id": t.ID, "host": t.Host, "method": t.Method, "path": t.Path, "status_code": t.StatusCode, "finding_id": t.FindingID})
		}
		return okJSON(map[string]any{"total": len(out), "items": out})

	case "bind_evidence":
		if err := st.BindTrafficEvidence(int64(argInt("traffic_id", 0)), int64(argInt("finding_id", 0))); err != nil {
			return fail(err)
		}
		return okJSON(map[string]any{"bound": true})
	}
	return `{"error": "unknown tool ` + call.Name + `"}`
}

func workflowsDir() string {
	return filepath.Join(baseDir(), "workflows")
}

func orDef(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
