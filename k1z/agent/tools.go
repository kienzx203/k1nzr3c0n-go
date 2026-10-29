package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/k1z/runner"
	"github.com/Autumn-27/artex/k1z/store"
	"github.com/Autumn-27/artex/k1z/targetgraph"
)

// SystemPrompt is the recon-agent persona, adapted from ScopeWeaver's
// independent pentest agent: it OPERATES the platform through tools instead
// of running commands itself.
const SystemPrompt = `You are the recon agent of an authorized penetration-testing platform (k1nzr3c0n). You operate the platform through TOOLS — you never run raw commands.

Division of labour: the OPERATOR runs reconnaissance workflows MANUALLY. Your job is to LOOK UP and ANALYSE each target from the data those scans produced — not to orchestrate scans.

Operating discipline:
1. To investigate a target, start with read_target_graph(target): it returns the FULL relationship map — hosts ↔ IPs ↔ ports ↔ ASN/subnet ↔ URLs/paths ↔ params ↔ findings, plus domain-level buckets/secrets/certs/dns/intel and counts. Use its q (search) / node (expand one node) options to drill in.
2. Read what the operator's scans did with get_target_logs(target) (aggregated across that target's runs), or get_run_logs(run_id) for one specific run; get_run_status for progress.
3. Review and triage findings (list_findings, patch_finding status="fp"), ingest hosts (insert_asset), and bind HTTP evidence (list_traffic + bind_evidence) when traffic proves a finding.
4. Targets are added by the operator and need NO scope check — create_target just registers one if asked. There is no out-of-scope refusal.
5. Do NOT launch workflows on your own. Call launch_run / cancel_run ONLY when the operator explicitly asks you to.
6. Report facts from actual tool returns — never invent results. Mark uncertainty explicitly.
7. Answer in the user's language. Be concise; summarize with hosts/counts, not raw dumps.

Workflow catalog (the operator runs these manually): 01-full-recon-pipeline.yaml (full recon + vuln scan), 02-full-recon-artex.yaml (full recon, NO vuln scan), 03-js-secrets-recon.yaml (JS/secrets), 04-param-discovery.yaml (parameter discovery).`

// PentestSystemPrompt drives the standalone "Penetration testing" chat agent —
// an autonomous operator that plans, executes and validates through the platform.
const PentestSystemPrompt = `You are the penetration-testing analysis agent of an authorized platform (k1nzr3c0n). The OPERATOR runs reconnaissance workflows MANUALLY; you investigate, correlate and advise over the data they produce, through the platform's TOOLS.

Operating discipline:
1. Investigate a target with read_target_graph(target) — the full host ↔ ip ↔ port ↔ asn/subnet ↔ url/path ↔ param ↔ finding relationship map (plus buckets/secrets/certs/dns/intel). Drill in with q=<search> or node=<id>; read scan activity with get_target_logs(target) or get_run_logs(run_id).
2. Triage findings (list_findings, patch_finding), ingest assets (insert_asset), and bind HTTP evidence (list_traffic + bind_evidence) to proven findings.
3. Think adversarially: chain findings (entry → credentials → lateral → escalation) using the relationship map. Verify before claiming — never invent results.
4. Targets are operator-asserted — there is NO scope gate. Do NOT launch workflows yourself; call launch_run only when the operator explicitly asks.
5. Answer in the user's language. Be concise; summarize with hosts/severities/counts.`

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
			Description: "Tail ONE run's logs by run id (default last 40 lines).",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"run_id": str("run id"),
				"limit":  map[string]any{"type": "integer", "description": "number of lines (default 40, max 200)"},
			}, "required": []any{"run_id"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "read_target_graph",
			Description: "PRIMARY per-target lookup. Returns the FULL attack-surface relationship map for a target: every host with its IPs/ports/provider/URLs/paths/params/findings, every IP with its ASN/subnet/hosts, plus domain-level buckets/secrets/certs/dns/intel, node counts by type and findings-by-severity. Optional q also searches node labels; optional node returns one node's neighbours.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"target": str("the target host, e.g. example.com (scheme/path/port are ignored)"),
				"q":      str("optional: also return nodes whose label/id contains this substring"),
				"node":   str("optional: a node id to expand (returns its immediate neighbours)"),
			}, "required": []any{"target"}},
		}},
		{Type: "function", Function: FunctionSpec{
			Name:        "get_target_logs",
			Description: "Aggregate the most recent run logs ACROSS all of a target's runs (newest run first). Use this to read what the manually-launched workflows did for a target, without needing a run id.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{
				"target": str("the target host"),
				"grep":   str("optional: only lines containing this substring"),
				"limit":  map[string]any{"type": "integer", "description": "number of lines (default 60, max 200)"},
			}, "required": []any{"target"}},
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

	case "read_target_graph":
		g, code, err := targetgraph.For(st, arg("target"))
		if err != nil {
			return okJSON(map[string]any{"target": targetgraph.NormTarget(arg("target")), "status": code, "error": err.Error()})
		}
		out := map[string]any{"map": g.TargetMap(0)}
		if q := arg("q"); q != "" {
			out["search"] = g.Search(q, 0)
		}
		if node := arg("node"); node != "" {
			out["neighbors"] = g.Neighbors(node, 200)
		}
		return okJSON(out)

	case "get_target_logs":
		target := targetgraph.NormTarget(arg("target"))
		grep := strings.ToLower(arg("grep"))
		limit := argInt("limit", 60)
		if limit > 200 {
			limit = 200
		} else if limit < 1 {
			limit = 60
		}
		runs, _, err := st.ListRuns(store.RunFilter{Limit: 200})
		if err != nil {
			return fail(err)
		}
		var tr []*store.Run
		for _, run := range runs {
			if targetgraph.NormTarget(run.Target) == target {
				tr = append(tr, run)
			}
		}
		sort.Slice(tr, func(i, j int) bool { return tr[i].CreatedAt.After(tr[j].CreatedAt) })
		win := limit
		if grep != "" {
			win = 1000 // scan a wider window per run so the filter has material
		}
		var lines []map[string]string
		for _, run := range tr {
			if len(lines) >= limit {
				break
			}
			_, total, e := st.ListLogs(run.ID, 0, 1)
			if e != nil {
				continue
			}
			off := total - win
			if off < 0 {
				off = 0
			}
			msgs, _, e2 := st.ListLogs(run.ID, off, win)
			if e2 != nil {
				continue
			}
			for i := len(msgs) - 1; i >= 0 && len(lines) < limit; i-- { // newest line first
				if grep != "" && !strings.Contains(strings.ToLower(msgs[i]), grep) {
					continue
				}
				lines = append(lines, map[string]string{"run": run.ID, "msg": msgs[i]})
			}
		}
		return okJSON(map[string]any{"target": target, "runs": len(tr), "lines": lines})

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
