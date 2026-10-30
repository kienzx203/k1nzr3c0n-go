package server

// Integration B/C: tools that let an ARTEX worker read (and optionally drive) the
// Workflow Runner (k1z) which is mounted on the same binary. They call the local
// /api/v1 over localhost so there is no cross-DB coupling. All read tools are
// read-only + concurrency-safe; guardPanic (agent/assembly.go) already turns any
// handler panic into a plain tool error, so these can't crash the engine.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// ReconAPIBase is the base URL of the mounted k1z API. Default is overridden by
// SetReconAPIBase(addr) from main (the server's own listen addr) or RECON_API_BASE.
var ReconAPIBase = "http://127.0.0.1:8787"

func init() {
	if v := os.Getenv("RECON_API_BASE"); v != "" {
		ReconAPIBase = v
	}
}

// SetReconAPIBase derives the localhost base URL from the server's listen addr
// (e.g. ":8000" or "0.0.0.0:8000" → http://127.0.0.1:8000). Env wins if set.
func SetReconAPIBase(addr string) {
	if os.Getenv("RECON_API_BASE") != "" {
		return
	}
	port := "8787"
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		port = p
	}
	ReconAPIBase = "http://127.0.0.1:" + port
}

func reconHTTP(ctx context.Context, method, path string, body io.Reader) actool.Result {
	req, err := http.NewRequestWithContext(ctx, method, ReconAPIBase+path, body)
	if err != nil {
		return actool.Errorf("recon request: " + err.Error())
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return actool.Errorf("recon call failed: " + err.Error())
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return actool.Errorf(fmt.Sprintf("recon API %d: %s", resp.StatusCode, strings.TrimSpace(string(data))))
	}
	return actool.Text(string(data))
}

func reconReadTool(name, desc string, schema map[string]any, path func(json.RawMessage) string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return reconHTTP(ctx, "GET", path(in), nil), nil
		},
	})
}

func rtStr(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
func rtInt(d string) map[string]any { return map[string]any{"type": "integer", "description": d} }
func rtObj(props map[string]any, req ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(req) > 0 {
		m["required"] = req
	}
	return m
}

// reconTools: read-only lookups into existing Workflow-Runner recon results so the
// worker reuses the mapped surface instead of re-scanning (integration B).
func reconTools() []actool.CoreTool {
	return []actool.CoreTool{
		reconReadTool("recon_findings",
			"Read EXISTING recon findings from the Workflow Runner for a host/domain (kinds: vuln, http, port, subdomain, url). Call this BEFORE scanning — the surface may already be mapped by a prior workflow run.",
			rtObj(map[string]any{
				"target":   rtStr("host or domain to filter (substring), e.g. example.com"),
				"kind":     rtStr("optional: vuln|http|port|subdomain|url"),
				"severity": rtStr("optional: critical|high|medium|low|info (vuln only)"),
				"limit":    rtInt("max rows (default 200)"),
			}, "target"),
			func(in json.RawMessage) string {
				var p struct {
					Target   string `json:"target"`
					Kind     string `json:"kind"`
					Severity string `json:"severity"`
					Limit    int    `json:"limit"`
				}
				_ = json.Unmarshal(in, &p)
				if p.Limit <= 0 {
					p.Limit = 200
				}
				q := url.Values{}
				q.Set("host", p.Target)
				q.Set("limit", fmt.Sprint(p.Limit))
				if p.Kind != "" {
					q.Set("kind", p.Kind)
				}
				if p.Severity != "" {
					q.Set("severity", p.Severity)
				}
				return "/api/v1/findings?" + q.Encode()
			}),
		reconReadTool("recon_assets",
			"List cross-run HTTP assets (live hosts: status, title, tech, IP, port) that the Workflow Runner discovered for a target/company.",
			rtObj(map[string]any{
				"target": rtStr("domain/company to filter, e.g. example.com"),
				"limit":  rtInt("max rows (default 500)"),
			}, "target"),
			func(in json.RawMessage) string {
				var p struct {
					Target string `json:"target"`
					Limit  int    `json:"limit"`
				}
				_ = json.Unmarshal(in, &p)
				if p.Limit <= 0 {
					p.Limit = 500
				}
				q := url.Values{}
				q.Set("q", p.Target)
				q.Set("limit", fmt.Sprint(p.Limit))
				return "/api/v1/assets?" + q.Encode()
			}),
		reconReadTool("recon_graph",
			"Read the attack-surface RELATIONSHIP MAP for a target — 4 modes, cheapest first (prefer narrow reads; the full map of a big target is huge):\n"+
				"• summary=true → ONLY node counts by type + findings-by-severity. START HERE to size the surface cheaply, then drill.\n"+
				"• q=<text> → SEARCH: matching nodes (host/ip/url/param/finding…) as a flat list. Use to find e.g. admin panels, a specific host, a param — token-light.\n"+
				"• node=<id> → DRILL ONE node and its neighbours (ids come from a prior map/search, e.g. h:example.com, ip:1.2.3.4). Walk pivots/chains step by step.\n"+
				"• (none) → FULL map: every host with its IPs/ports/provider/URLs/paths/params/findings, every IP with ASN/subnet/hosts, plus domain buckets/secrets/certs/dns/intel. Bounded by hosts (default 400, highest-risk first); a `truncated` map reports what was dropped — narrow with q/node instead of raising it.\n"+
				"RUN DELTA: pass run_id=<id> to scope ANY mode to the surface THAT ONE run produced (rebuilt live per finished step) — follow a run with run_log, then recon_graph(run_id, summary) to see what it just added, instead of re-reading the whole target map. Omit run_id for the target-wide graph (every run merged).\n"+
				"Call again as new runs finish (it rebuilds live per completed step). Exhaustive flat lists: recon_findings/recon_assets; live run progress: run_log.",
			rtObj(map[string]any{
				"target":  rtStr("the target host/domain, e.g. example.com (scheme/path/port are ignored). Ignored when run_id is set."),
				"run_id":  rtStr("optional: scope the graph to just this run's surface (its delta), rebuilt live per step. From run_workflow/recon_runs."),
				"summary": map[string]any{"type": "boolean", "description": "true = cheap overview only (counts by type + findings-by-severity). Start here."},
				"q":       rtStr("search text → return only matching nodes as a flat list (token-light)"),
				"node":    rtStr("a node id (e.g. h:host, ip:1.2.3.4) → return just that node + its neighbours"),
				"hosts":   rtInt("full-map mode only: max hosts, highest-risk first (default 400)"),
				"limit":   rtInt("q/node modes: max rows (search default 50, neighbours default 200)"),
			}, "target"),
			func(in json.RawMessage) string {
				var p struct {
					Target  string `json:"target"`
					RunID   string `json:"run_id"`
					Summary bool   `json:"summary"`
					Q       string `json:"q"`
					Node    string `json:"node"`
					Hosts   int    `json:"hosts"`
					Limit   int    `json:"limit"`
				}
				_ = json.Unmarshal(in, &p)
				base := "/api/v1/targets/" + url.PathEscape(p.Target) + "/graph2"
				if strings.TrimSpace(p.RunID) != "" { // run-scoped delta
					base = "/api/v1/runs/" + url.PathEscape(p.RunID) + "/graph2"
				}
				switch {
				case p.Summary:
					return base + "/stats"
				case strings.TrimSpace(p.Node) != "":
					lim := p.Limit
					if lim <= 0 {
						lim = 200
					}
					return base + "/neighbors?id=" + url.QueryEscape(p.Node) + "&limit=" + fmt.Sprint(lim)
				case strings.TrimSpace(p.Q) != "":
					lim := p.Limit
					if lim <= 0 {
						lim = 50
					}
					return base + "/search?q=" + url.QueryEscape(p.Q) + "&limit=" + fmt.Sprint(lim)
				default:
					if p.Hosts <= 0 {
						p.Hosts = 400
					}
					return base + "/map?hosts=" + fmt.Sprint(p.Hosts)
				}
			}),
		reconReadTool("run_status",
			"Check a Workflow Runner run's progress (status, step counts, findings so far). Poll after run_workflow until status is completed/failed/paused, then read results with recon_findings/recon_assets.",
			rtObj(map[string]any{"run_id": rtStr("the run id returned by run_workflow")}, "run_id"),
			func(in json.RawMessage) string {
				var p struct {
					RunID string `json:"run_id"`
				}
				_ = json.Unmarshal(in, &p)
				return "/api/v1/runs/" + url.PathEscape(p.RunID)
			}),
		reconReadTool("run_log",
			"Follow a run's LIVE log while it runs, concurrently with your other recon. By DEFAULT returns ONLY the progress skeleton (step start/done, per-step one-line stats, warnings) — cheap to tail; the thousands of raw per-tool records (httpx/tlsx JSON) are withheld unless raw=true. To TAIL only new lines, pass the previous response's `total` as `offset`. Returns {total, offset, limit, items:[line,...]} (total/offset count ALL lines, so advance offset by your limit each poll). For the cheapest progress check use run_status; use raw=true only to inspect one step's detailed output. Structured results: recon_findings/recon_assets.",
			rtObj(map[string]any{
				"run_id": rtStr("the run id returned by run_workflow"),
				"offset": rtInt("line offset to start from; to tail only new lines, pass the previous response's total (default 0)"),
				"limit":  rtInt("max lines to scan this poll (default 500, max 2000)"),
				"raw":    map[string]any{"type": "boolean", "description": "default false: progress/stat/warning lines only (cheap). true: include the full raw per-tool output (httpx/tlsx/naabu records) — only when inspecting one step, and keep the limit small."},
			}, "run_id"),
			func(in json.RawMessage) string {
				var p struct {
					RunID  string `json:"run_id"`
					Offset int    `json:"offset"`
					Limit  int    `json:"limit"`
					Raw    bool   `json:"raw"`
				}
				_ = json.Unmarshal(in, &p)
				q := url.Values{}
				if p.Offset > 0 {
					q.Set("offset", fmt.Sprint(p.Offset))
				}
				if p.Limit > 0 {
					q.Set("limit", fmt.Sprint(p.Limit))
				}
				if !p.Raw {
					q.Set("progress", "1") // default: withhold raw per-tool records
				}
				u := "/api/v1/runs/" + url.PathEscape(p.RunID) + "/logs"
				if e := q.Encode(); e != "" {
					u += "?" + e
				}
				return u
			}),
		reconReadTool("list_workflows",
			"List the recon workflows available to run_workflow, each with a description. Call this FIRST to pick the workflow(s) that fit the current situation — then run_workflow the ones you need (you can run several). Pick by purpose: broad surface mapping, JS/secrets, parameter discovery, etc.",
			rtObj(map[string]any{}),
			func(json.RawMessage) string { return "/api/v1/workflows?detail=1" }),
		reconDescribeWorkflow(),
		reconRunWorkflow(),
		reconListRuns(),
		reconStopWorkflow(),
		reconGraphNote(),
	}
}

// reconGraphNote is the agent's WRITE channel into the attack-surface graph (every
// other recon_* graph tool is read-only): pin a note + priority tag on a node so
// the lead persists — it shows in the graph viewer, survives context compaction,
// and is readable later. With no node it LISTS the target's annotations.
func reconGraphNote() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "graph_note",
		Description: "Write a NOTE and/or priority TAG back onto a graph node so the lead persists (shown in the graph viewer, survives compaction, readable later). Record a lead on a node — e.g. node=h:admin.example.com, tag=priority, note='login panel, default-cred + SQLi candidate'. Node ids come from recon_graph (h:host, ip:1.2.3.4, u:url, p:param, f:finding…). Empty tag AND note on an existing node deletes its annotation. With NO node, it LISTS every annotation for the target (recover your own pinned leads after a compaction). recon_graph reads the surface; graph_note is how you mark it.",
		Schema: rtObj(map[string]any{
			"target": rtStr("the target host/domain the node belongs to, e.g. example.com"),
			"node":   rtStr("node id to annotate (h:host, ip:1.2.3.4, u:url, p:param, f:finding…). Omit to LIST all annotations for the target."),
			"tag":    rtStr("optional short tag, e.g. priority|owned|verified|false-positive|revisit"),
			"note":   rtStr("optional free note (≤4000 chars). Empty tag+note on an existing node removes its annotation."),
		}, "target"),
		ReadOnly: func(in json.RawMessage) bool {
			var p struct {
				Node string `json:"node"`
			}
			_ = json.Unmarshal(in, &p)
			return strings.TrimSpace(p.Node) == "" // listing is read-only; writing is not
		},
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p struct {
				Target string `json:"target"`
				Node   string `json:"node"`
				Tag    string `json:"tag"`
				Note   string `json:"note"`
			}
			_ = json.Unmarshal(in, &p)
			if strings.TrimSpace(p.Target) == "" {
				return actool.Errorf("target required"), nil
			}
			base := "/api/v1/targets/" + url.PathEscape(p.Target) + "/graph2/annotations"
			if strings.TrimSpace(p.Node) == "" {
				return reconHTTP(ctx, "GET", base, nil), nil // list
			}
			body, _ := json.Marshal(map[string]string{"id": p.Node, "tag": p.Tag, "note": p.Note})
			return reconHTTP(ctx, "POST", base, bytes.NewReader(body)), nil
		},
	})
}

// reconDescribeWorkflow exposes ONE workflow's tunable variables (its run_* toggles,
// wordlists, threads, auth/session vars, …) + description + step count, so the agent
// can run a TARGETED or STEALTH variant (set specific vars + full=false) instead of
// always launching the max-coverage default. Trimmed: it never dumps the hundreds of
// raw steps — only their count.
func reconDescribeWorkflow() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "describe_workflow",
		Description: "Show ONE workflow's tunable variables (vars) + description + step count, so you can run a TARGETED/STEALTH variant: set specific vars and pass full=false to run_workflow (otherwise full=true turns every option on). E.g. a param-discovery workflow exposes session_cookie/auth_header/method; a full-recon workflow exposes run_portscan/run_nuclei/run_screenshot toggles you can switch off to stay quiet. Pick the workflow name from list_workflows.",
		Schema: rtObj(map[string]any{
			"workflow": rtStr("workflow file name, e.g. 01-full-recon-pipeline.yaml"),
		}, "workflow"),
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p struct {
				Workflow string `json:"workflow"`
			}
			_ = json.Unmarshal(in, &p)
			if strings.TrimSpace(p.Workflow) == "" {
				return actool.Errorf("workflow is required"), nil
			}
			data, code, err := reconRaw(ctx, "GET", "/api/v1/workflows/"+url.PathEscape(p.Workflow), nil)
			if err != nil || code != 200 {
				return actool.Errorf(fmt.Sprintf("describe_workflow: workflow %q not found (HTTP %d)", p.Workflow, code)), nil
			}
			var wf struct {
				Name        string         `json:"name"`
				Description string         `json:"description"`
				Vars        map[string]any `json:"vars"`
				Steps       []any          `json:"steps"`
			}
			if json.Unmarshal(data, &wf) != nil {
				return actool.Errorf("describe_workflow: could not parse workflow"), nil
			}
			body, _ := json.Marshal(map[string]any{
				"workflow": p.Workflow, "name": wf.Name, "description": wf.Description,
				"vars": wf.Vars, "step_count": len(wf.Steps),
			})
			return actool.Text(string(body)), nil
		},
	})
}

// reconStopWorkflow lets the agent CANCEL a running workflow (wrong one launched, a
// run gone out of scope, or the operator said stop). Without this the agent could
// launch but never stop a run.
func reconStopWorkflow() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "stop_workflow",
		Description: "Cancel a running Workflow Runner run by run_id (e.g. you launched the wrong workflow, a run is drifting out of scope, or the operator said stop). Use recon_runs(target, status=running) to find the run_id if you lost it. Irreversible for that run; relaunch with run_workflow if needed.",
		Schema: rtObj(map[string]any{
			"run_id": rtStr("the run id to cancel (from run_workflow / recon_runs)"),
		}, "run_id"),
		ReadOnly:   func(json.RawMessage) bool { return false },
		Concurrent: func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p struct {
				RunID string `json:"run_id"`
			}
			_ = json.Unmarshal(in, &p)
			if strings.TrimSpace(p.RunID) == "" {
				return actool.Errorf("run_id is required"), nil
			}
			data, code, err := reconRaw(ctx, "POST", "/api/v1/runs/"+url.PathEscape(p.RunID)+"/cancel", nil)
			if err != nil {
				return actool.Errorf("stop_workflow failed: " + err.Error()), nil
			}
			if code >= 300 {
				return actool.Errorf(fmt.Sprintf("stop_workflow failed (HTTP %d): %s", code, strings.TrimSpace(string(data)))), nil
			}
			return actool.Text(fmt.Sprintf("Run %s cancelled. %s", p.RunID, strings.TrimSpace(string(data)))), nil
		},
	})
}

// normHost canonicalises a target to its bare lowercase host (no scheme/path/port),
// mirroring targetgraph.NormTarget so "https://x", "x" and "x:443" all match one
// target. Kept inline to avoid pulling the k1z graph packages into server.
func normHost(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if !strings.Contains(t, "]") {
		if i := strings.IndexByte(t, ':'); i >= 0 {
			t = t[:i]
		}
	}
	return strings.ToLower(strings.TrimSuffix(t, "."))
}

// reconListRuns lets the agent RE-DISCOVER a target's runs (id/workflow/status)
// after it loses a run_id to a context compaction — so "don't wrap up while a run
// is unread" survives. Filters the runs list by normalised target and returns a
// compact list (not the heavy steps/vars blobs).
func reconListRuns() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "recon_runs",
		Description: "List this target's Workflow Runner runs (most recent first) as {run_id, workflow, status, started, finished}. USE IT to recover a run_id you lost (e.g. after a context compaction) so you can keep following an in-flight run with run_status/run_log, or to see what recon already ran. Filter by status (e.g. running) to find what is still in flight. This is how you make sure no launched run is left unread.",
		Schema: rtObj(map[string]any{
			"target": rtStr("target host/domain to filter by (scheme/path/port ignored)"),
			"status": rtStr("optional: only runs in this status (queued/running/completed/failed/paused)"),
			"limit":  rtInt("max runs to scan (default 50, max 200)"),
		}, "target"),
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p struct {
				Target string `json:"target"`
				Status string `json:"status"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &p)
			if p.Limit <= 0 {
				p.Limit = 50
			}
			if p.Limit > 200 {
				p.Limit = 200
			}
			q := url.Values{}
			q.Set("limit", fmt.Sprint(p.Limit))
			if p.Status != "" {
				q.Set("status", p.Status)
			}
			data, code, err := reconRaw(ctx, "GET", "/api/v1/runs?"+q.Encode(), nil)
			if err != nil || code != 200 {
				return actool.Errorf(fmt.Sprintf("recon_runs failed (HTTP %d)", code)), nil
			}
			var resp struct {
				Items []struct {
					ID         string `json:"id"`
					Workflow   string `json:"workflow"`
					Target     string `json:"target"`
					Status     string `json:"status"`
					StartedAt  any    `json:"started_at"`
					FinishedAt any    `json:"finished_at"`
				} `json:"items"`
			}
			if json.Unmarshal(data, &resp) != nil {
				return actool.Errorf("recon_runs: could not parse runs"), nil
			}
			want := normHost(p.Target)
			type runRow struct {
				RunID    string `json:"run_id"`
				Workflow string `json:"workflow"`
				Status   string `json:"status"`
				Started  any    `json:"started"`
				Finished any    `json:"finished"`
			}
			out := []runRow{}
			for _, it := range resp.Items {
				if normHost(it.Target) != want {
					continue
				}
				out = append(out, runRow{it.ID, it.Workflow, it.Status, it.StartedAt, it.FinishedAt})
			}
			body, _ := json.Marshal(map[string]any{"target": want, "count": len(out), "runs": out})
			return actool.Text(string(body)), nil
		},
	})
}

// targetExists reports whether a target is registered (so it carries a deny-wins
// scope). Autonomous scans are only allowed against registered targets.
func targetExists(ctx context.Context, name string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", ReconAPIBase+"/api/v1/targets/"+url.PathEscape(name), nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode == 200
}

// reconRunWorkflow (integration C): let the worker launch a recon workflow against
// a REGISTERED target. Write tool; scope-guarded to registered targets only.
const runWorkflowWaitCap = 3 * time.Hour // block until the run finishes so the task reads the COMPLETE brief before continuing; push-back only covers a pathological overrun

// reconRaw is a raw HTTP call to the local k1z API returning (body, status, err),
// used where the tool needs to parse the response (run id) rather than surface it.
func reconRaw(ctx context.Context, method, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, ReconAPIBase+path, body)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, nil
}

// reconPollRun blocks until the run reaches a terminal state, or the cap / ctx
// expires. Returns ("completed", nil) on success; (status, err) on a bad terminal
// state; ("", context.DeadlineExceeded) on cap/ctx timeout; ("", context.Canceled)
// on cancel.
func reconPollRun(ctx context.Context, runID string, cap time.Duration) (string, error) {
	deadline := time.Now().Add(cap)
	for {
		data, code, err := reconRaw(ctx, "GET", "/api/v1/runs/"+url.PathEscape(runID), nil)
		if err == nil && code < 300 {
			var r struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(data, &r)
			switch strings.ToLower(r.Status) {
			case "completed", "done", "finished", "success":
				return "completed", nil
			case "failed", "error", "cancelled", "canceled", "paused", "timeout":
				return r.Status, fmt.Errorf("run %s ended with status %s", runID, r.Status)
			}
		}
		if time.Now().After(deadline) {
			return "", context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
}

func reconBriefMarkdown(data []byte) string {
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		var r struct {
			Markdown string `json:"markdown"`
		}
		if json.Unmarshal(data, &r) == nil && strings.TrimSpace(r.Markdown) != "" {
			return r.Markdown
		}
	}
	return string(data)
}

// fullOptionExclude: boolean toggles that stay at their workflow default even in
// "full options" mode — the operator opted these out as too aggressive/out-of-scope:
// the pivot scan and the PTR sweep of neighboring /24 CIDR blocks.
var fullOptionExclude = map[string]bool{
	"run_st_pivot_scan": true, // pivot scan
	"pivot_rescan_all":  true, // re-scan ALL pivots
	"run_ip_pivot":      true, // mapcidr PTR sweep of neighboring /24 (touches out-of-scope IPs)
}

// maxWorkflowVars returns var overrides that turn ON every boolean toggle a
// workflow defines (its run_* / pivot options) EXCEPT the fullOptionExclude set,
// so a run exercises nearly all options — including the heavier ones (favicon/vhost
// pivot, recursive, active amass) that ship disabled by default — while leaving the
// opted-out pivot/neighbor-CIDR scans off. Workflow-agnostic: it reads the
// workflow's own vars, so new workflows are covered automatically.
func maxWorkflowVars(ctx context.Context, workflow string) []string {
	data, code, err := reconRaw(ctx, "GET", "/api/v1/workflows/"+url.PathEscape(workflow), nil)
	if err != nil || code >= 300 {
		return nil
	}
	var parsed struct {
		Vars map[string]any `json:"vars"`
	}
	if json.Unmarshal(data, &parsed) != nil {
		return nil
	}
	var out []string
	for k, v := range parsed.Vars {
		if fullOptionExclude[k] {
			continue // leave at the workflow's default (operator opted out)
		}
		if sv, ok := v.(string); ok && (sv == "true" || sv == "false") {
			out = append(out, k+"=true")
		}
	}
	return out
}

// mergeMaxVars appends the workflow's max-option overrides to vars, without
// clobbering any key the caller already set.
func mergeMaxVars(ctx context.Context, workflow string, vars []string) []string {
	have := map[string]bool{}
	for _, kv := range vars {
		if i := strings.IndexByte(kv, '='); i > 0 {
			have[kv[:i]] = true
		}
	}
	for _, kv := range maxWorkflowVars(ctx, workflow) {
		if i := strings.IndexByte(kv, '='); i > 0 && !have[kv[:i]] {
			vars = append(vars, kv)
		}
	}
	return vars
}

func reconRunWorkflow() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "run_workflow",
		Description: "Launch a Workflow Runner recon workflow against a REGISTERED target (a deny-wins scope must already exist for it). By DEFAULT it is NON-BLOCKING: it returns a run_id immediately and the workflow runs CONCURRENTLY while you keep reconning — follow it in REAL TIME with run_log(run_id) (tail the step output) and run_status(run_id), and read recon_findings/recon_assets as results land. The full brief is ALSO pushed back into the task when the run finishes, so nothing is missed — but do not wrap up while a run is still unread. Pass wait=true to block until it finishes and get the brief inline instead. CHOOSE the workflow via list_workflows. Check recon_findings first — only run recon you don't already have.",
		Schema: rtObj(map[string]any{
			"target":   rtStr("registered target domain, e.g. example.com"),
			"workflow": rtStr("workflow file name, e.g. 01-full-recon-pipeline.yaml"),
			"vars":     map[string]any{"type": "object", "description": "optional variable overrides (key -> value)"},
			"wait":     map[string]any{"type": "boolean", "description": "default false (non-blocking): return the run_id immediately and run CONCURRENTLY — follow with run_log/run_status while you keep reconning. true: block until the run finishes and return its recon brief inline."},
			"full":     map[string]any{"type": "boolean", "description": "default true: enable ALL of the workflow's options for maximum coverage (except the pivot scan and neighbor /24 PTR sweep, which stay off for scope safety). false: use the workflow's own defaults."},
		}, "target", "workflow"),
		ReadOnly:   func(json.RawMessage) bool { return false },
		Concurrent: func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p struct {
				Target   string            `json:"target"`
				Workflow string            `json:"workflow"`
				Vars     map[string]string `json:"vars"`
				Wait     *bool             `json:"wait"`
				Full     *bool             `json:"full"`
			}
			_ = json.Unmarshal(in, &p)
			if p.Target == "" || p.Workflow == "" {
				return actool.Errorf("target and workflow are required"), nil
			}
			if !targetExists(ctx, strings.ToLower(p.Target)) {
				return actool.Errorf("Target '" + p.Target + "' is not registered. Register it with a scope first (POST /api/v1/targets) — autonomous scans must stay inside a defined deny-wins scope. Ask the operator if unsure."), nil
			}
			var vars []string
			for k, v := range p.Vars {
				vars = append(vars, k+"="+v)
			}
			if p.Full == nil || *p.Full { // default: enable all options (minus the opted-out pivots)
				vars = mergeMaxVars(ctx, p.Workflow, vars)
			}
			body, _ := json.Marshal(map[string]any{"workflow": p.Workflow, "target": p.Target, "vars": vars})
			data, code, err := reconRaw(ctx, "POST", "/api/v1/runs", bytes.NewReader(body))
			if err != nil {
				return actool.Errorf("run_workflow start failed: " + err.Error()), nil
			}
			if code >= 300 {
				return actool.Errorf(fmt.Sprintf("run_workflow start failed (HTTP %d): %s", code, strings.TrimSpace(string(data)))), nil
			}
			var started struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(data, &started)
			runID := started.ID

			// Task that launched this run (for push-back if the agent doesn't consume it inline).
			taskID := ""
			if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
				taskID = strconv.FormatInt(ri.TaskID, 10)
			}

			if runID == "" {
				return actool.Errorf("run_workflow: the server did not return a run id"), nil
			}

			// DEFAULT is non-blocking: launch and return the run_id immediately so
			// the task runs CONCURRENTLY with the workflow — the agent follows it in
			// real time with run_log/run_status and keeps reconning. The completed
			// brief is ALSO pushed back into this task on any terminal outcome, so
			// nothing is missed. Pass wait=true to block until the run finishes.
			if p.Wait == nil || !*p.Wait {
				registerPushBack(runID, taskID)
				return actool.Text(fmt.Sprintf("Launched run %s for workflow %s against %s — running CONCURRENTLY (non-blocking). Now DO your other recon/analysis and check back periodically (don't busy-poll). Cheapest progress: run_status(run_id=%s). Follow step-by-step with run_log(run_id=%s) (progress-only by default; pass the previous total as offset to tail new lines; raw=true only to inspect one step). Read recon_findings/recon_assets as results land. The FULL brief is also pushed back into this task when the run finishes — nothing is lost — so do NOT wrap up while this run is still unread.", runID, p.Workflow, p.Target, runID, runID)), nil
			}

			// wait=true: block until the run reaches a terminal state, then return
			// the brief inline. taskID feeds the rare-overrun push-back safety net.
			_, perr := reconPollRun(ctx, runID, runWorkflowWaitCap)
			switch {
			case perr == nil:
				bdata, bcode, berr := reconRaw(ctx, "GET", "/api/v1/runs/"+url.PathEscape(runID)+"/recon-brief", nil)
				if berr == nil && bcode < 300 {
					return actool.Text(fmt.Sprintf("Run %s (%s) COMPLETED.\n\n%s", runID, p.Workflow, reconBriefMarkdown(bdata))), nil
				}
				return actool.Text(fmt.Sprintf("Run %s (%s) completed. Read results with recon_findings / recon_assets (target=%s).", runID, p.Workflow, p.Target)), nil
			case perr == context.DeadlineExceeded:
				registerPushBack(runID, taskID) // slow run — seed its brief back when it finishes
				return actool.Text(fmt.Sprintf("Run %s (%s) is STILL RUNNING after %s — it was NOT abandoned and its findings are NOT lost. RECORD a TodoWrite item \"poll run_status(%s) and read %s results\" so you don't forget, keep polling run_status(run_id=%s) until status=completed, then read recon_findings/recon_assets. Do NOT treat empty interim results as 'no findings', and do NOT wrap up while this run is unread.", runID, p.Workflow, runWorkflowWaitCap, runID, p.Workflow, runID)), nil
			case perr == context.Canceled:
				return actool.Text(fmt.Sprintf("run_workflow wait was cancelled; run %s may still be running — poll run_status(run_id=%s) later.", runID, runID)), nil
			default:
				return actool.Errorf(perr.Error()), nil
			}
		},
	})
}

// CreateTriageTask creates AND launches an autonomous task from a recon handoff
// (integrations A/D). This mirrors the POST /api/tasks flow: CreateTaskWithOptions
// then launchTask — the latter is what actually starts the planner/engine, which a
// bare Manager.CreateTaskWithOptions does not do.
func (s *Server) CreateTriageTask(name, goal, brief string) (*Task, error) {
	if goal == "" {
		goal = "Triage the recon surface and prove impact with a minimal PoC. Stay strictly in scope."
	}
	t, err := s.m.CreateTaskWithOptions(brief, goal, db.TaskCreateOptions{Name: name})
	if err != nil {
		return nil, err
	}
	s.launchTask(t, brief+" "+goal, false)
	return t, nil
}
