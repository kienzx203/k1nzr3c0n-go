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
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
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
		reconRunWorkflow(),
	}
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
func reconRunWorkflow() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "run_workflow",
		Description: "Launch a Workflow Runner recon workflow against a REGISTERED target (a deny-wins scope must already exist for it). Returns a run_id immediately; poll run_status, then read results with recon_findings/recon_assets. Only run recon you don't already have — check recon_findings first.",
		Schema: rtObj(map[string]any{
			"target":   rtStr("registered target domain, e.g. example.com"),
			"workflow": rtStr("workflow file name, e.g. 01-full-recon-pipeline.yaml"),
			"vars":     map[string]any{"type": "object", "description": "optional variable overrides (key -> value)"},
		}, "target", "workflow"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Concurrent:  func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision { return permission.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p struct {
				Target   string            `json:"target"`
				Workflow string            `json:"workflow"`
				Vars     map[string]string `json:"vars"`
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
			body, _ := json.Marshal(map[string]any{"workflow": p.Workflow, "target": p.Target, "vars": vars})
			return reconHTTP(ctx, "POST", "/api/v1/runs", bytes.NewReader(body)), nil
		},
	})
}
