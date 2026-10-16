package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"k1nzr3c0n/internal/store"
)

// CustomToolDefs builds LLM tool definitions from the enabled custom tools.
func CustomToolDefs(st *store.Store) []ToolDef {
	tools, err := st.ListCustomTools()
	if err != nil {
		return nil
	}
	var out []ToolDef
	for _, t := range tools {
		if !t.Enabled {
			continue
		}
		var params map[string]any
		if json.Unmarshal([]byte(t.Schema), &params) != nil || params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, ToolDef{Type: "function", Function: FunctionSpec{
			Name: t.Key, Description: t.Description + " (custom tool)", Parameters: params,
		}})
	}
	return out
}

// IsCustomTool reports whether name is a defined custom tool.
func IsCustomTool(st *store.Store, name string) bool {
	t, err := st.GetCustomTool(name)
	return err == nil && t != nil
}

// ExecCustomTool runs a custom tool call and returns its textual result.
func ExecCustomTool(st *store.Store, call FunctionCall) string {
	t, err := st.GetCustomTool(call.Name)
	if err != nil || t == nil {
		return `{"error":"unknown custom tool ` + call.Name + `"}`
	}
	if !t.Enabled {
		return `{"error":"custom tool disabled"}`
	}
	var params map[string]any
	_ = json.Unmarshal([]byte(call.Arguments), &params)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	switch t.Kind {
	case "http":
		return runHTTPTool(ctx, t.Exec, params)
	case "script":
		return runScriptTool(ctx, t.Key, t.Exec, params)
	default: // "command"
		return runCommandTool(ctx, t.Exec, params)
	}
}

// substitute replaces {{name}} placeholders with the param value.
func substitute(tmpl string, params map[string]any) string {
	out := tmpl
	for k, v := range params {
		out = strings.ReplaceAll(out, "{{"+k+"}}", fmt.Sprintf("%v", v))
	}
	return out
}

func runCommandTool(ctx context.Context, execRaw string, params map[string]any) string {
	var cfg struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal([]byte(execRaw), &cfg)
	cmd := substitute(cfg.Command, params)
	if strings.TrimSpace(cmd) == "" {
		return `{"error":"empty command"}`
	}
	c := exec.CommandContext(ctx, "bash", "-lc", cmd)
	out, err := c.CombinedOutput()
	s := truncOut(string(out))
	if err != nil {
		return `{"output":` + jsonString(s) + `,"error":` + jsonString(err.Error()) + `}`
	}
	return `{"output":` + jsonString(s) + `}`
}

func runScriptTool(ctx context.Context, key, execRaw string, params map[string]any) string {
	var cfg struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal([]byte(execRaw), &cfg)
	script := cfg.Command
	if strings.TrimSpace(script) == "" {
		return `{"error":"empty script"}`
	}
	// write the script to a temp file and run it through bash with params as env
	f, err := os.CreateTemp("", "k1z-tool-"+key+"-*.sh")
	if err != nil {
		return `{"error":"temp: ` + err.Error() + `"}`
	}
	defer os.Remove(f.Name())
	f.WriteString(substitute(script, params))
	f.Close()
	c := exec.CommandContext(ctx, "bash", f.Name())
	c.Env = os.Environ()
	for k, v := range params {
		c.Env = append(c.Env, strings.ToUpper(k)+"="+fmt.Sprintf("%v", v))
	}
	out, err := c.CombinedOutput()
	s := truncOut(string(out))
	if err != nil {
		return `{"output":` + jsonString(s) + `,"error":` + jsonString(err.Error()) + `}`
	}
	return `{"output":` + jsonString(s) + `}`
}

func runHTTPTool(ctx context.Context, execRaw string, params map[string]any) string {
	var cfg struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	_ = json.Unmarshal([]byte(execRaw), &cfg)
	method := strings.ToUpper(cfg.Method)
	if method == "" {
		method = "GET"
	}
	url := substitute(cfg.URL, params)
	body := substitute(cfg.Body, params)
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader([]byte(body)))
	if err != nil {
		return `{"error":` + jsonString(err.Error()) + `}`
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, substitute(v, params))
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return `{"error":` + jsonString(err.Error()) + `}`
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return fmt.Sprintf(`{"status":%d,"body":%s}`, resp.StatusCode, jsonString(truncOut(string(data))))
}

func truncOut(s string) string {
	if len(s) > 6000 {
		return s[:6000] + "…(truncated)"
	}
	return s
}
