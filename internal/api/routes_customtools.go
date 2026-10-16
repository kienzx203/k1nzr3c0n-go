package api

import (
	"encoding/json"
	"net/http"
	"regexp"

	"k1nzr3c0n/internal/agent"
	"k1nzr3c0n/internal/store"
)

var reToolKey = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func customToolDTO(t store.CustomTool) map[string]any {
	return map[string]any{
		"key": t.Key, "description": t.Description, "kind": t.Kind,
		"schema": rawJSON(t.Schema), "exec": rawJSON(t.Exec),
		"enabled": t.Enabled, "updated_at": iso(t.UpdatedAt),
	}
}

func (s *Server) handleCustomToolList(w http.ResponseWriter, r *http.Request) {
	tools, _ := s.St.ListCustomTools()
	out := []map[string]any{}
	for _, t := range tools {
		out = append(out, customToolDTO(t))
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

type customToolBody struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	Schema      json.RawMessage `json:"schema"`
	Exec        json.RawMessage `json:"exec"`
	Enabled     *bool           `json:"enabled"`
}

func (s *Server) saveCustomTool(w http.ResponseWriter, body customToolBody) {
	if !reToolKey.MatchString(body.Key) {
		writeDetail(w, 422, "key must be lowercase: ^[a-z][a-z0-9_]*$")
		return
	}
	if body.Kind != "command" && body.Kind != "script" && body.Kind != "http" {
		writeDetail(w, 422, "kind must be command, script or http")
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	t := &store.CustomTool{
		Key: body.Key, Description: body.Description, Kind: body.Kind,
		Schema: string(body.Schema), Exec: string(body.Exec), Enabled: enabled,
	}
	if err := s.St.UpsertCustomTool(t); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"key": t.Key})
}

func (s *Server) handleCustomToolCreate(w http.ResponseWriter, r *http.Request) {
	var body customToolBody
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	s.saveCustomTool(w, body)
}

func (s *Server) handleCustomToolUpdate(w http.ResponseWriter, r *http.Request) {
	var body customToolBody
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	body.Key = r.PathValue("key")
	s.saveCustomTool(w, body)
}

func (s *Server) handleCustomToolDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.St.DeleteCustomTool(r.PathValue("key")); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": r.PathValue("key")})
}

// handleCustomToolTest runs a tool definition once with sample params (no persistence).
func (s *Server) handleCustomToolTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind   string          `json:"kind"`
		Exec   json.RawMessage `json:"exec"`
		Params map[string]any  `json:"params"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	argsJSON, _ := json.Marshal(body.Params)
	// persist a throwaway tool under a reserved key, run it, then remove it
	tmp := &store.CustomTool{Key: "_test_tool", Kind: body.Kind, Exec: string(body.Exec), Enabled: true, Schema: "{}"}
	_ = s.St.UpsertCustomTool(tmp)
	out := agent.ExecCustomTool(s.St, agent.FunctionCall{Name: "_test_tool", Arguments: string(argsJSON)})
	_ = s.St.DeleteCustomTool("_test_tool")
	writeJSON(w, 200, map[string]any{"result": rawJSON(out)})
}
