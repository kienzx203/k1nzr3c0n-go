package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/workflow"
)

func validWorkflowName(name string) bool {
	if !strings.HasSuffix(name, ".yaml") {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return false
	}
	return true
}

func (s *Server) handleListWorkflows(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(config.WorkflowsDir())
	if err != nil {
		writeJSON(w, 200, []string{})
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".yaml") && !strings.HasPrefix(n, ".") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if names == nil {
		names = []string{}
	}
	// ?detail=1 returns [{name, description}] so an agent can auto-select the right
	// workflow for a situation; the default []string shape is kept for the UI.
	if r.URL.Query().Get("detail") != "" {
		type wfInfo struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		out := make([]wfInfo, 0, len(names))
		for _, n := range names {
			out = append(out, wfInfo{Name: n, Description: workflowDescription(n)})
		}
		writeJSON(w, 200, out)
		return
	}
	writeJSON(w, 200, names)
}

// workflowDescription reads a workflow file's top-level `description` field (best
// effort; empty if missing or unreadable).
func workflowDescription(name string) string {
	data, err := os.ReadFile(filepath.Join(config.WorkflowsDir(), name))
	if err != nil {
		return ""
	}
	var parsed struct {
		Description string `yaml:"description"`
	}
	if yaml.Unmarshal(data, &parsed) != nil {
		return ""
	}
	return parsed.Description
}

func (s *Server) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validWorkflowName(name) {
		writeDetail(w, 400, "Invalid workflow name")
		return
	}
	data, err := os.ReadFile(filepath.Join(config.WorkflowsDir(), name))
	if err != nil {
		writeDetail(w, 404, "Workflow not found: "+name)
		return
	}
	var parsed any
	if yaml.Unmarshal(data, &parsed) != nil || parsed == nil {
		parsed = map[string]any{}
	}
	writeJSON(w, 200, parsed)
}

func (s *Server) handleWorkflowDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validWorkflowName(name) {
		writeDetail(w, 400, "Invalid workflow name")
		return
	}
	data, err := os.ReadFile(filepath.Join(config.WorkflowsDir(), name))
	if err != nil {
		writeDetail(w, 404, "Workflow not found: "+name)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Write(data)
}

func snapshotWorkflow(name string) {
	data, err := os.ReadFile(filepath.Join(config.WorkflowsDir(), name))
	if err != nil {
		return
	}
	os.MkdirAll(config.HistoryDir(), 0o755)
	ts := time.Now().Format("20060102-150405")
	_ = os.WriteFile(filepath.Join(config.HistoryDir(), name+"."+ts+".yaml"), data, 0o644)
	// keep last 10
	entries, _ := os.ReadDir(config.HistoryDir())
	var snaps []string
	prefix := name + "."
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".yaml") {
			snaps = append(snaps, e.Name())
		}
	}
	sort.Strings(snaps)
	for len(snaps) > 10 {
		_ = os.Remove(filepath.Join(config.HistoryDir(), snaps[0]))
		snaps = snaps[1:]
	}
}

func validateWorkflowYAML(data []byte) error {
	tmp, err := os.CreateTemp("", "k1z-wf-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	tmp.Write(data)
	tmp.Close()
	if _, err := workflow.Load(tmp.Name()); err != nil {
		return err
	}
	return nil
}

func (s *Server) handlePutWorkflow(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validWorkflowName(name) {
		writeDetail(w, 400, "Invalid workflow name")
		return
	}
	var body any
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	data, err := yaml.Marshal(body)
	if err != nil {
		writeDetail(w, 400, "Invalid YAML: "+err.Error())
		return
	}
	if err := validateWorkflowYAML(data); err != nil {
		writeDetail(w, 400, "Workflow validation failed: "+err.Error())
		return
	}
	snapshotWorkflow(name)
	if err := os.MkdirAll(config.WorkflowsDir(), 0o755); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(config.WorkflowsDir(), name), data, 0o644); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"saved": name})
}

func (s *Server) handleDeleteWorkflow(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validWorkflowName(name) {
		writeDetail(w, 400, "Invalid workflow name")
		return
	}
	path := filepath.Join(config.WorkflowsDir(), name)
	if _, err := os.Stat(path); err != nil {
		writeDetail(w, 404, "Workflow not found: "+name)
		return
	}
	snapshotWorkflow(name)
	os.Remove(path)
	writeJSON(w, 200, map[string]any{"deleted": name})
}

func (s *Server) handleImportWorkflow(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		YamlText string `json:"yaml_text"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if !validWorkflowName(body.Name) {
		writeDetail(w, 400, "Invalid workflow name")
		return
	}
	if err := validateWorkflowYAML([]byte(body.YamlText)); err != nil {
		if strings.HasPrefix(err.Error(), "Invalid YAML") {
			writeDetail(w, 400, err.Error())
			return
		}
		writeDetail(w, 400, "Workflow validation failed: "+err.Error())
		return
	}
	snapshotWorkflow(body.Name)
	os.MkdirAll(config.WorkflowsDir(), 0o755)
	if err := os.WriteFile(filepath.Join(config.WorkflowsDir(), body.Name), []byte(body.YamlText), 0o644); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"imported": body.Name})
}

func (s *Server) handleWorkflowHistory(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	entries, _ := os.ReadDir(config.HistoryDir())
	prefix := name + "."
	var snaps []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".yaml") {
			snaps = append(snaps, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(snaps)))
	if snaps == nil {
		snaps = []string{}
	}
	writeJSON(w, 200, map[string]any{"name": name, "snapshots": snaps})
}

func (s *Server) handleWorkflowSnapshot(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	snap := r.PathValue("snapshot")
	if !strings.HasPrefix(snap, name+".") || strings.Contains(snap, "/") || strings.Contains(snap, "\\") {
		writeDetail(w, 400, "Invalid snapshot name")
		return
	}
	data, err := os.ReadFile(filepath.Join(config.HistoryDir(), snap))
	if err != nil {
		writeDetail(w, 404, "Snapshot not found")
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", snap))
	w.Write(data)
}

var sanitizeRe = regexp.MustCompile(`[^\w\-.]+`)

// sanitizeUploadName strips directories and replaces hostile characters.
func sanitizeUploadName(name string) string {
	name = filepath.Base(name)
	name = sanitizeRe.ReplaceAllString(name, "_")
	if name == "" || name == "_" {
		name = "upload"
	}
	return name
}

func (s *Server) handleUploadWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 100<<20 {
		writeDetail(w, 413, "File too large (max 100 MB)")
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeDetail(w, 422, "multipart form with 'file' field is required")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeDetail(w, 422, "file field is required")
		return
	}
	defer file.Close()
	name := sanitizeUploadName(hdr.Filename)
	if !strings.HasSuffix(strings.ToLower(name), ".yaml") && !strings.HasSuffix(strings.ToLower(name), ".yml") {
		writeDetail(w, 400, "Only .yaml files are allowed")
		return
	}
	name = strings.TrimSuffix(name, ".yml")
	name = strings.TrimSuffix(name, ".yaml") + ".yaml"
	data := make([]byte, 0)
	buf := make([]byte, 32*1024)
	for {
		n, err := file.Read(buf)
		data = append(data, buf[:n]...)
		if err != nil {
			break
		}
	}
	os.MkdirAll(config.WorkflowsDir(), 0o755)
	if err := os.WriteFile(filepath.Join(config.WorkflowsDir(), name), data, 0o644); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"name": name, "size": len(data)})
}
