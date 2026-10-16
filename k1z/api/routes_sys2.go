package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/k1z/agent"
	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/notify"
	"github.com/Autumn-27/artex/k1z/store"
)

// ── skills ───────────────────────────────────────────────────────────────────

func (s *Server) handleSkillsList(w http.ResponseWriter, r *http.Request) {
	var out []map[string]any
	for _, sk := range agent.LoadSkillsDir() {
		out = append(out, map[string]any{
			"name": sk.Name, "description": sk.Description,
			"instructions_len": len(sk.Instructions), "dir": sk.Dir,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, 200, out)
}

// ── agent persona ────────────────────────────────────────────────────────────

func (s *Server) handleAgentPrompt(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"system_prompt": agent.SystemPrompt})
}

// ── llm usage rows ───────────────────────────────────────────────────────────

func (s *Server) handleLLMUsageList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.St.ListLLMUsageRows(atoiDefault(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rows)
}

// ── workspace (shared artifacts under <base>/workspace) ─────────────────────

func workspaceDir() string { return filepath.Join(config.BaseDir(), "workspace") }

func (s *Server) handleWorkspaceList(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(workspaceDir())
	if err != nil {
		writeJSON(w, 200, []any{})
		return
	}
	type item struct {
		Name  string `json:"name"`
		Size  int64  `json:"size"`
		IsDir bool   `json:"is_dir"`
	}
	out := []item{}
	for _, e := range entries {
		fi, _ := e.Info()
		out = append(out, item{Name: e.Name(), Size: fi.Size(), IsDir: e.IsDir()})
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleWorkspaceUpload(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 100<<20 {
		writeDetail(w, 413, "File too large (max 100 MB)")
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeDetail(w, 422, "multipart 'file' field required")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeDetail(w, 422, "file field required")
		return
	}
	defer file.Close()
	name := sanitizeUploadName(hdr.Filename)
	os.MkdirAll(workspaceDir(), 0o755)
	dst, err := os.Create(filepath.Join(workspaceDir(), name))
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	defer dst.Close()
	n, _ := io.Copy(dst, file)
	writeJSON(w, 200, map[string]any{"name": name, "size": n})
}

func (s *Server) handleWorkspaceDownload(w http.ResponseWriter, r *http.Request) {
	name := sanitizeUploadName(r.PathValue("name"))
	full := filepath.Join(workspaceDir(), name)
	if fi, err := os.Stat(full); err != nil || fi.IsDir() {
		writeDetail(w, 404, "File not found")
		return
	}
	http.ServeFile(w, r, full)
}

func (s *Server) handleWorkspaceDelete(w http.ResponseWriter, r *http.Request) {
	name := sanitizeUploadName(r.PathValue("name"))
	_ = os.Remove(filepath.Join(workspaceDir(), name))
	w.WriteHeader(204)
}

// ── notifications ────────────────────────────────────────────────────────────

func (s *Server) handleNotifyGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.St.GetNotifySettings())
}

func (s *Server) handleNotifyPut(w http.ResponseWriter, r *http.Request) {
	var n store.NotifySettings
	if err := readJSON(r, &n); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if err := s.St.SetNotifySettings(n); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, n)
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	n := s.St.GetNotifySettings()
	prev := notify.DBWebhookURL
	notify.DBWebhookURL = func() string { return n.WebhookURL }
	notify.CriticalFindings(1, 0, []string{"[TEST] webhook from k1nzr3c0n settings"})
	notify.DBWebhookURL = prev
	if n.WebhookURL == "" && config.WebhookURL() == "" {
		writeDetail(w, 400, "No webhook URL configured")
		return
	}
	writeJSON(w, 200, map[string]any{"sent": true})
}

// ── system logs (merged activity: tool audit + run logs) ────────────────────

func (s *Server) handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	limit := atoiDefault(r.URL.Query().Get("limit"), 200)
	audit, _ := s.St.ListAgentAudit(limit)
	type logRow struct {
		Source string `json:"source"`
		Text   string `json:"text"`
		TS     any    `json:"ts"`
	}
	out := []logRow{}
	for _, a := range audit {
		args, _ := a["args"].(string)
		out = append(out, logRow{Source: "agent:" + a["tool"].(string), Text: args, TS: a["created_at"]})
	}
	runs, _, _ := s.St.ListRuns(store.RunFilter{Limit: 20})
	for _, run := range runs {
		lines, _, _ := s.St.ListLogs(run.ID, 0, 10)
		for _, l := range lines {
			out = append(out, logRow{Source: "run:" + run.ID, Text: l, TS: run.CreatedAt})
		}
	}
	writeJSON(w, 200, map[string]any{"total": len(out), "items": out})
}

// ── ScopeSentry asset sync ───────────────────────────────────────────────────

type ssAsset struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

// handleScopeSentrySync pulls domains/subdomains from a ScopeSentry instance
// into the asset graph (best-effort; API shape per ScopeSentry docs).
func (s *Server) handleScopeSentrySync(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL    string `json:"url"`
		APIKey string `json:"api_key"`
		Scope  string `json:"scope"` // optional company name for the graph
	}
	if err := readJSON(r, &body); err != nil || body.URL == "" || body.APIKey == "" {
		writeDetail(w, 422, "url and api_key are required")
		return
	}
	base := strings.TrimSuffix(body.URL, "/")
	client := &http.Client{Timeout: http.DefaultClient.Timeout}
	_ = client
	var companyID *int64
	if body.Scope != "" {
		if c, err := s.St.UpsertCompany(body.Scope, nil); err == nil {
			companyID = &c.ID
		}
	}
	imported := 0
	// ScopeSentry REST: /api/assets/common/list with X-API-Key (paginated)
	page := 1
	for page <= 20 {
		req, _ := http.NewRequest(http.MethodGet,
			fmt.Sprintf("%s/api/assets/common/list?pageIndex=%d&pageSize=200&type=domain", base, page), nil)
		req.Header.Set("X-API-Key", body.APIKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			writeDetail(w, 502, "ScopeSentry: "+err.Error())
			return
		}
		var payload struct {
			Data []struct {
				Type  string          `json:"type"`
				Value json.RawMessage `json:"value"`
			} `json:"data"`
			Message string `json:"message"`
		}
		err = json.NewDecoder(resp.Body).Decode(&payload)
		resp.Body.Close()
		if err != nil {
			writeDetail(w, 502, "ScopeSentry decode: "+err.Error())
			return
		}
		if len(payload.Data) == 0 {
			break
		}
		for _, d := range payload.Data {
			val := extractStr(d.Value)
			if val == "" {
				continue
			}
			a := store.Asset{CompanyID: companyID, Type: "subdomain", Value: val, Source: "scopesentry"}
			if d.Type == "ip" {
				a.Type = "ip"
			}
			if err := s.St.UpsertAsset(&a); err == nil {
				imported++
			}
		}
		if len(payload.Data) < 200 {
			break
		}
		page++
	}
	writeJSON(w, 200, map[string]any{"imported": imported})
}

func extractStr(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

var _ = sort.Strings
