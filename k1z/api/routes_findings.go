package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/k1z/store"
)

// ── findings ─────────────────────────────────────────────────────────────────

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 100)
	offset := atoiDefault(q.Get("offset"), 0)
	items, total, err := s.St.ListFindings(store.FindingFilter{
		Kind: q.Get("kind"), Severity: q.Get("severity"), Status: q.Get("status"),
		Host: q.Get("host"), RunID: q.Get("run_id"), Limit: limit, Offset: offset,
	})
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []*findingJSON{}
	for _, f := range items {
		out = append(out, findingToDict(f))
	}
	writeJSON(w, 200, map[string]any{"total": total, "offset": offset, "limit": limit, "items": out})
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("finding_id"), 10, 64)
	f, err := s.St.GetFinding(id)
	if err == store.ErrNotFound {
		writeDetail(w, 404, "Finding not found")
		return
	}
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, findingToDict(f))
}

func (s *Server) handlePatchFinding(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("finding_id"), 10, 64)
	var body struct {
		Status *string   `json:"status"`
		Notes  *string   `json:"notes"`
		Tags   *[]string `json:"tags"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if body.Status != nil {
		switch *body.Status {
		case "open", "fp", "resolved":
		default:
			writeDetail(w, 400, "status must be one of: open, fp, resolved")
			return
		}
	}
	var tagsJSON *string
	if body.Tags != nil {
		clean := []string{}
		for _, t := range *body.Tags {
			if t = strings.TrimSpace(t); t != "" {
				clean = append(clean, t)
			}
		}
		if clean == nil {
			clean = []string{}
		}
		b, _ := json.Marshal(clean)
		s := string(b)
		tagsJSON = &s
	}
	if err := s.St.PatchFinding(id, body.Status, body.Notes, tagsJSON); err == store.ErrNotFound {
		writeDetail(w, 404, "Finding not found")
		return
	} else if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	f, _ := s.St.GetFinding(id)
	writeJSON(w, 200, findingToDict(f))
}

func (s *Server) handleFindingStats(w http.ResponseWriter, r *http.Request) {
	total, bySeverity, byKind, err := s.St.FindingStats()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"total": total, "by_severity": bySeverity, "by_kind": byKind,
	})
}

func (s *Server) handleDuplicates(w http.ResponseWriter, r *http.Request) {
	groups, err := s.St.DuplicateGroups()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for _, g := range groups {
		out = append(out, map[string]any{
			"host": g.Host, "template_id": g.TemplateID, "count": g.Count,
			"severity": g.Severity, "keep_id": g.KeepID,
			"duplicate_ids": g.DupIDs,
		})
	}
	writeJSON(w, 200, map[string]any{"total": len(out), "groups": out})
}

func (s *Server) handleResolveDuplicates(w http.ResponseWriter, r *http.Request) {
	n, err := s.St.ResolveDuplicates()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"resolved": n})
}

// ── assets (cross-run inventory) ─────────────────────────────────────────────

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AssetFilter{
		Q:           q.Get("q"),
		Tech:        q["tech"],
		Targets:     q["target"],
		StatusCodes: atoiSlice(q["status_code"]),
		Ports:       atoiSlice(q["port"]),
		Limit:       atoiDefault(q.Get("limit"), 500),
		Offset:      atoiDefault(q.Get("offset"), 0),
	}
	items, total, err := s.St.ListAssets(f)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for _, a := range items {
		target := a.Host
		if run, err := s.St.GetRun(a.RunID); err == nil {
			target = run.Target
		}
		var tech any = []string{}
		var arr []string
		if json.Unmarshal([]byte(a.Tech), &arr) == nil && arr != nil {
			tech = arr
		}
		out = append(out, map[string]any{
			"host": a.Host, "port": a.Port, "ip": a.IP, "url": a.URL, "title": a.Title,
			"status_code": a.StatusCode, "tech": tech, "screenshot": a.Screenshot,
			"run_id": a.RunID, "target": target, "last_seen": iso(a.CreatedAt),
		})
	}
	writeJSON(w, 200, map[string]any{"total": total, "offset": f.Offset, "limit": f.Limit, "items": out})
}

func (s *Server) handleAssetStats(w http.ResponseWriter, r *http.Request) {
	total, withShot, byTech, byTarget, byStatus, byPort, err := s.St.AssetStats()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"total": total, "with_screenshot": withShot,
		"by_tech":   rankedMap(byTech, 50),
		"by_target": rankedMap(byTarget, 0),
		"by_status": sortedKeysMap(byStatus),
		"by_port":   rankedMap(byPort, 20),
	})
}

// rankedMap builds an order-preserving map sorted count-desc (top n; 0 = all).
func rankedMap(m map[string]int, topN int) *orderedMap {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if topN > 0 && len(keys) > topN {
		keys = keys[:topN]
	}
	out := newOrdered()
	for _, k := range keys {
		out.set(k, m[k])
	}
	return out
}

// sortedKeysMap builds an order-preserving map with lexicographically sorted
// keys (matches Python's by_status serialization).
func sortedKeysMap(m map[string]int) *orderedMap {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := newOrdered()
	for _, k := range keys {
		out.set(k, m[k])
	}
	return out
}

func (s *Server) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
		Port *int   `json:"port"`
	}
	if err := readJSON(r, &body); err != nil || body.Host == "" {
		writeDetail(w, 422, "host is required")
		return
	}
	port := -1
	if body.Port != nil {
		port = *body.Port
	}
	if err := s.St.DeleteHTTPAssets(body.Host, port); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	w.WriteHeader(204)
}

func atoiSlice(ss []string) []int {
	var out []int
	for _, s := range ss {
		if n, err := strconv.Atoi(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}
