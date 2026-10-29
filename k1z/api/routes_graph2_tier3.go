package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/targetgraph"
)

// ── annotations (per-node tag + note, persisted per target) ─────────────────

type annotation struct {
	Tag  string `json:"tag,omitempty"`
	Note string `json:"note,omitempty"`
}

func annotationsPath(target string) string {
	return filepath.Join(config.BaseDir(), "targetgraphs", targetgraph.SafeTargetDir(targetgraph.NormTarget(target)), "annotations.json")
}

func readAnnotations(target string) map[string]annotation {
	m := map[string]annotation{}
	if b, err := os.ReadFile(annotationsPath(target)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (s *Server) handleGraph2Annotations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"annotations": readAnnotations(r.PathValue("name"))})
}

func (s *Server) handleGraph2AnnotationsSave(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("name")
	var in struct {
		ID   string `json:"id"`
		Tag  string `json:"tag"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeDetail(w, 400, "bad json")
		return
	}
	in.ID = strings.TrimSpace(in.ID)
	if in.ID == "" || len(in.ID) > 512 {
		writeDetail(w, 400, "node id required")
		return
	}
	if len(in.Tag) > 120 {
		in.Tag = in.Tag[:120]
	}
	if len(in.Note) > 4000 {
		in.Note = in.Note[:4000]
	}
	m := readAnnotations(target)
	if strings.TrimSpace(in.Tag) == "" && strings.TrimSpace(in.Note) == "" {
		delete(m, in.ID)
	} else {
		m[in.ID] = annotation{Tag: in.Tag, Note: in.Note}
	}
	p := annotationsPath(target)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "count": len(m)})
}
