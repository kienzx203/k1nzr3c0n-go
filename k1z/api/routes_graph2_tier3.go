package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/graph"
	"github.com/Autumn-27/artex/k1z/store"
)

// ── runs list (for the run-diff picker) ─────────────────────────────────────

type graph2Run struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Workflow string `json:"workflow"`
	Status   string `json:"status"`
	When     string `json:"when"`
}

func (s *Server) runsForTarget(target string) []*store.Run {
	runs, _, err := s.St.ListRuns(store.RunFilter{Limit: 200})
	if err != nil {
		return nil
	}
	var out []*store.Run
	for _, run := range runs {
		if run.Target == target && run.Workspace != "" && dirExists(run.Workspace) {
			out = append(out, run)
		}
	}
	sort.Slice(out, func(i, j int) bool { return runWhen(out[i]).After(runWhen(out[j])) })
	return out
}

func runWhen(r *store.Run) time.Time {
	for _, t := range []time.Time{r.FinishedAt, r.StartedAt, r.CreatedAt} {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

func (s *Server) handleGraph2Runs(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("name")
	var out []graph2Run
	for _, run := range s.runsForTarget(target) {
		t := runWhen(run)
		out = append(out, graph2Run{
			ID: run.ID, Workflow: run.Workflow, Status: run.Status,
			When:  t.Format("2006-01-02 15:04"),
			Label: run.Workflow + " · " + t.Format("01-02 15:04"),
		})
	}
	writeJSON(w, 200, map[string]any{"runs": out})
}

func (s *Server) handleGraph2Diff(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("name")
	fromID := r.URL.Query().Get("from")
	toID := r.URL.Query().Get("to")
	if fromID == "" || toID == "" {
		writeDetail(w, 400, "from and to run ids are required")
		return
	}
	var fromWS, toWS string
	for _, run := range s.runsForTarget(target) {
		if run.ID == fromID {
			fromWS = run.Workspace
		}
		if run.ID == toID {
			toWS = run.Workspace
		}
	}
	if fromWS == "" || toWS == "" {
		writeDetail(w, 404, "run workspace not found for this target")
		return
	}
	gFrom := graph.Build(fromWS, target)
	gTo := graph.Build(toWS, target)
	writeJSON(w, 200, graph.Diff(gFrom, gTo))
}

// ── annotations (per-node tag + note, persisted per target) ─────────────────

type annotation struct {
	Tag  string `json:"tag,omitempty"`
	Note string `json:"note,omitempty"`
}

func annotationsPath(target string) string {
	return filepath.Join(config.BaseDir(), "targetgraphs", safeTargetDir(target), "annotations.json")
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
