package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/graph"
	"github.com/Autumn-27/artex/k1z/store"
)

// graph2 = the Go-native graph engine (BloodHound-style): the server holds the
// whole attack-surface graph per target and the UI pulls subgraphs on demand
// (overview / neighbors / path / search), instead of shipping one giant HTML.

type cachedGraph struct {
	g       *graph.Graph
	builtAt time.Time
}

var (
	graph2Mu    sync.Mutex
	graph2Cache = map[string]*cachedGraph{}
	errNoRuns   = errors.New("no run workspace found for this target")
)

// targetGraph builds (or returns a cached) graph for a target by unioning every
// run's workspace. Rebuilt only when a newer run exists or the generator changed.
func (s *Server) targetGraph(target string) (*graph.Graph, int, error) {
	if target == "" {
		return nil, 400, errors.New("target required")
	}
	runs, _, err := s.St.ListRuns(store.RunFilter{Limit: 200})
	if err != nil {
		return nil, 500, err
	}
	var wss []string
	var newest time.Time
	for _, run := range runs {
		if run.Target != target || run.Workspace == "" || !dirExists(run.Workspace) {
			continue
		}
		wss = append(wss, run.Workspace)
		for _, t := range []time.Time{run.FinishedAt, run.StartedAt, run.CreatedAt} {
			if t.After(newest) {
				newest = t
			}
		}
	}
	if len(wss) == 0 {
		return nil, 404, errNoRuns
	}
	graph2Mu.Lock()
	defer graph2Mu.Unlock()
	if c, ok := graph2Cache[target]; ok && !newest.After(c.builtAt) {
		return c.g, 200, nil
	}
	merged := filepath.Join(config.BaseDir(), "targetgraphs", safeTargetDir(target))
	os.MkdirAll(merged, 0o755)
	for _, f := range graphMergeFiles {
		var buf []byte
		for _, ws := range wss {
			if b, e := os.ReadFile(filepath.Join(ws, f)); e == nil && len(b) > 0 {
				buf = append(buf, b...)
				if b[len(b)-1] != '\n' {
					buf = append(buf, '\n')
				}
			}
		}
		_ = os.WriteFile(filepath.Join(merged, f), buf, 0o644)
	}
	g := graph.Build(merged, target)
	graph2Cache[target] = &cachedGraph{g: g, builtAt: time.Now()}
	return g, 200, nil
}

func (s *Server) graphFor(w http.ResponseWriter, r *http.Request) *graph.Graph {
	g, code, err := s.targetGraph(r.PathValue("name"))
	if err != nil {
		writeDetail(w, code, err.Error())
		return nil
	}
	return g
}

func (s *Server) handleGraph2Overview(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Overview(atoiDefault(r.URL.Query().Get("hostCap"), 150)))
	}
}

func (s *Server) handleGraph2Neighbors(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Neighbors(r.URL.Query().Get("id")))
	}
}

func (s *Server) handleGraph2Path(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Path(r.URL.Query().Get("from"), r.URL.Query().Get("to")))
	}
}

func (s *Server) handleGraph2Search(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, map[string]any{"nodes": g.Search(r.URL.Query().Get("q"), atoiDefault(r.URL.Query().Get("limit"), 50))})
	}
}

func (s *Server) handleGraph2Stats(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Stats())
	}
}
