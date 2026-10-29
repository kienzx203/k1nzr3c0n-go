package api

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	sig     string // run-set signature (ids+times) this graph was built from
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
	nt := normTarget(target) // group runs by canonical host, not raw string
	runs, _, err := s.St.ListRuns(store.RunFilter{Limit: 200})
	if err != nil {
		return nil, 500, err
	}
	var wss []string
	var sigs []string
	for _, run := range runs {
		if normTarget(run.Target) != nt || run.Workspace == "" || !dirExists(run.Workspace) {
			continue
		}
		wss = append(wss, run.Workspace)
		var newest time.Time
		for _, t := range []time.Time{run.FinishedAt, run.StartedAt, run.CreatedAt} {
			if t.After(newest) {
				newest = t
			}
		}
		sigs = append(sigs, run.ID+":"+strconv.FormatInt(newest.Unix(), 10))
	}
	if len(wss) == 0 {
		return nil, 404, errNoRuns
	}
	// cache signature = the exact set of runs + their newest times, so the cache
	// rebuilds when a run is ADDED, FINISHES, or is DELETED (a max-timestamp
	// check alone never shrank the graph after a deletion).
	sort.Strings(sigs)
	sig := strings.Join(sigs, "|")
	graph2Mu.Lock()
	defer graph2Mu.Unlock()
	if c, ok := graph2Cache[nt]; ok && c.sig == sig {
		return c.g, 200, nil
	}
	merged := filepath.Join(config.BaseDir(), "targetgraphs", safeTargetDir(nt))
	mergeRunFiles(wss, merged)
	g := graph.Build(merged, nt)
	graph2Cache[nt] = &cachedGraph{g: g, sig: sig, builtAt: time.Now()}
	return g, 200, nil
}

// mergeRunFiles concatenates each graphMergeFiles entry across run workspaces
// into `merged`, expanding glob patterns and preserving subdirs (e.g. gf/).
// Shared by the graph2 engine and the legacy python renderer so they don't
// pollute the shared targetgraphs dir with literal "*"-named junk files.
// Callers serialize on graph2Mu since both write into the same target dir.
func mergeRunFiles(wss []string, merged string) {
	os.MkdirAll(merged, 0o755)
	agg := map[string][]byte{}
	for _, pat := range graphMergeFiles {
		for _, ws := range wss {
			var paths []string
			if strings.ContainsAny(pat, "*?[") {
				paths, _ = filepath.Glob(filepath.Join(ws, pat))
			} else {
				paths = []string{filepath.Join(ws, pat)}
			}
			for _, p := range paths {
				b, e := os.ReadFile(p)
				if e != nil || len(b) == 0 {
					continue
				}
				rel, re := filepath.Rel(ws, p)
				if re != nil || strings.HasPrefix(rel, "..") {
					rel = filepath.Base(p)
				}
				agg[rel] = append(agg[rel], b...)
				if b[len(b)-1] != '\n' {
					agg[rel] = append(agg[rel], '\n')
				}
			}
		}
	}
	for rel, buf := range agg {
		dst := filepath.Join(merged, rel)
		_ = os.MkdirAll(filepath.Dir(dst), 0o755)
		_ = os.WriteFile(dst, buf, 0o644)
	}
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

func (s *Server) handleGraph2Full(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Full())
	}
}

func (s *Server) handleGraph2Metrics(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Metrics())
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

// graph2ViewHTML is the WebGL (Sigma.js) client — a page that pulls subgraphs
// from the graph2 API on demand (no embedded data), so it stays fast regardless
// of graph size. Embedded so it ships in the binary without the frontend build.
//
//go:embed assets/graph2_view.html
var graph2ViewHTML string

func (s *Server) handleGraph2View(w http.ResponseWriter, r *http.Request) {
	tj, _ := json.Marshal(normTarget(r.PathValue("name"))) // canonical host → BASE + annotations key off it
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(strings.Replace(graph2ViewHTML, `"__TARGET__"`, string(tj), 1)))
}

// handleGraph2Export streams the whole graph as GraphML (default) or GEXF.
func (s *Server) handleGraph2Export(w http.ResponseWriter, r *http.Request) {
	g := s.graphFor(w, r)
	if g == nil {
		return
	}
	name := safeTargetDir(r.PathValue("name"))
	switch r.URL.Query().Get("fmt") {
	case "gexf":
		w.Header().Set("Content-Type", "application/gexf+xml")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+name+".gexf\"")
		w.Write(g.ExportGEXF())
	default:
		w.Header().Set("Content-Type", "application/graphml+xml")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+name+".graphml\"")
		w.Write(g.ExportGraphML())
	}
}

