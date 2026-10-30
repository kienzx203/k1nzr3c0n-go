package api

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/k1z/graph"
	"github.com/Autumn-27/artex/k1z/targetgraph"
)

// graph2 = the Go-native graph engine (BloodHound-style): the server holds the
// whole attack-surface graph per target and the UI pulls subgraphs on demand
// (overview / neighbors / path / search), instead of shipping one giant HTML.
//
// The aggregation (union every run's workspace) + run-set-signature cache now
// live in k1z/targetgraph so the LLM agent can reuse the exact same graph.
func (s *Server) targetGraph(target string) (*graph.Graph, int, error) {
	return targetgraph.For(s.St, target)
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
		writeJSON(w, 200, g.Neighbors(r.URL.Query().Get("id"), atoiDefault(r.URL.Query().Get("limit"), 500)))
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
		// fold in the agent's pinned leads so a single summary read shows both the
		// surface size AND what was flagged (counts stays flat for back-compat).
		writeJSON(w, 200, map[string]any{"counts": g.Stats(), "annotations": readAnnotations(r.PathValue("name"))})
	}
}

// handleGraph2Map returns the full target relationship map (hosts↔ips↔asn↔
// urls↔params↔findings + domain-level buckets/secrets/certs/dns/intel) — the
// structured per-target lookup consumed by the recon_graph agent/task tool.
func (s *Server) handleGraph2Map(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		// attach the pinned leads so the agent sees them in the same map read
		writeJSON(w, 200, map[string]any{"map": g.TargetMap(atoiDefault(r.URL.Query().Get("hosts"), 0)), "annotations": readAnnotations(r.PathValue("name"))})
	}
}

// ── run-scoped graph: the surface ONE run produced (rebuilt live per step) ──
// Same shapes as the target graph (stats/map/search/neighbors) but built from a
// single run's workspace, so an agent following a run can read its own delta via
// recon_graph(run_id=…) instead of re-reading the whole target map each poll.
func (s *Server) runGraphFor(w http.ResponseWriter, r *http.Request) *graph.Graph {
	g, code, err := targetgraph.ForRun(s.St, r.PathValue("id"))
	if err != nil {
		writeDetail(w, code, err.Error())
		return nil
	}
	return g
}

func (s *Server) handleRunGraphStats(w http.ResponseWriter, r *http.Request) {
	if g := s.runGraphFor(w, r); g != nil {
		writeJSON(w, 200, g.Stats())
	}
}

func (s *Server) handleRunGraphMap(w http.ResponseWriter, r *http.Request) {
	if g := s.runGraphFor(w, r); g != nil {
		writeJSON(w, 200, g.TargetMap(atoiDefault(r.URL.Query().Get("hosts"), 0)))
	}
}

func (s *Server) handleRunGraphSearch(w http.ResponseWriter, r *http.Request) {
	if g := s.runGraphFor(w, r); g != nil {
		writeJSON(w, 200, map[string]any{"nodes": g.Search(r.URL.Query().Get("q"), atoiDefault(r.URL.Query().Get("limit"), 50))})
	}
}

func (s *Server) handleRunGraphNeighbors(w http.ResponseWriter, r *http.Request) {
	if g := s.runGraphFor(w, r); g != nil {
		writeJSON(w, 200, g.Neighbors(r.URL.Query().Get("id"), atoiDefault(r.URL.Query().Get("limit"), 500)))
	}
}

// handleRunGraphDelta is the TRUE delta: nodes this run produced that are NOT in
// any OTHER run of the same target (run graph minus the all-other-runs graph).
// So an agent re-scanning an already-mapped target sees only what is genuinely new.
func (s *Server) handleRunGraphDelta(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	run, err := s.St.GetRun(runID)
	if err != nil || run == nil {
		writeDetail(w, 404, "run not found")
		return
	}
	runG, code, err := targetgraph.ForRun(s.St, runID)
	if err != nil {
		writeDetail(w, code, err.Error())
		return
	}
	prior := map[string]bool{}
	if pg, _, perr := targetgraph.ForExcept(s.St, run.Target, runID); perr == nil && pg != nil {
		for id := range pg.Nodes {
			prior[id] = true
		}
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 500)
	counts := map[string]int{}
	newNodes := make([]map[string]string, 0, 32)
	for id, n := range runG.Nodes {
		if prior[id] {
			continue
		}
		counts[n.Group]++
		if len(newNodes) < limit {
			newNodes = append(newNodes, map[string]string{"id": id, "label": n.Label, "group": n.Group})
		}
	}
	sort.Slice(newNodes, func(i, j int) bool { return newNodes[i]["id"] < newNodes[j]["id"] })
	total := 0
	for _, c := range counts {
		total += c
	}
	writeJSON(w, 200, map[string]any{"total_new": total, "counts_by_type": counts, "new_nodes": newNodes, "truncated": total > len(newNodes)})
}

// graph2ViewHTML is the WebGL (Sigma.js) client — a page that pulls subgraphs
// from the graph2 API on demand (no embedded data), so it stays fast regardless
// of graph size. Embedded so it ships in the binary without the frontend build.
//
//go:embed assets/graph2_view.html
var graph2ViewHTML string

func (s *Server) handleGraph2View(w http.ResponseWriter, r *http.Request) {
	tj, _ := json.Marshal(targetgraph.NormTarget(r.PathValue("name"))) // canonical host → BASE + annotations key off it
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
	name := targetgraph.SafeTargetDir(r.PathValue("name"))
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
