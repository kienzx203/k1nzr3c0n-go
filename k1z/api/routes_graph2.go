package api

import (
	_ "embed"
	"encoding/json"
	"net/http"
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
		writeJSON(w, 200, g.Stats())
	}
}

// handleGraph2Map returns the full target relationship map (hosts↔ips↔asn↔
// urls↔params↔findings + domain-level buckets/secrets/certs/dns/intel) — the
// structured per-target lookup consumed by the recon_graph agent/task tool.
func (s *Server) handleGraph2Map(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.TargetMap(atoiDefault(r.URL.Query().Get("hosts"), 0)))
	}
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
