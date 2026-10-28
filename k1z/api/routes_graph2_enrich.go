package api

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/k1z/graph"
)

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$`)

func ipGroup(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return "ip_pub"
	}
	if p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() {
		return "ip_int"
	}
	return "ip_pub"
}

// handleGraph2Enrich runs a safe, read-only DNS transform (Maltego-style) on a
// node and returns a subgraph to append. Only DNS lookups via the stdlib
// resolver — no shell, strict input validation. Live network from the server.
func (s *Server) handleGraph2Enrich(w http.ResponseWriter, r *http.Request) {
	g := s.graphFor(w, r)
	if g == nil {
		return
	}
	id := r.URL.Query().Get("id")
	kind := r.URL.Query().Get("kind")
	n, ok := g.Nodes[id]
	if !ok {
		writeDetail(w, 404, "node not found")
		return
	}
	val := strings.TrimSpace(strings.TrimSuffix(n.Label, "."))

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res := &net.Resolver{}
	out := graph.SubGraph{Nodes: []*graph.Node{}, Edges: []graph.Edge{}, Meta: map[string]any{"kind": kind, "on": val}}
	add := func(nid, label, group string) {
		out.Nodes = append(out.Nodes, &graph.Node{ID: nid, Label: label, Group: group})
	}
	const cap = 60

	switch kind {
	case "ptr":
		if net.ParseIP(val) == nil {
			writeDetail(w, 400, "node is not an IP")
			return
		}
		names, _ := res.LookupAddr(ctx, val)
		for i, h := range names {
			if i >= cap {
				break
			}
			h = strings.TrimSuffix(h, ".")
			add("h:"+h, h, "sub")
			out.Edges = append(out.Edges, graph.Edge{From: id, To: "h:" + h, Label: "PTR"})
		}
	case "dns":
		if !hostRe.MatchString(val) {
			writeDetail(w, 400, "node is not a hostname")
			return
		}
		ips, _ := res.LookupIPAddr(ctx, val)
		for i, ip := range ips {
			if i >= cap {
				break
			}
			a := ip.IP.String()
			add("ip:"+a, a, ipGroup(a))
			out.Edges = append(out.Edges, graph.Edge{From: id, To: "ip:" + a, Label: "A"})
		}
	case "ns":
		if !hostRe.MatchString(val) {
			writeDetail(w, 400, "node is not a hostname")
			return
		}
		nss, _ := res.LookupNS(ctx, val)
		for i, ns := range nss {
			if i >= cap {
				break
			}
			h := strings.TrimSuffix(ns.Host, ".")
			add("h:"+h, h, "sub")
			out.Edges = append(out.Edges, graph.Edge{From: id, To: "h:" + h, Label: "NS"})
		}
	case "mx":
		if !hostRe.MatchString(val) {
			writeDetail(w, 400, "node is not a hostname")
			return
		}
		mxs, _ := res.LookupMX(ctx, val)
		for i, mx := range mxs {
			if i >= cap {
				break
			}
			h := strings.TrimSuffix(mx.Host, ".")
			add("h:"+h, h, "sub")
			out.Edges = append(out.Edges, graph.Edge{From: id, To: "h:" + h, Label: "MX"})
		}
	case "txt":
		if !hostRe.MatchString(val) {
			writeDetail(w, 400, "node is not a hostname")
			return
		}
		txts, _ := res.LookupTXT(ctx, val)
		out.Meta["txt"] = txts
	default:
		writeDetail(w, 400, "unknown transform")
		return
	}
	out.Meta["added"] = len(out.Nodes)
	writeJSON(w, 200, out)
}
