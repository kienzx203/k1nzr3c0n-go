package graph

import "testing"

// the multi-run file merge duplicates source lines, so g.link must collapse an
// exact (from,to,label) edge to one — otherwise edge counts, exports and risk
// ordering inflate (bug B1).
func TestLinkDedup(t *testing.T) {
	g := &Graph{Nodes: map[string]*Node{}, adj: map[string]map[string]struct{}{},
		inc: map[string][]int{}, childrenOf: map[string][]string{}, edgeSeen: map[string]bool{}}
	g.add(&Node{ID: "a"})
	g.add(&Node{ID: "b"})
	g.link("a", "b", "x") // kept
	g.link("a", "b", "x") // duplicate → dropped
	g.link("a", "b", "y") // different label → kept
	g.link("a", "c", "x") // missing node c → dropped by existence check
	if len(g.Edges) != 2 {
		t.Fatalf("want 2 edges (a-b:x, a-b:y), got %d", len(g.Edges))
	}
	if len(g.adj["a"]) != 1 { // adj is a set, still just {b}
		t.Fatalf("want 1 neighbour of a, got %d", len(g.adj["a"]))
	}
}
