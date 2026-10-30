package graph

import (
	"fmt"
	"math"
	"testing"
)

// Layout must give every node a finite position + size and leave NO two node
// radii overlapping — that guarantee is the whole point of computing it server
// side (the browser then just renders fixed positions).
func TestLayoutNoOverlap(t *testing.T) {
	g := newTestGraph("example.com")
	g.add(&Node{ID: "dom:example.com", Group: "domain"})
	g.add(&Node{ID: "net:1.2.3.0/24", Group: "subnet"})
	g.link("dom:example.com", "net:1.2.3.0/24", "scope")
	for i := 0; i < 40; i++ {
		ip := fmt.Sprintf("ip:1.2.3.%d", i)
		g.add(&Node{ID: ip, Group: "ip_pub"})
		g.link("net:1.2.3.0/24", ip, "in")
		h := fmt.Sprintf("h:h%d.example.com", i)
		g.add(&Node{ID: h, Group: "sub", Risk: i % 5})
		g.link(h, ip, "A")
	}

	g.Layout()

	ids := make([]string, 0, len(g.Nodes))
	for id, n := range g.Nodes {
		if math.IsNaN(n.X) || math.IsNaN(n.Y) || math.IsInf(n.X, 0) || math.IsInf(n.Y, 0) {
			t.Fatalf("node %s has non-finite position (%v,%v)", id, n.X, n.Y)
		}
		if n.Sz <= 0 {
			t.Fatalf("node %s has no size", id)
		}
		ids = append(ids, id)
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			a, b := g.Nodes[ids[i]], g.Nodes[ids[j]]
			d := math.Hypot(a.X-b.X, a.Y-b.Y)
			if d < a.Sz+b.Sz-0.5 { // must be at least the sum of radii apart
				t.Errorf("overlap: %s & %s are %.1f apart, radii %.1f+%.1f", ids[i], ids[j], d, a.Sz, b.Sz)
			}
		}
	}
}
