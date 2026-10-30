package graph

import (
	"math"
	"sort"
	"strings"
)

// layoutTier mirrors the viewer's TIER map: domain(0) → ASN/subnet(1) →
// IP/provider(2) → host/bucket(3) → leaves(4, incl. vuln).
func layoutTier(group string) int {
	if strings.HasPrefix(group, "vuln") {
		return 4
	}
	switch group {
	case "domain":
		return 0
	case "asn", "subnet":
		return 1
	case "ip_pub", "ip_int", "ip_origin", "provider":
		return 2
	case "sub", "sub_int", "sub_dead", "vhost", "bucket":
		return 3
	default:
		return 4
	}
}

// layoutSize mirrors the viewer's sizeOf so collision uses the same radii the
// client will render with: a tier-based base, boosted by cluster size + risk.
func layoutSize(n *Node) float64 {
	base := map[int]float64{0: 17, 1: 11, 2: 7.5, 3: 5.5, 4: 4.5}[layoutTier(n.Group)]
	if base == 0 {
		base = 4.5
	}
	if n.Count > 0 {
		base += math.Min(9, math.Log2(float64(n.Count)+1)*1.3)
	}
	if n.Risk > 0 {
		base += math.Min(9, float64(n.Risk))
	}
	return base
}

// Layout assigns every node a deterministic (X,Y): a radial hierarchy — the
// domain at the centre, each tier on a wider ring, children fanned under their
// parent proportional to subtree size — then a collision pass so no two node
// radii overlap. Computed once per graph build; the client renders these fixed
// positions and runs NO force simulation, so there is zero layout lag in the
// browser. Pairs naturally with the viewer's depth drill-down (expanding a node
// reveals its children already laid out in a neat arc around it).
func (g *Graph) Layout() {
	n := len(g.Nodes)
	if n == 0 {
		return
	}
	tier := make(map[string]int, n)
	ids := make([]string, 0, n)
	for id, nd := range g.Nodes {
		tier[id] = layoutTier(nd.Group)
		nd.Sz = layoutSize(nd)
		ids = append(ids, id)
	}
	sort.Strings(ids) // determinism

	root := ""
	for _, id := range ids {
		if g.Nodes[id].Group == "domain" {
			root = id
			break
		}
	}
	if root == "" {
		root = ids[0]
		for _, id := range ids {
			if tier[id] < tier[root] {
				root = id
			}
		}
	}

	// parent = the lowest-tier neighbour (deterministic); orphans attach to root.
	parent := make(map[string]string, n)
	for _, id := range ids {
		if id == root {
			continue
		}
		nbs := make([]string, 0, len(g.adj[id]))
		for nb := range g.adj[id] {
			nbs = append(nbs, nb)
		}
		sort.Strings(nbs)
		best, bt := "", 100
		for _, nb := range nbs {
			if tier[nb] < tier[id] && tier[nb] < bt {
				bt = tier[nb]
				best = nb
			}
		}
		if best == "" {
			best = root
		}
		parent[id] = best
	}
	children := make(map[string][]string, n)
	for _, id := range ids {
		if p, ok := parent[id]; ok {
			children[p] = append(children[p], id)
		}
	}
	for p := range children {
		sort.Strings(children[p])
	}

	// DFS order per tier: a parent's whole subtree is contiguous, so its children
	// land in a block "under" the parent's wedge and edges radiate outward.
	orderT := map[int][]string{}
	var dfs func(string)
	dfs = func(id string) {
		orderT[tier[id]] = append(orderT[tier[id]], id)
		for _, c := range children[id] {
			dfs(c)
		}
	}
	dfs(root)

	maxOverall := 1.0
	for _, id := range ids {
		if g.Nodes[id].Sz > maxOverall {
			maxOverall = g.Nodes[id].Sz
		}
	}
	gapArc := maxOverall * 0.9   // spacing between neighbours along a ring
	gapRing := maxOverall*3 + 40 // clearance between concentric rings

	tiers := make([]int, 0, len(orderT))
	for t := range orderT {
		tiers = append(tiers, t)
	}
	sort.Ints(tiers)

	// Concentric rings around the centre: each tier on its own circle, the radius
	// grown so the whole tier fits without overlap and clears the ring inside it;
	// nodes are spread around the ring proportional to their footprint. Clean,
	// deterministic, radiates outward from the domain — no collision scatter.
	prevR, prevMax := 0.0, 0.0
	for _, t := range tiers {
		list := orderT[t]
		mx, total := 0.0, 0.0
		for _, id := range list {
			s := g.Nodes[id].Sz
			if s > mx {
				mx = s
			}
			total += 2*s + gapArc
		}
		if total <= 0 {
			total = 1
		}
		r := math.Max(total/(2*math.Pi), prevR+prevMax+mx+gapRing)
		if t == tiers[0] && len(list) <= 1 { // the centre (domain) sits at the origin
			r = 0
		}
		ang := 0.0
		for _, id := range list {
			w := (2*g.Nodes[id].Sz + gapArc) / total * 2 * math.Pi
			mid := ang + w/2
			if r == 0 {
				g.Nodes[id].X, g.Nodes[id].Y = 0, 0
			} else {
				g.Nodes[id].X = r * math.Cos(mid)
				g.Nodes[id].Y = r * math.Sin(mid)
			}
			ang += w
		}
		prevR, prevMax = r, mx
	}
}

// deOverlap pushes every pair of nodes apart until (distance ≥ r1 + r2 + gap),
// so no two node radii intersect. Grid-accelerated; deterministic given sorted ids.
func deOverlap(g *Graph, ids []string) {
	n := len(ids)
	if n < 2 {
		return
	}
	x := make([]float64, n)
	y := make([]float64, n)
	r := make([]float64, n)
	maxr := 1.0
	for i, id := range ids {
		nd := g.Nodes[id]
		x[i], y[i], r[i] = nd.X, nd.Y, nd.Sz
		if nd.Sz > maxr {
			maxr = nd.Sz
		}
	}
	gap := maxr * 1.1 // generous spacing so radii never touch, with margin to spare
	cell := maxr*2 + gap
	iters := 140
	if n > 5000 {
		iters = 50
	} else if n > 2000 {
		iters = 90
	}
	type key struct{ a, b int }
	for it := 0; it < iters; it++ {
		grid := make(map[key][]int, n)
		for i := 0; i < n; i++ {
			k := key{int(math.Floor(x[i] / cell)), int(math.Floor(y[i] / cell))}
			grid[k] = append(grid[k], i)
		}
		moved := false
		for i := 0; i < n; i++ {
			cx, cy := int(math.Floor(x[i]/cell)), int(math.Floor(y[i]/cell))
			for gx := cx - 1; gx <= cx+1; gx++ {
				for gy := cy - 1; gy <= cy+1; gy++ {
					for _, j := range grid[key{gx, gy}] {
						if j <= i {
							continue
						}
						dx, dy := x[j]-x[i], y[j]-y[i]
						d := math.Hypot(dx, dy)
						if d < 1e-6 {
							// coincident: deterministic tiny offset by index
							dx, dy, d = 0.01+float64((j-i)%7)*0.001, 0.007, 0.012
						}
						min := r[i] + r[j] + gap
						if d < min {
							push := (min - d) / 2
							ux, uy := dx/d, dy/d
							x[i] -= ux * push
							y[i] -= uy * push
							x[j] += ux * push
							y[j] += uy * push
							moved = true
						}
					}
				}
			}
		}
		if !moved {
			break
		}
	}
	for i, id := range ids {
		g.Nodes[id].X = x[i]
		g.Nodes[id].Y = y[i]
	}
}
