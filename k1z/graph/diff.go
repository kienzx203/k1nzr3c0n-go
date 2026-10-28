package graph

// DiffResult is the union of two graphs with a per-node status describing how
// the "to" graph differs from the "from" graph.
type DiffResult struct {
	Nodes  []*Node           `json:"nodes"`
	Edges  []Edge            `json:"edges"`
	Status map[string]string `json:"status"` // id -> new | gone | changed | same
	Meta   map[string]any    `json:"meta"`
}

// Diff compares two graphs (earlier `from`, later `to`) and returns their union
// annotated with what changed: nodes only in `to` are "new", only in `from` are
// "gone", in both with a different risk are "changed", otherwise "same".
func Diff(from, to *Graph) DiffResult {
	res := DiffResult{Status: map[string]string{}, Meta: map[string]any{}, Nodes: []*Node{}, Edges: []Edge{}}
	counts := map[string]int{"new": 0, "gone": 0, "changed": 0, "same": 0}
	for id, tn := range to.Nodes {
		cp := *tn
		if fn, ok := from.Nodes[id]; ok {
			// a host can change without a risk delta (came alive, new ports,
			// group sub_dead→sub, internal flip) — compare those too.
			if fn.Risk != tn.Risk || fn.Group != tn.Group || fn.Alive != tn.Alive || fn.Internal != tn.Internal {
				res.Status[id] = "changed"
			} else {
				res.Status[id] = "same"
			}
		} else {
			res.Status[id] = "new"
		}
		counts[res.Status[id]]++
		res.Nodes = append(res.Nodes, &cp)
	}
	for id, fn := range from.Nodes {
		if _, ok := to.Nodes[id]; ok {
			continue
		}
		cp := *fn
		res.Status[id] = "gone"
		counts["gone"]++
		res.Nodes = append(res.Nodes, &cp)
	}
	seen := map[string]bool{}
	addEdge := func(e Edge) {
		k := e.From + "\x00" + e.To
		if seen[k] {
			return
		}
		seen[k] = true
		res.Edges = append(res.Edges, e)
	}
	for _, e := range to.Edges {
		addEdge(e)
	}
	for _, e := range from.Edges {
		addEdge(e)
	}
	for k, v := range counts {
		res.Meta[k] = v
	}
	res.Meta["nodes"] = len(res.Nodes)
	return res
}
