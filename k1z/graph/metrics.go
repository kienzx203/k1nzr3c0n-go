package graph

import (
	"math/rand"
	"sort"
)

// NodeMetrics holds the analytical scores computed for a single node.
type NodeMetrics struct {
	Degree      int     `json:"deg"`
	PageRank    float64 `json:"pr"`
	Betweenness float64 `json:"btw"`
	Community   int     `json:"comm"`
	Cut         bool    `json:"cut"` // articulation point (chokepoint)
}

// MetricsResult is the full analysis of the graph.
type MetricsResult struct {
	Nodes map[string]*NodeMetrics `json:"nodes"`
	Meta  map[string]any          `json:"meta"`
}

// Metrics computes degree, PageRank, betweenness centrality, Louvain
// communities and articulation points for every node. Result is memoized per
// Graph instance (graphs are rebuilt when stale, so the memo self-invalidates).
func (g *Graph) Metrics() MetricsResult {
	g.metricsOnce.Do(func() { g.metricsVal = g.computeMetrics() })
	return g.metricsVal
}

func (g *Graph) computeMetrics() MetricsResult {
	ids := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic ordering
	idx := make(map[string]int, len(ids))
	for i, id := range ids {
		idx[id] = i
	}
	n := len(ids)
	adj := make([][]int, n)
	for i, id := range ids {
		for nb := range g.adj[id] {
			if j, ok := idx[nb]; ok {
				adj[i] = append(adj[i], j)
			}
		}
		sort.Ints(adj[i])
	}

	res := MetricsResult{Nodes: make(map[string]*NodeMetrics, n), Meta: map[string]any{}}
	if n == 0 {
		return res
	}
	pr := pageRank(adj, 0.85, 50)
	cut := articulation(adj)
	comm := louvain(adj)

	exact := n <= 2500
	var btw []float64
	if exact {
		btw = betweenness(adj, nil)
	} else {
		k := 600
		if k > n {
			k = n
		}
		perm := rand.New(rand.NewSource(1)).Perm(n)
		btw = betweenness(adj, perm[:k])
		scale := float64(n) / float64(k)
		for i := range btw {
			btw[i] *= scale
		}
	}
	for i, id := range ids {
		res.Nodes[id] = &NodeMetrics{Degree: len(adj[i]), PageRank: pr[i], Betweenness: btw[i], Community: comm[i], Cut: cut[i]}
	}
	nc := 0
	seen := map[int]bool{}
	for _, c := range comm {
		if !seen[c] {
			seen[c] = true
			nc++
		}
	}
	res.Meta["nodes"] = n
	res.Meta["communities"] = nc
	res.Meta["betweennessExact"] = exact
	return res
}

// pageRank over the undirected adjacency (power iteration, dangling-aware).
func pageRank(adj [][]int, damp float64, iters int) []float64 {
	n := len(adj)
	pr := make([]float64, n)
	for i := range pr {
		pr[i] = 1.0 / float64(n)
	}
	for it := 0; it < iters; it++ {
		next := make([]float64, n)
		dangling := 0.0
		for i := 0; i < n; i++ {
			if len(adj[i]) == 0 {
				dangling += pr[i]
			}
		}
		base := (1-damp)/float64(n) + damp*dangling/float64(n)
		for i := 0; i < n; i++ {
			next[i] = base
		}
		for i := 0; i < n; i++ {
			if len(adj[i]) == 0 {
				continue
			}
			share := damp * pr[i] / float64(len(adj[i]))
			for _, j := range adj[i] {
				next[j] += share
			}
		}
		pr = next
	}
	return pr
}

// articulation points (chokepoints) via iterative Tarjan DFS.
func articulation(adj [][]int) []bool {
	n := len(adj)
	cut := make([]bool, n)
	disc := make([]int, n)
	low := make([]int, n)
	for i := range disc {
		disc[i] = -1
	}
	timer := 0
	type frame struct {
		u, parent, ci int
	}
	for s := 0; s < n; s++ {
		if disc[s] != -1 {
			continue
		}
		stack := []frame{{s, -1, 0}}
		children := make(map[int]int)
		for len(stack) > 0 {
			f := &stack[len(stack)-1]
			if f.ci == 0 {
				disc[f.u] = timer
				low[f.u] = timer
				timer++
			}
			if f.ci < len(adj[f.u]) {
				v := adj[f.u][f.ci]
				f.ci++
				if v == f.parent {
					continue
				}
				if disc[v] == -1 {
					children[f.u]++
					stack = append(stack, frame{v, f.u, 0})
				} else if disc[v] < low[f.u] {
					low[f.u] = disc[v]
				}
			} else {
				// done with f.u; propagate to parent
				u, parent := f.u, f.parent
				stack = stack[:len(stack)-1]
				if parent != -1 {
					if low[u] < low[parent] {
						low[parent] = low[u]
					}
					if low[u] >= disc[parent] && stack[len(stack)-1].parent != -1 {
						cut[parent] = true
					}
				}
			}
		}
		if children[s] > 1 {
			cut[s] = true
		}
	}
	return cut
}

// louvain: one-level modularity local-moving community detection.
func louvain(adj [][]int) []int {
	n := len(adj)
	comm := make([]int, n)
	deg := make([]float64, n)
	m2 := 0.0
	for i := range adj {
		comm[i] = i
		deg[i] = float64(len(adj[i]))
		m2 += deg[i]
	}
	if m2 == 0 {
		return comm
	}
	sigTot := make([]float64, n)
	copy(sigTot, deg)
	order := rand.New(rand.NewSource(1)).Perm(n)
	for pass := 0; pass < 12; pass++ {
		improved := false
		for _, i := range order {
			ci := comm[i]
			sigTot[ci] -= deg[i]
			links := map[int]float64{}
			for _, j := range adj[i] {
				links[comm[j]]++
			}
			best, bestGain := ci, links[ci]-sigTot[ci]*deg[i]/m2
			for c, k := range links {
				if g := k - sigTot[c]*deg[i]/m2; g > bestGain {
					bestGain, best = g, c
				}
			}
			comm[i] = best
			sigTot[best] += deg[i]
			if best != ci {
				improved = true
			}
		}
		if !improved {
			break
		}
	}
	remap := map[int]int{}
	next := 0
	for i := range comm {
		if _, ok := remap[comm[i]]; !ok {
			remap[comm[i]] = next
			next++
		}
		comm[i] = remap[comm[i]]
	}
	return comm
}

// betweenness via Brandes. pivots==nil computes exact over all sources;
// otherwise it sums only over the given source nodes (sampling).
func betweenness(adj [][]int, pivots []int) []float64 {
	n := len(adj)
	bc := make([]float64, n)
	sources := pivots
	if sources == nil {
		sources = make([]int, n)
		for i := range sources {
			sources[i] = i
		}
	}
	for _, s := range sources {
		stack := make([]int, 0, n)
		pred := make([][]int, n)
		sigma := make([]float64, n)
		sigma[s] = 1
		dist := make([]int, n)
		for i := range dist {
			dist[i] = -1
		}
		dist[s] = 0
		queue := []int{s}
		for len(queue) > 0 {
			v := queue[0]
			queue = queue[1:]
			stack = append(stack, v)
			for _, w := range adj[v] {
				if dist[w] < 0 {
					dist[w] = dist[v] + 1
					queue = append(queue, w)
				}
				if dist[w] == dist[v]+1 {
					sigma[w] += sigma[v]
					pred[w] = append(pred[w], v)
				}
			}
		}
		delta := make([]float64, n)
		for i := len(stack) - 1; i >= 0; i-- {
			w := stack[i]
			for _, v := range pred[w] {
				delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
			}
			if w != s {
				bc[w] += delta[w]
			}
		}
	}
	for i := range bc {
		bc[i] /= 2 // undirected: each shortest path counted from both ends
	}
	return bc
}
