// Package graph builds an attack-surface graph from a recon run's workspace and
// answers subgraph queries (overview / neighbors / path / search) — the backend
// half of the BloodHound-style design: the server holds the whole graph and the
// UI pulls only the slice it needs, instead of shipping one giant HTML.
package graph

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Node struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Group    string `json:"group"`
	Title    string `json:"title,omitempty"`
	Risk     int    `json:"risk,omitempty"`
	Internal bool   `json:"internal,omitempty"`
	Alive    bool   `json:"alive,omitempty"`
	Count    int    `json:"count,omitempty"` // cluster nodes: number of members
}

type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"`
}

type SubGraph struct {
	Nodes []*Node        `json:"nodes"`
	Edges []Edge         `json:"edges"`
	Meta  map[string]any `json:"meta,omitempty"`
}

type Graph struct {
	Nodes      map[string]*Node
	Edges      []Edge
	adj        map[string]map[string]struct{} // undirected neighbour ids
	inc        map[string][]int               // node id -> edge indices
	childrenOf map[string][]string            // subnet id -> member ip ids
	Target     string

	metricsOnce sync.Once
	metricsVal  MetricsResult
}

var (
	reIP   = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	reHost = regexp.MustCompile(`^[a-z0-9_.-]+\.[a-z]{2,}$`)
	sevW   = map[string]int{"critical": 8, "high": 5, "medium": 3, "low": 1}
)

func isInternal(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

// ── low-level file readers ────────────────────────────────────────────────────

func firstExisting(dir string, names ...string) string {
	for _, n := range names {
		p := filepath.Join(dir, n)
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			return p
		}
	}
	return ""
}

func lines(path string) []string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func jsonl(path string, fn func(map[string]any)) {
	for _, ln := range lines(path) {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil {
			fn(m)
		}
	}
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func intOf(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}
func hostOfURL(u string) string {
	u = regexp.MustCompile(`^[a-z]+://`).ReplaceAllString(u, "")
	u = strings.SplitN(u, "/", 2)[0]
	return strings.ToLower(strings.SplitN(u, ":", 2)[0])
}

// ── build ─────────────────────────────────────────────────────────────────────

// Build reads the recon output files in dir and assembles the graph.
func Build(dir, target string) *Graph {
	g := &Graph{Nodes: map[string]*Node{}, adj: map[string]map[string]struct{}{},
		inc: map[string][]int{}, childrenOf: map[string][]string{}, Target: target}

	hostIP := map[string]map[string]struct{}{} // host -> ip set
	hostCname := map[string]string{}
	hostPorts := map[string]map[string]struct{}{}
	ipPorts := map[string]map[string]struct{}{}
	alive := map[string]map[string]string{} // host -> httpx fields
	internalH := map[string]bool{}
	interesting := map[string]bool{}
	originIP := map[string]bool{}
	ipASN := map[string]string{}
	ipPrefix := map[string]string{}
	ipOrg := map[string]string{}
	subnets := map[string]bool{}
	hosts := map[string]bool{}
	type finding struct{ host, name, sev, url string }
	var findings []finding

	addIP := func(h, ip string) {
		if reIP.MatchString(ip) {
			if hostIP[h] == nil {
				hostIP[h] = map[string]struct{}{}
			}
			hostIP[h][ip] = struct{}{}
			hosts[h] = true
		}
	}

	for _, p := range []string{"subdomains.txt", "subdomains_resolved.txt", "passive_merged.txt", "p_dns_zone.txt", "dns_zone_nsec.txt"} {
		for _, h := range lines(firstExisting(dir, p)) {
			h = strings.ToLower(strings.Trim(h, "."))
			if reHost.MatchString(h) {
				hosts[h] = true
			}
		}
	}
	// dnsx -resp: host [cname] [ip]
	brack := regexp.MustCompile(`\[([^\]]+)\]`)
	for _, ln := range lines(firstExisting(dir, "subdomains_resolved_resp.txt")) {
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		h := strings.ToLower(strings.Trim(f[0], "."))
		if !reHost.MatchString(h) {
			continue
		}
		hosts[h] = true
		for _, m := range brack.FindAllStringSubmatch(ln, -1) {
			v := strings.TrimSpace(m[1])
			if reIP.MatchString(v) {
				addIP(h, v)
			} else if l := strings.ToLower(strings.Trim(v, ".")); reHost.MatchString(l) {
				hostCname[h] = l
			}
		}
	}
	for _, p := range []string{"resolved.txt", "dns_resolved.txt"} {
		for _, ln := range lines(firstExisting(dir, p)) {
			c := strings.Split(ln, "\t")
			if len(c) >= 2 {
				addIP(strings.ToLower(c[0]), strings.TrimSpace(c[1]))
			}
		}
	}
	for _, p := range []string{"censys_ip.txt", "fofa_ip_port.txt"} {
		for _, ln := range lines(firstExisting(dir, p)) {
			c := strings.Split(ln, "\t")
			if len(c) >= 2 {
				h := strings.ToLower(c[0])
				addIP(h, strings.TrimSpace(c[1]))
				if len(c) >= 3 {
					if port := strings.TrimSpace(c[2]); port != "" {
						if hostPorts[h] == nil {
							hostPorts[h] = map[string]struct{}{}
						}
						hostPorts[h][port] = struct{}{}
					}
				}
			}
		}
	}
	for _, p := range []string{"internal_hosts.txt", "dns_internal_hosts.txt"} {
		for _, ln := range lines(firstExisting(dir, p)) {
			c := strings.Split(ln, "\t")
			if len(c) >= 1 {
				h := strings.ToLower(c[0])
				internalH[h] = true
				hosts[h] = true
				if len(c) >= 2 {
					addIP(h, strings.TrimSpace(c[1]))
				}
			}
		}
	}
	jsonl(firstExisting(dir, "httpx.json", "httpx.jsonl"), func(m map[string]any) {
		h := strings.ToLower(str(m["host"]))
		if h == "" {
			h = hostOfURL(str(m["url"]))
		}
		if h == "" {
			return
		}
		hosts[h] = true
		if arr, ok := m["a"].([]any); ok {
			for _, ip := range arr {
				addIP(h, str(ip))
			}
		}
		cdn := str(m["cdn_name"])
		if cdn == "" {
			if b, _ := m["cdn"].(bool); b {
				cdn = "CDN"
			}
		}
		title := str(m["title"])
		if len(title) > 70 {
			title = title[:70]
		}
		alive[h] = map[string]string{"status": strconv.Itoa(intOf(m["status_code"]) + intOf(m["status-code"])),
			"title": title, "server": str(m["webserver"]), "cdn": cdn}
	})
	jsonl(firstExisting(dir, "naabu.json", "naabu.jsonl"), func(m map[string]any) {
		ip := str(m["ip"])
		port := intOf(m["port"])
		if reIP.MatchString(ip) && port > 0 {
			if ipPorts[ip] == nil {
				ipPorts[ip] = map[string]struct{}{}
			}
			ipPorts[ip][strconv.Itoa(port)] = struct{}{}
		}
	})
	nucleiHandler := func(m map[string]any) {
		info, _ := m["info"].(map[string]any)
		name := ""
		sev := "info"
		if info != nil {
			name = str(info["name"])
			if s := str(info["severity"]); s != "" {
				sev = s
			}
		}
		if name == "" {
			name = str(m["template-id"])
		}
		if name == "" {
			name = "finding"
		}
		matched := str(m["matched-at"])
		h := strings.ToLower(str(m["host"]))
		if h == "" {
			h = hostOfURL(matched)
		}
		if h == "" {
			h = str(m["ip"])
		}
		if _, ok := sevW[sev]; !ok && sev != "info" {
			sev = "info"
		}
		findings = append(findings, finding{h, name, strings.ToLower(sev), matched})
	}
	// nuclei writes nuclei*.jsonl (not .json); afrog writes afrog.json(l). Glob so
	// every scan file is read regardless of the exact step name.
	nfiles := map[string]bool{}
	for _, pat := range []string{"nuclei*.jsonl", "nuclei*.json", "afrog.json", "afrog.jsonl"} {
		ms, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, f := range ms {
			nfiles[f] = true
		}
	}
	for f := range nfiles {
		jsonl(f, nucleiHandler)
	}
	for _, ln := range lines(firstExisting(dir, "takeover_findings.txt")) {
		h := hostOfURL(ln)
		if h == "" {
			if f := strings.Fields(ln); len(f) > 0 {
				h = strings.ToLower(f[0])
			}
		}
		if h != "" {
			findings = append(findings, finding{h, "subdomain takeover", "high", ln})
		}
	}
	for _, ln := range lines(firstExisting(dir, "censys_hosts.txt")) {
		c := strings.Split(ln, "\t")
		if len(c) >= 4 && reIP.MatchString(c[0]) {
			ipASN[c[0]] = strings.TrimSpace(c[1])
			ipOrg[c[0]] = strings.TrimSpace(c[2])
			ipPrefix[c[0]] = strings.TrimSpace(c[3])
		}
	}
	for _, p := range []string{"internal_subnets.txt", "dns_internal_subnets.txt"} {
		for _, ln := range lines(firstExisting(dir, p)) {
			if f := strings.Fields(ln); len(f) > 0 && strings.Contains(f[0], "/") {
				subnets[f[0]] = true
			}
		}
	}
	for _, h := range lines(firstExisting(dir, "interesting.txt")) {
		interesting[strings.ToLower(strings.Trim(h, "."))] = true
	}
	for _, ip := range lines(firstExisting(dir, "origin_ips.txt")) {
		if reIP.MatchString(ip) {
			originIP[ip] = true
		}
	}

	// ── extended surface coverage (permutation/tlsx/pivot/vhost/favicon/js/ptr) ──
	for _, p := range []string{"subdomains_all_resolved.txt", "subdomains_all.txt", "subdomains_tlsx_resolved.txt",
		"tlsx_new_subs.txt", "js_subs.txt", "jsubfinder_subs.txt", "st_intel_subs.txt", "reverse_dns_subs.txt",
		"ptr_subs.txt", "dns_records_subs.txt", "http_redirect_subs.txt", "recursive_parents.txt"} {
		for _, h := range lines(firstExisting(dir, p)) {
			h = strings.ToLower(strings.Trim(h, "."))
			if reHost.MatchString(h) {
				hosts[h] = true
			}
		}
	}
	// hosts found via vhost/favicon/pivot = non-standard (interesting) surface
	for _, p := range []string{"vhost_new_hosts.txt", "favicon_in_scope.txt", "pivot_new_resolved.txt",
		"http_redirect_resolved.txt", "dns_svc_new_hosts.txt"} {
		for _, ln := range lines(firstExisting(dir, p)) {
			f := strings.Fields(ln)
			if len(f) == 0 {
				continue
			}
			h := strings.ToLower(strings.Trim(f[0], "."))
			if reHost.MatchString(h) {
				hosts[h] = true
				interesting[h] = true
			}
		}
	}
	// PTR: "ip [host ...]" or "ip\thost" → link host↔ip
	for _, p := range []string{"ptr_resolved.txt", "dns_ptr.txt"} {
		for _, ln := range lines(firstExisting(dir, p)) {
			var ip string
			var hs []string
			for _, tok := range strings.Fields(ln) {
				tok = strings.Trim(tok, "[],.")
				if reIP.MatchString(tok) {
					ip = tok
				} else if l := strings.ToLower(tok); reHost.MatchString(l) {
					hs = append(hs, l)
				}
			}
			if ip != "" {
				for _, h := range hs {
					hosts[h] = true
					addIP(h, ip)
				}
			}
		}
	}
	// org/ASN CIDR ranges → subnet nodes
	for _, p := range []string{"asn_ipv4_cidrs.txt", "amass_intel_cidrs.txt", "censys_prefixes.txt"} {
		for _, ln := range lines(firstExisting(dir, p)) {
			if f := strings.Fields(ln); len(f) > 0 && strings.Contains(f[0], "/") {
				subnets[f[0]] = true
			}
		}
	}
	// CDN classification: host/ip → provider name
	cdnOf := map[string]string{}
	jsonl(firstExisting(dir, "cdncheck.jsonl", "cdncheck.json"), func(m map[string]any) {
		name := str(m["cdn_name"])
		if name == "" {
			name = str(m["cdn"])
		}
		if name == "" || name == "false" || name == "true" {
			return
		}
		if h := strings.ToLower(str(m["host"])); reHost.MatchString(h) {
			cdnOf[h] = name
		}
		if ip := str(m["ip"]); reIP.MatchString(ip) {
			cdnOf[ip] = name
		}
		if in := strings.ToLower(str(m["input"])); reHost.MatchString(in) || reIP.MatchString(in) {
			cdnOf[in] = name
		}
	})
	// cloud buckets (s3scanner)
	type bkt struct{ name, info string }
	var buckets []bkt
	jsonl(firstExisting(dir, "s3scanner.json", "s3scanner.jsonl"), func(m map[string]any) {
		name := str(m["name"])
		if name == "" {
			name = str(m["bucket"])
		}
		if name != "" {
			buckets = append(buckets, bkt{name, strings.TrimSpace(str(m["region"]) + " " + str(m["provider"]))})
		}
	})
	// high-cardinality surface (URLs/endpoints/params/secrets) → counts on the domain
	cnt := func(names ...string) int { return len(lines(firstExisting(dir, names...))) }
	nURL := cnt("all_urls.txt", "live_urls.txt")
	nEnd := cnt("all_endpoints.txt", "linkfinder_endpoints.txt")
	nParam := cnt("all_params.txt", "found_params.txt")
	nSecret := cnt("jsubfinder_secrets.txt") + cnt("secretfinder_results.txt") +
		cnt("trufflehog_results.jsonl") + cnt("swaggerspy_results.txt")

	// ── assemble nodes/edges ───────────────────────────────────────────────────
	if target != "" {
		dtitle := fmt.Sprintf("%s\nURLs: %d · endpoints: %d · params: %d · secrets: %d", target, nURL, nEnd, nParam, nSecret)
		g.add(&Node{ID: "dom:" + target, Label: target, Group: "domain", Title: dtitle})
	}
	riskOf := map[string]int{}
	for _, f := range findings {
		riskOf["h:"+f.host] += sevW[f.sev]
	}
	for h := range hosts {
		if !reHost.MatchString(h) {
			continue
		}
		internal := internalH[h]
		for ip := range hostIP[h] {
			if isInternal(ip) {
				internal = true
			}
		}
		hh := alive[h]
		grp := "sub_dead"
		if internal {
			grp = "sub_int"
		} else if interesting[h] {
			grp = "vhost"
		} else if hh != nil {
			grp = "sub"
		}
		title := h
		if hh != nil {
			title += "\n" + hh["status"] + " " + hh["title"]
			if hh["cdn"] != "" {
				title += "\nCDN: " + hh["cdn"]
			}
		}
		short := h
		if target != "" && strings.HasSuffix(h, "."+target) {
			short = strings.TrimSuffix(h, "."+target)
		}
		g.add(&Node{ID: "h:" + h, Label: short, Group: grp, Title: title,
			Risk: riskOf["h:"+h], Internal: internal, Alive: hh != nil})
	}
	allIP := map[string]bool{}
	for h, ips := range hostIP {
		for ip := range ips {
			allIP[ip] = true
			grp := "ip_pub"
			if isInternal(ip) {
				grp = "ip_int"
			} else if originIP[ip] {
				grp = "ip_origin"
			}
			t := ip
			if ipASN[ip] != "" {
				t += "\n" + ipASN[ip] + " " + ipOrg[ip]
			}
			if ps := sortedKeys(ipPorts[ip]); len(ps) > 0 {
				t += "\nports: " + strings.Join(ps, ",")
			}
			g.add(&Node{ID: "ip:" + ip, Label: ip, Group: grp, Title: t, Internal: isInternal(ip)})
			if _, ok := g.Nodes["h:"+h]; ok {
				g.link("h:"+h, "ip:"+ip, "A")
			}
		}
	}
	for h, c := range hostCname {
		if _, ok := g.Nodes["h:"+h]; !ok {
			continue
		}
		if target != "" && strings.HasSuffix(c, "."+target) {
			continue
		}
		g.add(&Node{ID: "prov:" + c, Label: c, Group: "provider", Title: "CNAME → " + c})
		g.link("h:"+h, "prov:"+c, "CNAME")
	}
	for ip := range allIP {
		if ipASN[ip] != "" {
			aid := "as:" + ipASN[ip]
			g.add(&Node{ID: aid, Label: ipASN[ip] + " " + ipOrg[ip], Group: "asn"})
			g.link("ip:"+ip, aid, "ASN")
		}
		pfx := ipPrefix[ip]
		if pfx == "" || pfx == "?" {
			if isInternal(ip) {
				pfx = slash24(ip)
			}
		}
		if pfx != "" {
			nid := "net:" + pfx
			g.add(&Node{ID: nid, Label: pfx, Group: "subnet"})
			g.link("ip:"+ip, nid, "in")
			g.childrenOf[nid] = appendUniq(g.childrenOf[nid], "ip:"+ip)
		}
	}
	for s := range subnets {
		g.add(&Node{ID: "net:" + s, Label: s, Group: "subnet"})
	}
	for _, f := range findings {
		sev := f.sev
		if _, ok := sevW[sev]; !ok {
			sev = "info"
		}
		fid := "v:" + sev + ":" + f.name + ":" + f.host
		g.add(&Node{ID: fid, Label: f.name, Group: "vuln_" + sev, Title: "[" + strings.ToUpper(sev) + "] " + f.name + "\n" + f.url})
		if _, ok := g.Nodes["h:"+f.host]; ok {
			g.link("h:"+f.host, fid, sev)
		} else if _, ok := g.Nodes["ip:"+f.host]; ok {
			g.link("ip:"+f.host, fid, sev)
		}
	}
	// CDN providers: host/ip → provider node
	for key, name := range cdnOf {
		var anchor string
		if _, ok := g.Nodes["h:"+key]; ok {
			anchor = "h:" + key
		} else if _, ok := g.Nodes["ip:"+key]; ok {
			anchor = "ip:" + key
		}
		if anchor != "" {
			g.add(&Node{ID: "cdn:" + name, Label: name, Group: "provider", Title: "CDN: " + name})
			g.link(anchor, "cdn:"+name, "CDN")
		}
	}
	// cloud buckets → attached to the domain
	for _, b := range buckets {
		bid := "bkt:" + b.name
		g.add(&Node{ID: bid, Label: b.name, Group: "bucket", Title: "bucket: " + b.name + "\n" + b.info})
		if target != "" {
			g.link("dom:"+target, bid, "bucket")
		}
	}

	// connected backbone: domain → subnet/ASN clusters, so the graph is one
	// component and attack-paths (domain → internal host) resolve.
	if target != "" {
		for id, n := range g.Nodes {
			if n.Group == "asn" || n.Group == "subnet" {
				g.link("dom:"+target, id, "scope")
			}
		}
	}
	return g
}

func (g *Graph) add(n *Node) {
	if _, ok := g.Nodes[n.ID]; !ok {
		g.Nodes[n.ID] = n
	}
}
func (g *Graph) link(a, b, label string) {
	if _, ok := g.Nodes[a]; !ok {
		return
	}
	if _, ok := g.Nodes[b]; !ok {
		return
	}
	idx := len(g.Edges)
	g.Edges = append(g.Edges, Edge{From: a, To: b, Label: label})
	g.inc[a] = append(g.inc[a], idx)
	g.inc[b] = append(g.inc[b], idx)
	if g.adj[a] == nil {
		g.adj[a] = map[string]struct{}{}
	}
	if g.adj[b] == nil {
		g.adj[b] = map[string]struct{}{}
	}
	g.adj[a][b] = struct{}{}
	g.adj[b][a] = struct{}{}
}

// ── queries ─────────────────────────────────────────────────────────────────

// Overview returns the skeleton: domain + subnet/ASN clusters (with counts) +
// findings + the most notable hosts, capped.
func (g *Graph) Overview(hostCap int) SubGraph {
	keep := map[string]bool{}
	for id, n := range g.Nodes {
		switch {
		case n.Group == "domain" || n.Group == "asn" || n.Group == "subnet" || strings.HasPrefix(n.Group, "vuln"):
			keep[id] = true
		}
	}
	// notable hosts by score
	type hs struct {
		id    string
		score int
	}
	var hl []hs
	for id, n := range g.Nodes {
		if !strings.HasPrefix(id, "h:") {
			continue
		}
		if n.Group == "sub_dead" {
			continue
		}
		sc := n.Risk*100 + len(g.adj[id])
		if n.Group == "sub_int" {
			sc += 60
		} else if n.Group == "vhost" {
			sc += 40
		} else if n.Group == "sub" {
			sc += 25
		}
		hl = append(hl, hs{id, sc})
	}
	sort.Slice(hl, func(i, j int) bool { return hl[i].score > hl[j].score })
	for i, h := range hl {
		if i >= hostCap {
			break
		}
		keep[h.id] = true
	}
	// representative IPs (those attached to kept hosts or carrying ports/ASN)
	for _, e := range g.Edges {
		if e.Label == "A" && keep[e.From] {
			keep[e.To] = true
		}
	}
	return g.slice(keep, map[string]any{"total": len(g.Nodes), "shown": len(keep),
		"hosts": len(hl), "hostCap": hostCap})
}

// Full returns the entire graph — every node and edge.
func (g *Graph) Full() SubGraph {
	keep := make(map[string]bool, len(g.Nodes))
	for id := range g.Nodes {
		keep[id] = true
	}
	return g.slice(keep, map[string]any{"total": len(g.Nodes), "shown": len(g.Nodes), "edgeCount": len(g.Edges)})
}

// Neighbors returns a node and its immediate neighbours.
func (g *Graph) Neighbors(id string) SubGraph {
	keep := map[string]bool{id: true}
	for nb := range g.adj[id] {
		keep[nb] = true
	}
	return g.slice(keep, nil)
}

// Path returns the shortest path (BFS, undirected) between two nodes.
func (g *Graph) Path(from, to string) SubGraph {
	if _, ok := g.Nodes[from]; !ok {
		return SubGraph{Nodes: []*Node{}, Edges: []Edge{}}
	}
	prev := map[string]string{from: ""}
	q := []string{from}
	for len(q) > 0 && prev[to] == "" && to != from {
		cur := q[0]
		q = q[1:]
		for nb := range g.adj[cur] {
			if _, seen := prev[nb]; !seen {
				prev[nb] = cur
				q = append(q, nb)
			}
		}
	}
	keep := map[string]bool{}
	for at := to; at != ""; at = prev[at] {
		keep[at] = true
		if at == from {
			break
		}
		if _, ok := prev[at]; !ok {
			return SubGraph{Nodes: []*Node{}, Edges: []Edge{}, Meta: map[string]any{"path": false}}
		}
	}
	return g.slice(keep, map[string]any{"path": keep[to]})
}

// Search returns node summaries matching q.
func (g *Graph) Search(q string, limit int) []*Node {
	q = strings.ToLower(q)
	var out []*Node
	for _, n := range g.Nodes {
		if strings.Contains(strings.ToLower(n.Label), q) || strings.Contains(strings.ToLower(n.ID), q) {
			out = append(out, n)
			if len(out) >= limit {
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Risk > out[j].Risk })
	return out
}

func (g *Graph) Stats() map[string]int {
	s := map[string]int{"nodes": len(g.Nodes), "edges": len(g.Edges)}
	for _, n := range g.Nodes {
		s[n.Group]++
	}
	return s
}

// slice returns the induced subgraph over the kept node ids, annotating cluster
// nodes with their total member count.
func (g *Graph) slice(keep map[string]bool, meta map[string]any) SubGraph {
	sg := SubGraph{Nodes: []*Node{}, Edges: []Edge{}, Meta: meta}
	for id := range keep {
		if n, ok := g.Nodes[id]; ok {
			cp := *n
			if c := len(g.childrenOf[id]); c > 0 {
				cp.Count = c
			}
			sg.Nodes = append(sg.Nodes, &cp)
		}
	}
	for _, e := range g.Edges {
		if keep[e.From] && keep[e.To] {
			sg.Edges = append(sg.Edges, e)
		}
	}
	return sg
}

// ── helpers ───────────────────────────────────────────────────────────────────

func slash24(ip string) string {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return ""
	}
	return strconv.Itoa(int(p[0])) + "." + strconv.Itoa(int(p[1])) + "." + strconv.Itoa(int(p[2])) + ".0/24"
}
func sortedKeys(m map[string]struct{}) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Slice(k, func(i, j int) bool { a, _ := strconv.Atoi(k[i]); b, _ := strconv.Atoi(k[j]); return a < b })
	return k
}
func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
