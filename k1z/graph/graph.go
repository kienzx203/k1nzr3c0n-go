// Package graph builds an attack-surface graph from a recon run's workspace and
// answers subgraph queries (overview / neighbors / path / search) — the backend
// half of the BloodHound-style design: the server holds the whole graph and the
// UI pulls only the slice it needs, instead of shipping one giant HTML.
package graph

import (
	"bufio"
	"bytes"
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
	ID       string  `json:"id"`
	Label    string  `json:"label"`
	Group    string  `json:"group"`
	Title    string  `json:"title,omitempty"`
	Risk     int     `json:"risk,omitempty"`
	Internal bool    `json:"internal,omitempty"`
	Alive    bool    `json:"alive,omitempty"`
	Count    int     `json:"count,omitempty"` // cluster nodes: number of members
	Ports    []int   `json:"ports,omitempty"` // open ports (host / ip nodes)
	X        float64 `json:"x"`               // server-computed layout position
	Y        float64 `json:"y"`
	Sz       float64 `json:"sz,omitempty"` // server-computed node size (radius)
}

// portsOf converts a set of port strings to a sorted []int.
func portsOf(m map[string]struct{}) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for p := range m {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
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
	edgeSeen   map[string]bool                // dedup exact (from,to,label) edges
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

// readTruffle returns one secret label per trufflehog/gitleaks finding.
func readTruffle(dir string) []string {
	var out []string
	for _, ln := range lines(firstExisting(dir, "trufflehog_results.jsonl")) {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil {
			if d := str(m["DetectorName"]); d != "" {
				out = append(out, d)
			}
		}
	}
	if b, e := os.ReadFile(filepath.Join(dir, "gitleaks_results.json")); e == nil && len(b) > 0 {
		// the multi-run merge concatenates arrays ([...][...]) → not valid single
		// JSON, so decode successive arrays from the stream instead of one Unmarshal.
		dec := json.NewDecoder(bytes.NewReader(b))
		for {
			var arr []map[string]any
			if err := dec.Decode(&arr); err != nil {
				break
			}
			for _, m := range arr {
				if r := str(m["RuleID"]); r != "" {
					out = append(out, r)
				}
			}
		}
	}
	return out
}

// gitleaksCount returns the number of entries in gitleaks_results.json (array).
func gitleaksCount(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, "gitleaks_results.json"))
	if err != nil || len(b) == 0 {
		return 0
	}
	var a []any
	if json.Unmarshal(b, &a) == nil {
		return len(a)
	}
	// multi-run merge concatenates arrays → invalid JSON; count by RuleID
	return strings.Count(string(b), "\"RuleID\"")
}

// globAll returns the deduped union of files matching any pattern under dir.
func globAll(dir string, pats ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range pats {
		ms, _ := filepath.Glob(filepath.Join(dir, p))
		for _, m := range ms {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// shortURL returns the path+query portion of a URL (for compact path labels).
func shortURL(u string) string {
	s := regexp.MustCompile(`^[a-z]+://`).ReplaceAllString(u, "")
	if i := strings.Index(s, "/"); i >= 0 {
		p := s[i:]
		if len(p) > 48 {
			p = p[:48] + "…"
		}
		return p
	}
	return "/"
}

// ── build ─────────────────────────────────────────────────────────────────────

// Build reads the recon output files in dir and assembles the graph.
func Build(dir, target string) *Graph {
	g := &Graph{Nodes: map[string]*Node{}, adj: map[string]map[string]struct{}{},
		inc: map[string][]int{}, childrenOf: map[string][]string{}, edgeSeen: map[string]bool{}, Target: target}

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
	// censys_ports.txt: ip\tport\tproto — open ports on in-scope IPs
	for _, ln := range lines(firstExisting(dir, "censys_ports.txt")) {
		c := strings.Split(ln, "\t")
		if len(c) >= 2 {
			ip := strings.TrimSpace(c[0])
			if reIP.MatchString(ip) {
				if ipPorts[ip] == nil {
					ipPorts[ip] = map[string]struct{}{}
				}
				ipPorts[ip][strings.TrimSpace(c[1])] = struct{}{}
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
	httpxH := func(m map[string]any) {
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
	}
	// glob so probe/pivot/st-pivot httpx runs (the only httpx in templates 03/04)
	// are read, not just the first httpx.json(l).
	for _, f := range globAll(dir, "httpx*.jsonl", "httpx*.json", "*httpx*.jsonl") {
		jsonl(f, httpxH)
	}
	naabuH := func(m map[string]any) {
		ip := str(m["ip"])
		port := intOf(m["port"])
		if reIP.MatchString(ip) && port > 0 {
			if ipPorts[ip] == nil {
				ipPorts[ip] = map[string]struct{}{}
			}
			ipPorts[ip][strconv.Itoa(port)] = struct{}{}
		}
	}
	for _, f := range globAll(dir, "naabu*.jsonl", "naabu*.json", "st_pivot_naabu.jsonl", "ports.jsonl") {
		jsonl(f, naabuH)
	}
	// nmap/rustscan service scan (normal -oN output) → open ports on hosts/ips
	for _, f := range globAll(dir, "nmap_service.txt", "rustscan_full.txt") {
		var curIP, curHost string
		for _, ln := range lines(f) {
			ls := strings.TrimSpace(ln)
			if strings.HasPrefix(ls, "Nmap scan report for ") {
				rest := strings.TrimSpace(strings.TrimPrefix(ls, "Nmap scan report for "))
				curHost, curIP = "", ""
				if i := strings.Index(rest, "("); i >= 0 {
					curHost = strings.ToLower(strings.TrimSpace(rest[:i]))
					curIP = strings.Trim(strings.TrimSpace(rest[i:]), "()")
				} else if reIP.MatchString(rest) {
					curIP = rest
				} else {
					curHost = strings.ToLower(rest)
				}
				if reHost.MatchString(curHost) {
					hosts[curHost] = true
					if curIP != "" {
						addIP(curHost, curIP)
					}
				}
				continue
			}
			ff := strings.Fields(ls)
			if len(ff) >= 2 && strings.Contains(ff[0], "/") && ff[1] == "open" {
				port := strings.SplitN(ff[0], "/", 2)[0]
				if curIP != "" {
					if ipPorts[curIP] == nil {
						ipPorts[curIP] = map[string]struct{}{}
					}
					ipPorts[curIP][port] = struct{}{}
				}
				if curHost != "" {
					if hostPorts[curHost] == nil {
						hostPorts[curHost] = map[string]struct{}{}
					}
					hostPorts[curHost][port] = struct{}{}
				}
			}
		}
	}
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
	for _, pat := range []string{"nuclei*.jsonl", "nuclei*.json"} {
		ms, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, f := range ms {
			nfiles[f] = true
		}
	}
	for f := range nfiles {
		jsonl(f, nucleiHandler)
	}
	// afrog writes a (pretty-printed) JSON array with pocinfo/fulltarget fields —
	// not JSONL and not nuclei-shaped, so it needs its own reader.
	for _, f := range globAll(dir, "afrog.json", "afrog.jsonl") {
		b, e := os.ReadFile(f)
		if e != nil || len(b) == 0 {
			continue
		}
		// the target merge concatenates arrays across runs ([...][...]); decode as
		// a stream of JSON values so multi-run afrog findings aren't lost.
		var arr []map[string]any
		dec := json.NewDecoder(bytes.NewReader(b))
		for {
			var a []map[string]any
			if err := dec.Decode(&a); err != nil {
				break
			}
			arr = append(arr, a...)
		}
		if len(arr) == 0 { // JSONL fallback
			for _, ln := range lines(f) {
				var m map[string]any
				if json.Unmarshal([]byte(ln), &m) == nil {
					arr = append(arr, m)
				}
			}
		}
		for _, m := range arr {
			name, sev := "", ""
			if poc, ok := m["pocinfo"].(map[string]any); ok {
				if in, ok := poc["info"].(map[string]any); ok {
					name, sev = str(in["name"]), str(in["severity"])
				}
				if name == "" {
					name = str(poc["infoname"])
				}
				if name == "" {
					name = str(poc["id"])
				}
				if sev == "" {
					sev = str(poc["severity"])
				}
			}
			if info, ok := m["info"].(map[string]any); ok {
				if name == "" {
					name = str(info["name"])
				}
				if sev == "" {
					sev = str(info["severity"])
				}
			}
			for _, k := range []string{"poc-id", "id", "name"} {
				if name == "" {
					name = str(m[k])
				}
			}
			if sev == "" {
				sev = str(m["severity"])
			}
			tgt := str(m["fulltarget"])
			if tgt == "" {
				tgt = str(m["target"])
			}
			if tgt == "" {
				tgt = str(m["url"])
			}
			h := strings.ToLower(hostOfURL(tgt))
			if h == "" {
				h = strings.ToLower(str(m["host"]))
			}
			if name == "" {
				name = "afrog finding"
			}
			sev = strings.ToLower(sev)
			if _, ok := sevW[sev]; !ok {
				sev = "info"
			}
			findings = append(findings, finding{h, name, sev, tgt})
		}
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
			name = str(m["waf_name"])
		}
		if name == "" {
			name = str(m["cloud_name"])
		}
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
		name, region, provider := "", "", ""
		if bk, ok := m["bucket"].(map[string]any); ok { // s3scanner v2 nests under .bucket
			name, region, provider = str(bk["name"]), str(bk["region"]), str(bk["provider"])
		} else {
			name, region, provider = str(m["name"]), str(m["region"]), str(m["provider"])
			if name == "" {
				name = str(m["bucket"])
			}
		}
		if name != "" {
			buckets = append(buckets, bkt{name, strings.TrimSpace(region + " " + provider)})
		}
	})
	cnt := func(names ...string) int { return len(lines(firstExisting(dir, names...))) }
	// EVERYTHING discovered becomes a node (purpose of the graph: omit nothing).
	// Capped per class so the WebGL viewer stays renderable; Overview hides these,
	// Full (default) + click-to-expand show them.
	urlByHost := map[string]int{}
	endByHost := map[string]int{}
	reNotable := regexp.MustCompile(`(?i)/(admin|login|signin|sign-in|dashboard|api|graphql|swagger|openapi|actuator|\.git|\.env|wp-admin|wp-login|phpmyadmin|jenkins|grafana|kibana|console|debug|backup|upload|config|phpinfo|server-status|metrics|\.sql|\.bak|\.zip|internal|private|token|secret|password)`)
	type leaf struct {
		host, val, group, title string
		ep                      bool
	}
	var leaves []leaf
	leafSeen := map[string]bool{}
	const urlNodeCap, epNodeCap = 5000, 4000
	nURLnodes, nEPnodes := 0, 0
	// in-scope = the target apex, a subdomain of it, or an already-known host.
	// Crawlers pull lots of third-party URLs (w3.org, github.com, cdn libs…) —
	// those are noise and must NOT become graph nodes.
	base := hostOfURL(target)
	inScope := func(h string) bool {
		if h == "" {
			return false
		}
		if hosts[h] {
			return true
		}
		return base != "" && (h == base || strings.HasSuffix(h, "."+base))
	}
	addURL := func(u string) {
		u = strings.TrimSpace(u)
		if !strings.HasPrefix(u, "http") || leafSeen["u\x00"+u] {
			return
		}
		h := hostOfURL(u)
		if !inScope(h) {
			return
		}
		leafSeen["u\x00"+u] = true
		urlByHost[h]++
		if nURLnodes >= urlNodeCap {
			return
		}
		nURLnodes++
		grp := "url"
		if reNotable.MatchString(u) {
			grp = "path"
		}
		leaves = append(leaves, leaf{h, u, grp, u, false})
	}
	addEP := func(u, tag string) {
		u = strings.TrimSpace(u)
		if !strings.HasPrefix(u, "http") || leafSeen["e\x00"+u] {
			return
		}
		h := hostOfURL(u)
		if !inScope(h) {
			return
		}
		leafSeen["e\x00"+u] = true
		endByHost[h]++
		if nEPnodes >= epNodeCap {
			return
		}
		nEPnodes++
		grp, title := "endpoint", u
		if tag != "" {
			title = "[" + tag + "] " + u
		} else if reNotable.MatchString(u) {
			grp = "path"
		}
		leaves = append(leaves, leaf{h, u, grp, title, true})
	}
	nURL := 0
	for _, ln := range lines(firstExisting(dir, "all_urls.txt", "live_urls.txt")) {
		if strings.HasPrefix(strings.TrimSpace(ln), "http") {
			nURL++
			addURL(ln)
		}
	}
	nEnd := 0
	for _, p := range []string{"all_endpoints.txt", "linkfinder_endpoints.txt"} {
		for _, ln := range lines(firstExisting(dir, p)) {
			if strings.HasPrefix(strings.TrimSpace(ln), "http") {
				nEnd++
				addEP(ln, "")
			}
		}
	}
	if ms, _ := filepath.Glob(filepath.Join(dir, "gf", "*.txt")); len(ms) > 0 {
		for _, f := range ms {
			cat := strings.TrimSuffix(filepath.Base(f), ".txt")
			for _, ln := range lines(f) {
				if strings.HasPrefix(strings.TrimSpace(ln), "http") {
					addEP(ln, cat)
				}
			}
		}
	}
	nParam := cnt("all_params.txt", "found_params.txt")
	nSecret := cnt("jsubfinder_secrets.txt") + cnt("secretfinder_results.txt") +
		cnt("trufflehog_results.jsonl") + cnt("swaggerspy_results.txt") + gitleaksCount(dir)
	nRelated := cnt("st_associated.txt") + cnt("st_pivot_domains.txt") + cnt("amass_intel.txt")

	// ── assemble nodes/edges ───────────────────────────────────────────────────
	if target != "" {
		dtitle := fmt.Sprintf("%s\nURLs: %d · endpoints: %d · params: %d · secrets: %d · related-domains: %d", target, nURL, nEnd, nParam, nSecret, nRelated)
		g.add(&Node{ID: "dom:" + target, Label: target, Group: "domain", Title: dtitle})
	}
	// dedupe findings: the multi-run file merge concatenates nuclei/afrog output,
	// so identical findings repeat — count risk and draw edges once each.
	{
		seenF := make(map[string]bool, len(findings))
		uniq := findings[:0]
		for _, f := range findings {
			k := f.sev + "\x00" + f.name + "\x00" + f.host
			if seenF[k] {
				continue
			}
			seenF[k] = true
			uniq = append(uniq, f)
		}
		findings = uniq
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
		if urlByHost[h] > 0 || endByHost[h] > 0 {
			title += fmt.Sprintf("\npaths: %d urls · %d endpoints", urlByHost[h], endByHost[h])
		}
		short := h
		if target != "" && strings.HasSuffix(h, "."+target) {
			short = strings.TrimSuffix(h, "."+target)
		}
		g.add(&Node{ID: "h:" + h, Label: short, Group: grp, Title: title,
			Risk: riskOf["h:"+h], Internal: internal, Alive: hh != nil, Ports: portsOf(hostPorts[h])})
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
			g.add(&Node{ID: "ip:" + ip, Label: ip, Group: grp, Title: t, Internal: isInternal(ip), Ports: portsOf(ipPorts[ip])})
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
	// discovered parameters → nodes attached to the domain (bounded)
	if target != "" {
		pseen := map[string]bool{}
		np := 0
		for _, ln := range lines(firstExisting(dir, "all_params.txt", "found_params.txt")) {
			p := strings.TrimSpace(ln)
			if p == "" || pseen[p] || np >= 300 {
				continue
			}
			pseen[p] = true
			np++
			pid := "param:" + p
			g.add(&Node{ID: pid, Label: p, Group: "param", Title: "parameter: " + p})
			g.link("dom:"+target, pid, "param")
		}
	}
	// every URL / endpoint → a node attached to its host (or the domain if the
	// host node isn't present), notable ones flagged as "path".
	for _, lf := range leaves {
		pfx := "url:"
		if lf.ep {
			pfx = "ep:"
		}
		id := pfx + lf.val
		if g.Nodes[id] == nil {
			g.add(&Node{ID: id, Label: shortURL(lf.val), Group: lf.group, Title: lf.title})
		}
		a := "dom:" + target
		if lf.host != "" {
			if _, ok := g.Nodes["h:"+lf.host]; ok {
				a = "h:" + lf.host
			}
		}
		if _, ok := g.Nodes[a]; ok {
			g.link(a, id, lf.group)
		}
	}
	// secrets / dns records / certs / favicons / related-domain intel → nodes
	if target != "" {
		detail := func(prefix, group string, max int, names ...string) {
			seen := map[string]bool{}
			n := 0
			for _, nm := range names {
				fp := firstExisting(dir, nm)
				if fp == "" {
					continue
				}
				for _, ln := range lines(fp) {
					v := strings.TrimSpace(ln)
					if v == "" || seen[v] || n >= max {
						continue
					}
					seen[v] = true
					n++
					lbl := v
					if len(lbl) > 40 {
						lbl = lbl[:40] + "…"
					}
					id := prefix + v
					if g.Nodes[id] == nil {
						g.add(&Node{ID: id, Label: lbl, Group: group, Title: v})
					}
					g.link("dom:"+target, id, group)
				}
			}
		}
		detail("sec:", "secret", 600, "jsubfinder_secrets.txt", "secretfinder_results.txt", "swaggerspy_results.txt")
		detail("dns:", "dns", 1000, "dns_records_subs.txt", "dns_records_raw.txt", "st_dns_records.txt")
		detail("cert:", "cert", 600, "tlsx_raw.txt")
		detail("intel:", "intel", 600, "st_associated.txt", "st_pivot_domains.txt", "amass_intel.txt")
		detail("fav:", "favicon", 400, "favicon_hashes.txt")
		// trufflehog (jsonl) + gitleaks (array) secrets → one node per finding
		for i, m := range readTruffle(dir) {
			if i >= 600 {
				break
			}
			id := "sec:x:" + strconv.Itoa(i)
			g.add(&Node{ID: id, Label: "secret: " + m, Group: "secret", Title: m})
			g.link("dom:"+target, id, "secret")
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
		// Rescue orphan hosts — dead subdomains that never resolved to an IP and
		// have no CNAME end up with zero edges, so the force layout flings them
		// far off-screen and they look "missing". Reconnect every in-scope host
		// that isn't reachable from the apex domain (dead subs with no IP, and
		// live hosts whose IP has no ASN/subnet enrichment → a 2-node island) by
		// hanging it off the domain. Only real subdomains of the target are
		// linked, so foreign intel hosts aren't falsely implied as subdomains.
		dom := "dom:" + target
		if _, ok := g.Nodes[dom]; ok {
			reach := map[string]bool{dom: true}
			queue := []string{dom}
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for nb := range g.adj[cur] {
					if !reach[nb] {
						reach[nb] = true
						queue = append(queue, nb)
					}
				}
			}
			for id := range g.Nodes {
				if !strings.HasPrefix(id, "h:") || reach[id] {
					continue
				}
				h := strings.TrimPrefix(id, "h:")
				if h == target || strings.HasSuffix(h, "."+target) {
					g.link(id, dom, "sub")
				}
			}
		}
	}
	g.Layout() // precompute node positions (radial hierarchy + collision) once
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
	k := a + "\x00" + b + "\x00" + label
	if g.edgeSeen[k] { // the file merge can duplicate source lines → dedup edges
		return
	}
	g.edgeSeen[k] = true
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
		if n.Group == "domain" || n.Group == "asn" || n.Group == "subnet" {
			keep[id] = true // scope backbone always kept
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
	// vuln / provider / bucket / cdn: keep ONLY if anchored to an already-kept
	// node (no orphan floating nodes), and cap vuln so a finding-heavy target
	// doesn't blow past the skeleton budget.
	vulnCap, nv := hostCap*2, 0
	for id, n := range g.Nodes {
		if keep[id] {
			continue
		}
		if !(strings.HasPrefix(n.Group, "vuln") || n.Group == "provider" || n.Group == "bucket" || n.Group == "cdn") {
			continue
		}
		anchored := false
		for nb := range g.adj[id] {
			if keep[nb] {
				anchored = true
				break
			}
		}
		if !anchored {
			continue
		}
		if strings.HasPrefix(n.Group, "vuln") {
			if nv >= vulnCap {
				continue
			}
			nv++
		}
		keep[id] = true
	}
	return g.slice(keep, map[string]any{"total": len(g.Nodes), "shown": len(keep),
		"hosts": len(hl), "hostCap": hostCap})
}

// Full returns the entire graph — every node and edge — but caps very large
// graphs (keeping the backbone + highest risk/degree nodes) so the WebGL
// viewer can't be handed an unbounded payload that OOMs the browser.
func (g *Graph) Full() SubGraph {
	const maxNodes = 12000
	if len(g.Nodes) <= maxNodes {
		keep := make(map[string]bool, len(g.Nodes))
		for id := range g.Nodes {
			keep[id] = true
		}
		return g.slice(keep, map[string]any{"total": len(g.Nodes), "shown": len(g.Nodes), "edgeCount": len(g.Edges)})
	}
	keep := map[string]bool{}
	type sc struct {
		id  string
		val int
	}
	var all []sc
	for id, n := range g.Nodes {
		if n.Group == "domain" || n.Group == "asn" || n.Group == "subnet" {
			keep[id] = true // backbone always
			continue
		}
		all = append(all, sc{id, n.Risk*100 + len(g.adj[id])})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].val > all[j].val })
	for _, s := range all {
		if len(keep) >= maxNodes {
			break
		}
		keep[s.id] = true
	}
	return g.slice(keep, map[string]any{"total": len(g.Nodes), "shown": len(keep),
		"edgeCount": len(g.Edges), "truncated": true})
}

// Neighbors returns a node and its immediate neighbours, capped: a hub like the
// apex domain can be adjacent to thousands of nodes, so return only the top
// `limit` by risk+degree (limit<=0 means the built-in default) and flag it.
func (g *Graph) Neighbors(id string, limit int) SubGraph {
	if limit <= 0 {
		limit = 500
	}
	keep := map[string]bool{id: true}
	nbs := make([]string, 0, len(g.adj[id]))
	for nb := range g.adj[id] {
		nbs = append(nbs, nb)
	}
	truncated := false
	if len(nbs) > limit {
		sort.Slice(nbs, func(i, j int) bool {
			ni, nj := g.Nodes[nbs[i]], g.Nodes[nbs[j]]
			si, sj := len(g.adj[nbs[i]]), len(g.adj[nbs[j]])
			if ni != nil {
				si += ni.Risk * 100
			}
			if nj != nil {
				sj += nj.Risk * 100
			}
			return si > sj
		})
		nbs = nbs[:limit]
		truncated = true
	}
	for _, nb := range nbs {
		keep[nb] = true
	}
	var meta map[string]any
	if truncated {
		meta = map[string]any{"truncated": true, "degree": len(g.adj[id])}
	}
	return g.slice(keep, meta)
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
		}
	}
	// sort ALL matches by risk BEFORE truncating, so the top-risk matches are
	// the ones returned (map iteration is random — truncating first was both
	// nondeterministic and dropped the highest-risk hits).
	sort.Slice(out, func(i, j int) bool { return out[i].Risk > out[j].Risk })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
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
