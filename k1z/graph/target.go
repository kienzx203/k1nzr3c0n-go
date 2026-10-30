package graph

import (
	"sort"
	"strings"
)

// TargetMapResult is a structured, target-centric enumeration of the whole
// attack surface and how every entity relates: hosts with their IPs/ports/
// provider/URLs/paths/params/findings, IPs with their ASN/subnet/hosts, and the
// domain-level buckets/secrets/certs/dns/intel. It is built for an LLM to read
// in one shot (so caps keep it bounded), replacing a raw node/edge dump.
type TargetMapResult struct {
	Target        string         `json:"target"`
	Stats         TargetStats    `json:"stats"`
	Hosts         []HostEntry    `json:"hosts"`
	IPs           []IPEntry      `json:"ips"`
	ASNs          []string       `json:"asns,omitempty"`
	Subnets       []string       `json:"subnets,omitempty"`
	Providers     []string       `json:"providers,omitempty"`
	CDNs          []string       `json:"cdns,omitempty"`
	Buckets       []string       `json:"buckets,omitempty"`
	Secrets       []string       `json:"secrets,omitempty"`
	DNS           []string       `json:"dns,omitempty"`
	Certs         []string       `json:"certs,omitempty"`
	Favicons      []string       `json:"favicons,omitempty"`
	Intel         []string       `json:"intel,omitempty"`
	FindingsBySev map[string]int `json:"findings_by_sev,omitempty"`
	Truncated     map[string]int `json:"truncated,omitempty"` // section -> items dropped
}

type TargetStats struct {
	Nodes  int            `json:"nodes"`
	Edges  int            `json:"edges"`
	ByType map[string]int `json:"by_type"`
}

type Finding struct {
	Sev  string `json:"sev"`
	Name string `json:"name"`
}

type HostEntry struct {
	Host      string    `json:"host"`
	Group     string    `json:"group"` // sub | sub_int | sub_dead | vhost
	Alive     bool      `json:"alive,omitempty"`
	Risk      int       `json:"risk,omitempty"`
	Ports     []int     `json:"ports,omitempty"`
	IPs       []string  `json:"ips,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	URLs      []string  `json:"urls,omitempty"`
	Paths     []string  `json:"paths,omitempty"`
	Endpoints []string  `json:"endpoints,omitempty"`
	Params    []string  `json:"params,omitempty"`
	Secrets   []string  `json:"secrets,omitempty"`
	Certs     []string  `json:"certs,omitempty"`
	DNS       []string  `json:"dns,omitempty"`
	Tech      []string  `json:"tech,omitempty"`
	Findings  []Finding `json:"findings,omitempty"`
}

type IPEntry struct {
	IP       string   `json:"ip"`
	Group    string   `json:"group"` // ip_pub | ip_int | ip_origin
	Internal bool     `json:"internal,omitempty"`
	Ports    []int    `json:"ports,omitempty"`
	ASN      string   `json:"asn,omitempty"`
	Subnet   string   `json:"subnet,omitempty"`
	Hosts    []string `json:"hosts,omitempty"`
}

func isHostGroup(g string) bool {
	return g == "sub" || g == "sub_int" || g == "sub_dead" || g == "vhost"
}
func isIPGroup(g string) bool {
	return g == "ip_pub" || g == "ip_int" || g == "ip_origin"
}

// capAppend appends s to *dst unless it is full; returns 1 when an item was
// dropped (for the truncation tally), 0 otherwise.
func capAppend(dst *[]string, s string, max int) int {
	if len(*dst) >= max {
		return 1
	}
	*dst = append(*dst, s)
	return 0
}

// TargetMap enumerates the full relationship map of the graph. Caps keep each
// section bounded (hostCap<=0 → 2000); the Truncated map reports how many items
// were dropped where.
func (g *Graph) TargetMap(hostCap int) TargetMapResult {
	if hostCap <= 0 {
		hostCap = 2000
	}
	const ipCap, perList, leafCap = 2000, 60, 800
	res := TargetMapResult{
		Target:        g.Target,
		Stats:         TargetStats{Nodes: len(g.Nodes), Edges: len(g.Edges), ByType: map[string]int{}},
		FindingsBySev: map[string]int{},
		Truncated:     map[string]int{},
	}
	for _, n := range g.Nodes {
		res.Stats.ByType[n.Group]++
		if strings.HasPrefix(n.Group, "vuln_") {
			res.FindingsBySev[strings.TrimPrefix(n.Group, "vuln_")]++
		}
	}
	var hosts []HostEntry
	var ips []IPEntry
	for id, n := range g.Nodes {
		switch {
		case n.Group == "domain":
			for nb := range g.adj[id] {
				nn := g.Nodes[nb]
				if nn == nil {
					continue
				}
				switch nn.Group {
				case "bucket":
					res.Truncated["buckets"] += capAppend(&res.Buckets, nn.Label, leafCap)
				case "secret":
					res.Truncated["secrets"] += capAppend(&res.Secrets, nn.Label, leafCap)
				case "dns":
					res.Truncated["dns"] += capAppend(&res.DNS, nn.Label, leafCap)
				case "cert":
					res.Truncated["certs"] += capAppend(&res.Certs, nn.Label, leafCap)
				case "favicon":
					res.Truncated["favicons"] += capAppend(&res.Favicons, nn.Label, leafCap)
				case "intel":
					res.Truncated["intel"] += capAppend(&res.Intel, nn.Label, leafCap)
				}
			}

		case isHostGroup(n.Group):
			he := HostEntry{Host: strings.TrimPrefix(id, "h:"), Group: n.Group, Alive: n.Alive, Risk: n.Risk, Ports: n.Ports}
			for nb := range g.adj[id] {
				nn := g.Nodes[nb]
				if nn == nil {
					continue
				}
				switch {
				case isIPGroup(nn.Group):
					he.IPs = append(he.IPs, nn.Label)
				case nn.Group == "provider":
					he.Provider = nn.Label
				case nn.Group == "url":
					res.Truncated["urls"] += capAppend(&he.URLs, nn.Label, perList)
				case nn.Group == "path":
					res.Truncated["paths"] += capAppend(&he.Paths, nn.Label, perList)
				case nn.Group == "endpoint":
					res.Truncated["endpoints"] += capAppend(&he.Endpoints, nn.Label, perList)
				case nn.Group == "param":
					res.Truncated["params"] += capAppend(&he.Params, nn.Label, perList)
				case nn.Group == "secret":
					capAppend(&he.Secrets, nn.Label, perList)
				case nn.Group == "cert":
					capAppend(&he.Certs, nn.Label, perList)
				case nn.Group == "dns":
					capAppend(&he.DNS, nn.Label, perList)
				case nn.Group == "tech":
					capAppend(&he.Tech, nn.Label, perList)
				case strings.HasPrefix(nn.Group, "vuln_"):
					if len(he.Findings) < perList {
						he.Findings = append(he.Findings, Finding{Sev: strings.TrimPrefix(nn.Group, "vuln_"), Name: nn.Label})
					}
				}
			}
			hosts = append(hosts, he)

		case isIPGroup(n.Group):
			ie := IPEntry{IP: n.Label, Group: n.Group, Internal: n.Internal, Ports: n.Ports}
			for nb := range g.adj[id] {
				nn := g.Nodes[nb]
				if nn == nil {
					continue
				}
				switch {
				case nn.Group == "asn":
					ie.ASN = nn.Label
				case nn.Group == "subnet":
					ie.Subnet = nn.Label
				case isHostGroup(nn.Group):
					capAppend(&ie.Hosts, strings.TrimPrefix(nb, "h:"), perList)
				}
			}
			ips = append(ips, ie)

		case n.Group == "asn":
			res.Truncated["asns"] += capAppend(&res.ASNs, n.Label, leafCap)
		case n.Group == "subnet":
			res.Truncated["subnets"] += capAppend(&res.Subnets, n.Label, leafCap)
		case n.Group == "provider":
			res.Truncated["providers"] += capAppend(&res.Providers, n.Label, leafCap)
		case n.Group == "cdn":
			res.Truncated["cdns"] += capAppend(&res.CDNs, n.Label, leafCap)
		}
	}

	// highest-risk hosts first, then cap
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Risk > hosts[j].Risk })
	if len(hosts) > hostCap {
		res.Truncated["hosts"] += len(hosts) - hostCap
		hosts = hosts[:hostCap]
	}
	if len(ips) > ipCap {
		res.Truncated["ips"] += len(ips) - ipCap
		ips = ips[:ipCap]
	}
	res.Hosts, res.IPs = hosts, ips
	for k, v := range res.Truncated {
		if v == 0 {
			delete(res.Truncated, k)
		}
	}
	return res
}
