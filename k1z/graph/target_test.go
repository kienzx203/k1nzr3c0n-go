package graph

import "testing"

func newTestGraph(target string) *Graph {
	return &Graph{Nodes: map[string]*Node{}, adj: map[string]map[string]struct{}{},
		inc: map[string][]int{}, childrenOf: map[string][]string{}, edgeSeen: map[string]bool{}, Target: target}
}

// TargetMap must enumerate the relationships: host→ip, ip→asn, host→finding,
// host→path — the whole point of the per-target lookup.
func TestTargetMap(t *testing.T) {
	g := newTestGraph("example.com")
	g.add(&Node{ID: "dom:example.com", Label: "example.com", Group: "domain"})
	g.add(&Node{ID: "h:a.example.com", Label: "a", Group: "sub", Alive: true, Risk: 5, Ports: []int{443}})
	g.add(&Node{ID: "ip:1.2.3.4", Label: "1.2.3.4", Group: "ip_pub", Ports: []int{80, 443}})
	g.add(&Node{ID: "as:AS123", Label: "AS123 Corp", Group: "asn"})
	g.add(&Node{ID: "v:high:XSS:a.example.com", Label: "XSS", Group: "vuln_high"})
	g.add(&Node{ID: "u:1", Label: "/admin", Group: "path"})
	g.link("dom:example.com", "h:a.example.com", "sub")
	g.link("h:a.example.com", "ip:1.2.3.4", "A")
	g.link("ip:1.2.3.4", "as:AS123", "ASN")
	g.link("h:a.example.com", "v:high:XSS:a.example.com", "high")
	g.link("h:a.example.com", "u:1", "path")

	m := g.TargetMap(0)
	if m.Target != "example.com" || m.Stats.Nodes != 6 {
		t.Fatalf("stats: target=%q nodes=%d", m.Target, m.Stats.Nodes)
	}
	var he *HostEntry
	for i := range m.Hosts {
		if m.Hosts[i].Host == "a.example.com" {
			he = &m.Hosts[i]
		}
	}
	if he == nil {
		t.Fatal("host a.example.com missing from map")
	}
	if len(he.IPs) != 1 || he.IPs[0] != "1.2.3.4" {
		t.Errorf("host→ip = %v, want [1.2.3.4]", he.IPs)
	}
	if len(he.Findings) != 1 || he.Findings[0].Sev != "high" || he.Findings[0].Name != "XSS" {
		t.Errorf("host→finding = %+v", he.Findings)
	}
	if len(he.Paths) != 1 || he.Paths[0] != "/admin" {
		t.Errorf("host→path = %v", he.Paths)
	}
	if len(he.Ports) != 1 || he.Ports[0] != 443 {
		t.Errorf("host ports = %v", he.Ports)
	}
	var ie *IPEntry
	for i := range m.IPs {
		if m.IPs[i].IP == "1.2.3.4" {
			ie = &m.IPs[i]
		}
	}
	if ie == nil || ie.ASN != "AS123 Corp" {
		t.Errorf("ip→asn = %+v", ie)
	}
	if m.FindingsBySev["high"] != 1 {
		t.Errorf("findings_by_sev = %v", m.FindingsBySev)
	}
}
