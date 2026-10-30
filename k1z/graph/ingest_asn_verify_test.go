package graph

import (
	"os"
	"path/filepath"
	"testing"
)

// Verifies the asn_expand + uncover_asn outputs are ingested into the graph:
// CIDR files -> subnet nodes, uncover in-scope hosts -> host nodes.
func TestASNUncoverIngestion(t *testing.T) {
	dir := t.TempDir()
	w := func(name, c string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("subdomains_resolved_resp.txt", "sub.example.com [1.2.3.4]\n")
	w("asn_ipv4_cidrs.txt", "1.2.3.0/24\n")        // per-IP/ASN ranges (Cymru+RIPEstat+HE+bgpview+bgpq4)
	w("asn_org_cidrs.txt", "9.9.9.0/24\n")         // org-wide intel (auto org)
	w("uncover_asn_in_scope.txt", "found.example.com\n") // live host in ASN (Shodan/Censys/FOFA)

	g := Build(dir, "example.com")
	checks := map[string]string{
		"net:1.2.3.0/24":       "asn_ipv4_cidrs -> subnet",
		"net:9.9.9.0/24":       "asn_org_cidrs -> subnet",
		"h:found.example.com":  "uncover_asn_in_scope -> host",
	}
	for id, what := range checks {
		if g.Nodes[id] == nil {
			t.Errorf("MISSING node %q (%s) — ingestion gap", id, what)
		}
	}
}
