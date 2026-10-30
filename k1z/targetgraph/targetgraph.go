// Package targetgraph builds the aggregate attack-surface graph for a target by
// unioning every run's workspace, with a run-set-signature cache. It lives in
// its own package (not k1z/api) so both the HTTP layer and the LLM agent can use
// one implementation — api imports agent, so this shared code can't live in api.
package targetgraph

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/graph"
	"github.com/Autumn-27/artex/k1z/store"
)

// ErrNoRuns means the target has no run workspace to build a graph from.
var ErrNoRuns = errors.New("no run workspace found for this target")

// NormTarget canonicalises a target to its bare host — lowercase, no scheme, no
// path, no port — so runs entered as "https://example.com", "example.com" and
// "example.com:443" all aggregate into ONE target graph / annotation set.
func NormTarget(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if !strings.Contains(t, "]") { // keep bracketed IPv6 literals intact
		if i := strings.IndexByte(t, ':'); i >= 0 {
			t = t[:i]
		}
	}
	return strings.ToLower(strings.TrimSuffix(t, "."))
}

// SafeTargetDir turns a target into a filesystem-safe single path segment.
func SafeTargetDir(t string) string {
	var b strings.Builder
	for _, c := range t {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "target"
	}
	if s := b.String(); s == "." || s == ".." || strings.Trim(s, ".") == "" {
		return "target" // never a path-traversal segment
	}
	return b.String()
}

// MergeFiles are the per-run workspace files the target graph unions across all
// of a target's runs.
var MergeFiles = []string{
	// host name sources
	"subdomains.txt", "subdomains_resolved.txt", "subdomains_all_resolved.txt", "subdomains_all.txt",
	"passive_merged.txt", "subdomains_resolved_resp.txt", "subdomains_tlsx_resolved.txt", "tlsx_new_subs.txt",
	"js_subs.txt", "jsubfinder_subs.txt", "st_intel_subs.txt", "reverse_dns_subs.txt", "ptr_subs.txt",
	"dns_records_subs.txt", "http_redirect_subs.txt", "recursive_parents.txt", "uncover_asn_in_scope.txt",
	// edge/interesting surface
	"vhost_new_hosts.txt", "favicon_in_scope.txt", "pivot_new_resolved.txt", "http_redirect_resolved.txt",
	"dns_svc_new_hosts.txt", "interesting.txt",
	// resolve / ip
	"resolved.txt", "dns_resolved.txt", "ptr_resolved.txt", "dns_ptr.txt",
	// http / ports / vulns (nuclei*.jsonl + afrog globbed)
	"httpx.json", "httpx.jsonl", "httpx_probe.jsonl", "pivot_httpx_probe.jsonl", "st_pivot_httpx.jsonl",
	"naabu.json", "naabu.jsonl", "naabu_asn.jsonl", "st_pivot_naabu.jsonl",
	"nuclei*.jsonl", "nuclei*.json", "afrog.json", "afrog.jsonl", "takeover_findings.txt", "s3scanner.json", "s3scanner.jsonl",
	// intel: censys / fofa / asn / internal / origin / cdn
	"censys_hosts.txt", "censys_ip.txt", "censys_ports.txt", "censys_prefixes.txt", "fofa_ip_port.txt",
	"asn_ipv4_cidrs.txt", "asn_org_cidrs.txt", "amass_intel_cidrs.txt", "internal_hosts.txt", "dns_internal_hosts.txt",
	"internal_subnets.txt", "dns_internal_subnets.txt", "origin_ips.txt", "cdncheck.jsonl", "cdncheck.json",
	"dns_zone_nsec.txt", "p_dns_zone.txt",
	// high-cardinality counts (urls/endpoints/params/secrets)
	"all_urls.txt", "live_urls.txt", "all_endpoints.txt", "linkfinder_endpoints.txt",
	"all_params.txt", "found_params.txt", "jsubfinder_secrets.txt", "secretfinder_results.txt",
	"trufflehog_results.jsonl", "gitleaks_results.json", "swaggerspy_results.txt",
	// gf attack-candidates (subdir preserved by the merge), related-domain intel
	"gf/*.txt", "st_associated.txt", "st_pivot_domains.txt", "amass_intel.txt",
	// service-version scans (graph reads these for port badges on IPs)
	"nmap_service.txt", "rustscan_full.txt",
	// cert / favicon / raw-dns sources — graph.Build's detail() DOES read these
	// (cert + favicon + extra dns nodes); they must be merged or the aggregate
	// target graph silently renders zero cert/favicon nodes and partial dns.
	"tlsx_raw.txt", "favicon_hashes.txt", "dns_records_raw.txt", "st_dns_records.txt",
	// technology fingerprinting (webanalyze) → tech nodes
	"webanalyze.jsonl", "webanalyze.json",
	// shared hosting (co-located domains per IP) → graph reads ip_groups/shared_hosting.txt;
	// rel path is preserved by the merge (like gf/).
	"ip_groups/shared_hosting.txt",
	// dir-brute status (feroxbuster jsonl + ffuf json) → HTTP status on endpoint nodes
	"feroxbuster.json", "ffuf_paths.json",
}

// Mu serializes merge writes into a target dir. Callers that write into the same
// targetgraphs/<target> dir (e.g. the legacy python renderer) lock on it.
var Mu sync.Mutex

// Merge concatenates each MergeFiles entry across run workspaces into `merged`,
// expanding glob patterns and preserving subdirs (e.g. gf/).
func Merge(wss []string, merged string) {
	os.MkdirAll(merged, 0o755)
	agg := map[string][]byte{}
	for _, pat := range MergeFiles {
		for _, ws := range wss {
			var paths []string
			if strings.ContainsAny(pat, "*?[") {
				paths, _ = filepath.Glob(filepath.Join(ws, pat))
			} else {
				paths = []string{filepath.Join(ws, pat)}
			}
			for _, p := range paths {
				b, e := os.ReadFile(p)
				if e != nil || len(b) == 0 {
					continue
				}
				rel, re := filepath.Rel(ws, p)
				if re != nil || strings.HasPrefix(rel, "..") {
					rel = filepath.Base(p)
				}
				agg[rel] = append(agg[rel], b...)
				if b[len(b)-1] != '\n' {
					agg[rel] = append(agg[rel], '\n')
				}
			}
		}
	}
	for rel, buf := range agg {
		dst := filepath.Join(merged, rel)
		_ = os.MkdirAll(filepath.Dir(dst), 0o755)
		_ = os.WriteFile(dst, buf, 0o644)
	}
}

// MergedDir returns the shared merge directory for a (already-normalised) target.
func MergedDir(nt string) string {
	return filepath.Join(config.BaseDir(), "targetgraphs", SafeTargetDir(nt))
}

type cached struct {
	g       *graph.Graph
	sig     string
	builtAt time.Time
}

var (
	mu    sync.Mutex
	cache = map[string]*cached{}
)

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// doneSteps counts the completed steps in a run's steps_json so the graph cache
// signature advances each time a tool finishes during a live run.
func doneSteps(stepsJSON string) int {
	if stepsJSON == "" {
		return 0
	}
	var steps []struct {
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(stepsJSON), &steps) != nil {
		return 0
	}
	n := 0
	for _, s := range steps {
		switch s.Status {
		case "ok", "done", "failed", "skipped", "completed":
			n++
		}
	}
	return n
}

// For builds (or returns a cached) graph for a target by unioning every run's
// workspace. Runs are grouped by canonical host, so "https://x" and "x" merge.
// The returned int is an HTTP-style status (200/400/404/500).
func For(st *store.Store, target string) (*graph.Graph, int, error) {
	if target == "" {
		return nil, 400, errors.New("target required")
	}
	nt := NormTarget(target)
	runs, _, err := st.ListRuns(store.RunFilter{Limit: 200})
	if err != nil {
		return nil, 500, err
	}
	var wss, sigs []string
	for _, run := range runs {
		if NormTarget(run.Target) != nt || run.Workspace == "" || !dirExists(run.Workspace) {
			continue
		}
		wss = append(wss, run.Workspace)
		var newest time.Time
		for _, t := range []time.Time{run.FinishedAt, run.StartedAt, run.CreatedAt} {
			if t.After(newest) {
				newest = t
			}
		}
		ver := ""
		if run.FinishedAt.IsZero() { // live run: rebuild the graph as each tool/step finishes
			ver = ":s" + strconv.Itoa(doneSteps(run.StepsJSON))
		}
		sigs = append(sigs, run.ID+":"+strconv.FormatInt(newest.Unix(), 10)+ver)
	}
	if len(wss) == 0 {
		return nil, 404, ErrNoRuns
	}
	// cache signature = the exact run set + newest times, so the cache rebuilds
	// when a run is ADDED, FINISHES, or is DELETED.
	sort.Strings(sigs)
	sig := strings.Join(sigs, "|")
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cache[nt]; ok && c.sig == sig {
		return c.g, 200, nil
	}
	merged := MergedDir(nt)
	Mu.Lock()
	Merge(wss, merged)
	Mu.Unlock()
	g := graph.Build(merged, nt)
	cache[nt] = &cached{g: g, sig: sig, builtAt: time.Now()}
	return g, 200, nil
}

// ForRun builds the graph from ONE run's workspace only — the attack surface THIS
// run produced, NOT merged across every run of the target. It rebuilds live as the
// run's steps finish (the signature folds in the done-step count for an in-flight
// run), so an agent following a run sees its own graph grow tool-by-tool. This is
// the "what did this run add" delta the recon_graph(run_id=…) mode reads. Cached
// per run under a "run:" key so it never collides with the target-wide cache.
func ForRun(st *store.Store, runID string) (*graph.Graph, int, error) {
	if runID == "" {
		return nil, 400, errors.New("run_id required")
	}
	run, err := st.GetRun(runID)
	if err != nil || run == nil {
		return nil, 404, errors.New("run not found")
	}
	if run.Workspace == "" || !dirExists(run.Workspace) {
		return nil, 404, ErrNoRuns
	}
	nt := NormTarget(run.Target)
	ver := ""
	if run.FinishedAt.IsZero() { // live run: rebuild per finished step
		ver = ":s" + strconv.Itoa(doneSteps(run.StepsJSON))
	} else {
		ver = ":" + strconv.FormatInt(run.FinishedAt.Unix(), 10)
	}
	sig := run.ID + ver
	key := "run:" + run.ID
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cache[key]; ok && c.sig == sig {
		return c.g, 200, nil
	}
	// a single run's workspace already holds every tool-output file graph.Build
	// reads (the per-run Merge only unions same-named files ACROSS runs), so we
	// build straight from it — no merge needed.
	g := graph.Build(run.Workspace, nt)
	cache[key] = &cached{g: g, sig: sig, builtAt: time.Now()}
	return g, 200, nil
}
