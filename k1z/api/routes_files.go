package api

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/store"
)

// graphMergeFiles are the per-run workspace files the target graph unions across
// all of a target's runs (recon-graph.py dedupes internally).
var graphMergeFiles = []string{
	// host name sources
	"subdomains.txt", "subdomains_resolved.txt", "subdomains_all_resolved.txt", "subdomains_all.txt",
	"passive_merged.txt", "subdomains_resolved_resp.txt", "subdomains_tlsx_resolved.txt", "tlsx_new_subs.txt",
	"js_subs.txt", "jsubfinder_subs.txt", "st_intel_subs.txt", "reverse_dns_subs.txt", "ptr_subs.txt",
	"dns_records_subs.txt", "http_redirect_subs.txt", "recursive_parents.txt",
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
	"asn_ipv4_cidrs.txt", "amass_intel_cidrs.txt", "internal_hosts.txt", "dns_internal_hosts.txt",
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
	// NOTE: tlsx_raw / favicon_hashes / dns_records_raw / ip_groups/shared_hosting
	// are DB-only (graph has no reader) — intentionally NOT merged, to keep the
	// list == what graph.Build actually consumes.
}

func safeTargetDir(t string) string {
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

// handleTargetGraph builds (or serves cached) the aggregate attack-surface graph
// for a target by unioning the output of all its runs' workspaces and rendering
// it with recon-graph.py. Serves the HTML directly (opened in a new tab by the UI).
func (s *Server) handleTargetGraph(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("name")
	if target == "" {
		writeDetail(w, 400, "target required")
		return
	}
	runs, _, err := s.St.ListRuns(store.RunFilter{Limit: 200})
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	var wss []string
	var newest time.Time
	for _, run := range runs {
		if run.Target != target || run.Workspace == "" || !dirExists(run.Workspace) {
			continue
		}
		wss = append(wss, run.Workspace)
		for _, t := range []time.Time{run.FinishedAt, run.StartedAt, run.CreatedAt} {
			if t.After(newest) {
				newest = t
			}
		}
	}
	if len(wss) == 0 {
		writeDetail(w, 404, "no run workspace found for this target")
		return
	}
	// invalidate the cache when the generator changed (after a deploy)
	if si, e := os.Stat(graphScript()); e == nil && si.ModTime().After(newest) {
		newest = si.ModTime()
	}
	merged := filepath.Join(config.BaseDir(), "targetgraphs", safeTargetDir(target))
	gh := filepath.Join(merged, "recon-graph.html")
	// cache: serve if the graph is newer than the latest run (and the generator)
	if fi, e := os.Stat(gh); e == nil && !newest.After(fi.ModTime()) {
		http.ServeFile(w, r, gh)
		return
	}
	graph2Mu.Lock()
	mergeRunFiles(wss, merged)
	graph2Mu.Unlock()
	script := graphScript()
	if !fileExists(script) {
		writeDetail(w, 500, "recon-graph.py not found (deploy scripts/)")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", script, merged, "-o", filepath.Join(merged, "recon-graph"), "--target", target)
	cmd.Dir = merged
	if out, e := cmd.CombinedOutput(); e != nil {
		writeDetail(w, 500, "graph build failed: "+strings.TrimSpace(string(out)))
		return
	}
	http.ServeFile(w, r, gh)
}

// graphFresh reports whether recon-graph.{json,html} already exist and are at
// least as new as every other file in the workspace (so a rebuild is a no-op).
// graphScript resolves the recon-graph.py path (deployed, else source checkout).
func graphScript() string {
	s := filepath.Join(config.BaseDir(), "scripts", "recon-graph.py")
	if !fileExists(s) {
		s = "/opt/k1nzr3c0n-src/scripts/recon-graph.py"
	}
	return s
}

func graphFresh(ws string) bool {
	gj, err1 := os.Stat(filepath.Join(ws, "recon-graph.json"))
	gh, err2 := os.Stat(filepath.Join(ws, "recon-graph.html"))
	if err1 != nil || err2 != nil {
		return false
	}
	gt := gj.ModTime()
	if gh.ModTime().Before(gt) {
		gt = gh.ModTime()
	}
	// invalidate when the generator itself changed (e.g. after a deploy)
	if si, e := os.Stat(graphScript()); e == nil && si.ModTime().After(gt) {
		return false
	}
	fresh := true
	filepath.WalkDir(ws, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !fresh {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, "recon-graph.") || name == "resume.json" {
			return nil
		}
		if fi, e := d.Info(); e == nil && fi.ModTime().After(gt) {
			fresh = false
		}
		return nil
	})
	return fresh
}

// handleGenGraph (re)builds the attack-surface graph for a run from its workspace
// by invoking scripts/recon-graph.py, writing recon-graph.{html,json} into the
// workspace. The FE then renders recon-graph.html via the file endpoint.
func (s *Server) handleGenGraph(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.runWorkspace(w, r.PathValue("run_id"))
	if !ok {
		return
	}
	script := graphScript()
	if !fileExists(script) {
		writeDetail(w, 500, "recon-graph.py not found (deploy scripts/)")
		return
	}
	// cache: skip the rebuild if recon-graph.{json,html} already reflect the latest
	// workspace state (nothing written since they were generated).
	if graphFresh(ws) {
		writeJSON(w, 200, map[string]any{"ok": true, "cached": true, "html": "recon-graph.html", "json": "recon-graph.json"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", script, ws, "-o", filepath.Join(ws, "recon-graph"))
	cmd.Dir = ws
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeDetail(w, 500, "graph build failed: "+strings.TrimSpace(string(out)))
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "html": "recon-graph.html", "json": "recon-graph.json", "log": strings.TrimSpace(string(out))})
}

// ── run workspace files ──────────────────────────────────────────────────────

var imageExts = []string{".png", ".jpg", ".jpeg", ".webp", ".gif"}
var textExts = []string{".txt", ".log", ".md", ".yaml", ".json", ".jsonl", ".csv", ".xml"}

func isImage(name string) bool {
	for _, e := range imageExts {
		if strings.HasSuffix(strings.ToLower(name), e) {
			return true
		}
	}
	return false
}

func isText(name string) bool {
	for _, e := range textExts {
		if strings.HasSuffix(strings.ToLower(name), e) {
			return true
		}
	}
	return false
}

func (s *Server) runWorkspace(w http.ResponseWriter, runID string) (string, bool) {
	run := s.getRunOr404(w, runID)
	if run == nil {
		return "", false
	}
	if run.Workspace == "" {
		writeDetail(w, 404, "Workspace not set")
		return "", false
	}
	return run.Workspace, true
}

func (s *Server) handleScreenshots(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.runWorkspace(w, r.PathValue("run_id"))
	if !ok {
		return
	}
	shotDir := filepath.Join(ws, "screenshots")
	entries, err := os.ReadDir(shotDir)
	if err != nil {
		writeJSON(w, 200, []any{})
		return
	}
	type shot struct {
		File   string `json:"file"`
		Name   string `json:"name"`
		URL    any    `json:"url"`
		Title  any    `json:"title"`
		Status any    `json:"status"`
		Size   int64  `json:"size"`
	}
	var out []shot
	for _, e := range entries {
		if e.IsDir() || !isImage(e.Name()) {
			continue
		}
		fi, _ := e.Info()
		out = append(out, shot{
			File: "screenshots/" + e.Name(), Name: e.Name(),
			Status: nil, Size: fi.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	if out == nil {
		out = []shot{}
	}
	writeJSON(w, 200, out)
}

type fileNode struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Size int64  `json:"size"`
	Ext  string `json:"ext"`
}

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.runWorkspace(w, r.PathValue("run_id"))
	if !ok {
		return
	}
	var nodes []fileNode
	filepath.WalkDir(ws, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(ws, path)
		rel = filepath.ToSlash(rel)
		if rel == "resume.json" {
			return nil
		}
		fi, _ := d.Info()
		nodes = append(nodes, fileNode{
			Path: rel, Name: d.Name(), Size: fi.Size(),
			Ext: strings.ToLower(filepath.Ext(d.Name())),
		})
		return nil
	})
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Path < nodes[j].Path })
	if nodes == nil {
		nodes = []fileNode{}
	}
	writeJSON(w, 200, nodes)
}

const maxPreview = 10 * 1024 * 1024

func (s *Server) handleGetFile(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.runWorkspace(w, r.PathValue("run_id"))
	if !ok {
		return
	}
	rel := r.PathValue("path")
	full := filepath.Clean(filepath.Join(ws, rel))
	// strict containment: equal or nested under the workspace (separator
	// boundary — plain prefix checks are bypassable with sibling dirs)
	if full != filepath.Clean(ws) && !strings.HasPrefix(full, filepath.Clean(ws)+string(os.PathSeparator)) {
		writeDetail(w, 403, "Path traversal not allowed")
		return
	}
	fi, err := os.Stat(full)
	if err != nil || fi.IsDir() {
		writeDetail(w, 404, "File not found")
		return
	}
	ext := strings.ToLower(filepath.Ext(full))
	if ext == ".json" || ext == ".jsonl" {
		data, _ := os.ReadFile(full)
		w.Header().Set("Content-Type", "application/json")
		if len(data) > maxPreview {
			suffix := fmt.Sprintf("\n\n[... truncated: file is %d bytes, showing first %d ...]", len(data), maxPreview)
			w.Write(data[:maxPreview])
			w.Write([]byte(suffix))
			return
		}
		w.Write(data)
		return
	}
	if isText(full) {
		data, _ := os.ReadFile(full)
		contentType := "text/plain; charset=utf-8"
		w.Header().Set("Content-Type", contentType)
		if len(data) > maxPreview {
			suffix := fmt.Sprintf("\n\n[... truncated: file is %d bytes, showing first %d ...]", len(data), maxPreview)
			w.Write(data[:maxPreview])
			w.Write([]byte(suffix))
			return
		}
		w.Write(data)
		return
	}
	http.ServeFile(w, r, full) // binary with guessed content type
}

// ── wordlists ────────────────────────────────────────────────────────────────

func (s *Server) handleListWordlists(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(config.WordlistsDir())
	if err != nil {
		writeJSON(w, 200, []any{})
		return
	}
	type wl struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	var out []wl
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, _ := e.Info()
		out = append(out, wl{Name: e.Name(), Size: fi.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if out == nil {
		out = []wl{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleUploadWordlist(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 100<<20 {
		writeDetail(w, 413, "File too large (max 100 MB)")
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeDetail(w, 422, "multipart form with 'file' field is required")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeDetail(w, 422, "file field is required")
		return
	}
	defer file.Close()
	name := sanitizeUploadName(hdr.Filename)
	if !strings.HasSuffix(strings.ToLower(name), ".txt") {
		writeDetail(w, 400, "Only .txt files are allowed")
		return
	}
	os.MkdirAll(config.WordlistsDir(), 0o755)
	dst, err := os.Create(filepath.Join(config.WordlistsDir(), name))
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	defer dst.Close()
	data := make([]byte, 0)
	buf := make([]byte, 32*1024)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	dst.Write(data)
	lines := int64(0)
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		lines++
	}
	writeJSON(w, 200, map[string]any{"name": name, "size": len(data), "lines": lines})
}

func (s *Server) handleDeleteWordlist(w http.ResponseWriter, r *http.Request) {
	name := sanitizeUploadName(r.PathValue("name"))
	path := filepath.Join(config.WordlistsDir(), name)
	if _, err := os.Stat(path); err != nil {
		writeDetail(w, 404, "File not found")
		return
	}
	os.Remove(path)
	writeJSON(w, 200, map[string]any{"deleted": name})
}

// ── static SPA ───────────────────────────────────────────────────────────────

func (s *Server) mountStatic(m *http.ServeMux) {
	// static/ holds the ScopeWeaver UI (a Next.js static export, detected by
	// _next/). If it's a plain SPA instead, serveUI still works.
	uiDir := config.StaticDir()
	nextExport := dirExists(filepath.Join(uiDir, "_next"))
	m.HandleFunc("GET /{path...}", func(w http.ResponseWriter, r *http.Request) {
		serveUI(w, r, uiDir, nextExport)
	})
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// serveUI resolves a request to a file in the UI dir. For a Next.js static
// export, a route like /function/tasks maps to function/tasks/index.html; hashed
// assets under /_next are cached, HTML is never cached.
func serveUI(w http.ResponseWriter, r *http.Request, dir string, nextExport bool) {
	rel := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if strings.Contains(rel, "..") {
		writeDetail(w, 400, "bad path")
		return
	}
	var candidates []string
	if rel == "" || rel == "." {
		candidates = []string{"index.html"}
	} else {
		candidates = []string{rel}
		if filepath.Ext(rel) == "" { // extensionless → a route
			candidates = append(candidates, rel+"/index.html", rel+".html")
		}
	}
	for _, c := range candidates {
		full := filepath.Join(dir, filepath.FromSlash(c))
		if fileExists(full) {
			setUICache(w, full)
			http.ServeFile(w, r, full)
			return
		}
	}
	// SPA / route fallback
	if nextExport {
		if f := filepath.Join(dir, "404.html"); fileExists(f) {
			setUICache(w, f)
			w.WriteHeader(404)
			http.ServeFile(w, r, f)
			return
		}
	}
	index := filepath.Join(dir, "index.html")
	if !fileExists(index) {
		writeDetail(w, 404, "static frontend not built")
		return
	}
	setUICache(w, index)
	http.ServeFile(w, r, index)
}

func setUICache(w http.ResponseWriter, full string) {
	if strings.Contains(full, string(os.PathSeparator)+"_next"+string(os.PathSeparator)) ||
		strings.HasSuffix(full, ".woff2") || strings.HasSuffix(full, ".woff") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}
