package api

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"k1nzr3c0n/internal/config"
	"k1nzr3c0n/internal/schedule"
	"k1nzr3c0n/internal/store"
	"k1nzr3c0n/internal/toolsmeta"
)

// ── health ───────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	degraded := false
	checks := map[string]any{}

	// dns
	if _, err := net.LookupHost("dns.google"); err != nil {
		checks["dns"] = map[string]any{"ok": false, "error": trunc(err.Error(), 200)}
		degraded = true
	} else {
		checks["dns"] = map[string]any{"ok": true}
	}
	// worker (in-process — always up when this handler runs)
	checks["worker"] = map[string]any{"ok": true, "workers": []string{"k1nzr3c0n-go"}}
	// redis: replaced by the in-process bus — always healthy when serving
	checks["redis"] = map[string]any{"ok": true}
	// beat
	var lastTick any
	beatOK := false
	if t := schedule.LastTick(); t != "" {
		lastTick = t
		beatOK = true
	}
	checks["beat"] = map[string]any{"ok": beatOK, "last_tick": lastTick}
	// disk
	if st, err := statfs(config.RunsDir()); err == nil {
		free := st.Bavail * uint64(st.Bsize)
		total := st.Blocks * uint64(st.Bsize)
		if total == 0 || float64(free)/float64(total) <= 0.05 {
			checks["disk"] = map[string]any{"ok": false, "error": "low disk space"}
			degraded = true
		} else {
			checks["disk"] = map[string]any{
				"ok": true, "free_gb": f2(float64(free) / 1e9), "total_gb": f2(float64(total) / 1e9),
			}
		}
	}
	// tools
	versions, _ := s.St.ListToolVersions()
	var outdated []string
	var updateFailed []string
	tracked := 0
	for name, tv := range versions {
		tracked++
		if tv.Status == "outdated" {
			outdated = append(outdated, name)
		}
		if tv.Status == "failed" {
			updateFailed = append(updateFailed, name)
		}
	}
	checks["tools"] = map[string]any{
		"ok": true, "tracked": tracked,
		"outdated": outdated, "update_failed": updateFailed,
	}
	// resolvers
	resolversPath := filepath.Join(config.WordlistsDir(), "resolvers-trickest.txt")
	_, err := os.Stat(resolversPath)
	checks["resolvers"] = map[string]any{"ok": err == nil, "path": resolversPath}
	// webhook (informational)
	checks["webhook"] = map[string]any{"ok": config.WebhookURL() != "", "configured": config.WebhookURL() != ""}
	// stuck runs (>13h running)
	runs, _, _ := s.St.ListRuns(store.RunFilter{Status: "running", Limit: 1000})
	stuck := 0
	for _, run := range runs {
		if !run.StartedAt.IsZero() && time.Since(run.StartedAt) > 13*time.Hour {
			stuck++
		}
	}
	checks["stuck_runs"] = map[string]any{"ok": stuck == 0, "count": stuck}
	if stuck > 0 {
		degraded = true
	}

	status := "ok"
	if degraded {
		status = "degraded"
	}
	writeJSON(w, 200, map[string]any{
		"status": status, "time": store.FmtTime(store.NowUTC()), "checks": checks,
	})
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func f2(f float64) float64 { return float64(int(f*100)) / 100 }

// ── network ──────────────────────────────────────────────────────────────────

type netDiag struct {
	Verdict     string         `json:"verdict"`
	Hint        string         `json:"hint"`
	SystemDNS   map[string]any `json:"system_dns"`
	DirectDNS   map[string]any `json:"direct_dns"`
	HTTPS       map[string]any `json:"https"`
	Nameservers []string       `json:"nameservers"`
	IsStub      bool           `json:"is_stub"`
	IPs         []string       `json:"ips"`
}

func networkCheck() netDiag {
	d := netDiag{Verdict: "ok", Hint: "Network looks healthy."}
	// system dns
	if _, err := net.LookupHost("dns.google"); err == nil {
		d.SystemDNS = map[string]any{"ok": true, "detail": "resolved dns.google"}
	} else {
		d.SystemDNS = map[string]any{"ok": false, "detail": trunc(err.Error(), 160)}
	}
	// direct dns @1.1.1.1
	detail := "1.1.1.1 → no answer"
	if addrs, err := directResolve("1.1.1.1", "dns.google"); err == nil && len(addrs) > 0 {
		detail = "1.1.1.1 → " + addrs[0]
		d.DirectDNS = map[string]any{"ok": true, "detail": detail}
	} else {
		d.DirectDNS = map[string]any{"ok": false, "detail": detail}
	}
	// https probe
	client := &http.Client{Timeout: 8 * time.Second, Transport: insecureTransport()}
	resp, err := client.Get("https://1.1.1.1")
	if err == nil && resp != nil {
		d.HTTPS = map[string]any{"ok": true, "detail": fmt.Sprintf("1.1.1.1 → HTTP %d", resp.StatusCode)}
		resp.Body.Close()
	} else {
		d.HTTPS = map[string]any{"ok": false, "detail": trunc(fmt.Sprint(err), 160)}
	}
	// resolv.conf
	d.Nameservers, d.IsStub = readResolvConf()
	d.IPs = localIPs()

	if !d.SystemDNS["ok"].(bool) {
		d.Verdict, d.Hint = "dns_broken", "DNS resolution fails — check /etc/resolv.conf or use Network fix."
	}
	if !d.DirectDNS["ok"].(bool) && d.Verdict == "ok" {
		d.Verdict, d.Hint = "no_internet", "No connectivity — check the network interface or NAT."
	}
	return d
}

func (s *Server) handleNetworkCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, networkCheck())
}

func (s *Server) handleNetworkFix(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Nameservers []string `json:"nameservers"`
		RestoreStub bool     `json:"restore_stub"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	action := ""
	if body.RestoreStub {
		action = "Restored systemd-resolved stub (127.0.0.53)"
		writeResolvConf("nameserver 127.0.0.53\n")
	} else {
		ns := body.Nameservers
		if len(ns) == 0 {
			ns = []string{"1.1.1.1", "8.8.8.8"}
		}
		for _, n := range ns {
			if net.ParseIP(n) == nil || net.ParseIP(n).To4() == nil {
				writeDetail(w, 400, "Invalid IPv4 nameserver: "+n)
				return
			}
		}
		var b strings.Builder
		for _, n := range ns {
			b.WriteString("nameserver " + n + "\n")
		}
		if err := writeResolvConf(b.String()); err != nil {
			writeDetail(w, 500, "write failed (service not root?): "+err.Error())
			return
		}
		action = "Set resolv.conf nameservers: " + strings.Join(ns, ", ")
	}
	out := map[string]any{"action": action}
	check := networkCheck()
	out["verdict"] = check.Verdict
	out["hint"] = check.Hint
	out["system_dns"] = check.SystemDNS
	out["direct_dns"] = check.DirectDNS
	out["https"] = check.HTTPS
	out["nameservers"] = check.Nameservers
	out["is_stub"] = check.IsStub
	out["ips"] = check.IPs
	writeJSON(w, 200, out)
}

func readResolvConf() ([]string, bool) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return []string{}, false
	}
	var ns []string
	stub := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			if strings.Contains(line, "systemd-resolved") || strings.Contains(line, "stub-resolv.conf") {
				stub = true
			}
			continue
		}
		if strings.HasPrefix(line, "nameserver ") {
			ns = append(ns, strings.TrimPrefix(line, "nameserver "))
		}
	}
	if ns == nil {
		ns = []string{}
	}
	return ns, stub
}

func writeResolvConf(content string) error {
	// keep last 5 backups
	for _, old := range listBackups() {
		_ = os.Remove(old)
	}
	data, _ := os.ReadFile("/etc/resolv.conf")
	if data != nil {
		ts := time.Now().Format("20060102-150405")
		_ = os.WriteFile("/etc/resolv.conf.bak-"+ts, data, 0o644)
	}
	return os.WriteFile("/etc/resolv.conf", []byte(content), 0o644)
}

func listBackups() []string {
	m, _ := filepath.Glob("/etc/resolv.conf.bak-*")
	sort.Strings(m)
	for len(m) > 5 {
		m = m[1:]
	}
	return m
}

func localIPs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				out = append(out, ipn.IP.String())
			}
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// ── system ───────────────────────────────────────────────────────────────────

// Version is stamped at build time via -ldflags; fallback "dev".
var BuildVersion = "dev"

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"version": BuildVersion})
}

// handleUpdateCheck queries the GitHub latest release.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	repo := os.Getenv("K1NZR3C0N_UPDATE_REPO")
	if repo == "" {
		repo = "kienzx203/k1nzr3c0n-go"
	}
	resp, err := http.Get("https://api.github.com/repos/" + repo + "/releases/latest")
	if err != nil {
		writeDetail(w, 502, "github: "+err.Error())
		return
	}
	defer resp.Body.Close()
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if json.NewDecoder(resp.Body).Decode(&rel) != nil || rel.TagName == "" {
		writeDetail(w, 502, "no release found")
		return
	}
	asset := ""
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, "linux_amd64") {
			asset = a.BrowserDownloadURL
			break
		}
	}
	writeJSON(w, 200, map[string]any{
		"current": BuildVersion, "latest": rel.TagName,
		"update_available": asset != "" && rel.TagName != BuildVersion,
		"asset_url":        asset, "repo": repo,
	})
}

// handleSelfUpdate downloads the release binary and atomically replaces the
// running executable (rename swap — safe while executing). Caller restarts.
func (s *Server) handleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	check, err := http.Get("https://api.github.com/repos/" + envOrDefault("K1NZR3C0N_UPDATE_REPO", "kienzx203/k1nzr3c0n-go") + "/releases/latest")
	if err != nil {
		writeDetail(w, 502, err.Error())
		return
	}
	var rel struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	json.NewDecoder(check.Body).Decode(&rel)
	check.Body.Close()
	asset := ""
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, "linux_amd64") {
			asset = a.BrowserDownloadURL
			break
		}
	}
	if asset == "" {
		writeDetail(w, 404, "no linux_amd64 release asset")
		return
	}
	resp, err := http.Get(asset)
	if err != nil {
		writeDetail(w, 502, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		writeDetail(w, 502, "asset HTTP "+strconv.Itoa(resp.StatusCode))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	tmp := exe + ".__updating__"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tmp)
		writeDetail(w, 500, err.Error())
		return
	}
	out.Close()
	os.Chmod(tmp, 0o755)
	if err := os.Rename(tmp, exe); err != nil {
		writeDetail(w, 500, "swap: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"updated": true, "note": "restart the service: systemctl restart k1nzr3c0n-go"})
}

func envOrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// handleBackup streams a tar.gz of DB (VACUUM INTO snapshot) + workflows + skills.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	tmpDir, err := os.MkdirTemp("", "k1z-backup-*")
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)
	snap := filepath.Join(tmpDir, "k1nzr3c0n.db")
	if _, err := s.St.Exec("VACUUM INTO ?", snap); err != nil {
		writeDetail(w, 500, "snapshot: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"k1nzr3c0n-backup-%s.tar.gz\"", time.Now().Format("20060102-150405")))
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	addFile := func(path, name string) {
		fi, err := os.Stat(path)
		if err != nil {
			return
		}
		hdr, _ := tar.FileInfoHeader(fi, "")
		hdr.Name = name
		tw.WriteHeader(hdr)
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		io.Copy(tw, f)
	}
	addFile(snap, "k1nzr3c0n.db")
	filepath.Walk(filepath.Join(config.BaseDir(), "workflows"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasPrefix(info.Name(), ".") {
			rel, _ := filepath.Rel(config.BaseDir(), p)
			addFile(p, rel)
		}
		return nil
	})
	filepath.Walk(filepath.Join(config.BaseDir(), "skills"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(config.BaseDir(), p)
			addFile(p, rel)
		}
		return nil
	})
}

func (s *Server) handleSystemUsage(w http.ResponseWriter, r *http.Request) {
	u, _ := s.St.Usage()
	dirs, bytes := workspaceUsage()
	writeJSON(w, 200, map[string]any{
		"runs": u.Runs, "findings": u.Findings, "new_assets": u.NewAssets,
		"run_logs": u.RunLogs, "api_keys": u.ApiKeys, "targets": u.Targets,
		"schedules": u.Schedules, "tool_versions": u.ToolVersions,
		"workspace_dirs": dirs, "workspace_bytes": bytes,
	})
}

func workspaceUsage() (int, int64) {
	root := config.RunsDir()
	count := 0
	var total int64
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		base := filepath.Base(path)
		if !info.IsDir() && base != "k1nzr3c0n.db" && base != "k1nzr3c0n.db-wal" && base != "k1nzr3c0n.db-shm" {
			if !info.IsDir() {
				total += info.Size()
			}
		}
		if info.IsDir() && path != root {
			count++
		}
		return nil
	})
	return count, total
}

func (s *Server) handleSystemReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope   string `json:"scope"`
		Confirm string `json:"confirm"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if body.Confirm != "RESET" {
		writeDetail(w, 400, "confirm must be the literal string 'RESET'")
		return
	}
	if body.Scope == "" {
		body.Scope = "runs"
	}
	if body.Scope != "runs" && body.Scope != "all" {
		writeDetail(w, 400, "scope must be 'runs' or 'all'")
		return
	}
	if runs, _ := s.St.ActiveRuns(); len(runs) > 0 {
		writeDetail(w, 409, fmt.Sprintf("%d run(s) still active — cancel them before resetting", len(runs)))
		return
	}
	deleted, err := s.St.Reset(body.Scope)
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	// wipe workspace dirs (keep DB files)
	dirs, freed := wipeRunWorkspaces()
	deletedRows := map[string]any{}
	for k, v := range deleted {
		deletedRows[k] = v
	}
	writeJSON(w, 200, map[string]any{
		"scope": body.Scope, "deleted_rows": deletedRows,
		"removed_workspace_dirs": dirs, "freed_bytes": freed,
	})
}

func wipeRunWorkspaces() (int, int64) {
	root := config.RunsDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, 0
	}
	dirs := 0
	var freed int64
	for _, e := range entries {
		name := e.Name()
		if name == "k1nzr3c0n.db" || name == "k1nzr3c0n.db-wal" || name == "k1nzr3c0n.db-shm" {
			continue
		}
		path := filepath.Join(root, name)
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				freed += info.Size()
			}
			return nil
		})
		if err := os.RemoveAll(path); err == nil {
			dirs++
		}
	}
	return dirs, freed
}

// ── tools ────────────────────────────────────────────────────────────────────

func (s *Server) handleListTools(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, toolsmeta.Inventory(s.St))
}

func (s *Server) handleToolsCheck(w http.ResponseWriter, r *http.Request) {
	go toolsmeta.CheckVersions(s.St)
	writeJSON(w, 200, map[string]any{"task_id": newUUID(), "status": "queued"})
}

func (s *Server) handleToolsUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tools     *[]string `json:"tools"`
		Wordlists *[]string `json:"wordlists"`
	}
	_ = readJSON(r, &body)
	var dispatched []map[string]any
	if body.Tools == nil && body.Wordlists == nil {
		for i := range toolsmeta.All() {
			if t := &toolsmeta.All()[i]; t.Updatable() {
				dispatched = append(dispatched, map[string]any{"name": t.Name, "kind": "tool", "task_id": newUUID()})
				go toolsmeta.UpdateTool(s.St, t.Name)
			}
		}
		for i := range toolsmeta.Wordlists() {
			wl := &toolsmeta.Wordlists()[i]
			dispatched = append(dispatched, map[string]any{"name": wl.Name, "kind": "wordlist", "task_id": newUUID()})
			go toolsmeta.UpdateWordlist(s.St, wl.Name)
		}
	} else {
		if body.Tools != nil {
			for _, name := range *body.Tools {
				if t := toolsmeta.ByName(name); t != nil && t.Updatable() {
					dispatched = append(dispatched, map[string]any{"name": name, "kind": "tool", "task_id": newUUID()})
					go toolsmeta.UpdateTool(s.St, name)
				}
			}
		}
		if body.Wordlists != nil {
			for _, name := range *body.Wordlists {
				if toolsmeta.WordlistByName(name) != nil {
					dispatched = append(dispatched, map[string]any{"name": name, "kind": "wordlist", "task_id": newUUID()})
					go toolsmeta.UpdateWordlist(s.St, name)
				}
			}
		}
	}
	if dispatched == nil {
		dispatched = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"dispatched": dispatched, "count": len(dispatched)})
}
