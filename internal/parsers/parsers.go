// Package parsers turns workspace tool outputs into structured findings.
// Mirrors tasks.py's parse_workspace scanners (delete-then-insert, idempotent).
package parsers

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"k1nzr3c0n/internal/bus"
	"k1nzr3c0n/internal/notify"
	"k1nzr3c0n/internal/store"
)

// ParseWorkspace re-parses every scanner for the run's workspace. Serialized
// per run: incremental mid-run parses and the completion parse may race.
func ParseWorkspace(st *store.Store, run *store.Run, b *bus.Bus) error {
	parseMu.Lock()
	if _, busy := parseRunning[run.ID]; busy {
		parseMu.Unlock()
		return nil
	}
	parseRunning[run.ID] = true
	parseMu.Unlock()
	defer func() {
		parseMu.Lock()
		delete(parseRunning, run.ID)
		parseMu.Unlock()
	}()

	_ = st.DeleteFindingsByRun(run.ID)
	ws := run.Workspace
	if ws == "" {
		return nil
	}
	scanNuclei(st, run, ws)
	scanHTTPX(st, run, ws)
	scanNaabu(st, run, ws)
	scanSubdomains(st, run, ws)
	scanKatana(st, run, ws)
	scanGAU(st, run, ws)
	ingestAssetGraph(st, run)
	DetectNewAssets(st, run)
	alertCritical(st, run, b)
	return nil
}

// ingestAssetGraph feeds confirmed findings into the company asset graph
// (ScopeWeaver concept: findings enrich the graph the agent explores).
func ingestAssetGraph(st *store.Store, run *store.Run) {
	company, _ := st.UpsertCompany(run.Target, nil)
	fl, _, _ := st.ListFindings(store.FindingFilter{RunID: run.ID, Limit: 1000})
	for _, f := range fl {
		a := store.Asset{CompanyID: &company.ID, Value: f.Host, Source: "run:" + run.ID}
		switch f.Kind {
		case "subdomain":
			a.Type = "subdomain"
		case "http":
			a.Type = "site"
			meta := map[string]any{}
			if f.Title != nil {
				meta["title"] = *f.Title
			}
			if f.StatusCode != nil {
				meta["status_code"] = *f.StatusCode
			}
			if f.Port != nil {
				meta["port"] = *f.Port
			}
			var tech []string
			_ = json.Unmarshal([]byte(f.Tech), &tech)
			if len(tech) > 0 {
				meta["tech"] = tech
			}
			mb, _ := json.Marshal(meta)
			a.Meta = string(mb)
		case "port":
			a.Type = "port"
			meta := map[string]any{}
			if f.Port != nil {
				meta["port"] = *f.Port
			}
			if f.Protocol != nil {
				meta["protocol"] = *f.Protocol
			}
			mb, _ := json.Marshal(meta)
			a.Meta = string(mb)
		default:
			continue
		}
		_ = st.UpsertAsset(&a)
		st.EnrichAssetDNS(a)
	}
}

var (
	parseMu      sync.Mutex
	parseRunning = map[string]bool{}
)

func firstExisting(ws string, names ...string) string {
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(ws, n)); err == nil {
			return filepath.Join(ws, n)
		}
	}
	return ""
}

func sp(s string) *string { return &s }

func severity(s string) *string {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low", "info":
		return sp(strings.ToLower(s))
	}
	return sp("info")
}

// ── nuclei ───────────────────────────────────────────────────────────────────

func scanNuclei(st *store.Store, run *store.Run, ws string) {
	seen := map[string]bool{}
	var files []string
	if f := firstExisting(ws, "nuclei.jsonl"); f != "" {
		files = append(files, f)
	} else if f := firstExisting(ws, "nuclei_results.jsonl"); f != "" {
		files = append(files, f)
	} else if f := firstExisting(ws, "nuclei_urls.jsonl"); f != "" {
		files = append(files, f)
	}
	// glob nuclei*.jsonl
	matches, _ := filepath.Glob(filepath.Join(ws, "nuclei*.jsonl"))
	for _, m := range matches {
		if !seen[m] {
			files = append(files, m)
		}
	}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		eachJSONLine(f, func(m map[string]any) {
			host := str(m["host"])
			if host == "" {
				host = str(m["ip"])
			}
			info, _ := m["info"].(map[string]any)
			name := ""
			if info != nil {
				name = str(info["name"])
			}
			if name == "" {
				name = str(m["template-id"])
			}
			matchedAt := str(m["matched-at"])
			if matchedAt == "" {
				matchedAt = host
			}
			sev := ""
			if info != nil {
				sev = str(info["severity"])
			}
			st.InsertFinding(&store.Finding{
				RunID: run.ID, Kind: "vuln", Severity: severity(sev),
				Host: host, Name: sp(name), TemplateID: strp(m["template-id"]),
				URL: strp(matchedAt), Evidence: strp(m["curl-command"]),
				Description: strp(m["description"]),
			})
		})
	}
}

// ── httpx ────────────────────────────────────────────────────────────────────

func scanHTTPX(st *store.Store, run *store.Run, ws string) {
	shots := gowitnessShots(ws)
	var f string
	if f = firstExisting(ws, "httpx.jsonl", "httpx.json", "http_alive.jsonl"); f == "" {
		f = firstExisting(ws, "alive.txt", "http_alive.txt", "httpx.txt")
		if f == "" {
			return
		}
		// plain-text fallback: lines starting with http
		sc, err := os.Open(f)
		if err != nil {
			return
		}
		defer sc.Close()
		b := bufio.NewScanner(sc)
		for b.Scan() {
			line := strings.TrimSpace(b.Text())
			if strings.HasPrefix(line, "http") {
				st.InsertFinding(&store.Finding{
					RunID: run.ID, Kind: "http", Host: hostOfURL(line), URL: sp(line),
				})
			}
		}
		return
	}
	eachJSONLine(f, func(m map[string]any) {
		host := str(m["host"])
		u := str(m["url"])
		if host == "" {
			host = hostOfURL(u)
		}
		ip := ""
		if arr, ok := m["a"].([]any); ok && len(arr) > 0 {
			ip = str(arr[0])
		}
		port := intFromAny(m["port"])
		sc := intFromAny(m["status_code"])
		if sc == 0 {
			sc = intFromAny(m["status-code"])
		}
		tech := "[]"
		if t := anyTech(m["technologies"]); t != "" {
			tech = t
		} else if t := anyTech(m["tech"]); t != "" {
			tech = t
		}
		var shot *string
		if s, ok := shots[screenshotKey(host, port)]; ok {
			shot = sp("screenshots/" + s)
		}
		st.InsertFinding(&store.Finding{
			RunID: run.ID, Kind: "http", Host: host, IP: strp(ip), Port: intPtr(port),
			StatusCode: intPtr(sc), URL: strp(u), Title: strp(m["title"]), Tech: tech,
			Screenshot: shot,
		})
	})
}

func anyTech(v any) string {
	switch t := v.(type) {
	case []any:
		b, _ := json.Marshal(t)
		return string(b)
	case string:
		if strings.HasPrefix(t, "[") {
			return t
		}
	}
	return ""
}

func intPtr(n int) *int { return &n }

// gowitnessShots reads screenshots/<name>.png keyed by normalized host:port.
func gowitnessShots(ws string) map[string]string {
	out := map[string]string{}
	shotDir := filepath.Join(ws, "screenshots")
	entries, err := os.ReadDir(shotDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".png") {
			continue
		}
		key := strings.TrimSuffix(name, ".png")
		parts := strings.Split(key, "_")
		if len(parts) >= 2 {
			host := parts[len(parts)-2]
			port := parts[len(parts)-1]
			out[normalizeShotKey(host, port)] = name
		}
	}
	return out
}

func normalizeShotKey(host, port string) string {
	if port == "80" || port == "443" {
		return host
	}
	return host + ":" + port
}

func screenshotKey(host string, port int) string {
	if port == 80 || port == 443 || port == 0 {
		return host
	}
	return host + ":" + strconv.Itoa(port)
}

func hostOfURL(u string) string {
	if u == "" {
		return ""
	}
	pu, err := url.Parse(u)
	if err != nil {
		return u
	}
	return pu.Hostname()
}

// ── naabu ────────────────────────────────────────────────────────────────────

func scanNaabu(st *store.Store, run *store.Run, ws string) {
	var f string
	if f = firstExisting(ws, "naabu.jsonl", "naabu.json", "ports.jsonl"); f != "" {
		eachJSONLine(f, func(m map[string]any) {
			host := str(m["host"])
			if host == "" {
				host = str(m["ip"])
			}
			port := intFromAny(m["port"])
			proto := str(m["protocol"])
			if proto == "" {
				proto = "tcp"
			}
			st.InsertFinding(&store.Finding{
				RunID: run.ID, Kind: "port", Host: host, IP: strp(str(m["ip"])),
				Port: intPtr(port), Protocol: sp(proto), Name: sp("Open port " + strconv.Itoa(port)),
			})
		})
		return
	}
	if f = firstExisting(ws, "naabu.txt", "ports.txt"); f != "" {
		eachLine(f, func(line string) {
			host, portS, ok := strings.Cut(line, ":")
			if !ok {
				return
			}
			p, err := strconv.Atoi(portS)
			if err != nil {
				return
			}
			st.InsertFinding(&store.Finding{
				RunID: run.ID, Kind: "port", Host: host, Port: intPtr(p), Protocol: sp("tcp"),
				Name: sp("Open port " + portS),
			})
		})
	}
}

// ── subdomains ───────────────────────────────────────────────────────────────

func scanSubdomains(st *store.Store, run *store.Run, ws string) {
	f := firstExisting(ws, "subdomains_resolved.txt", "subdomains.txt")
	if f == "" {
		return
	}
	eachLine(f, func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		st.InsertFinding(&store.Finding{
			RunID: run.ID, Kind: "subdomain", Host: line, Name: sp(line),
		})
	})
}

// ── katana / gau ─────────────────────────────────────────────────────────────

func scanKatana(st *store.Store, run *store.Run, ws string) {
	f := filepath.Join(ws, "katana.jsonl")
	if _, err := os.Stat(f); err != nil {
		return
	}
	seen := map[string]bool{}
	eachJSONLine(f, func(m map[string]any) {
		u := str(m["request.endpoint"])
		if u == "" {
			u = str(m["endpoint"])
		}
		if u == "" {
			u = str(m["url"])
		}
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		title := ""
		if req, ok := m["request"].(map[string]any); ok {
			title = str(req["tag"])
			if title == "" {
				title = str(req["attribute"])
			}
		}
		st.InsertFinding(&store.Finding{
			RunID: run.ID, Kind: "url", Host: hostOfURL(u), URL: sp(u), Title: strp(title),
		})
	})
}

func scanGAU(st *store.Store, run *store.Run, ws string) {
	f := filepath.Join(ws, "gau.jsonl")
	if _, err := os.Stat(f); err != nil {
		return
	}
	seen := map[string]bool{}
	eachJSONLine(f, func(m map[string]any) {
		u := []string{}
		for _, k := range []string{"url", "endpoint"} {
			if v := str(m[k]); v != "" {
				u = append(u, v)
				break
			}
		}
		if len(u) == 0 || seen[u[0]] {
			return
		}
		seen[u[0]] = true
		st.InsertFinding(&store.Finding{
			RunID: run.ID, Kind: "url", Host: hostOfURL(u[0]), URL: sp(u[0]),
			Name: strp(str(m["technique"])),
		})
	})
}

// ── new assets + alerts ──────────────────────────────────────────────────────

// DetectNewAssets diffs this run's hosts against all previous runs of the same
// target and records/alerts first-seen hosts.
func DetectNewAssets(st *store.Store, run *store.Run) {
	currentKind := map[string]string{}
	fl, _, _ := st.ListFindings(store.FindingFilter{RunID: run.ID, Kind: "subdomain", Limit: 100000})
	for _, f := range fl {
		h := strings.ToLower(f.Host)
		if h != "" {
			if _, ok := currentKind[h]; !ok {
				currentKind[h] = "subdomain"
			}
		}
	}
	fl, _, _ = st.ListFindings(store.FindingFilter{RunID: run.ID, Kind: "http", Limit: 100000})
	for _, f := range fl {
		h := strings.ToLower(f.Host)
		if h != "" {
			if _, ok := currentKind[h]; !ok {
				currentKind[h] = "http"
			}
		}
	}
	// past runs of the same target
	var pastHosts = map[string]bool{}
	runs, _, _ := st.ListRuns(store.RunFilter{Limit: 100000})
	for _, r := range runs {
		if r.ID == run.ID || r.Target != run.Target {
			continue
		}
		pf, _, _ := st.ListFindings(store.FindingFilter{RunID: r.ID, Limit: 100000})
		for _, f := range pf {
			if f.Kind == "subdomain" || f.Kind == "http" {
				pastHosts[strings.ToLower(f.Host)] = true
			}
		}
	}
	alerted, _ := st.AlertedHosts(run.Target)
	var newHosts []string
	for h, kind := range currentKind {
		if pastHosts[h] || alerted[h] {
			continue
		}
		newHosts = append(newHosts, h)
		k := kind
		st.InsertNewAsset(&store.NewAsset{RunID: run.ID, Target: run.Target, Host: h, Kind: &k})
	}
	if len(newHosts) == 0 {
		return
	}
	sortStrings(newHosts)
	// suppress if a schedule launched this run with alert_new_assets off
	if sc := st.ScheduleForRun(run.ID); sc != nil && !sc.AlertNewAssets {
		return
	}
	notify.NewAssets(run.Target, run.ID, run.Workflow, newHosts)
}

func alertCritical(st *store.Store, run *store.Run, b *bus.Bus) {
	fl, _, _ := st.ListFindings(store.FindingFilter{RunID: run.ID, Kind: "vuln", Status: "open", Limit: 1000})
	var crit, high int
	var rows []string
	for _, f := range fl {
		if f.Severity == nil {
			continue
		}
		switch *f.Severity {
		case "critical":
			crit++
			if len(rows) < 8 {
				rows = append(rows, "[CRITICAL] "+tplHost(f))
			}
		case "high":
			high++
			if len(rows) < 8 {
				rows = append(rows, "[HIGH] "+tplHost(f))
			}
		}
	}
	if crit > 0 || high > 0 {
		notify.CriticalFindings(crit, high, rows)
	}
}

func tplHost(f *store.Finding) string {
	t := ""
	if f.TemplateID != nil {
		t = *f.TemplateID
	}
	return t + " — " + f.Host
}

// ── line iteration helpers ───────────────────────────────────────────────────

func eachJSONLine(path string, fn func(map[string]any)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			fn(m)
		}
	}
}

func eachLine(path string, fn func(string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		fn(sc.Text())
	}
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return ""
}

func strp(v any) *string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return &t
	default:
		s := str(v)
		return &s
	}
}

func intFromAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(t)
		return n
	}
	return 0
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

var _ = sql.ErrNoRows
