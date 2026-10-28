package parsers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/k1z/store"
)

var reStatusTok = regexp.MustCompile(`(?i)status:\s*(\d{3})`)

// parseDirsearch: "200   305B  http://host/path" → (url, status)
func parseDirsearch(l string) (string, int) {
	ff := strings.Fields(l)
	if len(ff) == 0 {
		return "", 0
	}
	code, _ := strconv.Atoi(ff[0])
	return firstURLTok(l), code
}

// parseGobuster: "/admin (Status: 200) [Size: 1234]" → (url, status)
func parseGobuster(l, target string) (string, int) {
	code := 0
	if m := reStatusTok.FindStringSubmatch(l); m != nil {
		code, _ = strconv.Atoi(m[1])
	}
	u := firstURLTok(l)
	if u == "" {
		if ff := strings.Fields(l); len(ff) > 0 && strings.HasPrefix(ff[0], "/") {
			u = "https://" + target + ff[0]
		}
	}
	return u, code
}

// This file extends ingestion so EVERY workspace tool output reaches the DB.
// New finding kinds: url, endpoint, secret, param, cert, asn, net, cdn, bucket,
// ptr, intel, service — in addition to the core vuln/http/port/subdomain.

const rowCap = 60000 // safety cap per high-cardinality scanner (crawl URLs etc.)

// globFiles resolves literal names and glob patterns to existing file paths.
func globFiles(ws string, patterns ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range patterns {
		var ms []string
		if strings.ContainsAny(p, "*?[") {
			ms, _ = filepath.Glob(filepath.Join(ws, p))
		} else if full := filepath.Join(ws, p); fileExists(full) {
			ms = []string{full}
		}
		for _, m := range ms {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func parseJSONArray(path string, fn func(map[string]any)) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var arr []map[string]any
	if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
		for _, m := range arr {
			fn(m)
		}
		return
	}
	var obj map[string]any
	if json.Unmarshal(b, &obj) == nil {
		for _, key := range []string{"results", "findings", "urls"} {
			if a, ok := obj[key].([]any); ok {
				for _, it := range a {
					if m, ok := it.(map[string]any); ok {
						fn(m)
					}
				}
			}
		}
	}
}

func parseJSONObj(path string, fn func(string, any)) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var obj map[string]any
	if json.Unmarshal(b, &obj) == nil {
		for k, v := range obj {
			fn(k, v)
		}
	}
}

func firstURLTok(line string) string {
	for _, t := range strings.Fields(line) {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			return t
		}
	}
	return ""
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ── afrog (separate vuln scanner; nuclei glob doesn't cover it) ──────────────

func scanAfrog(st *store.Store, run *store.Run, ws string) {
	handle := func(m map[string]any) {
		name, sev := "", ""
		if poc, ok := m["pocinfo"].(map[string]any); ok {
			name = str(poc["infoname"])
			if name == "" {
				name = str(poc["id"])
			}
			sev = str(poc["severity"])
		}
		if info, ok := m["info"].(map[string]any); ok {
			if name == "" {
				name = str(info["name"])
			}
			if sev == "" {
				sev = str(info["severity"])
			}
		}
		host := str(m["fulltarget"])
		if host == "" {
			host = str(m["target"])
		}
		if name == "" {
			name = "afrog finding"
		}
		st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "vuln", Severity: severity(sev),
			Host: hostOfURL(host), Name: sp(name), URL: strp(host)})
	}
	for _, f := range globFiles(ws, "afrog.jsonl") {
		eachJSONLine(f, handle)
	}
	for _, f := range globFiles(ws, "afrog.json") {
		var arr []map[string]any
		if b, e := os.ReadFile(f); e == nil && json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
			for _, m := range arr {
				handle(m)
			}
		} else {
			eachJSONLine(f, handle)
		}
	}
}

// ── URLs (crawlers + archives) ───────────────────────────────────────────────

func scanURLs(st *store.Store, run *store.Run, ws string) {
	seen := map[string]bool{}
	n := 0
	emit := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || !strings.HasPrefix(u, "http") || seen[u] {
			return
		}
		seen[u] = true
		if n >= rowCap {
			return
		}
		n++
		st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "url", Host: hostOfURL(u), URL: sp(u)})
	}
	for _, f := range globFiles(ws, "katana.jsonl", "gau.jsonl") {
		eachJSONLine(f, func(m map[string]any) {
			u := str(m["endpoint"])
			if u == "" {
				u = str(m["url"])
			}
			if u == "" {
				if r, ok := m["request"].(map[string]any); ok {
					u = str(r["endpoint"])
				}
			}
			emit(u)
		})
	}
	for _, f := range globFiles(ws, "katana_urls.txt", "hakrawler_urls.txt", "cariddi_urls.txt",
		"gau_urls.txt", "gauplus_urls.txt", "waymore_urls.txt", "waybackurls_urls.txt",
		"urlfinder_urls.txt", "all_urls.txt", "live_urls.txt", "js_urls.txt") {
		eachLine(f, emit)
	}
}

// ── endpoints (JS/linkfinder + dir brute) ────────────────────────────────────

func scanEndpoints(st *store.Store, run *store.Run, ws string) {
	seen := map[string]bool{}
	n := 0
	emit := func(u string, code int) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		if code == 404 { // drop not-found noise from content discovery
			return
		}
		seen[u] = true
		if n >= rowCap {
			return
		}
		n++
		fd := &store.Finding{RunID: run.ID, Kind: "endpoint", Host: hostOfURL(u), URL: sp(u), Name: sp(trunc(u, 200))}
		if code > 0 {
			fd.StatusCode = intPtr(code)
		}
		st.InsertFinding(fd)
	}
	// status-bearing content discovery FIRST so the status variant wins dedup
	for _, f := range globFiles(ws, "ffuf_paths.json") {
		parseJSONArray(f, func(m map[string]any) { emit(str(m["url"]), intFromAny(m["status"])) })
	}
	for _, f := range globFiles(ws, "feroxbuster.json") {
		eachJSONLine(f, func(m map[string]any) {
			if t := str(m["type"]); t == "" || t == "response" {
				emit(str(m["url"]), intFromAny(m["status"]))
			}
		})
	}
	for _, f := range globFiles(ws, "dirsearch.txt") {
		eachLine(f, func(l string) { u, c := parseDirsearch(l); if u != "" { emit(u, c) } })
	}
	for _, f := range globFiles(ws, "gobuster_dir.txt") {
		eachLine(f, func(l string) { u, c := parseGobuster(l, run.Target); if u != "" { emit(u, c) } })
	}
	// crawl / JS / linkfinder endpoints (no status)
	for _, f := range globFiles(ws, "linkfinder_endpoints.txt", "jsapiscan_results.txt",
		"all_endpoints.txt", "nuclei_urls.txt") {
		eachLine(f, func(l string) {
			if u := firstURLTok(l); u != "" {
				emit(u, 0)
			} else if l = strings.TrimSpace(l); strings.HasPrefix(l, "/") {
				emit("https://"+run.Target+l, 0)
			}
		})
	}
}

// ── secrets ──────────────────────────────────────────────────────────────────

func scanSecrets(st *store.Store, run *store.Run, ws string) {
	add := func(name, evidence, host string) {
		if host == "" {
			host = run.Target
		}
		st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "secret", Severity: sp("high"),
			Host: host, Name: sp(trunc(name, 180)), Evidence: strp(evidence)})
	}
	for _, f := range globFiles(ws, "trufflehog_results.jsonl") {
		eachJSONLine(f, func(m map[string]any) {
			det := str(m["DetectorName"])
			if det == "" {
				return
			}
			add("secret: "+det, str(m["Redacted"]), "")
		})
	}
	for _, f := range globFiles(ws, "gitleaks_results.json") {
		parseJSONArray(f, func(m map[string]any) {
			add("secret: "+str(m["RuleID"]), str(m["Secret"]), "")
		})
	}
	for _, f := range globFiles(ws, "secretfinder_results.txt", "jsubfinder_secrets.txt", "swaggerspy_results.txt") {
		eachLine(f, func(l string) {
			if l = strings.TrimSpace(l); l != "" {
				add(l, "", hostOfURL(firstURLTok(l)))
			}
		})
	}
}

// ── parameters ───────────────────────────────────────────────────────────────

func scanParams(st *store.Store, run *store.Run, ws string) {
	n := 0
	add := func(host, u, name string) {
		if n >= rowCap || name == "" {
			return
		}
		n++
		st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "param", Host: host, URL: strp(u), Name: sp(trunc(name, 120))})
	}
	for _, f := range globFiles(ws, "arjun.json", "x8_params.json") {
		parseJSONObj(f, func(k string, v any) {
			if arr, ok := v.([]any); ok {
				for _, p := range arr {
					add(hostOfURL(k), k, str(p))
				}
			}
		})
	}
	for _, f := range globFiles(ws, "ffuf_params.json") {
		parseJSONArray(f, func(m map[string]any) { add(hostOfURL(str(m["url"])), str(m["url"]), str(m["input"])) })
	}
	for _, f := range globFiles(ws, "all_params.txt", "found_params.txt") {
		eachLine(f, func(l string) {
			if l = strings.TrimSpace(l); l != "" {
				add(run.Target, "", l)
			}
		})
	}
}

// ── takeover / buckets / cdn ─────────────────────────────────────────────────

func scanTakeover(st *store.Store, run *store.Run, ws string) {
	for _, f := range globFiles(ws, "takeover_findings.txt") {
		eachLine(f, func(l string) {
			l = strings.TrimSpace(l)
			if l == "" {
				return
			}
			h := hostOfURL(firstURLTok(l))
			if h == "" {
				if ff := strings.Fields(l); len(ff) > 0 {
					h = strings.ToLower(ff[0])
				}
			}
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "vuln", Severity: sp("high"),
				Host: h, Name: sp("subdomain takeover"), Description: sp(trunc(l, 200))})
		})
	}
}

func scanBuckets(st *store.Store, run *store.Run, ws string) {
	for _, f := range globFiles(ws, "s3scanner.json", "s3scanner.jsonl") {
		eachJSONLine(f, func(m map[string]any) {
			name := str(m["name"])
			if name == "" {
				name = str(m["bucket"])
			}
			if name == "" {
				return
			}
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "bucket", Host: run.Target,
				Name: sp(name), Description: strp(strings.TrimSpace(str(m["region"]) + " " + str(m["provider"])))})
		})
	}
}

func scanCDN(st *store.Store, run *store.Run, ws string) {
	for _, f := range globFiles(ws, "cdncheck.jsonl", "cdncheck.json") {
		eachJSONLine(f, func(m map[string]any) {
			name := str(m["cdn_name"])
			if name == "" || name == "false" || name == "true" {
				return
			}
			host := str(m["host"])
			if host == "" {
				host = str(m["input"])
			}
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "cdn", Host: host,
				IP: strp(str(m["ip"])), Name: sp("CDN: " + name)})
		})
	}
}

// ── network intel (censys / fofa / asn / internal / origin / ptr) ────────────

func scanNetIntel(st *store.Store, run *store.Run, ws string) {
	// censys_hosts.txt  ip\tasn\torg\tprefix
	for _, f := range globFiles(ws, "censys_hosts.txt") {
		eachLine(f, func(l string) {
			c := strings.Split(l, "\t")
			if len(c) >= 3 && c[0] != "" {
				prefix := ""
				if len(c) >= 4 {
					prefix = strings.TrimSpace(c[3])
				}
				st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "asn", Host: c[0], IP: sp(c[0]),
					Name: sp(strings.TrimSpace("AS" + c[1] + " " + c[2])), Description: strp(prefix)})
			}
		})
	}
	// fofa_ip_port.txt  host\tip\tport
	for _, f := range globFiles(ws, "fofa_ip_port.txt") {
		eachLine(f, func(l string) {
			c := strings.Split(l, "\t")
			if len(c) >= 2 {
				fd := &store.Finding{RunID: run.ID, Kind: "port", Host: strings.ToLower(c[0]), IP: strp(strings.TrimSpace(c[1]))}
				if len(c) >= 3 {
					fd.Port = intPtr(intFromAny(strings.TrimSpace(c[2])))
				}
				st.InsertFinding(fd)
			}
		})
	}
	// org/ASN CIDRs + internal subnets + origin IPs → kind=net
	for _, f := range globFiles(ws, "asn_ipv4_cidrs.txt", "amass_intel_cidrs.txt", "censys_prefixes.txt",
		"internal_subnets.txt", "dns_internal_subnets.txt") {
		eachLine(f, func(l string) {
			if ff := strings.Fields(l); len(ff) > 0 && strings.Contains(ff[0], "/") {
				st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "net", Host: ff[0], Name: sp(ff[0])})
			}
		})
	}
	for _, f := range globFiles(ws, "origin_ips.txt") {
		eachLine(f, func(l string) {
			if l = strings.TrimSpace(l); l != "" {
				st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "net", Host: l, IP: sp(l), Name: sp("origin IP " + l)})
			}
		})
	}
	// shared-hosting IPs (many vhosts on one IP)
	for _, f := range globFiles(ws, "ip_groups/shared_hosting.txt") {
		eachLine(f, func(l string) {
			ip := strings.TrimSpace(strings.Fields(l+" ")[0])
			if ip != "" {
				st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "net", Host: ip, IP: sp(ip), Name: sp("shared-hosting IP " + ip)})
			}
		})
	}
	// internal hosts (RFC1918 / leaked) → subdomain tagged internal
	for _, f := range globFiles(ws, "internal_hosts.txt", "dns_internal_hosts.txt") {
		eachLine(f, func(l string) {
			c := strings.Fields(l)
			if len(c) == 0 {
				return
			}
			fd := &store.Finding{RunID: run.ID, Kind: "subdomain", Host: strings.ToLower(c[0]),
				Name: sp(c[0]), Tags: `["internal"]`}
			if len(c) >= 2 {
				fd.IP = strp(strings.TrimSpace(c[1]))
			}
			st.InsertFinding(fd)
		})
	}
	// PTR
	for _, f := range globFiles(ws, "ptr_resolved.txt", "dns_ptr.txt") {
		eachLine(f, func(l string) {
			var ip, host string
			for _, tok := range strings.Fields(l) {
				tok = strings.Trim(tok, "[],.")
				if strings.Count(tok, ".") == 3 && !strings.ContainsAny(tok, "abcdefghijklmnopqrstuvwxyz") {
					ip = tok
				} else if strings.Contains(tok, ".") {
					host = strings.ToLower(tok)
				}
			}
			if ip != "" && host != "" {
				st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "ptr", Host: host, IP: sp(ip), Name: sp(host + " ← " + ip)})
			}
		})
	}
}

// ── service versions (nmap / rustscan) ───────────────────────────────────────

func scanServices(st *store.Store, run *store.Run, ws string) {
	for _, f := range globFiles(ws, "nmap_service.txt", "rustscan_full.txt") {
		host := ""
		eachLine(f, func(l string) {
			ls := strings.TrimSpace(l)
			if strings.HasPrefix(ls, "Nmap scan report for ") {
				host = strings.TrimSpace(strings.TrimPrefix(ls, "Nmap scan report for "))
				host = strings.Trim(strings.Fields(host+" ")[0], "()")
				return
			}
			// "80/tcp open http nginx 1.18"
			ff := strings.Fields(ls)
			if len(ff) >= 3 && strings.Contains(ff[0], "/") && ff[1] == "open" {
				pp := strings.SplitN(ff[0], "/", 2)
				svc := strings.Join(ff[2:], " ")
				st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "port", Host: host,
					Port: intPtr(intFromAny(pp[0])), Protocol: sp(pp[1]), Name: sp(trunc("svc: "+svc, 160))})
			}
		})
	}
}

// ── gf attack-candidate patterns (xss/sqli/lfi/ssrf/…) ───────────────────────

func scanGF(st *store.Store, run *store.Run, ws string) {
	ms, _ := filepath.Glob(filepath.Join(ws, "gf", "*.txt"))
	n := 0
	for _, f := range ms {
		cat := strings.TrimSuffix(filepath.Base(f), ".txt")
		eachLine(f, func(l string) {
			u := firstURLTok(l)
			if u == "" {
				u = strings.TrimSpace(l)
			}
			if u == "" || n >= rowCap {
				return
			}
			n++
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "endpoint", Host: hostOfURL(u),
				URL: strp(u), Name: sp(trunc(u, 200)), Tags: `["gf:` + cat + `"]`})
		})
	}
}

// ── DNS records / certs / favicons ───────────────────────────────────────────

func scanDNSRecords(st *store.Store, run *store.Run, ws string) {
	for _, f := range globFiles(ws, "dns_records_raw.txt", "dns_records_subs_raw.txt", "st_dns_records.txt") {
		eachLine(f, func(l string) {
			if l = strings.TrimSpace(l); l == "" {
				return
			}
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "dns",
				Host: strings.ToLower(strings.Fields(l+" ")[0]), Name: sp(trunc(l, 200))})
		})
	}
}

func scanCerts(st *store.Store, run *store.Run, ws string) {
	for _, f := range globFiles(ws, "tlsx_raw.txt") {
		eachLine(f, func(l string) {
			if l = strings.TrimSpace(l); l == "" {
				return
			}
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "cert",
				Host: strings.ToLower(strings.Fields(l+" ")[0]), Name: sp(trunc(l, 200))})
		})
	}
	for _, f := range globFiles(ws, "st_ssl.json") {
		if b, e := os.ReadFile(f); e == nil && len(b) > 0 {
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "cert", Host: run.Target,
				Name: sp("SSL intel: " + filepath.Base(f)), Evidence: sp(trunc(string(b), 2000))})
		}
	}
}

func scanFavicon(st *store.Store, run *store.Run, ws string) {
	for _, f := range globFiles(ws, "favicon_hashes.txt") {
		eachLine(f, func(l string) {
			c := strings.Split(l, ",")
			if len(c) < 2 {
				c = strings.Fields(l)
			}
			if len(c) < 2 {
				return
			}
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "favicon",
				Host: strings.ToLower(strings.TrimSpace(c[0])), Name: sp("favicon " + strings.TrimSpace(c[1]))})
		})
	}
}

// ── intel (whois / domain info) ──────────────────────────────────────────────

func scanIntel(st *store.Store, run *store.Run, ws string) {
	for _, f := range globFiles(ws, "st_whois.json", "st_domain_info.json") {
		if b, e := os.ReadFile(f); e == nil && len(b) > 0 {
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "intel", Host: run.Target,
				Name: sp("whois/domain-info: " + filepath.Base(f)), Evidence: sp(trunc(string(b), 2000))})
		}
	}
	// related / associated / org-pivot domains (scope-expansion intel)
	for _, f := range globFiles(ws, "st_associated.txt", "st_pivot_domains.txt", "amass_intel.txt") {
		eachLine(f, func(l string) {
			d := strings.ToLower(strings.Trim(strings.TrimSpace(l), "."))
			if fld := strings.Fields(d); len(fld) > 0 {
				d = fld[0]
			}
			if d == "" || !strings.Contains(d, ".") {
				return
			}
			st.InsertFinding(&store.Finding{RunID: run.ID, Kind: "intel", Host: d, Name: sp("related domain: " + d)})
		})
	}
}
