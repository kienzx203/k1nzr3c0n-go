package agent

// sast_scan: an official agent tool that runs the bundled SAST source→sink taint
// engine (/app/sast) over a source-code directory and returns a concise list of
// vulnerability CANDIDATES (category + file:line of the sink + the source + the
// function). It gives the review brain BREADTH (high recall) fast; the agent then
// confirms each candidate in the code (reachable + unsanitized) and builds a PoC
// before calling report_finding. This is the recall half of the review loop; the
// LLM is the precision half.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const sastEngineRoot = "/app/sast"

func sastPython() string {
	for _, p := range []string{"python3", "python"} {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	return "python3"
}

// sastScan is the sast_scan tool: run the taint engine on a directory, summarize.
func (t *ToolSet) sastScan() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "Path to the source-code DIRECTORY to scan (a folder, not a single file). Scan a subdirectory to narrow the result on a large codebase."},
			"lang": map[string]any{"type": "string", "description": "Optional language hint (php/python/java/javascript/typescript/go/ruby/perl/csharp/cpp/objc/kotlin/swift/rust/vbnet/plsql/vb6/cobol); omit to auto-detect per file."},
		},
		"required": []string{"path"},
	}
	desc := "Run the built-in SAST source→sink taint engine over a source-code directory and return a concise list of vulnerability CANDIDATES (category + file:line of the sink + the source + the enclosing function). HIGH RECALL by static data-flow — these are CANDIDATES, not confirmed vulnerabilities: you MUST confirm each by reading the actual code (entry attacker-reachable AND no effective sanitizer on the path) and build a reproducible PoC before calling report_finding. Use it to get breadth over a codebase fast, then verify with precision. Covers 18 languages and classes incl. SQLi/CMDi/XSS/path/LFI/SSRF/XXE/SSTI/deserialization/open-redirect/weak-crypto/buffer-overflow/UAF/double-free/OOB and more."
	return readTool("sast_scan", desc, schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var in struct {
			Path string `json:"path"`
			Lang string `json:"lang"`
		}
		_ = json.Unmarshal(raw, &in)
		in.Path = strings.TrimSpace(in.Path)
		if in.Path == "" {
			return actool.Errorf("sast_scan: 'path' is required (a source-code directory)"), nil
		}
		fi, err := os.Stat(in.Path)
		if err != nil {
			return actool.Errorf(fmt.Sprintf("sast_scan: path not found: %s", in.Path)), nil
		}
		if !fi.IsDir() {
			return actool.Errorf(fmt.Sprintf("sast_scan: 'path' must be a directory, not a file: %s (pass the containing folder)", in.Path)), nil
		}
		orch := filepath.Join(sastEngineRoot, "agent_c", "orchestrator.py")
		if _, err := os.Stat(orch); err != nil {
			return actool.Errorf(fmt.Sprintf("sast_scan: engine not available at %s", orch)), nil
		}
		tmp, err := os.CreateTemp("", "sastscan_*.json")
		if err != nil {
			return actool.Errorf("sast_scan: server temp error"), nil
		}
		outPath := tmp.Name()
		_ = tmp.Close()
		defer os.Remove(outPath)
		cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
		defer cancel()
		args := []string{orch, in.Path, "--db", filepath.Join(sastEngineRoot, "taint_spec.db"), "--json", outPath, "--multi"}
		if in.Lang != "" {
			args = append(args, "--lang", in.Lang)
		}
		cmd := exec.CommandContext(cctx, sastPython(), args...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			tail := strings.TrimSpace(stderr.String())
			if len(tail) > 400 {
				tail = tail[len(tail)-400:]
			}
			if cctx.Err() == context.DeadlineExceeded {
				return actool.Errorf("sast_scan: timed out (scan a smaller subdirectory). " + tail), nil
			}
			return actool.Errorf(fmt.Sprintf("sast_scan failed: %v: %s", err, tail)), nil
		}
		b, err := os.ReadFile(outPath)
		if err != nil {
			return actool.Errorf("sast_scan: no result produced"), nil
		}
		return actool.Text(summarizeSast(b)), nil
	})
}

// codeRefs is the code_refs tool: find a symbol's definition + all references (call
// sites / usages) across a code tree, for inter-procedural tracing and reachability
// ("who calls this entry?", "where does this tainted value flow?"). Backed by grep.
func (t *ToolSet) codeRefs() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"symbol": map[string]any{"type": "string", "description": "Function / method / variable / route name to locate (whole-word match)."},
			"path":   map[string]any{"type": "string", "description": "Directory to search (the source root or a subdir)."},
		},
		"required": []string{"symbol", "path"},
	}
	desc := "Find where a SYMBOL (function/method/variable/route) is DEFINED and every place it is REFERENCED/called across the source tree (whole-word, recursive grep). Use it to trace data-flow across files (who calls this function, where this value flows) and to prove REACHABILITY of an entry/sink — the core of not missing cross-file bugs. Returns file:line + the line, capped."
	return readTool("code_refs", desc, schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var in struct {
			Symbol string `json:"symbol"`
			Path   string `json:"path"`
		}
		_ = json.Unmarshal(raw, &in)
		in.Symbol = strings.TrimSpace(in.Symbol)
		in.Path = strings.TrimSpace(in.Path)
		if in.Symbol == "" || in.Path == "" {
			return actool.Errorf("code_refs: 'symbol' and 'path' are required"), nil
		}
		if fi, err := os.Stat(in.Path); err != nil || !fi.IsDir() {
			return actool.Errorf(fmt.Sprintf("code_refs: path not a directory: %s", in.Path)), nil
		}
		// grep -rnw: whole-word, recursive, with line numbers; skip common noise dirs.
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		args := []string{"-rnwI", "--", in.Symbol, in.Path}
		cmd := exec.CommandContext(cctx, "grep",
			append([]string{"--exclude-dir=.git", "--exclude-dir=node_modules", "--exclude-dir=vendor", "--exclude-dir=.svn"}, args...)...)
		out, _ := cmd.Output() // grep exits 1 on no-match; ignore the error, use the output
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			return actool.Text(fmt.Sprintf("code_refs: no reference to '%s' under %s (check spelling, or the symbol may be dynamically dispatched/renamed).", in.Symbol, in.Path)), nil
		}
		const capN = 100
		var sb strings.Builder
		fmt.Fprintf(&sb, "code_refs '%s': %d reference(s). A definition is usually where the name is preceded by def/func/function/class/sub/public/private or `=`; the rest are call-sites/usages — read the definition to understand it, read the call-sites to judge reachability.\n", in.Symbol, len(lines))
		for i, ln := range lines {
			if i >= capN {
				fmt.Fprintf(&sb, "… (%d more — narrow with a subdir path)\n", len(lines)-capN)
				break
			}
			if len(ln) > 240 {
				ln = ln[:240] + "…"
			}
			sb.WriteString(ln)
			sb.WriteByte('\n')
		}
		return actool.Text(sb.String()), nil
	})
}

// listCodeUnits is the list_code_units tool: the COMPLETE function inventory of a code
// tree (the SAST extractor misses no function — verified), so the review can be driven
// to cover EVERY function for EVERY vulnerability class with nothing silently skipped.
// This is the deterministic denominator for "no function missed".
func (t *ToolSet) listCodeUnits() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "Source-code directory to inventory."},
			"lang": map[string]any{"type": "string", "description": "Optional language hint; omit to auto-detect."},
			"file": map[string]any{"type": "string", "description": "Optional: only list functions in files whose path contains this substring (narrow a large inventory)."},
		},
		"required": []string{"path"},
	}
	desc := "List the COMPLETE inventory of functions/methods in a source-code directory (the SAST extractor enumerates every named function across 18 languages — nothing is missed). Use it as the DENOMINATOR for exhaustive review: every function must be reviewed for every applicable vulnerability class; ⚠ marks functions that already have a source→sink candidate. Pair with code_refs to find entry/route handlers. This guarantees you can prove no function was skipped."
	return readTool("list_code_units", desc, schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var in struct {
			Path string `json:"path"`
			Lang string `json:"lang"`
			File string `json:"file"`
		}
		_ = json.Unmarshal(raw, &in)
		in.Path = strings.TrimSpace(in.Path)
		if in.Path == "" {
			return actool.Errorf("list_code_units: 'path' is required"), nil
		}
		if fi, err := os.Stat(in.Path); err != nil || !fi.IsDir() {
			return actool.Errorf(fmt.Sprintf("list_code_units: path not a directory: %s", in.Path)), nil
		}
		orch := filepath.Join(sastEngineRoot, "agent_c", "orchestrator.py")
		tmp, err := os.CreateTemp("", "codeunits_*.json")
		if err != nil {
			return actool.Errorf("list_code_units: temp error"), nil
		}
		outPath := tmp.Name()
		_ = tmp.Close()
		defer os.Remove(outPath)
		cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
		defer cancel()
		args := []string{orch, in.Path, "--db", filepath.Join(sastEngineRoot, "taint_spec.db"), "--json", outPath, "--multi"}
		if in.Lang != "" {
			args = append(args, "--lang", in.Lang)
		}
		cmd := exec.CommandContext(cctx, sastPython(), args...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			tail := strings.TrimSpace(stderr.String())
			if len(tail) > 300 {
				tail = tail[len(tail)-300:]
			}
			return actool.Errorf(fmt.Sprintf("list_code_units failed: %v: %s", err, tail)), nil
		}
		b, err := os.ReadFile(outPath)
		if err != nil {
			return actool.Errorf("list_code_units: no result"), nil
		}
		return actool.Text(summarizeCodeUnits(b, in.File)), nil
	})
}

func summarizeCodeUnits(b []byte, fileFilter string) string {
	var r struct {
		Targets []struct {
			Graph struct {
				Nodes []struct {
					Label     string `json:"label"`
					File      string `json:"file"`
					Line      int    `json:"line"`
					Finding   bool   `json:"finding"`
					Entry     bool   `json:"entry"`
					Reachable bool   `json:"reachable"`
				} `json:"nodes"`
			} `json:"graph"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "list_code_units: could not parse engine output"
	}
	byFile := map[string][]string{}
	var files []string
	total, withCand, unreached := 0, 0, 0
	for _, tg := range r.Targets {
		for _, n := range tg.Graph.Nodes {
			if n.File == "" {
				continue
			}
			if fileFilter != "" && !strings.Contains(n.File, fileFilter) {
				continue
			}
			total++
			mark := ""
			if n.Finding {
				mark = " ⚠candidate"
				withCand++
			}
			if n.Entry {
				mark += " ⟵entry"
			}
			if !n.Reachable {
				mark += " ⌀unreached"
				unreached++
			}
			if _, ok := byFile[n.File]; !ok {
				files = append(files, n.File)
			}
			byFile[n.File] = append(byFile[n.File], fmt.Sprintf("  %s:%d  %s%s", n.File, n.Line, n.Label, mark))
		}
	}
	if total == 0 {
		return "list_code_units: 0 functions found (empty/unsupported directory, or narrow filter)."
	}
	sort.Strings(files)
	var sb strings.Builder
	fmt.Fprintf(&sb, "COMPLETE function inventory: %d functions across %d files (%d already have a source→sink candidate; %d ⌀unreached from any entry = dead/un-wired — investigate why they exist, then review). ⟵entry marks a route/handler. This is the full denominator — review EVERY function for EVERY applicable vuln class; nothing here may be silently skipped.\n\n", total, len(files), withCand, unreached)
	const capN = 200
	shown := 0
	for _, f := range files {
		if shown >= capN {
			fmt.Fprintf(&sb, "\n… (inventory truncated at %d functions; call again with file=<substr> to list a specific area)\n", capN)
			break
		}
		fmt.Fprintf(&sb, "%s (%d):\n", f, len(byFile[f]))
		for _, ln := range byFile[f] {
			if shown >= capN {
				break
			}
			sb.WriteString(ln)
			sb.WriteByte('\n')
			shown++
		}
	}
	return sb.String()
}

// endpointRE matches route/endpoint declarations across common web frameworks, so
// list_endpoints can enumerate the attacker-reachable HTTP surface deterministically.
// entrypoint is one attacker-reachable entry produced by agent_c/entrypoints.py.
type entrypoint struct {
	Kind   string `json:"kind"` // http | graphql | websocket | queue | schedule | cli | serverless
	Method string `json:"method"`
	Path   string `json:"path"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Label  string `json:"label"`
}

// runEntrypoints runs the framework-aware entry-point extractor (route expansion +
// composition + non-HTTP entries) and returns the parsed inventory.
func runEntrypoints(ctx context.Context, path string) ([]entrypoint, error) {
	script := filepath.Join(sastEngineRoot, "agent_c", "entrypoints.py")
	if _, err := os.Stat(script); err != nil {
		return nil, fmt.Errorf("entrypoint extractor not available")
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, sastPython(), script, path)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var eps []entrypoint
	if err := json.Unmarshal(out, &eps); err != nil {
		return nil, err
	}
	return eps, nil
}

// listEndpoints is the list_endpoints tool: enumerate every attacker-reachable ENTRY
// across the source (HTTP routes WITH convention-routing expanded and class/method paths
// composed, plus non-HTTP entries) — the endpoint denominator.
func (t *ToolSet) listEndpoints() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "Source-code directory to enumerate entry points in."},
		},
		"required": []string{"path"},
	}
	desc := "Enumerate every attacker-reachable ENTRY across the source: HTTP routes with convention routing EXPANDED (Rails resources→7, DRF/Laravel resource→CRUD) and class+method paths COMPOSED (Spring @RequestMapping+@GetMapping, NestJS @Controller, FastAPI/Blueprint prefixes), Next.js file-system routes, PHP front-controllers, PLUS non-HTTP entries (GraphQL resolvers, WebSocket, message-queue consumers, scheduled jobs, CLI commands, serverless handlers). Use it as the ENDPOINT denominator — each entry is a review obligation. Still confirm each in code and watch for fully-dynamic registration the extractor can't resolve."
	return readTool("list_endpoints", desc, schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var in struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(raw, &in)
		in.Path = strings.TrimSpace(in.Path)
		if in.Path == "" {
			return actool.Errorf("list_endpoints: 'path' is required"), nil
		}
		if fi, err := os.Stat(in.Path); err != nil || !fi.IsDir() {
			return actool.Errorf(fmt.Sprintf("list_endpoints: path not a directory: %s", in.Path)), nil
		}
		eps, err := runEntrypoints(ctx, in.Path)
		if err != nil {
			return actool.Errorf("list_endpoints: " + err.Error()), nil
		}
		if len(eps) == 0 {
			return actool.Text("list_endpoints: no entry points matched. The app may register routes fully dynamically, use a router the extractor doesn't cover, or run behind a single front controller — enumerate manually with code_refs on the dispatcher/main/router file."), nil
		}
		byKind := map[string]int{}
		for _, e := range eps {
			byKind[e.Kind]++
		}
		const capN = 200
		var sb strings.Builder
		fmt.Fprintf(&sb, "ENTRY POINTS: %d (the attacker-reachable denominator — review EVERY one for ALL applicable vuln classes).\nBy kind:", len(eps))
		for k, c := range byKind {
			fmt.Fprintf(&sb, " %s=%d", k, c)
		}
		sb.WriteString("\n\n")
		for i, e := range eps {
			if i >= capN {
				fmt.Fprintf(&sb, "… (%d more — narrow with a subdir path)\n", len(eps)-capN)
				break
			}
			loc := e.File
			if e.Line > 0 {
				loc = fmt.Sprintf("%s:%d", e.File, e.Line)
			}
			if e.Kind == "http" {
				fmt.Fprintf(&sb, "[http] %-6s %-30s  %s\n", e.Method, e.Path, loc)
			} else {
				fmt.Fprintf(&sb, "[%s] %s  %s\n", e.Kind, e.Label, loc)
			}
		}
		return actool.Text(sb.String()), nil
	})
}

// scaScan is the sca_scan tool: real Software Composition Analysis — parse the project's
// dependency manifests/lockfiles and check each library version against OSV.dev for KNOWN
// CVEs (authoritative data, not model-guessed), with the fixed version to upgrade to.
func (t *ToolSet) scaScan() actool.CoreTool {
	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"path": map[string]any{"type": "string", "description": "Source directory to audit dependencies in (must contain manifests/lockfiles)."}},
		"required":   []string{"path"},
	}
	desc := "Review third-party LIBRARY versions for KNOWN CVEs (real SCA via OSV.dev — authoritative, not guessed). Parses package-lock.json/package.json, requirements.txt, go.mod, pom.xml, composer.lock, Gemfile.lock, Cargo.lock and *.csproj, then reports each vulnerable dependency with its CVE/GHSA ids, severity and the FIXED version to upgrade to. Use it so outdated/vulnerable dependencies are never missed; still confirm the vulnerable code path is actually reachable/used before rating impact. Offline-safe (returns the dependency inventory if OSV is unreachable)."
	return readTool("sca_scan", desc, schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var in struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(raw, &in)
		in.Path = strings.TrimSpace(in.Path)
		if in.Path == "" {
			return actool.Errorf("sca_scan: 'path' is required"), nil
		}
		if fi, err := os.Stat(in.Path); err != nil || !fi.IsDir() {
			return actool.Errorf(fmt.Sprintf("sca_scan: path not a directory: %s", in.Path)), nil
		}
		script := filepath.Join(sastEngineRoot, "agent_c", "sca.py")
		if _, err := os.Stat(script); err != nil {
			return actool.Errorf("sca_scan: SCA engine not available"), nil
		}
		cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(cctx, sastPython(), script, in.Path).Output()
		if err != nil {
			if cctx.Err() == context.DeadlineExceeded {
				return actool.Errorf("sca_scan: timed out querying the vuln database"), nil
			}
			return actool.Errorf("sca_scan failed: " + err.Error()), nil
		}
		return actool.Text(summarizeSca(out)), nil
	})
}

// summarizeSca renders the SCA JSON into a compact CVE report for the agent.
func summarizeSca(b []byte) string {
	var r struct {
		Deps       int    `json:"deps"`
		Offline    bool   `json:"offline"`
		Note       string `json:"note"`
		Vulnerable []struct {
			Ecosystem string `json:"ecosystem"`
			Package   string `json:"package"`
			Version   string `json:"version"`
			Manifest  string `json:"manifest"`
			Vulns     []struct {
				ID       string `json:"id"`
				CVE      string `json:"cve"`
				Severity string `json:"severity"`
				Summary  string `json:"summary"`
				Fixed    string `json:"fixed"`
			} `json:"vulns"`
		} `json:"vulnerable"`
		Inventory []struct {
			Ecosystem string `json:"ecosystem"`
			Package   string `json:"package"`
			Version   string `json:"version"`
		} `json:"inventory"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "sca_scan: could not parse SCA output"
	}
	var sb strings.Builder
	if r.Offline {
		fmt.Fprintf(&sb, "DEPENDENCY CVE REVIEW — OFFLINE. %s.\nInventory (look these up manually):\n", r.Note)
		for i, d := range r.Inventory {
			if i >= 100 {
				fmt.Fprintf(&sb, "… (%d more)\n", len(r.Inventory)-100)
				break
			}
			fmt.Fprintf(&sb, "  [%s] %s@%s\n", d.Ecosystem, d.Package, d.Version)
		}
		return sb.String()
	}
	if r.Deps == 0 {
		return "sca_scan: no dependency manifests/lockfiles found in this path."
	}
	if len(r.Vulnerable) == 0 {
		return fmt.Sprintf("DEPENDENCY CVE REVIEW (OSV.dev): %d dependencies checked, 0 with known CVEs. (Lockfiles give exact versions; declared ranges are best-effort.)", r.Deps)
	}
	fmt.Fprintf(&sb, "DEPENDENCY CVE REVIEW (OSV.dev): %d checked, %d VULNERABLE. Confirm each vulnerable library is actually used/reachable before rating impact.\n\n", r.Deps, len(r.Vulnerable))
	for _, d := range r.Vulnerable {
		fmt.Fprintf(&sb, "[%s] %s@%s (%s):\n", d.Ecosystem, d.Package, d.Version, d.Manifest)
		for i, v := range d.Vulns {
			if i >= 6 {
				fmt.Fprintf(&sb, "    … (+%d more)\n", len(d.Vulns)-6)
				break
			}
			id := v.CVE
			if id == "" {
				id = v.ID
			}
			line := "    " + id
			if v.Severity != "" {
				line += " [" + v.Severity + "]"
			}
			if v.Fixed != "" {
				line += " → fixed in " + v.Fixed
			}
			if v.Summary != "" {
				line += " — " + v.Summary
			}
			sb.WriteString(line + "\n")
		}
	}
	return sb.String()
}

// ── Report / triage tool: consolidate findings into one severity-ranked deliverable ──

var _sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3, "info": 4, "informational": 4, "needs-review": 5}

func sevRank(s string) int {
	if r, ok := _sevRank[strings.ToLower(strings.TrimSpace(s))]; ok {
		return r
	}
	return 6
}

// reviewReport assembles every confirmed finding in the task into one triaged,
// deduplicated, severity-ranked Markdown report — the human-facing deliverable. It
// reuses the standard SOURCE→SINK block each finding already carries.
func (t *ToolSet) reviewReport() actool.CoreTool {
	desc := "Produce the consolidated vulnerability-review REPORT for this task: every confirmed finding, de-duplicated and ranked by severity, with its standard source→sink and a severity summary table. Call it at the end of a review to hand the user one professional deliverable (Markdown). Reads the findings already recorded via report_finding — it does not invent new ones."
	return readTool("review_report", schema2desc(desc), map[string]any{"type": "object", "properties": map[string]any{}}, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		if t.ts == nil {
			return actool.Errorf("review_report requires task context"), nil
		}
		nodes, _ := t.ts.ListByKindWithSources(db.KindFinding, 500)
		type fnd struct {
			vc, sev, name, summary, evidence string
		}
		var all []fnd
		seen := map[string]bool{}
		sevCount := map[string]int{}
		classCount := map[string]int{}
		for _, n := range nodes {
			var p map[string]any
			_ = json.Unmarshal(n.Payload, &p)
			gs := func(k string) string {
				if v, ok := p[k].(string); ok {
					return v
				}
				return ""
			}
			f := fnd{vc: gs("vulnclass"), sev: gs("severity"), name: gs("name"), summary: gs("summary"), evidence: gs("evidence")}
			if f.vc == "" && f.summary == "" {
				continue
			}
			// dedup on (class + SINK line) so the same sink reported twice collapses
			sinkLine := ""
			for _, ln := range strings.Split(f.evidence, "\n") {
				if strings.HasPrefix(strings.TrimSpace(ln), "SINK:") {
					sinkLine = strings.TrimSpace(ln)
					break
				}
			}
			key := strings.ToLower(f.vc + "|" + sinkLine + "|" + f.name)
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, f)
			sevCount[strings.ToLower(f.sev)]++
			if f.vc != "" {
				classCount[f.vc]++
			}
		}
		if len(all) == 0 {
			return actool.Text("review_report: no findings recorded yet for this task. Record confirmed vulnerabilities with report_finding first."), nil
		}
		sort.SliceStable(all, func(i, j int) bool {
			if sevRank(all[i].sev) != sevRank(all[j].sev) {
				return sevRank(all[i].sev) < sevRank(all[j].sev)
			}
			return all[i].vc < all[j].vc
		})
		var sb strings.Builder
		sb.WriteString("# Vulnerability Review Report\n\n")
		sb.WriteString(fmt.Sprintf("**Total findings:** %d  ", len(all)))
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			if sevCount[s] > 0 {
				sb.WriteString(fmt.Sprintf("· %s: %d ", strings.Title(s), sevCount[s]))
			}
		}
		sb.WriteString("\n\n## By vulnerability class\n\n| Class | Count |\n|---|---|\n")
		for cls, c := range classCount {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", cls, c))
		}
		sb.WriteString("\n---\n\n")
		for i, f := range all {
			sev := f.sev
			if sev == "" {
				sev = "unspecified"
			}
			title := f.name
			if title == "" {
				title = f.vc
			}
			sb.WriteString(fmt.Sprintf("## %d. [%s] %s — %s\n\n", i+1, strings.ToUpper(sev), f.vc, title))
			if f.summary != "" {
				sb.WriteString(f.summary + "\n\n")
			}
			if f.evidence != "" {
				sb.WriteString("```\n" + strings.TrimRight(f.evidence, "\n") + "\n```\n\n")
			}
		}
		return actool.Text(sb.String()), nil
	})
}

// ── Review-coverage ledger tools (engine-enforced "no function/endpoint missed") ──

// reviewSeed seeds the ledger with every function + endpoint of a code tree, so the
// denominator is deterministic and stored, not held in the agent's head.
func (t *ToolSet) reviewSeed() actool.CoreTool {
	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"path": map[string]any{"type": "string", "description": "Source-code directory to inventory into the review ledger."}},
		"required":   []string{"path"},
	}
	desc := "Seed the REVIEW-COVERAGE LEDGER with the complete inventory — every function (SAST, no function missed) and every endpoint (route extractor) — so coverage becomes engine-tracked. Call this ONCE at the start of a source-review task; then review_mark each unit as you review it, and the task cannot be completed until review_coverage shows 0 pending. Idempotent (re-running keeps existing review state)."
	return readTool("review_seed", schema2desc(desc), schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		if t.ts == nil || t.taskID == 0 {
			return actool.Errorf("review_seed requires task context"), nil
		}
		var in struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(raw, &in)
		in.Path = strings.TrimSpace(in.Path)
		if in.Path == "" {
			return actool.Errorf("review_seed: 'path' is required"), nil
		}
		if fi, err := os.Stat(in.Path); err != nil || !fi.IsDir() {
			return actool.Errorf(fmt.Sprintf("review_seed: path not a directory: %s", in.Path)), nil
		}
		units := collectFunctionUnits(ctx, in.Path)
		units = append(units, collectEndpointUnits(ctx, in.Path)...)
		units = append(units, collectAuxUnits(in.Path)...)
		if len(units) == 0 {
			return actool.Errorf("review_seed: no functions or endpoints found to seed"), nil
		}
		n, err := t.ts.DB().SeedReviewUnits(ctx, t.taskID, units)
		if err != nil {
			return actool.Errorf("review_seed: " + err.Error()), nil
		}
		cov, _ := t.ts.DB().ReviewCoverage(ctx, t.taskID)
		return actool.Text(fmt.Sprintf("review ledger seeded: +%d new units (%d functions + %d endpoints + %d template/config files just collected). Total ledger: %d units, %d still pending review. Review each (templates: check unescaped output / SSTI; config: secrets / debug / permissive CORS / default creds) and review_mark it; the task cannot complete until pending=0.",
			n, countKind(units, "function"), countKind(units, "endpoint"), countKind(units, "template")+countKind(units, "config"), cov.Total, cov.Pending)), nil
	})
}

// reviewMark records that a unit was reviewed for some classes with a verdict.
func (t *ToolSet) reviewMark() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"unit":    map[string]any{"type": "string", "description": "The function name or endpoint route (or its file:line) just reviewed, as shown by list_code_units / list_endpoints / review_coverage."},
			"classes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "The vuln classes you actually checked on this unit (injection, access-control, idor, ssrf, deserialization, crypto, race, logic, …)."},
			"verdict": map[string]any{"type": "string", "enum": []string{"reviewed", "vulnerable", "na"}, "description": "reviewed = checked, nothing found; vulnerable = a finding was reported; na = not applicable (test/generated/not reachable)."},
			"note":    map[string]any{"type": "string", "description": "One-line reason/result (e.g. 'parameterized query, no concat' / 'reported SQLi'). Required for na."},
		},
		"required": []string{"unit", "verdict"},
	}
	desc := "Mark a function/endpoint as reviewed in the coverage ledger (which classes you checked + the verdict). Do this for EVERY unit — the planner's completion gate requires 0 pending, so an un-marked unit blocks finishing (which is the point: it prevents silently skipping code)."
	return readTool("review_mark", schema2desc(desc), schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		if t.ts == nil || t.taskID == 0 {
			return actool.Errorf("review_mark requires task context"), nil
		}
		var in struct {
			Unit    string   `json:"unit"`
			Classes []string `json:"classes"`
			Verdict string   `json:"verdict"`
			Note    string   `json:"note"`
		}
		_ = json.Unmarshal(raw, &in)
		if strings.TrimSpace(in.Unit) == "" {
			return actool.Errorf("review_mark: 'unit' is required"), nil
		}
		n, err := t.ts.DB().MarkReviewUnit(ctx, t.taskID, in.Unit, in.Classes, in.Verdict, in.Note)
		if err != nil {
			return actool.Errorf("review_mark: " + err.Error()), nil
		}
		if n == 0 {
			return actool.Text(fmt.Sprintf("review_mark: no ledger unit matched '%s' (it may not be in the inventory, or already marked). Check review_coverage for the exact pending names; seed first with review_seed if the ledger is empty.", in.Unit)), nil
		}
		cov, _ := t.ts.DB().ReviewCoverage(ctx, t.taskID)
		return actool.Text(fmt.Sprintf("marked %d unit(s) '%s' as %s. Coverage: %d/%d reviewed, %d pending.", n, in.Unit, in.Verdict, cov.Reviewed, cov.Total, cov.Pending)), nil
	})
}

// reviewCoverage is the completion gate's data source: what is covered vs still pending.
func (t *ToolSet) reviewCoverage() actool.CoreTool {
	desc := "Read the engine-tracked REVIEW COVERAGE: how many functions/endpoints are reviewed vs still pending, with a sample of pending units. The source-review goal may NOT be marked met while pending > 0 — dispatch review intents for the pending units first. This is the hard, auditable guarantee that no function or endpoint was skipped."
	return readTool("review_coverage", schema2desc(desc), map[string]any{"type": "object", "properties": map[string]any{}}, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		if t.ts == nil || t.taskID == 0 {
			return actool.Errorf("review_coverage requires task context"), nil
		}
		cov, err := t.ts.DB().ReviewCoverage(ctx, t.taskID)
		if err != nil {
			return actool.Errorf("review_coverage: " + err.Error()), nil
		}
		if cov.Total == 0 {
			return actool.Text("review ledger is EMPTY — call review_seed(<source dir>) first to seed the function/endpoint denominator, otherwise coverage cannot be enforced."), nil
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "REVIEW COVERAGE: %d/%d units reviewed, %d PENDING, %d vulnerable.\n", cov.Reviewed, cov.Total, cov.Pending, cov.Vulnerable)
		for kind, rt := range cov.ByKind {
			fmt.Fprintf(&sb, "  %s: %d/%d reviewed\n", kind, rt[0], rt[1])
		}
		if cov.Pending == 0 {
			sb.WriteString("✓ ALL units reviewed — the no-miss coverage gate is satisfied.\n")
		} else {
			sb.WriteString("✗ NOT complete — these units still need review (sample):\n")
			for _, p := range cov.PendingSample {
				sb.WriteString("  - " + p + "\n")
			}
			sb.WriteString("Dispatch review intents for the pending units; do not conclude the task while pending > 0.\n")
		}
		return actool.Text(sb.String()), nil
	})
}

// schema2desc is identity; kept so tool descs read uniformly at the call sites above.
func schema2desc(s string) string { return s }

func countKind(u []ReviewUnit, kind string) int {
	n := 0
	for _, x := range u {
		if x.Kind == kind {
			n++
		}
	}
	return n
}

// ReviewUnit aliases db.ReviewUnit so the collectors below read without the pkg prefix.
type ReviewUnit = db.ReviewUnit

// collectFunctionUnits runs the SAST extractor and returns one unit per function.
func collectFunctionUnits(ctx context.Context, path string) []ReviewUnit {
	orch := filepath.Join(sastEngineRoot, "agent_c", "orchestrator.py")
	tmp, err := os.CreateTemp("", "revseed_*.json")
	if err != nil {
		return nil
	}
	outPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(outPath)
	cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, sastPython(), orch, path, "--db", filepath.Join(sastEngineRoot, "taint_spec.db"), "--json", outPath, "--multi")
	if cmd.Run() != nil {
		return nil
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		return nil
	}
	var r struct {
		Targets []struct {
			Graph struct {
				Nodes []struct {
					Label string `json:"label"`
					File  string `json:"file"`
					Line  int    `json:"line"`
				} `json:"nodes"`
			} `json:"graph"`
		} `json:"targets"`
	}
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	var units []ReviewUnit
	for _, tg := range r.Targets {
		for _, n := range tg.Graph.Nodes {
			if n.File == "" {
				continue
			}
			units = append(units, ReviewUnit{Kind: "function", UnitKey: fmt.Sprintf("%s:%d:%s", n.File, n.Line, n.Label), Label: n.Label, File: n.File, Line: n.Line})
		}
	}
	return units
}

// collectEndpointUnits runs the framework-aware entry extractor (expanded routes +
// composed paths + non-HTTP entries) and returns one ledger unit per entry.
func collectEndpointUnits(ctx context.Context, path string) []ReviewUnit {
	eps, err := runEntrypoints(ctx, path)
	if err != nil {
		return nil
	}
	var units []ReviewUnit
	for _, e := range eps {
		label := e.Label
		if e.Kind == "http" {
			label = strings.TrimSpace(e.Method + " " + e.Path)
		}
		// unit_key keeps method+path so the 7 expanded CRUD routes of one declaration
		// are distinct units (each must be reviewed), not collapsed to the file:line.
		key := fmt.Sprintf("%s:%d:%s:%s:%s", e.File, e.Line, e.Kind, e.Method, e.Path)
		units = append(units, ReviewUnit{Kind: "endpoint", UnitKey: key, Label: label, File: e.File, Line: e.Line})
	}
	return units
}

// template/config files the tree-sitter extractor does NOT parse, so they never reach the
// function inventory — yet XSS/SSTI live in templates and secrets/misconfig in config. We
// seed each as a review unit so the agent is OBLIGED to review it (recall, not silent skip).
var _tmplExt = map[string]bool{
	".jsp": true, ".jspx": true, ".erb": true, ".twig": true, ".vue": true, ".svelte": true,
	".ejs": true, ".hbs": true, ".handlebars": true, ".mustache": true, ".j2": true,
	".jinja": true, ".jinja2": true, ".haml": true, ".slim": true, ".pug": true,
	".cshtml": true, ".razor": true, ".tpl": true, ".liquid": true, ".blade": true,
}
var _cfgName = map[string]bool{
	".env": true, "dockerfile": true, "web.config": true, ".htaccess": true,
	"nginx.conf": true, "settings.py": true, ".npmrc": true, "secrets.yml": true,
}

func collectAuxUnits(path string) []ReviewUnit {
	var units []ReviewUnit
	const cap = 300
	_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", ".svn", "dist", "build", "__pycache__", ".next", "venv", ".venv", "target":
				return filepath.SkipDir
			}
			return nil
		}
		if len(units) >= cap {
			return nil
		}
		name := strings.ToLower(info.Name())
		ext := strings.ToLower(filepath.Ext(name))
		kind := ""
		switch {
		case _tmplExt[ext] || strings.HasSuffix(name, ".blade.php"):
			kind = "template"
		case _cfgName[name] || strings.HasPrefix(name, ".env") || strings.HasPrefix(name, "docker-compose") ||
			strings.HasSuffix(name, ".properties") || strings.HasSuffix(name, ".ini") ||
			strings.HasSuffix(name, ".toml") || name == "application.yml" || name == "application.yaml" ||
			name == "config.php" || name == "appsettings.json":
			kind = "config"
		}
		if kind == "" {
			return nil
		}
		rel, _ := filepath.Rel(path, p)
		if rel == "" {
			rel = p
		}
		units = append(units, ReviewUnit{Kind: kind, UnitKey: kind + ":" + rel, Label: rel, File: rel, Line: 1})
		return nil
	})
	return units
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// summarizeSast turns the orchestrator JSON into a compact, LLM-friendly candidate list.
func summarizeSast(b []byte) string {
	var r struct {
		Targets []struct {
			Name     string `json:"name"`
			Findings []struct {
				Category string `json:"category"`
				Func     string `json:"func"`
				Pos      string `json:"pos"`
				Line     int    `json:"line"`
				Sink     string `json:"sink"`
				Source   string `json:"source"`
				Severity string `json:"severity"`
				Search   bool   `json:"search"`
			} `json:"findings"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		if len(b) > 4000 {
			b = b[:4000]
		}
		return "sast_scan raw output (could not parse as JSON):\n" + string(b)
	}
	type F struct{ cat, loc, sink, src, fn, sev string }
	var fs []F
	catCount := map[string]int{}
	for _, tg := range r.Targets {
		for _, f := range tg.Findings {
			if f.Search {
				continue // keep taint source→sink findings; drop pattern/search hints to stay concise
			}
			loc := f.Pos
			if loc == "" {
				loc = fmt.Sprintf(":%d", f.Line)
			}
			fs = append(fs, F{f.Category, loc, f.Sink, f.Source, f.Func, f.Severity})
			catCount[f.Category]++
		}
	}
	if len(fs) == 0 {
		return "sast_scan: 0 source→sink taint candidates found (no tainted data-flow reached a dangerous sink). This is recall-limited to taint-reachable flows — still review manually for auth/access-control/logic/config issues the data-flow engine cannot model, and re-scan a subdir with an explicit lang if you expected hits."
	}
	sevRank := map[string]int{"high": 0, "medium": 1, "needs-review": 2, "low": 3}
	sort.SliceStable(fs, func(i, j int) bool {
		si, sj := sevRank[fs[i].sev], sevRank[fs[j].sev]
		if si != sj {
			return si < sj
		}
		return fs[i].cat < fs[j].cat
	})
	var sb strings.Builder
	fmt.Fprintf(&sb, "SAST source→sink CANDIDATES: %d (CANDIDATES only — confirm each in the code [reachable + unsanitized], build a PoC, THEN report_finding; never report an unconfirmed hit).\n", len(fs))
	var cats []string
	for c := range catCount {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	var parts []string
	for _, c := range cats {
		parts = append(parts, fmt.Sprintf("%s=%d", c, catCount[c]))
	}
	fmt.Fprintf(&sb, "by class: %s\n\n", strings.Join(parts, " "))
	const capN = 80
	for i, f := range fs {
		if i >= capN {
			fmt.Fprintf(&sb, "… (%d more — narrow with a subdir path or a lang hint)\n", len(fs)-capN)
			break
		}
		fmt.Fprintf(&sb, "[%s|%s] %s  sink:%s  source:%s  fn:%s\n", f.sev, f.cat, f.loc, f.sink, f.src, f.fn)
	}
	return sb.String()
}
