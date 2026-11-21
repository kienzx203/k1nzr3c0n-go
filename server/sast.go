package server

// SAST_k1nz source-review: upload a .zip of source, run the bundled SAST engine
// (/app/sast) and return findings + call graph as JSON. Native to artex (no
// separate service). Behind the normal auth+license gate like the rest of /api.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sastRoot   = "/app/sast"
	sastMaxZip = 80 << 20  // 80 MB upload
	sastMaxOut = 400 << 20 // 400 MB extracted
)

// sastSource is one entry in the SHARED source registry — a source uploaded either at the
// graph page (origin "graph") or staged in a new-task draft (origin "task"). Both pages
// read/write this registry, so a source uploaded in one place is available in the other.
type sastSource struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Path      string `json:"path"` // absolute source-root path to scan/review
	Files     int    `json:"files"`
	Created   int64  `json:"created"`
	HasResult bool   `json:"has_result"`
	Origin    string `json:"origin"` // "graph" | "task"
}

func (s *Server) sastSourcesRoot() string { return filepath.Join(s.m.dir, "sast_sources") }

// registerSastSource writes/updates a registry entry (and its result when scanned).
func (s *Server) registerSastSource(src sastSource) {
	dir := filepath.Join(s.sastSourcesRoot(), src.ID)
	_ = os.MkdirAll(dir, 0o755)
	b, _ := json.MarshalIndent(src, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o644)
}

// listSastSources reads all registry entries (newest first).
func (s *Server) listSastSources() []sastSource {
	entries, _ := os.ReadDir(s.sastSourcesRoot())
	var out []sastSource
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.sastSourcesRoot(), e.Name(), "meta.json"))
		if err != nil {
			continue
		}
		var src sastSource
		if json.Unmarshal(b, &src) == nil && src.ID != "" {
			out = append(out, src)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out
}

// sastScan handles POST /api/sast/scan. With a raw .zip body it extracts into the shared
// registry (persisted, so the graph upload is available to new-task too), scans it, caches
// the result, and returns the orchestrator JSON. With ?id=<registry id> it re-scans an
// already-registered source (e.g. one uploaded in new-task) without a new upload.
func (s *Server) sastScan(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	var src string
	var entry sastSource
	if id != "" {
		if strings.ContainsAny(id, "/\\.") {
			writeErr(w, 400, "invalid source id")
			return
		}
		found := false
		for _, e := range s.listSastSources() {
			if e.ID == id {
				entry, found = e, true
				break
			}
		}
		if !found {
			writeErr(w, 404, "source not found")
			return
		}
		src = entry.Path
	} else {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sastMaxZip))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "upload too large (max 80MB)")
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			name = "upload"
		}
		entry = sastSource{ID: "g" + strconv.FormatInt(time.Now().UnixNano(), 36), Name: name,
			Created: time.Now().Unix(), Origin: "graph"}
		src = filepath.Join(s.sastSourcesRoot(), entry.ID, "src")
		_ = os.MkdirAll(src, 0o755)
		if err := sastUnzip(body, src); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		entry.Path = src
		entry.Files = countSourceFiles(src)
	}
	py := detectPython()
	if py == "" {
		writeErr(w, 500, "python interpreter not found")
		return
	}
	out := filepath.Join(s.sastSourcesRoot(), entry.ID, "result.json")
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py,
		filepath.Join(sastRoot, "agent_c", "orchestrator.py"), src,
		"--db", filepath.Join(sastRoot, "taint_spec.db"),
		"--json", out, "--multi")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		writeErr(w, 500, "scan failed: "+sastTail(stderr.String(), 500))
		return
	}
	b, err := os.ReadFile(out)
	if err != nil {
		writeErr(w, 500, "no result produced")
		return
	}
	entry.HasResult = true
	s.registerSastSource(entry) // persist + make visible to new-task
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Sast-Source-Id", entry.ID)
	_, _ = w.Write(b)
}

// sastAgentFindings handles GET /api/sast/agent-findings?id=<registry id>: it returns the
// source→sink findings the review AGENT added during task runs (sast_add_flow wrote them to
// "<source path>/.sast_agent_findings.jsonl"). The graph/upload pages overlay these on the SAST
// graph so a vulnerability found while running a task shows up for that source.
func (s *Server) sastAgentFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" || strings.ContainsAny(id, "/\\.") {
		writeErr(w, 400, "invalid source id")
		return
	}
	var path string
	for _, e := range s.listSastSources() {
		if e.ID == id {
			path = filepath.Join(e.Path, ".sast_agent_findings.jsonl")
			break
		}
	}
	out := []map[string]any{}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var m map[string]any
				if json.Unmarshal([]byte(line), &m) == nil {
					out = append(out, m)
				}
			}
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"findings": out})
}

// sastSourceRoot is one candidate source the user can pick to review.
type sastSourceRoot struct {
	Path   string `json:"path"`   // absolute on-disk path (what the review targets)
	Name   string `json:"name"`   // display name (relative to the draft dir)
	Marker string `json:"marker"` // the project marker that identified it (or "files")
	Files  int    `json:"files"`  // source-file count under it (bounded)
}

// projectMarkers identify a source root (a buildable/reviewable project).
var projectMarkers = map[string]string{
	"package.json": "node", "pom.xml": "maven", "build.gradle": "gradle",
	"build.gradle.kts": "gradle", "go.mod": "go", "composer.json": "php",
	"requirements.txt": "python", "pyproject.toml": "python", "setup.py": "python",
	"Gemfile": "ruby", "Cargo.toml": "rust", "manage.py": "django",
	"artisan": "laravel", "pom.yml": "maven", "mix.exs": "elixir",
}

// sastDraftSources handles GET /api/sast/sources?draft=<id>: it stages the draft's
// uploads (extracting any .zip once), discovers candidate SOURCE ROOTS (dirs with a
// project marker, else top-level dirs / loose files), and returns them so the new-task
// UI can let the user CHOOSE which uploaded source to review.
func (s *Server) sastDraftSources(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	draft := strings.TrimSpace(r.URL.Query().Get("draft"))
	// No draft → just return the SHARED registry (every source uploaded anywhere). This is
	// what the new-task picker and the graph page both call to list available sources.
	if draft == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"sources": []sastSourceRoot{}, "registry": s.listSastSources()})
		return
	}
	if strings.ContainsAny(draft, "/\\.") {
		writeErr(w, 400, "invalid draft id")
		return
	}
	base := filepath.Join(s.m.dir, "drafts", draft)
	uploads := filepath.Join(base, "uploads")
	if fi, err := os.Stat(uploads); err != nil || !fi.IsDir() {
		_ = json.NewEncoder(w).Encode(map[string]any{"sources": []sastSourceRoot{}})
		return
	}
	srcDir := filepath.Join(base, "src")
	// extract any uploaded .zip once (into src/<zipname>/)
	entries, _ := os.ReadDir(uploads)
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".zip") {
			continue
		}
		dest := filepath.Join(srcDir, strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())))
		if _, err := os.Stat(dest); err == nil {
			continue // already extracted
		}
		data, err := os.ReadFile(filepath.Join(uploads, e.Name()))
		if err != nil {
			continue
		}
		_ = os.MkdirAll(dest, 0o755)
		_ = sastUnzip(data, dest) // zip-slip/symlink/size guarded
	}
	roots := discoverSourceRoots(base, uploads, srcDir)
	// Register each discovered root into the SHARED registry (stable id from its path, so
	// re-detection updates rather than duplicates) — this makes a new-task upload show up at
	// the graph page too. Keep a registry entry only if it is not already there.
	existing := map[string]bool{}
	for _, e := range s.listSastSources() {
		existing[e.Path] = true
	}
	for _, rt := range roots {
		if existing[rt.Path] {
			continue
		}
		id := "t" + strconv.FormatUint(fnvHash(rt.Path), 36)
		s.registerSastSource(sastSource{ID: id, Name: rt.Name, Path: rt.Path, Files: rt.Files,
			Created: time.Now().Unix(), Origin: "task"})
	}
	// Return the just-detected draft roots PLUS the whole shared registry, so the picker
	// shows both this upload's roots and anything uploaded elsewhere (graph page included).
	_ = json.NewEncoder(w).Encode(map[string]any{"sources": roots, "registry": s.listSastSources()})
}

// fnvHash is a small stable hash for deriving a registry id from a path.
func fnvHash(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// discoverSourceRoots finds candidate source roots under the draft's uploads/src dirs.
func discoverSourceRoots(base, uploads, srcDir string) []sastSourceRoot {
	seen := map[string]sastSourceRoot{}
	addMarkered := func(root string) {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d == nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "vendor", ".svn", "dist", "build", "__pycache__", ".next", "target":
					return filepath.SkipDir
				}
				return nil
			}
			if marker, ok := projectMarkers[d.Name()]; ok {
				dir := filepath.Dir(p)
				if _, dup := seen[dir]; !dup {
					seen[dir] = sastSourceRoot{Path: dir, Name: relOr(base, dir), Marker: marker, Files: countSourceFiles(dir)}
				}
			}
			return nil
		})
	}
	// PRIMARY candidate = the WHOLE upload (review everything). Each top-level extracted
	// directory in src/ is an entire uploaded project; if the user dropped loose files (no
	// zip), the uploads dir itself is the whole source. This is listed FIRST and is what the
	// user almost always wants — "review all of what I uploaded", not a nested sub-folder.
	whole := map[string]bool{}
	if subs, _ := os.ReadDir(srcDir); len(subs) > 0 {
		for _, sd := range subs {
			if sd.IsDir() {
				p := filepath.Join(srcDir, sd.Name())
				if n := countSourceFiles(p); n > 0 {
					seen[p] = sastSourceRoot{Path: p, Name: relOr(base, p) + "  (whole upload)", Marker: "whole", Files: n}
					whole[p] = true
				}
			}
		}
	}
	if n := countSourceFilesShallow(uploads); n > 0 { // loose source files directly in uploads
		seen[uploads] = sastSourceRoot{Path: uploads, Name: "uploads  (whole upload)", Marker: "whole", Files: countSourceFiles(uploads)}
		whole[uploads] = true
	}
	// SECONDARY candidates = detected sub-projects (project markers), offered ONLY as a way
	// to NARROW a monorepo. They never REPLACE the whole-upload root above.
	for _, root := range []string{srcDir, uploads} {
		if fi, err := os.Stat(root); err == nil && fi.IsDir() {
			addMarkered(root)
		}
	}
	out := make([]sastSourceRoot, 0, len(seen))
	for _, v := range seen {
		if v.Files > 0 {
			out = append(out, v)
		}
	}
	// whole-upload roots first (most files, the default), then sub-projects.
	sort.Slice(out, func(i, j int) bool {
		wi, wj := whole[out[i].Path], whole[out[j].Path]
		if wi != wj {
			return wi
		}
		return out[i].Files > out[j].Files
	})
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// countSourceFilesShallow counts source files directly in a dir (not recursing) — used to
// detect loose source dropped without a zip.
func countSourceFilesShallow(dir string) int {
	entries, _ := os.ReadDir(dir)
	n := 0
	for _, e := range entries {
		if !e.IsDir() && sastSourceExt[strings.ToLower(filepath.Ext(e.Name()))] {
			n++
		}
	}
	return n
}

var sastSourceExt = map[string]bool{
	".php": true, ".py": true, ".java": true, ".js": true, ".jsx": true, ".ts": true,
	".tsx": true, ".go": true, ".rb": true, ".cs": true, ".cpp": true, ".c": true,
	".h": true, ".kt": true, ".swift": true, ".rs": true, ".vb": true, ".pl": true,
	".m": true, ".scala": true, ".sql": true, ".blade.php": true, ".erb": true,
	".jsp": true, ".vue": true, ".twig": true,
}

func countSourceFiles(root string) int {
	n := 0
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".svn", "dist", "build", "__pycache__", ".next", "target":
				return filepath.SkipDir
			}
			return nil
		}
		if sastSourceExt[strings.ToLower(filepath.Ext(d.Name()))] {
			n++
			if n >= 100000 {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return n
}

func relOr(base, p string) string {
	if rel, err := filepath.Rel(base, p); err == nil {
		return rel
	}
	return p
}

func sastTail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// sastUnzip extracts a .zip safely (zip-slip / symlink / size guarded).
func sastUnzip(data []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return errSast("not a valid .zip")
	}
	destAbs, _ := filepath.Abs(dest)
	var total int64
	count := 0
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") || f.Mode()&os.ModeSymlink != 0 {
			continue
		}
		target := filepath.Join(dest, f.Name)
		ta, _ := filepath.Abs(target)
		if ta != destAbs && !strings.HasPrefix(ta, destAbs+string(os.PathSeparator)) {
			return errSast("unsafe path in zip: " + f.Name)
		}
		count++
		total += int64(f.UncompressedSize64)
		if count > 30000 {
			return errSast("too many files")
		}
		if total > sastMaxOut {
			return errSast("zip too large when extracted")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		o, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		_, cErr := io.Copy(o, io.LimitReader(rc, sastMaxOut))
		o.Close()
		rc.Close()
		if cErr != nil {
			return cErr
		}
	}
	return nil
}

type sastErr string

func (e sastErr) Error() string { return string(e) }
func errSast(s string) error    { return sastErr(s) }
