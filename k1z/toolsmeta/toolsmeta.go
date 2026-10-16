// Package toolsmeta is the full port of the Python tools.py registry and
// in-place update engine: gh_binary (GitHub release asset download), pip,
// git, rebuild_only, plus wordlist downloads. Catalog is generated
// (catalog_gen.go) from the original TOOLS/WORDLISTS lists — 1:1 parity.
package toolsmeta

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/store"
)

// Tool mirrors one entry of the Python TOOLS registry.
type Tool struct {
	Name       string
	Display    string
	Desc       string
	Cat        string // gh_binary | pip | git | rebuild_only
	Repo       string
	AssetGlobs []string
	AssetFmt   string // zip | tar | gz | zip_tar | binary | deb
	BinInArc   string
	Dest       string
	VersionCmd []string
	VersionRe  string
	PyPI       string
	GitDir     string
}

func (t Tool) Updatable() bool { return t.Cat != "rebuild_only" }

// destName is the binary name installed into /usr/local/bin.
func (t Tool) destName() string {
	if t.Dest != "" {
		return t.Dest
	}
	return t.Name
}

func (t Tool) binInArc() string {
	if t.BinInArc != "" {
		return t.BinInArc
	}
	return t.Name
}

// Wordlist mirrors one entry of the Python WORDLISTS registry.
type Wordlist struct {
	Name        string
	Display     string
	File        string
	URL         string
	Extract     string // "" | "tar"
	ExtractGlob string
}

// binDirPath returns the install directory (K1NZR3C0N_BIN_DIR override,
// default /usr/local/bin — Python parity).
func binDirPath() string {
	if v := os.Getenv("K1NZR3C0N_BIN_DIR"); v != "" {
		return v
	}
	return "/usr/local/bin"
}

func binDir() string { return binDirPath() }

var (
	ansiStripRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]|\r`)
	hexHashRe   = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
)

// All returns the full tool catalog.
func All() []Tool { return generatedTools }

// ByName returns the catalog entry for a tool name.
func ByName(name string) *Tool {
	for i := range generatedTools {
		if generatedTools[i].Name == name {
			return &generatedTools[i]
		}
	}
	return nil
}

// Wordlists returns the wordlist catalog.
func Wordlists() []Wordlist { return generatedWordlists }

// WordlistByName returns one wordlist entry.
func WordlistByName(name string) *Wordlist {
	for i := range generatedWordlists {
		if generatedWordlists[i].Name == name {
			return &generatedWordlists[i]
		}
	}
	return nil
}

// ── low-level helpers (ports of _sh / _ver / _download / _install) ──────────

func sh(cmd []string, timeout time.Duration) string {
	if len(cmd) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, _ := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	return ansiStripRe.ReplaceAllString(string(out), "")
}

func verExtract(output, pattern string) string {
	if pattern == "" {
		return strings.TrimSpace(output)
	}
	re, err := regexp.Compile("(?im)" + pattern)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return strings.TrimSpace(g)
		}
	}
	return strings.TrimSpace(m[0])
}

func download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "k1nzr3c0n-go/3")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = err
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// install atomically places src at /usr/local/bin/<destName> (rename swap —
// running processes keep the old inode; new executions get the new file).
func install(src, destName string) error {
	target := filepath.Join(binDir(), destName)
	tmp := target + ".__installing__"
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, target)
}

// ── GitHub / PyPI APIs ───────────────────────────────────────────────────────

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

func ghReleaseFetch(ctx context.Context, repo string) (*ghRelease, error) {
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "k1nzr3c0n-go/3")
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api %s: HTTP %d", repo, resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// ghAssetURL returns (version, downloadURL) for the first matching asset glob.
func ghAssetURL(ctx context.Context, t *Tool) (string, string, error) {
	rel, err := ghReleaseFetch(ctx, t.Repo)
	if err != nil {
		return "", "", err
	}
	ver := strings.TrimPrefix(rel.TagName, "v")
	for _, glob := range t.AssetGlobs {
		pat := strings.ReplaceAll(glob, "{ver}", ver)
		for _, a := range rel.Assets {
			if ok, _ := path.Match(pat, a.Name); ok {
				return ver, a.BrowserDownloadURL, nil
			}
		}
	}
	return "", "", fmt.Errorf("no matching asset in %s (globs %v)", t.Repo, t.AssetGlobs)
}

func ghLatest(ctx context.Context, repo string) string {
	rel, err := ghReleaseFetch(ctx, repo)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(rel.TagName, "v")
}

func gitHeadCommit(repo string) string {
	out := sh([]string{"git", "ls-remote", "https://github.com/" + repo, "HEAD"}, 20*time.Second)
	fields := strings.Fields(out)
	if len(fields) == 0 || len(fields[0]) < 7 {
		return ""
	}
	return fields[0][:7]
}

func pypiLatest(pkg string) string {
	resp, err := http.Get("https://pypi.org/pypi/" + pkg + "/json")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var v struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if json.NewDecoder(resp.Body).Decode(&v) != nil {
		return ""
	}
	return v.Info.Version
}

func pipVersion(pkg string) string {
	return verExtract(sh([]string{"pip3", "show", pkg}, 15*time.Second), `^Version:\s*([\d.a-z]+)`)
}

// ── archive extraction ──────────────────────────────────────────────────────

func extractZip(archive, binaryName, destName string) error {
	tmp, err := os.MkdirTemp("", "k1z-zip-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		out := filepath.Join(tmp, f.Name)
		os.MkdirAll(filepath.Dir(out), 0o755)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		dst, err := os.Create(out)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(dst, rc)
		dst.Close()
		rc.Close()
		if err != nil {
			return err
		}
		os.Chmod(out, 0o755)
	}
	return installFirstHit(tmp, binaryName, destName)
}

func extractTar(archive, binaryName, destName string) error {
	tmp, err := os.MkdirTemp("", "k1z-tar-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := untar(archive, tmp); err != nil {
		return err
	}
	return installFirstHit(tmp, binaryName, destName)
}

func untar(archive, destDir string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	var reader io.Reader = f
	if gz, err := gzip.NewReader(f); err == nil {
		defer gz.Close()
		reader = gz
	}
	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		out := filepath.Join(destDir, path.Clean(hdr.Name))
		if !strings.HasPrefix(out, filepath.Clean(destDir)) {
			continue // zip-slip style guard
		}
		os.MkdirAll(filepath.Dir(out), 0o755)
		dst, err := os.Create(out)
		if err != nil {
			return err
		}
		if _, err := io.Copy(dst, tr); err != nil {
			dst.Close()
			return err
		}
		dst.Close()
		os.Chmod(out, 0o755)
	}
}

func extractGz(archive, destName string) error {
	tmp, err := os.MkdirTemp("", "k1z-gz-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	in, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	outPath := filepath.Join(tmp, destName)
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, gz); err != nil {
		return err
	}
	os.Chmod(outPath, 0o755)
	return install(outPath, destName)
}

func extractZipTar(archive, binaryName, destName string) error {
	tmp, err := os.MkdirTemp("", "k1z-zt-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	var tarPath string
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() && (strings.HasSuffix(f.Name, ".tar.gz") || strings.HasSuffix(f.Name, ".tar")) {
			out := filepath.Join(tmp, f.Name)
			rc, err := f.Open()
			if err != nil {
				return err
			}
			dst, _ := os.Create(out)
			io.Copy(dst, rc)
			dst.Close()
			rc.Close()
			tarPath = out
			break
		}
	}
	if tarPath == "" {
		return fmt.Errorf("no tar inside %s", filepath.Base(archive))
	}
	if err := untar(tarPath, tmp); err != nil {
		return err
	}
	return installFirstHit(tmp, binaryName, destName)
}

// installFirstHit walks tmp for binaryName (or any extension-less file as a
// fallback) and installs it as destName.
func installFirstHit(tmp, binaryName, destName string) error {
	var hit string
	filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if hit == "" && d.Name() == binaryName {
			hit = p
		}
		return nil
	})
	if hit == "" { // fallback: any extension-less file
		filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || hit != "" {
				return nil
			}
			if !strings.Contains(d.Name(), ".") {
				hit = p
			}
			return nil
		})
	}
	if hit == "" {
		return fmt.Errorf("%s not found in archive", binaryName)
	}
	return install(hit, destName)
}

// ── version detection ────────────────────────────────────────────────────────

// InstalledVersion ports get_installed_version.
func InstalledVersion(t *Tool) string {
	switch t.Cat {
	case "pip":
		return pipVersion(t.PyPI)
	case "git":
		return strings.TrimSpace(sh([]string{"git", "-C", t.GitDir, "rev-parse", "--short", "HEAD"}, 10*time.Second))
	}
	if len(t.VersionCmd) == 0 {
		if _, err := os.Stat(filepath.Join(binDir(), t.destName())); err == nil {
			return "installed"
		}
		return ""
	}
	output := sh(t.VersionCmd, 10*time.Second)
	if strings.TrimSpace(output) == "" {
		return ""
	}
	if t.VersionRe == "" {
		return "installed"
	}
	if v := verExtract(output, t.VersionRe); v != "" {
		return v
	}
	return "installed" // installed, version undetectable
}

// LatestVersion ports get_latest_version.
func LatestVersion(ctx context.Context, t *Tool) string {
	switch t.Cat {
	case "gh_binary", "rebuild_only":
		if t.Repo == "" {
			return ""
		}
		return ghLatest(ctx, t.Repo)
	case "git":
		if t.Repo == "" {
			return ""
		}
		return gitHeadCommit(t.Repo)
	case "pip":
		return pypiLatest(t.PyPI)
	}
	return ""
}

// IsOutdated ports is_outdated: numeric tuple compare, hex hashes never dated.
func IsOutdated(installed, latest string) bool {
	if installed == "" || latest == "" || installed == "installed" || installed == "?" {
		return false
	}
	if hexHashRe.MatchString(installed) {
		return false
	}
	norm := func(v string) []int {
		v = strings.TrimPrefix(strings.SplitN(v, "-", 2)[0], "v")
		var out []int
		for _, part := range regexp.MustCompile(`[._]`).Split(v, -1) {
			if n, err := strconv.Atoi(part); err == nil {
				out = append(out, n)
			}
		}
		if len(out) == 0 {
			out = []int{0}
		}
		return out
	}
	li, ll := norm(installed), norm(latest)
	for i := 0; i < len(li) && i < len(ll); i++ {
		if ll[i] != li[i] {
			return ll[i] > li[i]
		}
	}
	return len(ll) > len(li)
}

// ── updates ─────────────────────────────────────────────────────────────────

// UpdateTool performs the in-place update and returns the new version string.
// Panic-safe: a panicking update seals the row as failed instead of killing
// the process.
func UpdateTool(st *store.Store, name string) {
	t := ByName(name)
	if t == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tools] update %s panicked: %v", name, r)
			msg := fmt.Sprintf("internal error: %v", r)
			_ = st.UpsertToolVersion(store.ToolVersion{Name: name, Status: "failed",
				ErrorMsg: &msg, LastCheckedAt: store.NowUTC()})
		}
	}()
	prev, _ := st.ListToolVersions()
	tv := store.ToolVersion{Name: name, Status: "updating", LastCheckedAt: store.NowUTC()}
	if p, ok := prev[name]; ok {
		tv.Installed = p.Installed
		tv.Latest = p.Latest
		tv.LatestURL = p.LatestURL
		tv.LastUpdatedAt = p.LastUpdatedAt
	}
	_ = st.UpsertToolVersion(tv)

	cachedVer := ""
	if tv.Latest != nil {
		cachedVer = *tv.Latest
	}
	ver, url, err := doUpdate(t, tv.LatestURL, cachedVer)
	errMsg := ""
	status := "ok"
	if err != nil {
		status = "failed"
		errMsg = err.Error()
		if len(errMsg) > 500 {
			errMsg = errMsg[:500]
		}
	} else {
		tv.Installed = &ver
		tv.Latest = &ver
		tv.LatestURL = url
		now := store.NowUTC()
		tv.LastUpdatedAt = now
		tv.LastCheckedAt = now
	}
	tv.Status = status
	tv.ErrorMsg = &errMsg
	_ = st.UpsertToolVersion(tv)
}

func doUpdate(t *Tool, cachedURL, cachedVer string) (string, string, error) {
	if t.Cat == "rebuild_only" {
		return "", "", fmt.Errorf("%s requires rebuild — cannot update in-place", t.Name)
	}
	if t.Cat == "gh_binary" {
		return updateGhBinary(t, cachedURL, cachedVer)
	}
	if t.Cat == "pip" {
		out, err := runPipUpgrade(t.PyPI)
		if err != nil {
			return "", "", err
		}
		if t.PyPI == "arjun" {
			refreshArjunWordlists()
		}
		v := pipVersion(t.PyPI)
		if v == "" {
			v = "?"
		}
		_ = out
		return v, "", nil
	}
	if t.Cat == "git" {
		out, err := exec.Command("git", "-C", t.GitDir, "pull", "--ff-only").CombinedOutput()
		if err != nil {
			return "", "", fmt.Errorf("%s", truncate(string(out), 400))
		}
		sha := strings.TrimSpace(sh([]string{"git", "-C", t.GitDir, "rev-parse", "--short", "HEAD"}, 10*time.Second))
		if sha == "" {
			sha = "?"
		}
		return sha, "", nil
	}
	return "", "", fmt.Errorf("unknown category %s", t.Cat)
}

func runPipUpgrade(pkg string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "pip3", "install", "--upgrade", pkg, "--break-system-packages").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s", truncate(string(out), 400))
	}
	return string(out), nil
}

func updateGhBinary(t *Tool, cachedURL, cachedVer string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ver, url := cachedVer, cachedURL
	var err error
	if ver == "" || url == "" {
		ver, url, err = ghAssetURL(ctx, t)
		if err != nil {
			return "", "", err
		}
	}
	tmp, err := os.MkdirTemp("", "k1z-dl-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(tmp)
	tmpFile := filepath.Join(tmp, "dl")
	if err := download(ctx, url, tmpFile); err != nil {
		return "", "", err
	}
	switch t.AssetFmt {
	case "zip":
		err = extractZip(tmpFile, t.binInArc(), t.destName())
	case "tar":
		err = extractTar(tmpFile, t.binInArc(), t.destName())
	case "gz":
		err = extractGz(tmpFile, t.destName())
	case "zip_tar":
		err = extractZipTar(tmpFile, t.binInArc(), t.destName())
	case "binary":
		os.Chmod(tmpFile, 0o755)
		err = install(tmpFile, t.destName())
	case "deb":
		deb := filepath.Join(tmp, "pkg.deb")
		if err := os.Rename(tmpFile, deb); err != nil {
			return "", "", err
		}
		out, err := exec.Command("dpkg", "-i", deb).CombinedOutput()
		if err != nil {
			return "", "", fmt.Errorf("%s", truncate(string(out), 300))
		}
	default:
		err = fmt.Errorf("unknown asset_fmt %s", t.AssetFmt)
	}
	if err != nil {
		return "", "", err
	}
	return ver, url, nil
}

func refreshArjunWordlists() {
	dirs := []string{"/usr/local/lib", "/usr/lib", "/usr/lib/python3/dist-packages", "/usr/local/bin"}
	for _, root := range dirs {
		for _, size := range []string{"medium", "large"} {
			src := filepath.Join(root, "arjun", "db", size+".txt")
			if _, err := os.Stat(src); err == nil {
				os.MkdirAll(config.WordlistsDir(), 0o755)
				_ = copyFile(src, filepath.Join(config.WordlistsDir(), "params-"+size+".txt"))
			}
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// UpdateWordlist re-downloads a wordlist; returns "<N> lines". Panic-safe.
func UpdateWordlist(st *store.Store, name string) {
	wl := WordlistByName(name)
	if wl == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tools] update wordlist %s panicked: %v", name, r)
			msg := fmt.Sprintf("internal error: %v", r)
			key := "wordlist:" + name
			_ = st.UpsertToolVersion(store.ToolVersion{Name: key, Status: "failed",
				ErrorMsg: &msg, LastCheckedAt: store.NowUTC()})
		}
	}()
	key := "wordlist:" + name
	prev, _ := st.ListToolVersions()
	tv := store.ToolVersion{Name: key, Status: "updating", LastCheckedAt: store.NowUTC()}
	if p, ok := prev[key]; ok {
		tv.Installed = p.Installed
	}
	_ = st.UpsertToolVersion(tv)

	errMsg := ""
	status := "ok"
	installed := ""
	if lines, err := downloadWordlist(wl); err != nil {
		status = "failed"
		errMsg = truncate(err.Error(), 500)
	} else {
		installed = fmt.Sprintf("%d lines", lines)
		tv.Installed = &installed
		now := store.NowUTC()
		tv.LastUpdatedAt = now
		tv.LastCheckedAt = now
	}
	tv.Status = status
	tv.ErrorMsg = &errMsg
	_ = st.UpsertToolVersion(tv)
}

func downloadWordlist(wl *Wordlist) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tmp, err := os.MkdirTemp("", "k1z-wl-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	tmpFile := filepath.Join(tmp, "dl")
	if err := download(ctx, wl.URL, tmpFile); err != nil {
		return 0, err
	}
	dest := filepath.Join(config.WordlistsDir(), wl.File)
	os.MkdirAll(config.WordlistsDir(), 0o755)
	if wl.Extract == "tar" {
		exDir := filepath.Join(tmp, "ex")
		os.MkdirAll(exDir, 0o755)
		if err := untar(tmpFile, exDir); err != nil {
			return 0, err
		}
		found := ""
		filepath.WalkDir(exDir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || found != "" {
				return nil
			}
			if ok, _ := path.Match(wl.ExtractGlob, d.Name()); ok || wl.ExtractGlob == "" || wl.ExtractGlob == "*" {
				found = p
			}
			return nil
		})
		if found == "" {
			return 0, fmt.Errorf("no %s in wordlist archive", wl.ExtractGlob)
		}
		if err := copyFile(found, dest); err != nil {
			return 0, err
		}
	} else if err := copyFile(tmpFile, dest); err != nil {
		return 0, err
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		return 0, err
	}
	return strings.Count(string(data), "\n") + boolToInt(!strings.HasSuffix(string(data), "\n") && len(data) > 0), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ── version check (ports check_tool_versions) ────────────────────────────────

// CheckVersions refreshes installed/latest for all tools + wordlists.
// Concurrency 5 — mirrors the anonymous GitHub rate-limit caution.
func CheckVersions(st *store.Store) {
	type result struct {
		name      string
		installed string
		latest    string
		url       string
		status    string
	}
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []result

	run := func(fn func() result) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					results = append(results, result{name: fmt.Sprint(r), status: "check_failed"})
					mu.Unlock()
				}
			}()
			mu.Lock()
			results = append(results, fn())
			mu.Unlock()
		}()
	}

	for i := range generatedTools {
		t := &generatedTools[i]
		run(func() result {
			installed := InstalledVersion(t)
			if t.Cat == "rebuild_only" {
				return result{t.Name, installed, "", "", "rebuild_only"}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			latest, url := "", ""
			if t.Cat == "gh_binary" {
				if v, u, err := ghAssetURL(ctx, t); err == nil {
					latest, url = v, u
				}
			} else {
				latest = LatestVersion(ctx, t)
			}
			status := ""
			switch {
			case installed == "":
				status = "unknown"
			case latest == "":
				status = "check_failed"
			case IsOutdated(installed, latest):
				status = "outdated"
			default:
				status = "ok"
			}
			return result{t.Name, installed, latest, url, status}
		})
	}
	for i := range generatedWordlists {
		wl := &generatedWordlists[i]
		run(func() result {
			name := "wordlist:" + wl.Name
			path := filepath.Join(config.WordlistsDir(), wl.File)
			if fi, err := os.Stat(path); err == nil {
				lines := countLines(path, fi.Size())
				return result{name, fmt.Sprintf("%d lines", lines), "", "", "ok"}
			}
			return result{name, "", "", "", "unknown"}
		})
	}
	wg.Wait()

	prev, _ := st.ListToolVersions()
	for _, r := range results {
		tv := store.ToolVersion{Name: r.name, Status: r.status, LastCheckedAt: store.NowUTC()}
		if p, ok := prev[r.name]; ok {
			// preserve in-progress updates entirely
			if p.Status == "updating" {
				continue
			}
			tv.Installed = p.Installed
			tv.Latest = p.Latest
			tv.LatestURL = p.LatestURL
			tv.LastUpdatedAt = p.LastUpdatedAt
			tv.ErrorMsg = p.ErrorMsg
		}
		if r.installed != "" {
			fresh := r.installed
			// DB version wins over a lower binary self-report (upstream
			// sometimes embeds the previous version string after a bump).
			if tv.Installed != nil && *tv.Installed != "" && IsOutdated(fresh, *tv.Installed) {
				// keep the higher recorded version
			} else {
				tv.Installed = &fresh
			}
		}
		if r.latest != "" {
			latest := r.latest
			tv.Latest = &latest
		}
		if r.url != "" {
			tv.LatestURL = r.url
		}
		_ = st.UpsertToolVersion(tv)
	}
}

func countLines(path string, size int64) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	buf := make([]byte, 64*1024)
	last := byte('\n')
	for {
		c, err := f.Read(buf)
		for i := 0; i < c; i++ {
			if buf[i] == '\n' {
				n++
			}
			last = buf[i]
		}
		if err != nil {
			break
		}
	}
	if last != '\n' {
		n++
	}
	return n
}

// ── inventory (GET /tools response) ─────────────────────────────────────────

type ToolRow struct {
	Name          string  `json:"name"`
	Display       string  `json:"display"`
	Desc          string  `json:"desc"`
	Cat           string  `json:"cat"`
	Updatable     bool    `json:"updatable"`
	Installed     *string `json:"installed"`
	Latest        *string `json:"latest"`
	Outdated      bool    `json:"outdated"`
	Status        string  `json:"status"`
	LastCheckedAt any     `json:"last_checked_at"`
	LastUpdatedAt any     `json:"last_updated_at"`
	ErrorMsg      *string `json:"error_msg"`
}

type WordlistRow struct {
	Name          string  `json:"name"`
	Display       string  `json:"display"`
	File          string  `json:"file"`
	Installed     *string `json:"installed"`
	Status        string  `json:"status"`
	LastCheckedAt any     `json:"last_checked_at"`
	LastUpdatedAt any     `json:"last_updated_at"`
	ErrorMsg      *string `json:"error_msg"`
}

// Inventory returns the /tools response using DB rows + live presence check.
func Inventory(st *store.Store) map[string]any {
	dbRows, _ := st.ListToolVersions()
	tools := []ToolRow{}
	wordlists := []WordlistRow{}
	outdatedN, failedN := 0, 0

	for i := range generatedTools {
		t := &generatedTools[i]
		row := ToolRow{
			Name: t.Name, Display: t.Display, Desc: t.Desc, Cat: t.Cat,
			Updatable: t.Updatable(), Status: "unknown",
		}
		if tv, ok := dbRows[t.Name]; ok {
			row.Installed = tv.Installed
			row.Latest = tv.Latest
			row.Status = tv.Status
			row.LastCheckedAt = isoOr(tv.LastCheckedAt)
			row.LastUpdatedAt = isoOr(tv.LastUpdatedAt)
			row.ErrorMsg = tv.ErrorMsg
			if tv.Status == "outdated" {
				row.Outdated = true
				outdatedN++
			}
			// live computation too (DB status may be stale pre-check)
			if !row.Outdated && tv.Installed != nil && tv.Latest != nil &&
				IsOutdated(*tv.Installed, *tv.Latest) {
				row.Outdated = true
				if tv.Status == "ok" {
					outdatedN++
				}
			}
			if tv.Status == "check_failed" || tv.Status == "failed" {
				failedN++
			}
		}
		tools = append(tools, row)
	}
	for i := range generatedWordlists {
		wl := &generatedWordlists[i]
		key := "wordlist:" + wl.Name
		row := WordlistRow{
			Name: wl.Name, Display: wl.Display, File: wl.File, Status: "unknown",
		}
		if tv, ok := dbRows[key]; ok {
			row.Installed = tv.Installed
			row.Status = tv.Status
			row.LastCheckedAt = isoOr(tv.LastCheckedAt)
			row.LastUpdatedAt = isoOr(tv.LastUpdatedAt)
			row.ErrorMsg = tv.ErrorMsg
		} else if fi, err := os.Stat(filepath.Join(config.WordlistsDir(), wl.File)); err == nil {
			lines := countLines(filepath.Join(config.WordlistsDir(), wl.File), fi.Size())
			s := fmt.Sprintf("%d lines", lines)
			row.Installed = &s
			row.Status = "ok"
		}
		wordlists = append(wordlists, row)
	}
	return map[string]any{
		"tools":              tools,
		"wordlists":          wordlists,
		"outdated_count":     outdatedN,
		"check_failed_count": failedN,
		"warning":            "Updates applied in-place. Restart k1nzr3c0n-worker to pick up changes: systemctl restart k1nzr3c0n-worker",
	}
}

func isoOr(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return store.FmtTime(t)
}

// SortedToolNames returns catalog names sorted (for deterministic dispatch).
func SortedToolNames() []string {
	names := make([]string, 0, len(generatedTools))
	for i := range generatedTools {
		names = append(names, generatedTools[i].Name)
	}
	sort.Strings(names)
	return names
}

// NucleiTemplateUpdate runs `nuclei -ut` (daily beat job, timeout 30m).
func NucleiTemplateUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nuclei", "-ut").CombinedOutput()
	if err != nil {
		log.Printf("[tools] nuclei -ut failed: %v: %s", err, truncate(string(out), 200))
	}
}

var _ = driver.IsValue
