// Package selfupdate implements ARTEX's one-click, in-page update: it pulls
// the new binary from a GitHub Release, verifies and stages it, and performs
// an atomic swap on the next startup.
//
// Overall division of labor (see start.sh / start.bat):
//
//	startup script = a dumb daemon loop, responsible only for "deciding whether to relaunch after the process exits, based on the exit code"
//	this package   = all the error-prone logic (download / SHA256 verification / smoke test / swap / rollback on failure)
//
// The swap lives in Go rather than in the scripts because the sha256
// verification and smoke test would have to be written twice, for sh and bat
// (sha256sum / shasum / certutil), and this is exactly the part that can least
// afford a mistake -- install a binary that won't run and the daemon will
// faithfully relaunch it over and over, leaving the user to rescue it by hand
// on the machine.
//
// A full upgrade goes through three process startups:
//
//	(1) old server receives /api/update/apply -> download and verify -> stage artex.new -> exit 75
//	(2) script relaunches the old version -> Bootstrap finds artex.new -> verify+smoke -> swap -> exit 75
//	(3) script relaunches, now the new version -> Bootstrap records one attempt -> clears the marker after a successful start
//
// Any failed step reverts to the old version: in (2) a failed verification
// deletes the staged binary and keeps running the old version; in (3) failing
// 3 times in a row to survive long enough to clear the marker (crashing before
// it can) automatically swaps artex.old back in.
package selfupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ExitRestart is the "please, daemon, relaunch me" exit code (EX_TEMPFAIL).
// When the startup script sees it, it reruns immediately and does not count it
// toward crash backoff. 0 means the user stopped normally (the script exits
// the loop); everything else is treated as a crash.
const ExitRestart = 75

// maxAttempts is the number of startup attempts allowed after a swap. Each
// startup of the new version bumps the count by 1; surviving settleDelay
// clears the marker; crashing maxAttempts times in a row means the new version
// simply won't start, triggering an auto-rollback.
const maxAttempts = 3

// Paths is every file involved in one upgrade, all kept under the
// **directory that holds the executable**. CWD is deliberately not used: when
// running as a service the working directory may be / or any path, and using
// CWD would drop the staged binary elsewhere, breaking the swap logic outright.
type Paths struct {
	Dir     string // directory holding the executable
	Current string // currently running binary        artex      / artex.exe
	New     string // staged new version              artex.new  / artex.new.exe
	Sum     string // new version's sha256 (hex)       artex.new.sha256 / artex.new.exe.sha256
	Old     string // old version backed up before the swap      artex.old  / artex.old.exe
	Marker  string // upgrade status marker            artex.upgrade.json
}

// ResolvePaths derives all upgrade paths from the current executable.
//
// On Windows .new/.old must also carry the .exe suffix, otherwise the smoke
// test and the post-swap execution both fail, so we strip the suffix first and
// then reassemble, making the naming symmetric across both platforms.
func ResolvePaths() (Paths, error) {
	exe, err := os.Executable()
	if err != nil {
		return Paths{}, fmt.Errorf("locating executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	name := filepath.Base(exe)
	ext := filepath.Ext(name) // ".exe" on Windows, usually empty on Unix
	stem := strings.TrimSuffix(name, ext)

	join := func(suffix string) string { return filepath.Join(dir, stem+suffix+ext) }
	return Paths{
		Dir:     dir,
		Current: exe,
		New:     join(".new"),
		Sum:     join(".new") + ".sha256",
		Old:     join(".old"),
		Marker:  filepath.Join(dir, stem+".upgrade.json"),
	}, nil
}

// marker records the progress of one swap, used to trigger an auto-rollback
// when the new version won't start.
type marker struct {
	From     string `json:"from"`     // version before the upgrade
	To       string `json:"to"`       // target version
	Attempts int    `json:"attempts"` // number of startup attempts since the swap
	StagedAt int64  `json:"staged_at"`
}

func readMarker(path string) (marker, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return marker{}, false
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		return marker{}, false
	}
	return m, true
}

func writeMarker(path string, m marker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// cleanStaged removes the staged binary. A successful swap, a failed
// verification, and a user cancellation all go through it, to avoid a leftover
// artex.new being retried on the next startup.
func cleanStaged(p Paths) {
	_ = os.Remove(p.New)
	_ = os.Remove(p.Sum)
}

// CompareVersions compares two version numbers, returning -1/0/1 (a<b / a==b /
// a>b). ok=false means at least one side is not a comparable version number
// (for example a local dev build's "dev", or a git describe output like
// "0.3.7-2-gabc1234-dirty"), in which case the caller should disable one-click
// update, otherwise an in-progress dev build would be "upgraded" to a stable
// release, overwriting uncommitted changes.
func CompareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range 3 {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion parses a version number of the form "v0.3.7" / "0.3.7" into a
// [3]int.
//
// It only accepts a clean three-part form: on non-tag builds build.sh uses git
// describe to produce suffixed versions like "0.3.7-2-gabc1234", which must be
// judged non-comparable rather than treated as 0.3.7 -- otherwise a dev build
// would be misjudged as "already the latest" or overwritten by a stable
// release.
func parseVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// InDocker reports whether the process is running inside a container. Under
// Docker the swap writes to the container's writable layer, and
// `docker compose up -d` rebuilding the container reverts to the version
// baked into the image -- this is expected behavior (at that point the user is
// pulling a new image anyway), but the frontend needs to be able to explain it
// clearly on that basis.
func InDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "containerd")
}
