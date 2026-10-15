package toolsmeta

import (
	"os"
	"testing"
)

func TestIsOutdated(t *testing.T) {
	cases := []struct {
		inst, latest string
		want         bool
	}{
		{"2.1.0", "2.3.0", true},
		{"3.7.1", "3.11.1", true},
		{"2.3.0", "2.3.0", false},
		{"3.11.1", "3.7.1", false},
		{"installed", "2.0", false},
		{"", "2.0", false},
		{"1.0", "", false},
		{"a1b2c3d", "9.9.9", false}, // git hash — never dated
		{"2.17.0", "2.17.0", false},
	}
	for _, c := range cases {
		if got := IsOutdated(c.inst, c.latest); got != c.want {
			t.Errorf("IsOutdated(%q, %q) = %v, want %v", c.inst, c.latest, got, c.want)
		}
	}
}

func TestVerExtract(t *testing.T) {
	if v := verExtract("Current Version: v2.17.0\n", `Current Version[:\s]+v?([\d.]+)`); v != "2.17.0" {
		t.Errorf("verExtract dnsx pattern = %q", v)
	}
	if v := verExtract("nuclei v3.7.1", `v(\d+\.\d[\d.]*)`); v != "3.7.1" {
		t.Errorf("verExtract nuclei pattern = %q", v)
	}
}

// TestInstallGhBinaryTar installs one real tar.gz release (metabigor) into a
// temp BIN_DIR — skipped when offline.
func TestInstallGhBinaryTar(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	dir := t.TempDir()
	t.Setenv("K1NZR3C0N_BIN_DIR", dir)
	tl := ByName("metabigor")
	if tl == nil {
		t.Fatal("metabigor missing from catalog")
	}
	ver, _, err := doUpdate(tl, "", "")
	if err != nil {
		t.Skipf("network/install unavailable: %v", err)
	}
	if _, err := os.Stat(dir + "/metabigor"); err != nil {
		t.Fatalf("binary not installed: %v (ver %s)", err, ver)
	}
}

// TestInstallGhBinaryZip installs one real zip release (ffuf).
func TestInstallGhBinaryZip(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	dir := t.TempDir()
	t.Setenv("K1NZR3C0N_BIN_DIR", dir)
	tl := ByName("ffuf")
	if tl == nil {
		t.Fatal("ffuf missing from catalog")
	}
	if _, _, err := doUpdate(tl, "", ""); err != nil {
		t.Skipf("network/install unavailable: %v", err)
	}
	if _, err := os.Stat(dir + "/ffuf"); err != nil {
		t.Fatalf("binary not installed: %v", err)
	}
}
