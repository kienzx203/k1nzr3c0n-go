package toolsmeta

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCatalogDifferential(t *testing.T) {
	if os.Getenv("K1Z_DIFF") == "" {
		t.Skip("set K1Z_DIFF=1")
	}
	data, err := os.ReadFile("/tmp/opencode/tools_catalog.json")
	if err != nil {
		t.Skip("no python catalog")
	}
	var py struct {
		Tools     []map[string]any `json:"tools"`
		Wordlists []map[string]any `json:"wordlists"`
	}
	if json.Unmarshal(data, &py) != nil {
		t.Fatal("bad json")
	}
	if len(py.Tools) != len(All()) {
		t.Fatalf("tool count: py=%d go=%d", len(py.Tools), len(All()))
	}
	if len(py.Wordlists) != len(Wordlists()) {
		t.Fatalf("wordlist count: py=%d go=%d", len(py.Wordlists), len(Wordlists()))
	}
	mism := 0
	for i, pt := range py.Tools {
		gt := All()[i]
		str := func(k string) string {
			v, _ := pt[k].(string)
			return v
		}
		if gt.Name != str("name") || gt.Display != str("display") || gt.Desc != str("desc") ||
			gt.Cat != str("cat") || gt.Repo != str("repo") || gt.AssetFmt != str("asset_fmt") ||
			gt.BinInArc != str("bin_in_arc") || gt.Dest != str("dest") ||
			gt.PyPI != str("pypi") || gt.GitDir != str("git_dir") || gt.VersionRe != str("version_re") {
			t.Errorf("tool #%d (%s) field mismatch", i, gt.Name)
			mism++
		}
		pvc, _ := pt["version_cmd"].([]any)
		if len(pvc) != len(gt.VersionCmd) {
			t.Errorf("tool %s version_cmd len mismatch", gt.Name)
			mism++
		} else {
			for j := range pvc {
				if s, _ := pvc[j].(string); s != gt.VersionCmd[j] {
					t.Errorf("tool %s version_cmd[%d] mismatch", gt.Name, j)
					mism++
				}
			}
		}
		pg, _ := pt["asset_globs"].([]any)
		if len(pg) != len(gt.AssetGlobs) {
			t.Errorf("tool %s asset_globs len mismatch", gt.Name)
			mism++
		} else {
			for j := range pg {
				if s, _ := pg[j].(string); s != gt.AssetGlobs[j] {
					t.Errorf("tool %s asset_globs[%d] mismatch", gt.Name, j)
					mism++
				}
			}
		}
	}
	for i, pw := range py.Wordlists {
		gw := Wordlists()[i]
		str := func(k string) string { v, _ := pw[k].(string); return v }
		if gw.Name != str("name") || gw.Display != str("display") || gw.File != str("file") ||
			gw.URL != str("url") || gw.Extract != str("extract") || gw.ExtractGlob != str("extract_glob") {
			t.Errorf("wordlist #%d (%s) mismatch", i, gw.Name)
			mism++
		}
	}
	if mism == 0 {
		t.Logf("catalog differential: %d tools + %d wordlists field-identical", len(py.Tools), len(py.Wordlists))
	}
}
