package api

import (
	"encoding/json"
	"os"
	"testing"
)

func TestKeysCatalogDifferential(t *testing.T) {
	if os.Getenv("K1Z_DIFF") == "" {
		t.Skip("set K1Z_DIFF=1")
	}
	data, err := os.ReadFile("/tmp/opencode/py_keys.json")
	if err != nil {
		t.Skip("no python keys")
	}
	var py []map[string]any
	if json.Unmarshal(data, &py) != nil {
		t.Fatal("bad json")
	}
	if len(py) != len(providers) {
		t.Fatalf("provider count: py=%d go=%d", len(py), len(providers))
	}
	mism := 0
	for i, p := range py {
		g := providers[i]
		b, _ := json.Marshal(g)
		var gm map[string]any
		json.Unmarshal(b, &gm)
		for k, pv := range p {
			gv, ok := gm[k]
			if !ok {
				t.Errorf("provider %s.%s missing in Go", p["id"], k)
				mism++
				continue
			}
			gb, _ := json.Marshal(gv)
			pb, _ := json.Marshal(pv)
			if string(gb) != string(pb) {
				t.Errorf("provider %s.%s: go=%s py=%s", p["id"], k, gb, pb)
				mism++
			}
		}
	}
	if mism == 0 {
		t.Logf("keys differential: %d providers field-identical", len(py))
	}
}
