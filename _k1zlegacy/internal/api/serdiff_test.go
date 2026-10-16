package api

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	"k1nzr3c0n/internal/store"
)

func TestSerializerDifferential(t *testing.T) {
	if os.Getenv("K1Z_DIFF") == "" {
		t.Skip("set K1Z_DIFF=1")
	}
	st, err := store.Open("/tmp/opencode/serdiff/runs/k1nzr3c0n.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pyRaw, err := os.ReadFile("/tmp/opencode/serdiff/py_ser.json")
	if err != nil {
		t.Skip("no python serializer output")
	}
	var py map[string]map[string]any
	if json.Unmarshal(pyRaw, &py) != nil {
		t.Fatal("bad json")
	}

	cmp := func(name string, got map[string]any) {
		t.Run(name, func(t *testing.T) {
			want := py[name]
			if want == nil {
				t.Skip("python side missing")
			}
			var keys []string
			for k := range want {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				gv, gok := got[k]
				wv := want[k]
				// datetimes: compare presence + rough shape, not exact ticks
				if k == "created_at" || k == "updated_at" || k == "last_run_at" || k == "next_run_at" || k == "first_seen" ||
					k == "started_at" || k == "finished_at" || k == "paused_at" {
					if (gv == nil) != (wv == nil) {
						t.Errorf("%s.%s null-mismatch: go=%v py=%v", name, k, gv, wv)
					}
					continue
				}
				if !gok {
					t.Errorf("%s.%s MISSING in Go serializer", name, k)
					continue
				}
				gb, _ := json.Marshal(gv)
				wb, _ := json.Marshal(wv)
				if string(gb) != string(wb) {
					t.Errorf("%s.%s: go=%s py=%s", name, k, gb, wb)
				}
			}
			// keys present in Go but not Python
			for k := range got {
				if _, ok := want[k]; !ok {
					t.Errorf("%s.%s EXTRA in Go serializer", name, k)
				}
			}
		})
	}

	runs, _, _ := st.ListRuns(store.RunFilter{Limit: 1})
	if len(runs) > 0 {
		b, _ := json.Marshal(runToDict(runs[0]))
		var m map[string]any
		json.Unmarshal(b, &m)
		cmp("run", m)
	}
	if f, err := st.GetFinding(1); err == nil { // same row as python (first by id)
		b, _ := json.Marshal(findingToDict(f))
		var m map[string]any
		json.Unmarshal(b, &m)
		cmp("finding", m)
	}
	scs, _ := st.ListSchedules()
	if len(scs) > 0 {
		b, _ := json.Marshal(scheduleToDict(scs[len(scs)-1]))
		var m map[string]any
		json.Unmarshal(b, &m)
		cmp("schedule", m)
	}
	tgs, _ := st.ListTargets()
	if len(tgs) > 0 {
		b, _ := json.Marshal(targetToDict(tgs[0]))
		var m map[string]any
		json.Unmarshal(b, &m)
		cmp("target", m)
	}
	nas, _ := st.ListNewAssetsByRun(runs[0].ID)
	if len(nas) > 0 {
		first := nas[0]
		for _, n := range nas { // python takes lowest id
			if n.ID < first.ID {
				first = n
			}
		}
		b, _ := json.Marshal(newAssetToDict(first))
		var m map[string]any
		json.Unmarshal(b, &m)
		cmp("new_asset", m)
	}
}
