package workflow

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDumpGoTopo(t *testing.T) {
	if os.Getenv("K1Z_DIFF") == "" {
		t.Skip("set K1Z_DIFF=1")
	}
	out := map[string]any{}
	for _, name := range []string{"01-full-recon-pipeline.yaml", "02-full-recon-artex.yaml", "03-js-secrets-recon.yaml", "04-param-discovery.yaml"} {
		wf, err := Load("/mnt/c/Users/kin/Downloads/k1nzr3c0n-go/workflows/" + name)
		if err != nil {
			t.Fatal(err)
		}
		order, _ := TopologicalOrder(wf.Steps)
		levels, _ := ExecutionLevels(wf.Steps)
		var orderIDs []string
		for _, s := range order {
			orderIDs = append(orderIDs, s.ID)
		}
		var levelIDs [][]string
		for _, l := range levels {
			var ids []string
			for _, s := range l {
				ids = append(ids, s.ID)
			}
			levelIDs = append(levelIDs, ids)
		}
		out[name] = map[string]any{"order": orderIDs, "levels": levelIDs}
	}
	b, _ := json.Marshal(out)
	os.WriteFile("/tmp/opencode/go_topo.json", b, 0o644)
}
