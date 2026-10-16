package db

import "testing"

func TestOllamaProfileRoundTripAndKeylessPool(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	p := &LLMProfile{Name: "t-native-ollama", Format: "ollama", Model: "qwen3:4b", BaseURL: "http://127.0.0.1:11434", KeepAlive: "45m", MaxConcurrent: 2, Streaming: true, ContextWindowK: 32}
	id, err := d.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = id
	t.Cleanup(func() { d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	check := func() {
		t.Helper()
		got, err := d.ProfileByID(id)
		if err != nil || got == nil {
			t.Fatalf("read=%+v err=%v", got, err)
		}
		if got.KeepAlive != p.KeepAlive || got.MaxConcurrent != p.MaxConcurrent || got.APIKey != p.APIKey {
			t.Fatalf("profile=%+v", got)
		}
	}
	check()
	p.KeepAlive = "1h"
	p.MaxConcurrent = 3
	if _, err = d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	check()
	p.APIKey = "bearer-token"
	if _, err = d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	check()
	ps, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range ps {
		found = found || v.ID == id
	}
	if !found {
		t.Fatal("native profile absent from pool")
	}
}
func TestChangingCloudProfileToOllamaDoesNotInheritKey(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	p := &LLMProfile{Name: "t-cloud-to-native", Format: "openai", Model: "m", APIKey: "cloud-secret"}
	id, err := d.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = id
	t.Cleanup(func() { d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	p.Format = "ollama"
	p.APIKey = ""
	if _, err = d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	got, err := d.ProfileByID(id)
	if err != nil || got.APIKey != "" {
		t.Fatalf("inherited key=%q err=%v", got.APIKey, err)
	}
	ps, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range ps {
		if v.ID == id {
			return
		}
	}
	t.Fatal("keyless native profile excluded")
}

func TestPoolProfilesIncludesKeylessLocalCompatibilityOnly(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ids := map[int64]bool{}
	for _, p := range []*LLMProfile{
		{Name: "t-pool-keyless-loopback", Format: "openai", Model: "local", BaseURL: "http://127.0.0.1:1234/v1"},
		{Name: "t-pool-keyless-private", Format: "openai-responses", Model: "local", BaseURL: "http://192.168.1.4:1234/v1"},
		{Name: "t-pool-keyless-public", Format: "openai", Model: "public", BaseURL: "http://192.0.2.1/v1"},
		{Name: "t-pool-keyless-default", Format: "anthropic", Model: "public"},
	} {
		id, err := d.SaveProfile(p)
		if err != nil {
			t.Fatal(err)
		}
		ids[id] = p.Model == "local"
		t.Cleanup(func() { d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	}
	ps, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	found := map[int64]bool{}
	for _, p := range ps {
		found[p.ID] = true
	}
	for id, want := range ids {
		if found[id] != want {
			t.Fatalf("profile %d included=%v want=%v", id, found[id], want)
		}
	}
}

func TestNativeProfileBlankEditPreservesOptionalBearerToken(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	p := &LLMProfile{Name: "t-native-optional-bearer", Format: "ollama", Model: "local", APIKey: "lan-bearer-secret"}
	id, err := d.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = id
	t.Cleanup(func() { d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	p.APIKey = ""
	p.KeepAlive = "1h"
	if _, err = d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	got, err := d.ProfileByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.APIKey != "lan-bearer-secret" || got.KeepAlive != "1h" {
		t.Fatalf("blank native edit lost stored token or changed options: %+v", got)
	}
	list, err := d.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range list {
		if v.ID == id {
			if v.APIKeyHint != "…cret" {
				t.Fatalf("stored token hint=%q", v.APIKeyHint)
			}
			return
		}
	}
	t.Fatal("native profile missing")
}
