package store

import "testing"

func TestParseTimeRoundTrip(t *testing.T) {
	s := SqlTime(NowUTC())
	ts := ParseTime(s.(string))
	if ts.IsZero() {
		t.Fatalf("ParseTime(%q) = zero", s)
	}
}

func TestTargetRoundTrip(t *testing.T) {
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateTarget(&Target{Name: "x.com", ScopeJSON: "[]", Mode: "bounty"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetTarget("x.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("CreatedAt zero after round trip")
	}
}
