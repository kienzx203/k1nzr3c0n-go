package store

import "testing"

func TestDebugRead(t *testing.T) {
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.CreateTarget(&Target{Name: "x.com", ScopeJSON: "[]", Mode: "bounty"})
	var created, updated any
	row := st.db.QueryRow(`SELECT created_at, updated_at FROM targets WHERE name = 'x.com'`)
	if err := row.Scan(&created, &updated); err != nil {
		t.Fatal("scan:", err)
	}
	t.Logf("created: %#v  updated: %#v", created, updated)
}
