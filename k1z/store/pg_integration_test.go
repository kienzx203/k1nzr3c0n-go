package store

// End-to-end test of the PostgreSQL path. It is skipped unless K1Z_PG_DSN points
// at a reachable PostgreSQL, so the normal test run (SQLite) is unaffected:
//
//	K1Z_PG_DSN='postgres://postgres:pw@127.0.0.1:55432/k1ztest?sslmode=disable' \
//	    go test ./k1z/store/ -run TestPostgresEndToEnd -v
//
// It exercises the constructs that differ from SQLite: IDENTITY inserts with
// RETURNING id, BOOLEAN round-trips, INSERT OR IGNORE -> ON CONFLICT DO NOTHING,
// the CURRENT_TIMESTAMP default, and the task/finding/schedule paths.

import (
	"database/sql"
	"os"
	"testing"
)

func TestPostgresEndToEnd(t *testing.T) {
	dsn := os.Getenv("K1Z_PG_DSN")
	if dsn == "" {
		t.Skip("K1Z_PG_DSN not set; skipping PostgreSQL integration test")
	}
	// Start from a clean schema so the test is repeatable against a persistent DB.
	if raw, err := sql.Open("pgx", dsn); err == nil {
		_, _ = raw.Exec("DROP SCHEMA IF EXISTS " + pgSchemaName + " CASCADE")
		raw.Close()
	}
	s, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	defer s.Close()
	if s.db.dia != dialectPostgres {
		t.Fatal("expected postgres dialect")
	}

	// a run (text PK) + a finding (IDENTITY PK via RETURNING id)
	run := &Run{ID: "run-pg-1", Workflow: "wf", Target: "example.com", Status: "running", ContinueOnError: true}
	if err := s.CreateRun(run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	got, err := s.GetRun("run-pg-1")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if !got.ContinueOnError {
		t.Error("BOOLEAN round-trip failed: continue_on_error should be true")
	}
	if got.CreatedAt.IsZero() {
		t.Error("created_at should be populated")
	}

	sev := "high"
	name := "test-finding"
	f := &Finding{RunID: "run-pg-1", Kind: "vuln", Severity: &sev, Host: "h.example.com", Name: &name, Status: "open"}
	if err := s.InsertFinding(f); err != nil {
		t.Fatalf("InsertFinding: %v", err)
	}
	if f.ID == 0 {
		t.Error("InsertFinding: RETURNING id did not populate f.ID (identity insert)")
	}

	// a task (goes through CreateTask -> exploration + node + task, all IDENTITY)
	task := &Task{Name: "pg-task", Goal: "g", Status: "created", CoverageEnabled: true}
	if err := s.CreateTask(task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if task.ID == 0 {
		t.Error("CreateTask: task id not populated")
	}
	reread, err := s.GetTask(task.ID)
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if !reread.CoverageEnabled {
		t.Error("task BOOLEAN coverage_enabled round-trip failed")
	}

	// INSERT OR IGNORE path: a schedule + DueSchedules (WHERE enabled = ?)
	sc := &Schedule{Name: "pg-sched", Workflow: "wf", Target: "example.com", Enabled: true}
	if err := s.CreateSchedule(sc); err != nil {
		t.Fatalf("CreateSchedule: %v", err)
	}
	if sc.ID == 0 {
		t.Error("CreateSchedule: id not populated")
	}

	// seed defaults use INSERT OR IGNORE INTO agent_configs; calling twice must be idempotent
	s.SeedAgentConfigs()
	s.SeedAgentConfigs()
	agents, err := s.ListChatAgents()
	if err != nil {
		t.Fatalf("ListChatAgents: %v", err)
	}
	if len(agents) == 0 {
		t.Error("expected seeded chat agents")
	}

	// nullable *string columns must scan back cleanly (Severity/Name set, others NULL)
	gf, err := s.GetFinding(f.ID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if gf.Severity == nil || *gf.Severity != "high" {
		t.Errorf("finding severity round-trip: %v", gf.Severity)
	}
	if gf.IP != nil {
		t.Errorf("finding IP should be NULL, got %v", *gf.IP)
	}

	// ---- upsert paths (ON CONFLICT ... DO UPDATE) must work on both branches ----

	// CreateLLMProfile: INSERT then conflict-UPDATE on name; id must stay stable,
	// and the RETURNING id path must populate p.ID even on the update branch.
	p1 := &LLMProfile{Name: "prof", BaseURL: "u1", Model: "m1", Temperature: 0.1}
	if err := s.CreateLLMProfile(p1); err != nil {
		t.Fatalf("CreateLLMProfile insert: %v", err)
	}
	if p1.ID == 0 {
		t.Error("CreateLLMProfile insert: id not populated")
	}
	// REAL->DOUBLE PRECISION: float64 must round-trip exactly (no float32 loss)
	if got, _ := s.GetLLMProfile(p1.ID); got == nil || got.Temperature != 0.1 {
		t.Errorf("Temperature round-trip (DOUBLE PRECISION): got %v want 0.1", got)
	}
	p2 := &LLMProfile{Name: "prof", BaseURL: "u2", Model: "m2", Temperature: 0.9}
	if err := s.CreateLLMProfile(p2); err != nil {
		t.Fatalf("CreateLLMProfile upsert: %v", err)
	}
	if p2.ID != p1.ID {
		t.Errorf("CreateLLMProfile upsert: id changed %d -> %d (should reuse row)", p1.ID, p2.ID)
	}
	if got, _ := s.GetLLMProfile(p1.ID); got == nil || got.BaseURL != "u2" {
		t.Errorf("CreateLLMProfile upsert did not update row: %+v", got)
	}

	// UpsertKey: ON CONFLICT(provider)
	if err := s.UpsertKey("openai", "k1"); err != nil {
		t.Fatalf("UpsertKey insert: %v", err)
	}
	if err := s.UpsertKey("openai", "k2"); err != nil {
		t.Fatalf("UpsertKey update: %v", err)
	}
	keys, _ := s.ListKeys()
	if len(keys) != 1 || keys[0].Value != "k2" {
		t.Errorf("UpsertKey: expected one key = k2, got %+v", keys)
	}

	// UpsertToolVersion: ON CONFLICT(name)
	if err := s.UpsertToolVersion(ToolVersion{Name: "nuclei", Status: "ok"}); err != nil {
		t.Fatalf("UpsertToolVersion insert: %v", err)
	}
	if err := s.UpsertToolVersion(ToolVersion{Name: "nuclei", Status: "updating"}); err != nil {
		t.Fatalf("UpsertToolVersion update: %v", err)
	}
	if tvs, _ := s.ListToolVersions(); tvs["nuclei"].Status != "updating" {
		t.Errorf("UpsertToolVersion did not update: %+v", tvs["nuclei"])
	}

	// CreateMCP: ON CONFLICT(name) returning id
	id1, err := s.CreateMCP(MCPServer{Name: "mcp1", Command: "c1", Enabled: true})
	if err != nil {
		t.Fatalf("CreateMCP insert: %v", err)
	}
	id2, err := s.CreateMCP(MCPServer{Name: "mcp1", Command: "c2", Enabled: false})
	if err != nil {
		t.Fatalf("CreateMCP upsert: %v", err)
	}
	if id1 == 0 || id1 != id2 {
		t.Errorf("CreateMCP: id %d -> %d (should be non-zero and stable)", id1, id2)
	}

	// UpsertCustomTool: ON CONFLICT(key); SetSetting: ON CONFLICT(key)
	if err := s.UpsertCustomTool(&CustomTool{Key: "t1", Description: "d1", Kind: "command", Schema: "{}", Exec: "e", Enabled: true}); err != nil {
		t.Fatalf("UpsertCustomTool insert: %v", err)
	}
	if err := s.UpsertCustomTool(&CustomTool{Key: "t1", Description: "d2", Kind: "command", Schema: "{}", Exec: "e", Enabled: false}); err != nil {
		t.Fatalf("UpsertCustomTool update: %v", err)
	}
	if ct, _ := s.GetCustomTool("t1"); ct == nil || ct.Description != "d2" {
		t.Errorf("UpsertCustomTool did not update: %+v", ct)
	}
	if err := s.SetSetting("theme", "dark"); err != nil {
		t.Fatalf("SetSetting insert: %v", err)
	}
	if err := s.SetSetting("theme", "light"); err != nil {
		t.Fatalf("SetSetting update: %v", err)
	}
	if v := s.GetSetting("theme", ""); v != "light" {
		t.Errorf("SetSetting did not update: %q", v)
	}

	// CreateCategory: ON CONFLICT(name) with the id==0 fallback
	c1, err := s.CreateCategory("cat", "#111")
	if err != nil {
		t.Fatalf("CreateCategory insert: %v", err)
	}
	c2, err := s.CreateCategory("cat", "#222")
	if err != nil {
		t.Fatalf("CreateCategory upsert: %v", err)
	}
	if c1.ID == 0 || c1.ID != c2.ID {
		t.Errorf("CreateCategory: id %d -> %d (should be non-zero and stable)", c1.ID, c2.ID)
	}

	// INSERT OR IGNORE runtime paths (edges/anchors): second call must be a no-op
	ex, _ := s.CreateExploration("e", "g")
	n1 := &ExplorationNode{ExplorationID: ex.ID, Kind: "begin", Payload: "{}", State: "open"}
	n2 := &ExplorationNode{ExplorationID: ex.ID, Kind: "goal", Payload: "{}", State: "open"}
	if err := s.CreateNode(n1); err != nil {
		t.Fatalf("CreateNode n1: %v", err)
	}
	if err := s.CreateNode(n2); err != nil {
		t.Fatalf("CreateNode n2: %v", err)
	}
	if err := s.AddEdge(ex.ID, n1.ID, n2.ID, "leads_to"); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	if err := s.AddEdge(ex.ID, n1.ID, n2.ID, "leads_to"); err != nil {
		t.Fatalf("AddEdge (ignore dup): %v", err)
	}

	// transaction + prepared statement (the only tx path): rebound ?->$N inside Prepare
	if err := s.InsertLogs("run-pg-1", []string{"line a", "line b", "line c"}); err != nil {
		t.Fatalf("InsertLogs (tx/prepared): %v", err)
	}
	if n, err := s.CountLogs("run-pg-1"); err != nil || n != 3 {
		t.Errorf("CountLogs after InsertLogs: n=%d err=%v (want 3)", n, err)
	}
}
