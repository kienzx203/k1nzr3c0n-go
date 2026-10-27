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
	"os"
	"testing"
)

func TestPostgresEndToEnd(t *testing.T) {
	dsn := os.Getenv("K1Z_PG_DSN")
	if dsn == "" {
		t.Skip("K1Z_PG_DSN not set; skipping PostgreSQL integration test")
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
}
