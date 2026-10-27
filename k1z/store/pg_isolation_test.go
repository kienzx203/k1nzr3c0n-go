package store

import (
	"database/sql"
	"os"
	"testing"
)

// TestPostgresSharesDatabaseWithArtex verifies the advertised "point K1Z_PG_DSN
// at the same database as ARTEX" mode is safe: k1z table names that also exist
// in public (ARTEX has its own tasks, agent_configs, …) must NOT make k1z's
// CREATE TABLE IF NOT EXISTS skip the k1z copy and silently bind to ARTEX's
// public table. k1z lives in its own schema; public is only a search_path
// fallback. Skipped unless K1Z_PG_DSN is set.
func TestPostgresSharesDatabaseWithArtex(t *testing.T) {
	dsn := os.Getenv("K1Z_PG_DSN")
	if dsn == "" {
		t.Skip("K1Z_PG_DSN not set; skipping PostgreSQL schema-isolation test")
	}
	// Reset, then plant ARTEX-shaped tables in public with a sentinel row.
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	for _, q := range []string{
		"DROP SCHEMA IF EXISTS " + pgSchemaName + " CASCADE",
		"DROP TABLE IF EXISTS public.tasks, public.agent_configs",
		"CREATE TABLE public.tasks (artex_only_col int)",
		"CREATE TABLE public.agent_configs (artex_only_col int)",
		"INSERT INTO public.tasks VALUES (999)",
	} {
		if _, err := raw.Exec(q); err != nil {
			raw.Close()
			t.Fatalf("setup %q: %v", q, err)
		}
	}
	raw.Close()

	s, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatalf("OpenPostgres with public.tasks present: %v", err)
	}
	defer s.Close()

	task := &Task{Name: "iso", Goal: "g", Status: "created"}
	if err := s.CreateTask(task); err != nil {
		t.Fatalf("CreateTask (schema isolation broken — bound to public.tasks?): %v", err)
	}
	tasks, err := s.ListTasks("")
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if len(tasks) != 1 || tasks[0].Name != "iso" {
		t.Fatalf("k1z read the wrong tasks table: %+v", tasks)
	}
	// seeding (INSERT OR IGNORE INTO agent_configs) must target k1z.agent_configs
	s.SeedAgentConfigs()
	if agents, err := s.ListChatAgents(); err != nil || len(agents) == 0 {
		t.Fatalf("ListChatAgents after seed: n=%d err=%v", len(agents), err)
	}
}
