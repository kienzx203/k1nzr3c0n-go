package store

// PostgreSQL open path. SQLite (Open) stays the default; a deployment opts into
// PostgreSQL ONLY by setting K1Z_PG_DSN explicitly. There is deliberately no
// implicit fallback to ARTEX's ARTEX_PG_DSN: an existing install that already
// sets ARTEX_PG_DSN (every ARTEX install does) would otherwise silently abandon
// its k1nzr3c0n.db for an empty PostgreSQL schema on the next restart. To run
// both halves on one database, set K1Z_PG_DSN to the same value as ARTEX_PG_DSN.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// PostgresDSN returns the explicit opt-in DSN for the k1z store, or "" when the
// store should stay on SQLite.
func PostgresDSN() string { return strings.TrimSpace(os.Getenv("K1Z_PG_DSN")) }

// OpenAuto opens the k1z store on PostgreSQL when K1Z_PG_DSN is set, else on the
// SQLite file at path. This is the single entry point the boot code uses.
func OpenAuto(path string) (*Store, error) {
	if dsn := PostgresDSN(); dsn != "" {
		return OpenPostgres(dsn)
	}
	return Open(path)
}

// OpenPostgres opens the store on PostgreSQL, pinning search_path to the k1z
// schema (plus public as a fallback) so the k1z tables live beside — but never
// collide with — the ARTEX tables in the same database. The schema itself is
// created by init (CREATE SCHEMA IF NOT EXISTS).
func OpenPostgres(dsn string) (*Store, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse K1Z_PG_DSN: %w", err)
	}
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	// Pin every pooled connection to the k1z schema. A not-yet-created schema in
	// search_path is harmlessly ignored until init's CREATE SCHEMA makes it real.
	cfg.RuntimeParams["search_path"] = pgSchemaName + ", public"

	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)

	s := &Store{db: &xdb{DB: db, dia: dialectPostgres}}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
