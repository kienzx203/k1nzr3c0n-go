// Package store is the SQLite persistence layer. The schema matches the Python
// original column-for-column so an existing k1nzr3c0n.db works as-is.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ── time helpers ─────────────────────────────────────────────────────────────

// NowUTC returns the naive-UTC timestamp Python's datetime.utcnow() produces.
func NowUTC() time.Time { return time.Now().UTC() }

// FmtTime serializes like Python's datetime.isoformat(): "2006-01-02T15:04:05"
// with microseconds appended only when non-zero.
func FmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	t = t.UTC()
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.999999")
}

// ParseTime accepts both "T" and space separators, with/without microseconds.
func ParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999", "2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999", "2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// parseDBTime converts a scanned DATETIME value (the SQLite driver may return
// time.Time or text) into time.Time.
func parseDBTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		return ParseTime(t)
	case []byte:
		return ParseTime(string(t))
	}
	return time.Time{}
}

func SqlTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format("2006-01-02 15:04:05.999999")
}

// sqlNow returns the SQL representation of the current instant.
func SqlNow() any { return SqlTime(NowUTC()) }

// ── models ───────────────────────────────────────────────────────────────────

type Run struct {
	ID              string
	Workflow        string
	Target          string
	Status          string
	Workspace       string
	VarsJSON        string
	OutDir          string
	ContinueOnError bool
	Resume          bool
	Returncode      *int
	ErrorMessage    *string
	StepsJSON       string
	CreatedAt       time.Time
	StartedAt       time.Time
	FinishedAt      time.Time
	PausedAt        time.Time
}

type RunLog struct {
	ID      int64
	RunID   string
	Message string
	TS      time.Time
}

type ApiKey struct {
	Provider  string
	Value     string
	UpdatedAt time.Time
}

type ToolVersion struct {
	Name          string
	Installed     *string
	Latest        *string
	LatestURL     string
	Status        string
	LastCheckedAt time.Time
	LastUpdatedAt time.Time
	ErrorMsg      *string
}

type Finding struct {
	ID          int64
	RunID       string
	Kind        string // vuln | port | http | subdomain | url
	Severity    *string
	Host        string
	IP          *string
	Port        *int
	StatusCode  *int
	Protocol    *string
	Name        *string
	TemplateID  *string
	URL         *string
	Title       *string
	Tech        string // JSON array text
	Evidence    *string
	Description *string
	Status      string // open | fp | resolved
	Notes       *string
	Tags        string // JSON array text
	Screenshot  *string
	CreatedAt   time.Time
}

type Schedule struct {
	ID             int64
	Name           string
	Workflow       string
	Target         string
	CronExpr       string
	VarsJSON       string
	Enabled        bool
	AlertNewAssets bool
	LastRunID      *string
	LastRunAt      time.Time
	NextRunAt      time.Time
	CreatedAt      time.Time
}

type Target struct {
	Name      string
	ScopeJSON string
	Mode      string
	Notes     *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type NewAsset struct {
	ID        int64
	RunID     string
	Target    string
	Host      string
	Kind      *string
	FirstSeen time.Time
}

type ScopeAudit struct {
	ID     int64
	Target string
	Action string
	Result string
	Detail *string
	TS     time.Time
}

// ── store ────────────────────────────────────────────────────────────────────

type Store struct {
	db *sql.DB
	mu sync.Mutex // serializes writes (SQLite-friendly)
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
	id VARCHAR(16) NOT NULL PRIMARY KEY,
	workflow VARCHAR(255) NOT NULL,
	target VARCHAR(512) NOT NULL,
	status VARCHAR(20) DEFAULT 'queued',
	workspace VARCHAR(1024),
	vars_json TEXT DEFAULT '{}',
	out_dir VARCHAR(1024),
	continue_on_error BOOLEAN DEFAULT 0,
	resume BOOLEAN DEFAULT 0,
	celery_task_id VARCHAR(64),
	pid INTEGER,
	returncode INTEGER,
	error_message TEXT,
	steps_json TEXT DEFAULT '[]',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	started_at DATETIME,
	finished_at DATETIME,
	paused_at DATETIME
);
CREATE INDEX IF NOT EXISTS ix_runs_status ON runs (status);
CREATE TABLE IF NOT EXISTS run_logs (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	run_id VARCHAR(16) NOT NULL,
	message TEXT NOT NULL,
	ts DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_run_logs_run_id ON run_logs (run_id);
CREATE TABLE IF NOT EXISTS api_keys (
	provider VARCHAR(64) NOT NULL PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tool_versions (
	name VARCHAR(64) NOT NULL PRIMARY KEY,
	installed VARCHAR(64),
	latest VARCHAR(64),
	latest_url TEXT,
	status VARCHAR(20) DEFAULT 'unknown',
	last_checked_at DATETIME,
	last_updated_at DATETIME,
	error_msg TEXT
);
CREATE TABLE IF NOT EXISTS findings (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	run_id VARCHAR(16) NOT NULL,
	kind VARCHAR(20) NOT NULL,
	severity VARCHAR(20),
	host VARCHAR(512) NOT NULL,
	notes TEXT,
	tags TEXT DEFAULT '[]',
	ip VARCHAR(64),
	port INTEGER,
	status_code INTEGER,
	protocol VARCHAR(20),
	name VARCHAR(512),
	template_id VARCHAR(256),
	url VARCHAR(2048),
	title VARCHAR(512),
	tech TEXT DEFAULT '[]',
	evidence TEXT,
	description TEXT,
	status VARCHAR(20) DEFAULT 'open',
	screenshot VARCHAR(1024),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_findings_kind ON findings (kind);
CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS ix_findings_host ON findings (host);
CREATE INDEX IF NOT EXISTS ix_findings_status ON findings (status);
CREATE TABLE IF NOT EXISTS schedules (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name VARCHAR(255) NOT NULL,
	workflow VARCHAR(255) NOT NULL,
	target VARCHAR(512) NOT NULL,
	cron_expr VARCHAR(64) NOT NULL,
	vars_json TEXT DEFAULT '{}',
	enabled BOOLEAN DEFAULT 1,
	alert_new_assets BOOLEAN DEFAULT 1,
	last_run_id VARCHAR(16),
	last_run_at DATETIME,
	next_run_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_schedules_target ON schedules (target);
CREATE INDEX IF NOT EXISTS ix_schedules_next_run_at ON schedules (next_run_at);
CREATE TABLE IF NOT EXISTS targets (
	name VARCHAR(512) NOT NULL PRIMARY KEY,
	scope_json TEXT DEFAULT '[]',
	mode VARCHAR(20) DEFAULT 'bounty',
	notes TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS new_assets (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	run_id VARCHAR(16) NOT NULL,
	target VARCHAR(512) NOT NULL,
	host VARCHAR(512) NOT NULL,
	kind VARCHAR(20),
	first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_new_assets_run_id ON new_assets (run_id);
CREATE INDEX IF NOT EXISTS ix_new_assets_target ON new_assets (target);
CREATE TABLE IF NOT EXISTS scope_audit (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	target VARCHAR(512) NOT NULL,
	action VARCHAR(64) NOT NULL,
	result VARCHAR(20) NOT NULL,
	detail TEXT,
	ts DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_scope_audit_target ON scope_audit (target);
`

var migrations = []string{
	"ALTER TABLE runs ADD COLUMN steps_json TEXT DEFAULT '[]'",
	"ALTER TABLE runs ADD COLUMN paused_at DATETIME",
	"ALTER TABLE runs ADD COLUMN pid INTEGER",
	"ALTER TABLE tool_versions ADD COLUMN latest_url TEXT",
	"ALTER TABLE findings ADD COLUMN status_code INTEGER",
	"ALTER TABLE findings ADD COLUMN screenshot TEXT",
	"ALTER TABLE findings ADD COLUMN notes TEXT",
	"ALTER TABLE findings ADD COLUMN tags TEXT DEFAULT '[]'",
}

// Open creates/opens the database, applies schema + idempotent migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // modernc sqlite + WAL: one writer connection is safest
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) init() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	for _, q := range migrations {
		_, _ = s.db.Exec(q) // ignore "duplicate column" errors
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// ── runs ─────────────────────────────────────────────────────────────────────

var ErrNotFound = errors.New("not found")

const runCols = `id, workflow, target, status, workspace, vars_json, out_dir,
	continue_on_error, resume, returncode, error_message, steps_json,
	created_at, started_at, finished_at, paused_at`

func scanRun(row interface{ Scan(...any) error }) (*Run, error) {
	var r Run
	var created, started, finished, paused any
	if err := row.Scan(&r.ID, &r.Workflow, &r.Target, &r.Status, &r.Workspace, &r.VarsJSON,
		&r.OutDir, &r.ContinueOnError, &r.Resume, &r.Returncode, &r.ErrorMessage, &r.StepsJSON,
		&created, &started, &finished, &paused); err != nil {
		return nil, err
	}
	r.CreatedAt = parseDBTime(created)
	r.StartedAt = parseDBTime(started)
	r.FinishedAt = parseDBTime(finished)
	r.PausedAt = parseDBTime(paused)
	return &r, nil
}

func (s *Store) CreateRun(r *Run) error {
	r.CreatedAt = NowUTC()
	if r.Status == "" {
		r.Status = "queued"
	}
	if r.VarsJSON == "" {
		r.VarsJSON = "{}"
	}
	if r.StepsJSON == "" {
		r.StepsJSON = "[]"
	}
	_, err := s.db.Exec(`INSERT INTO runs (id, workflow, target, status, workspace, vars_json,
		out_dir, continue_on_error, resume, steps_json, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Workflow, r.Target, r.Status, r.Workspace, r.VarsJSON,
		r.OutDir, r.ContinueOnError, r.Resume, r.StepsJSON, SqlTime(r.CreatedAt))
	return err
}

func (s *Store) GetRun(id string) (*Run, error) {
	row := s.db.QueryRow(`SELECT `+runCols+` FROM runs WHERE id = ?`, id)
	r, err := scanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// UpdateRunStatus sets status plus any of the optional timestamp/return/error fields.
func (s *Store) UpdateRunStatus(id string, status string, extra map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sets, args := []string{"status = ?"}, []any{status}
	for k, v := range extra {
		sets = append(sets, k+" = ?")
		args = append(args, v)
	}
	args = append(args, id)
	_, err := s.db.Exec(`UPDATE runs SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	return err
}

func (s *Store) SetRunStepsJSON(id, stepsJSON string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE runs SET steps_json = ? WHERE id = ?`, stepsJSON, id)
	return err
}

func (s *Store) SetRunWorkspace(id, ws string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE runs SET workspace = ? WHERE id = ?`, ws, id)
	return err
}

type RunFilter struct {
	Status   string
	Workflow string
	Limit    int
	Offset   int
}

func (s *Store) ListRuns(f RunFilter) ([]*Run, int, error) {
	where, args := "1=1", []any{}
	if f.Status != "" {
		where += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.Workflow != "" {
		where += " AND workflow = ?"
		args = append(args, f.Workflow)
	}
	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM runs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := f.Limit, f.Offset
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT ` + runCols + ` FROM runs WHERE ` + where + ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *Store) DeleteRun(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM run_logs WHERE run_id = ?`, id); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM findings WHERE run_id = ?`, id); err != nil {
		return err
	}
	res, err := s.db.Exec(`DELETE FROM runs WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CountRunsByStatus() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT status, count(*) FROM runs GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		m[st] = n
	}
	return m, rows.Err()
}

func (s *Store) ActiveRuns() ([]*Run, error) {
	rows, err := s.db.Query(`SELECT ` + runCols + ` FROM runs WHERE status IN ('queued','running','paused') ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		if r, err := scanRun(rows); err == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// TerminalRunsFinishedBefore returns completed/failed/paused runs whose
// finished_at is older than the cutoff (workspace cleanup query).
func (s *Store) TerminalRunsFinishedBefore(cutoff time.Time) ([]*Run, error) {
	rows, err := s.db.Query(`SELECT `+runCols+` FROM runs
		WHERE status IN ('completed','failed','cancelled') AND finished_at IS NOT NULL AND finished_at < ?
		ORDER BY finished_at`, SqlTime(cutoff))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		if r, err := scanRun(rows); err == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// ── run logs ─────────────────────────────────────────────────────────────────

func (s *Store) InsertLogs(runID string, msgs []string) error {
	if len(msgs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO run_logs (run_id, message, ts) VALUES (?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := SqlTime(NowUTC())
	for _, m := range msgs {
		if _, err := stmt.Exec(runID, m, now); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) CountLogs(runID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM run_logs WHERE run_id = ?`, runID).Scan(&n)
	return n, err
}

func (s *Store) ListLogs(runID string, offset, limit int) ([]string, int, error) {
	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM run_logs WHERE run_id = ?`, runID).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 500
	}
	if limit > 2000 {
		limit = 2000
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT message FROM run_logs WHERE run_id = ? ORDER BY id ASC LIMIT ? OFFSET ?`,
		runID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

// ── api keys ─────────────────────────────────────────────────────────────────

func (s *Store) UpsertKey(provider, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO api_keys (provider, value, updated_at) VALUES (?,?,?)
		ON CONFLICT (provider) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		provider, value, SqlTime(NowUTC()))
	return err
}

func (s *Store) DeleteKey(provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM api_keys WHERE provider = ?`, provider)
	return err
}

func (s *Store) ListKeys() ([]ApiKey, error) {
	rows, err := s.db.Query(`SELECT provider, value, updated_at FROM api_keys ORDER BY provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ApiKey
	for rows.Next() {
		var k ApiKey
		var ts any
		if err := rows.Scan(&k.Provider, &k.Value, &ts); err != nil {
			return nil, err
		}
		k.UpdatedAt = parseDBTime(ts)
		out = append(out, k)
	}
	return out, rows.Err()
}

// ── tool versions ────────────────────────────────────────────────────────────

func (s *Store) UpsertToolVersion(t ToolVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO tool_versions (name, installed, latest, latest_url, status,
		last_checked_at, last_updated_at, error_msg) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT (name) DO UPDATE SET installed=excluded.installed, latest=excluded.latest,
		latest_url=excluded.latest_url, status=excluded.status,
		last_checked_at=excluded.last_checked_at, last_updated_at=excluded.last_updated_at,
		error_msg=excluded.error_msg`,
		t.Name, t.Installed, t.Latest, t.LatestURL, t.Status,
		SqlTime(t.LastCheckedAt), SqlTime(t.LastUpdatedAt), t.ErrorMsg)
	return err
}

func (s *Store) ListToolVersions() (map[string]ToolVersion, error) {
	rows, err := s.db.Query(`SELECT name, installed, latest, latest_url, status,
		last_checked_at, last_updated_at, error_msg FROM tool_versions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]ToolVersion{}
	for rows.Next() {
		var t ToolVersion
		var chk, upd any
		if err := rows.Scan(&t.Name, &t.Installed, &t.Latest, &t.LatestURL, &t.Status, &chk, &upd, &t.ErrorMsg); err != nil {
			return nil, err
		}
		t.LastCheckedAt = parseDBTime(chk)
		t.LastUpdatedAt = parseDBTime(upd)
		m[t.Name] = t
	}
	return m, rows.Err()
}

// ── findings ─────────────────────────────────────────────────────────────────

func (s *Store) InsertFinding(f *Finding) error {
	if f.CreatedAt.IsZero() {
		f.CreatedAt = NowUTC()
	}
	if f.Status == "" {
		f.Status = "open"
	}
	if f.Tech == "" {
		f.Tech = "[]"
	}
	if f.Tags == "" {
		f.Tags = "[]"
	}
	res, err := s.db.Exec(`INSERT INTO findings (run_id, kind, severity, host, notes, tags, ip, port,
		status_code, protocol, name, template_id, url, title, tech, evidence, description, status,
		screenshot, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.RunID, f.Kind, f.Severity, f.Host, f.Notes, f.Tags, f.IP, f.Port,
		f.StatusCode, f.Protocol, f.Name, f.TemplateID, f.URL, f.Title, f.Tech, f.Evidence,
		f.Description, f.Status, f.Screenshot, SqlTime(f.CreatedAt))
	if err != nil {
		return err
	}
	f.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) DeleteFindingsByRun(runID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM findings WHERE run_id = ?`, runID)
	return err
}

const findingCols = `id, run_id, kind, severity, host, ip, port, protocol, name, template_id,
	url, title, tech, evidence, description, status, notes, tags, screenshot, status_code, created_at`

func scanFinding(row interface{ Scan(...any) error }) (*Finding, error) {
	var f Finding
	var created any
	if err := row.Scan(&f.ID, &f.RunID, &f.Kind, &f.Severity, &f.Host, &f.IP, &f.Port, &f.Protocol,
		&f.Name, &f.TemplateID, &f.URL, &f.Title, &f.Tech, &f.Evidence, &f.Description, &f.Status,
		&f.Notes, &f.Tags, &f.Screenshot, &f.StatusCode, &created); err != nil {
		return nil, err
	}
	f.CreatedAt = parseDBTime(created)
	return &f, nil
}

func (s *Store) GetFinding(id int64) (*Finding, error) {
	row := s.db.QueryRow(`SELECT `+findingCols+` FROM findings WHERE id = ?`, id)
	f, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return f, err
}

type FindingFilter struct {
	Kind     string
	Severity string
	Status   string
	Host     string // substring
	RunID    string
	Limit    int
	Offset   int
}

func (s *Store) ListFindings(f FindingFilter) ([]*Finding, int, error) {
	where, args := "1=1", []any{}
	if f.Kind != "" {
		where += " AND kind = ?"
		args = append(args, f.Kind)
	}
	if f.Severity != "" {
		where += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.Status != "" {
		where += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.Host != "" {
		where += " AND host LIKE ?"
		args = append(args, "%"+f.Host+"%")
	}
	if f.RunID != "" {
		where += " AND run_id = ?"
		args = append(args, f.RunID)
	}
	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM findings WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 && f.RunID == "" {
		limit = 500
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT `+findingCols+` FROM findings WHERE `+where+
		` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		fd, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, fd)
	}
	return out, total, rows.Err()
}

// ListRunFindings orders by severity rank then host (matches Python route).
func (s *Store) ListRunFindings(runID string, f FindingFilter) ([]*Finding, int, error) {
	f.RunID = runID
	where, args := "run_id = ?", []any{runID}
	if f.Kind != "" {
		where += " AND kind = ?"
		args = append(args, f.Kind)
	}
	if f.Severity != "" {
		where += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.Status != "" {
		where += " AND status = ?"
		args = append(args, f.Status)
	}
	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM findings WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT `+findingCols+` FROM findings WHERE `+where+
		` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		WHEN 'low' THEN 3 ELSE 4 END ASC, host ASC LIMIT ? OFFSET ?`,
		append(args, limit, max(f.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		fd, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, fd)
	}
	return out, total, rows.Err()
}

func (s *Store) PatchFinding(id int64, status *string, notes *string, tags *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sets, args := []string{}, []any{}
	if status != nil {
		sets = append(sets, "status = ?")
		args = append(args, *status)
	}
	if notes != nil {
		sets = append(sets, "notes = ?")
		args = append(args, *notes)
	}
	if tags != nil {
		sets = append(sets, "tags = ?")
		args = append(args, *tags)
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	res, err := s.db.Exec(`UPDATE findings SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) FindingStats() (total int, bySeverity, byKind map[string]int, err error) {
	bySeverity, byKind = map[string]int{}, map[string]int{}
	if err = s.db.QueryRow(`SELECT count(*) FROM findings`).Scan(&total); err != nil {
		return
	}
	rows, err := s.db.Query(`SELECT COALESCE(severity,'info'), count(*) FROM findings GROUP BY severity`)
	if err != nil {
		return
	}
	for rows.Next() {
		var k string
		var n int
		if rows.Scan(&k, &n) == nil {
			bySeverity[k] = n
		}
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT kind, count(*) FROM findings GROUP BY kind`)
	if err != nil {
		return
	}
	for rows.Next() {
		var k string
		var n int
		if rows.Scan(&k, &n) == nil {
			byKind[k] = n
		}
	}
	rows.Close()
	return
}

type DupGroup struct {
	Host       string
	TemplateID string
	Count      int
	Severity   *string
	KeepID     int64
	DupIDs     []int64
}

func (s *Store) DuplicateGroups() ([]DupGroup, error) {
	rows, err := s.db.Query(`SELECT host, template_id, count(*) c FROM findings
		WHERE kind='vuln' AND status='open' GROUP BY host, template_id HAVING c > 1
		ORDER BY c DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	type key struct{ h, t string }
	var groups []DupGroup
	var keys []key
	for rows.Next() {
		var g DupGroup
		if err := rows.Scan(&g.Host, &g.TemplateID, &g.Count); err != nil {
			rows.Close()
			return nil, err
		}
		groups = append(groups, g)
		keys = append(keys, key{g.Host, g.TemplateID})
	}
	rows.Close()
	for i, k := range keys {
		r, err := s.db.Query(`SELECT id, severity FROM findings WHERE kind='vuln' AND status='open'
			AND host = ? AND template_id = ? ORDER BY id DESC`, k.h, k.t)
		if err != nil {
			return nil, err
		}
		first := true
		for r.Next() {
			var id int64
			var sev *string
			if err := r.Scan(&id, &sev); err != nil {
				r.Close()
				return nil, err
			}
			if first {
				groups[i].KeepID = id
				groups[i].Severity = sev
				first = false
			} else {
				groups[i].DupIDs = append(groups[i].DupIDs, id)
			}
		}
		r.Close()
	}
	return groups, nil
}

func (s *Store) ResolveDuplicates() (int, error) {
	groups, err := s.DuplicateGroups()
	if err != nil {
		return 0, err
	}
	n := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range groups {
		for _, id := range g.DupIDs {
			var tags string
			if err := s.db.QueryRow(`SELECT tags FROM findings WHERE id = ?`, id).Scan(&tags); err == nil {
				var arr []string
				_ = json.Unmarshal([]byte(tags), &arr)
				arr = append(arr, "duplicate")
				b, _ := json.Marshal(arr)
				if _, err := s.db.Exec(`UPDATE findings SET status='resolved', tags=? WHERE id=?`, string(b), id); err == nil {
					n++
				}
			}
		}
	}
	return n, nil
}

// DeleteHTTPAssets removes kind=http findings for host(+port). port<0 → IS NULL.
func (s *Store) DeleteHTTPAssets(host string, port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if port < 0 {
		_, err := s.db.Exec(`DELETE FROM findings WHERE kind='http' AND host=? AND port IS NULL`, host)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM findings WHERE kind='http' AND host=? AND port=?`, host, port)
	return err
}

// AssetItem is one row of the cross-run inventory.
type AssetItem struct {
	Host       string
	Port       *int
	IP         *string
	URL        *string
	Title      *string
	StatusCode *int
	Tech       string
	Screenshot *string
	RunID      string
	CreatedAt  time.Time
}

type AssetFilter struct {
	Q           string
	Tech        []string
	Targets     []string
	StatusCodes []int
	Ports       []int
	Limit       int
	Offset      int
}

// ListAssets returns the newest kind=http finding per (host, port).
func (s *Store) ListAssets(f AssetFilter) ([]AssetItem, int, error) {
	base := `FROM findings f JOIN (SELECT host, COALESCE(port,0) cp, MAX(id) mid FROM findings
		WHERE kind='http' GROUP BY host, COALESCE(port,0)) g ON f.id = g.mid`
	where, args := "1=1", []any{}
	if f.Q != "" {
		where += " AND f.host LIKE ?"
		args = append(args, "%"+f.Q+"%")
	}
	if len(f.Tech) > 0 {
		// ANY-match (OR) over tech tokens
		var ors []string
		for _, t := range f.Tech {
			ors = append(ors, "f.tech LIKE ?")
			args = append(args, `%"`+t+`"%`)
		}
		where += " AND (" + strings.Join(ors, " OR ") + ")"
	}
	if len(f.Targets) > 0 {
		// restrict to runs of the given targets
		ph := strings.TrimSuffix(strings.Repeat("?,", len(f.Targets)), ",")
		where += " AND f.run_id IN (SELECT id FROM runs WHERE target IN (" + ph + "))"
		for _, t := range f.Targets {
			args = append(args, t)
		}
	}
	if len(f.StatusCodes) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(f.StatusCodes)), ",")
		where += " AND f.status_code IN (" + ph + ")"
		for _, sc := range f.StatusCodes {
			args = append(args, sc)
		}
	}
	if len(f.Ports) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(f.Ports)), ",")
		where += " AND f.port IN (" + ph + ")"
		for _, p := range f.Ports {
			args = append(args, p)
		}
	}
	var total int
	if err := s.db.QueryRow(`SELECT count(*) `+base+` WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	rows, err := s.db.Query(`SELECT f.host, f.port, f.ip, f.url, f.title, f.status_code, f.tech,
		f.screenshot, f.run_id, f.created_at `+base+` WHERE `+where+
		` ORDER BY f.created_at DESC, f.id DESC LIMIT ? OFFSET ?`, append(args, limit, max(f.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AssetItem
	for rows.Next() {
		var a AssetItem
		var created any
		if err := rows.Scan(&a.Host, &a.Port, &a.IP, &a.URL, &a.Title, &a.StatusCode, &a.Tech,
			&a.Screenshot, &a.RunID, &created); err != nil {
			return nil, 0, err
		}
		a.CreatedAt = parseDBTime(created)
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (s *Store) AssetStats() (total, withScreenshot int, byTech, byTarget, byStatus, byPort map[string]int, err error) {
	byTech, byTarget, byStatus, byPort = map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	base := `FROM findings WHERE kind='http' AND id IN (SELECT MAX(id) FROM findings WHERE kind='http' GROUP BY host, COALESCE(port,0))`
	if err = s.db.QueryRow(`SELECT count(*), count(screenshot) `+base).Scan(&total, &withScreenshot); err != nil {
		return
	}
	if rows, e := s.db.Query(`SELECT tech ` + base); e == nil {
		for rows.Next() {
			var tech string
			if rows.Scan(&tech) == nil {
				var arr []string
				if json.Unmarshal([]byte(tech), &arr) == nil {
					for _, t := range arr {
						byTech[t]++
					}
				}
			}
		}
		rows.Close()
	}
	if rows, e := s.db.Query(`SELECT COALESCE((SELECT target FROM runs WHERE id = run_id), host), count(*)
		FROM findings WHERE kind='http' AND id IN (SELECT MAX(id) FROM findings WHERE kind='http'
		GROUP BY host, COALESCE(port,0)) GROUP BY 1 ORDER BY 2 DESC`); e == nil {
		for rows.Next() {
			var k string
			var n int
			if rows.Scan(&k, &n) == nil {
				byTarget[k] = n
			}
		}
		rows.Close()
	}
	if rows, e := s.db.Query(`SELECT CAST(status_code AS TEXT), count(*) FROM findings WHERE kind='http'
		AND id IN (SELECT MAX(id) FROM findings WHERE kind='http' GROUP BY host, COALESCE(port,0))
		GROUP BY status_code`); e == nil {
		for rows.Next() {
			var k sql.NullString
			var n int
			if rows.Scan(&k, &n) == nil {
				byStatus[k.String] = n
			}
		}
		rows.Close()
	}
	if rows, e := s.db.Query(`SELECT CAST(port AS TEXT), count(*) FROM findings WHERE kind='http'
		AND id IN (SELECT MAX(id) FROM findings WHERE kind='http' GROUP BY host, COALESCE(port,0))
		GROUP BY port ORDER BY 2 DESC LIMIT 20`); e == nil {
		for rows.Next() {
			var k sql.NullString
			var n int
			if rows.Scan(&k, &n) == nil {
				byPort[k.String] = n
			}
		}
		rows.Close()
	}
	return
}

// ── schedules ────────────────────────────────────────────────────────────────

const schedCols = `id, name, workflow, target, cron_expr, vars_json, enabled, alert_new_assets,
	last_run_id, last_run_at, next_run_at, created_at`

func scanSchedule(row interface{ Scan(...any) error }) (*Schedule, error) {
	var s Schedule
	var lastRunID sql.NullString
	var lastRun, nextRun, created any
	if err := row.Scan(&s.ID, &s.Name, &s.Workflow, &s.Target, &s.CronExpr, &s.VarsJSON,
		&s.Enabled, &s.AlertNewAssets, &lastRunID, &lastRun, &nextRun, &created); err != nil {
		return nil, err
	}
	s.LastRunID = &lastRunID.String
	if !lastRunID.Valid {
		s.LastRunID = nil
	}
	s.LastRunAt = parseDBTime(lastRun)
	s.NextRunAt = parseDBTime(nextRun)
	s.CreatedAt = parseDBTime(created)
	return &s, nil
}

func (s *Store) CreateSchedule(sc *Schedule) error {
	sc.CreatedAt = NowUTC()
	if sc.VarsJSON == "" {
		sc.VarsJSON = "{}"
	}
	res, err := s.db.Exec(`INSERT INTO schedules (name, workflow, target, cron_expr, vars_json,
		enabled, alert_new_assets, next_run_at, created_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		sc.Name, sc.Workflow, sc.Target, sc.CronExpr, sc.VarsJSON,
		sc.Enabled, sc.AlertNewAssets, SqlTime(sc.NextRunAt), SqlTime(sc.CreatedAt))
	if err != nil {
		return err
	}
	sc.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) GetSchedule(id int64) (*Schedule, error) {
	row := s.db.QueryRow(`SELECT `+schedCols+` FROM schedules WHERE id = ?`, id)
	sc, err := scanSchedule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sc, err
}

func (s *Store) ListSchedules() ([]*Schedule, error) {
	rows, err := s.db.Query(`SELECT ` + schedCols + ` FROM schedules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Schedule
	for rows.Next() {
		if sc, err := scanSchedule(rows); err == nil {
			out = append(out, sc)
		}
	}
	return out, rows.Err()
}

// UpdateSchedule rewrites the mutable fields of one schedule row.
func (s *Store) UpdateSchedule(sc *Schedule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE schedules SET name=?, workflow=?, target=?, cron_expr=?, vars_json=?,
		enabled=?, alert_new_assets=?, last_run_id=?, last_run_at=?, next_run_at=? WHERE id=?`,
		sc.Name, sc.Workflow, sc.Target, sc.CronExpr, sc.VarsJSON,
		sc.Enabled, sc.AlertNewAssets, sc.LastRunID, SqlTime(sc.LastRunAt), SqlTime(sc.NextRunAt), sc.ID)
	return err
}

func (s *Store) DeleteSchedule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM schedules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DueSchedules returns enabled schedules with next_run_at <= now.
func (s *Store) DueSchedules(now time.Time) ([]*Schedule, error) {
	rows, err := s.db.Query(`SELECT `+schedCols+` FROM schedules
		WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?
		ORDER BY next_run_at ASC`, SqlTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Schedule
	for rows.Next() {
		if sc, err := scanSchedule(rows); err == nil {
			out = append(out, sc)
		}
	}
	return out, rows.Err()
}

// ScheduleForRun finds the schedule whose last_run_id is runID (if any).
func (s *Store) ScheduleForRun(runID string) *Schedule {
	sc, _ := s.ListSchedules()
	for _, x := range sc {
		if x.LastRunID != nil && *x.LastRunID == runID {
			return x
		}
	}
	return nil
}

// ── targets ──────────────────────────────────────────────────────────────────

const targetCols = `name, scope_json, mode, notes, created_at, updated_at`

func scanTarget(row interface{ Scan(...any) error }) (*Target, error) {
	var t Target
	var created, updated any
	if err := row.Scan(&t.Name, &t.ScopeJSON, &t.Mode, &t.Notes, &created, &updated); err != nil {
		return nil, err
	}
	t.CreatedAt = parseDBTime(created)
	t.UpdatedAt = parseDBTime(updated)
	return &t, nil
}

func (s *Store) CreateTarget(t *Target) error {
	t.CreatedAt = NowUTC()
	t.UpdatedAt = t.CreatedAt
	if t.ScopeJSON == "" {
		t.ScopeJSON = "[]"
	}
	if t.Mode == "" {
		t.Mode = "bounty"
	}
	_, err := s.db.Exec(`INSERT INTO targets (name, scope_json, mode, notes, created_at, updated_at)
		VALUES (?,?,?,?,?,?)`, t.Name, t.ScopeJSON, t.Mode, t.Notes, SqlTime(t.CreatedAt), SqlTime(t.UpdatedAt))
	return err
}

func (s *Store) GetTarget(name string) (*Target, error) {
	row := s.db.QueryRow(`SELECT `+targetCols+` FROM targets WHERE name = ?`, name)
	t, err := scanTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (s *Store) ListTargets() ([]*Target, error) {
	rows, err := s.db.Query(`SELECT ` + targetCols + ` FROM targets ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		if t, err := scanTarget(rows); err == nil {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

func (s *Store) UpdateTarget(t *Target) error {
	t.UpdatedAt = NowUTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE targets SET scope_json=?, mode=?, notes=?, updated_at=? WHERE name=?`,
		t.ScopeJSON, t.Mode, t.Notes, SqlTime(t.UpdatedAt), t.Name)
	return err
}

func (s *Store) DeleteTarget(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM targets WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── new assets ───────────────────────────────────────────────────────────────

func (s *Store) InsertNewAsset(n *NewAsset) error {
	if n.FirstSeen.IsZero() {
		n.FirstSeen = NowUTC()
	}
	res, err := s.db.Exec(`INSERT INTO new_assets (run_id, target, host, kind, first_seen)
		VALUES (?,?,?,?,?)`, n.RunID, n.Target, n.Host, n.Kind, SqlTime(n.FirstSeen))
	if err != nil {
		return err
	}
	n.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) ListNewAssetsByRun(runID string) ([]NewAsset, error) {
	rows, err := s.db.Query(`SELECT id, run_id, target, host, kind, first_seen FROM new_assets
		WHERE run_id = ? ORDER BY host ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NewAsset
	for rows.Next() {
		var n NewAsset
		var seen any
		if err := rows.Scan(&n.ID, &n.RunID, &n.Target, &n.Host, &n.Kind, &seen); err != nil {
			return nil, err
		}
		n.FirstSeen = parseDBTime(seen)
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) ListNewAssetsByTarget(target string, limit int) ([]NewAsset, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id, run_id, target, host, kind, first_seen FROM new_assets
		WHERE target = ? ORDER BY first_seen DESC LIMIT ?`, target, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NewAsset
	for rows.Next() {
		var n NewAsset
		var seen sql.NullString
		if err := rows.Scan(&n.ID, &n.RunID, &n.Target, &n.Host, &n.Kind, &seen); err != nil {
			return nil, err
		}
		n.FirstSeen = ParseTime(seen.String)
		out = append(out, n)
	}
	return out, rows.Err()
}

// AlertedHosts returns every host already recorded as new for the target.
func (s *Store) AlertedHosts(target string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT DISTINCT host FROM new_assets WHERE target = ?`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		m[h] = true
	}
	return m, rows.Err()
}

// ── scope audit ──────────────────────────────────────────────────────────────

func (s *Store) InsertScopeAudit(a *ScopeAudit) error {
	if a.TS.IsZero() {
		a.TS = NowUTC()
	}
	res, err := s.db.Exec(`INSERT INTO scope_audit (target, action, result, detail, ts) VALUES (?,?,?,?,?)`,
		a.Target, a.Action, a.Result, a.Detail, SqlTime(a.TS))
	if err != nil {
		return err
	}
	a.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) ListScopeAudit(target string, limit int) ([]ScopeAudit, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id, target, action, result, detail, ts FROM scope_audit
		WHERE target = ? ORDER BY id DESC LIMIT ?`, target, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScopeAudit
	for rows.Next() {
		var a ScopeAudit
		var ts any
		if err := rows.Scan(&a.ID, &a.Target, &a.Action, &a.Result, &a.Detail, &ts); err != nil {
			return nil, err
		}
		a.TS = parseDBTime(ts)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ── system usage ─────────────────────────────────────────────────────────────

type Usage struct {
	Runs, Findings, NewAssets, RunLogs, ApiKeys, Targets, Schedules, ToolVersions int
}

func (s *Store) Usage() (Usage, error) {
	var u Usage
	q := func(sqlq string, dst *int) {
		_ = s.db.QueryRow(sqlq).Scan(dst)
	}
	q(`SELECT count(*) FROM runs`, &u.Runs)
	q(`SELECT count(*) FROM findings`, &u.Findings)
	q(`SELECT count(*) FROM new_assets`, &u.NewAssets)
	q(`SELECT count(*) FROM run_logs`, &u.RunLogs)
	q(`SELECT count(*) FROM api_keys`, &u.ApiKeys)
	q(`SELECT count(*) FROM targets`, &u.Targets)
	q(`SELECT count(*) FROM schedules`, &u.Schedules)
	q(`SELECT count(*) FROM tool_versions`, &u.ToolVersions)
	return u, nil
}

// Reset removes run-history tables (scope=all adds targets+schedules). Keys and
// tool versions are never wiped. Returns rows deleted per table.
func (s *Store) Reset(scope string) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tables := []string{"runs", "run_logs", "findings", "new_assets", "scope_audit"}
	if scope == "all" {
		tables = append(tables, "targets", "schedules")
	}
	out := map[string]int{}
	for _, t := range tables {
		res, err := s.db.Exec(`DELETE FROM ` + t)
		if err != nil {
			return out, err
		}
		n, _ := res.RowsAffected()
		out[t] = int(n)
	}
	_, _ = s.db.Exec(`VACUUM`)
	return out, nil
}

// TargetSummary computes the run/finding summary shown on the Targets page.
type TargetSummary struct {
	TotalRuns  int
	LastRunID  *string
	LastRunAt  *time.Time
	LastStatus *string
	OpenVulns  int
	BySeverity map[string]int
}

func (s *Store) TargetSummary(name string) (TargetSummary, error) {
	var sum TargetSummary
	sum.BySeverity = map[string]int{}
	if err := s.db.QueryRow(`SELECT count(*) FROM runs WHERE target = ?`, name).Scan(&sum.TotalRuns); err != nil {
		return sum, err
	}
	var rid sql.NullString
	var created any
	var status sql.NullString
	_ = s.db.QueryRow(`SELECT id, created_at, status FROM runs WHERE target = ?
		ORDER BY created_at DESC, id DESC LIMIT 1`, name).Scan(&rid, &created, &status)
	if rid.Valid {
		sum.LastRunID = &rid.String
	}
	if t := parseDBTime(created); !t.IsZero() {
		sum.LastRunAt = &t
	}
	if status.Valid {
		sum.LastStatus = &status.String
	}
	hostFilter := `(host = ? OR host LIKE ?)`
	args := []any{name, "%." + name}
	if err := s.db.QueryRow(`SELECT count(*) FROM findings WHERE kind='vuln' AND status='open' AND `+hostFilter, args...).Scan(&sum.OpenVulns); err != nil {
		return sum, err
	}
	rows, err := s.db.Query(`SELECT COALESCE(severity,'info'), count(*) FROM findings
		WHERE kind='vuln' AND status='open' AND `+hostFilter+` GROUP BY severity`, args...)
	if err != nil {
		return sum, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return sum, err
		}
		sum.BySeverity[k] = n
	}
	return sum, rows.Err()
}

// RunStats aggregates the dashboard numbers.
type RunStatsData struct {
	FindingsTotal int
	OpenVulns     int
	BySeverity    map[string]int
}

func (s *Store) RunStats() (RunStatsData, error) {
	var d RunStatsData
	d.BySeverity = map[string]int{}
	if err := s.db.QueryRow(`SELECT count(*) FROM findings`).Scan(&d.FindingsTotal); err != nil {
		return d, err
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM findings WHERE kind='vuln' AND status='open'`).Scan(&d.OpenVulns); err != nil {
		return d, err
	}
	rows, err := s.db.Query(`SELECT COALESCE(severity,'info'), count(*) FROM findings
		WHERE kind='vuln' AND status='open' GROUP BY severity`)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return d, err
		}
		d.BySeverity[k] = n
	}
	return d, rows.Err()
}
