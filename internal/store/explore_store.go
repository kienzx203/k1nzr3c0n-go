// Exploration graph + tasks persistence — the ScopeWeaver/ARTEX two-graph model
// ported onto k1nzr3c0n's SQLite layer. This is ADDITIVE: it lives alongside the
// existing runs/findings/workflow tables and never touches them.
//
// Two graphs:
//   - asset graph (companies/assets, already present) = "what the target is"
//   - exploration graph (explorations/exploration_nodes/edges) = "how far it's
//     been tested", a per-task lineage chain of goal→intent→fact→finding/hint.
// They connect through exploration_anchors(node_id, asset_id).
package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ── schema (SQLite adaptation of db/schema.sql) ──────────────────────────────

const exploreSchema = `
CREATE TABLE IF NOT EXISTS explorations (
	id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	description TEXT DEFAULT '',
	goal        TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'open',          -- open|achieved|failed
	created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS exploration_nodes (
	id             INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	exploration_id INTEGER NOT NULL,
	kind           TEXT NOT NULL,                       -- begin|goal|intent|fact|finding|hint|digest
	payload        TEXT NOT NULL DEFAULT '{}',          -- JSON blob
	priority       INTEGER NOT NULL DEFAULT 0,
	state          TEXT NOT NULL DEFAULT 'open',
	origin         TEXT,
	owner          TEXT,
	blocked_reason TEXT,
	delete_reason  TEXT,
	created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
	completed_at   DATETIME
);
CREATE INDEX IF NOT EXISTS ix_expl_nodes_expl ON exploration_nodes (exploration_id);
CREATE INDEX IF NOT EXISTS ix_expl_nodes_kind ON exploration_nodes (exploration_id, kind, state);
CREATE TABLE IF NOT EXISTS exploration_edges (
	exploration_id INTEGER NOT NULL,
	src_id         INTEGER NOT NULL,
	dst_id         INTEGER NOT NULL,
	rel            TEXT NOT NULL,                       -- spawns|derived_from|yields|proves|covers
	created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (exploration_id, src_id, rel, dst_id)
);
CREATE INDEX IF NOT EXISTS ix_expl_edges_src ON exploration_edges (src_id);
CREATE INDEX IF NOT EXISTS ix_expl_edges_dst ON exploration_edges (dst_id);
CREATE TABLE IF NOT EXISTS exploration_anchors (
	node_id  INTEGER NOT NULL,
	asset_id INTEGER NOT NULL,
	PRIMARY KEY (node_id, asset_id)
);
CREATE INDEX IF NOT EXISTS ix_expl_anchors_asset ON exploration_anchors (asset_id);
CREATE TABLE IF NOT EXISTS activity (
	id                 INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	exploration_id     INTEGER NOT NULL,
	node_id            INTEGER,
	worker             TEXT,
	kind               TEXT,
	tool               TEXT,
	tool_use_id        TEXT,
	is_error           BOOLEAN NOT NULL DEFAULT 0,
	summary            TEXT,
	detail             TEXT,
	metadata           TEXT NOT NULL DEFAULT '{}',
	input_tokens       INTEGER,
	output_tokens      INTEGER,
	cache_read_tokens  INTEGER,
	cache_write_tokens INTEGER,
	created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_activity_expl ON activity (exploration_id);
CREATE INDEX IF NOT EXISTS ix_activity_node ON activity (node_id);
CREATE TABLE IF NOT EXISTS tasks (
	id                     INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name                   TEXT NOT NULL DEFAULT '',
	category_id            INTEGER,
	description            TEXT NOT NULL DEFAULT '',
	goal                   TEXT NOT NULL,
	exploration_id         INTEGER NOT NULL UNIQUE,
	status                 TEXT NOT NULL DEFAULT 'created', -- created|running|paused|done|failed|timeout
	paused                 BOOLEAN NOT NULL DEFAULT 0,
	queued                 BOOLEAN NOT NULL DEFAULT 0,
	queued_at              DATETIME,
	queue_mode             TEXT NOT NULL DEFAULT '',
	llm_profile_id         INTEGER,
	active_llm_profile_id  INTEGER,
	company_id             INTEGER,
	parent_ref             TEXT,
	timeout_seconds        INTEGER NOT NULL DEFAULT 0,
	plan_heartbeat_seconds INTEGER NOT NULL DEFAULT 300,
	coverage_enabled       BOOLEAN NOT NULL DEFAULT 1,
	max_workers            INTEGER NOT NULL DEFAULT 3,
	pinned_at              DATETIME,
	first_run_at           DATETIME,
	deadline_at            DATETIME,
	archived_at            DATETIME,
	deleted_at             DATETIME,
	completed_at           DATETIME,
	created_at             DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at             DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_tasks_status ON tasks (status);
CREATE TABLE IF NOT EXISTS task_scope (
	id             INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	task_id        INTEGER NOT NULL,
	pattern        TEXT NOT NULL,
	kind           TEXT NOT NULL DEFAULT 'include',     -- include|exclude
	created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_task_scope_task ON task_scope (task_id);
CREATE TABLE IF NOT EXISTS finding_retests (
	id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	finding_id  INTEGER NOT NULL,
	task_id     INTEGER,
	status      TEXT NOT NULL DEFAULT 'running',         -- running|done|failed|stopped
	conclusion  TEXT,                                     -- reproducible|fixed|cannot_confirm
	fix_version TEXT,
	conditions  TEXT,
	notes       TEXT,
	evidence    TEXT,
	session_ref TEXT,
	created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_finding_retests_finding ON finding_retests (finding_id);
`

// ── node kind / state / edge-rel constants (mirror ScopeWeaver) ──────────────

const (
	NodeBegin   = "begin"
	NodeGoal    = "goal"
	NodeIntent  = "intent"
	NodeFact    = "fact"
	NodeFinding = "finding"
	NodeHint    = "hint"
	NodeDigest  = "digest"

	// intent states
	IntentOpen      = "open"
	IntentRunning   = "running"
	IntentPaused    = "paused"
	IntentDone      = "done"
	IntentBlocked   = "blocked"
	IntentExhausted = "exhausted"
	IntentStopped   = "stopped"
	IntentDeleted   = "deleted"

	// edge relations
	RelSpawns      = "spawns"
	RelDerivedFrom = "derived_from"
	RelYields      = "yields"
	RelProves      = "proves"
	RelCovers      = "covers"
)

// ── models ───────────────────────────────────────────────────────────────────

type Exploration struct {
	ID          int64
	Description string
	Goal        string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ExplorationNode struct {
	ID            int64
	ExplorationID int64
	Kind          string
	Payload       string // JSON
	Priority      int
	State         string
	Origin        string
	Owner         string
	BlockedReason string
	DeleteReason  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	CompletedAt   time.Time
}

type ExplorationEdge struct {
	ExplorationID int64
	SrcID         int64
	DstID         int64
	Rel           string
	CreatedAt     time.Time
}

type Activity struct {
	ID               int64
	ExplorationID    int64
	NodeID           int64 // 0 = none
	Worker           string
	Kind             string
	Tool             string
	ToolUseID        string
	IsError          bool
	Summary          string
	Detail           string
	Metadata         string // JSON
	InputTokens      int
	OutputTokens     int
	CacheReadTokens  int
	CacheWriteTokens int
	CreatedAt        time.Time
}

type Task struct {
	ID                   int64
	Name                 string
	Description          string
	Goal                 string
	ExplorationID        int64
	Status               string
	Paused               bool
	Queued               bool
	QueuedAt             time.Time
	QueueMode            string
	LLMProfileID         int64
	ActiveLLMProfileID   int64
	CompanyID            int64
	ParentRef            string
	TimeoutSeconds       int
	PlanHeartbeatSeconds int
	CoverageEnabled      bool
	MaxWorkers           int
	PinnedAt             time.Time
	FirstRunAt           time.Time
	DeadlineAt           time.Time
	ArchivedAt           time.Time
	DeletedAt            time.Time
	CompletedAt          time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type FindingRetest struct {
	ID         int64
	FindingID  int64
	TaskID     int64
	Status     string
	Conclusion string
	FixVersion string
	Conditions string
	Notes      string
	Evidence   string
	SessionRef string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ── explorations ─────────────────────────────────────────────────────────────

func (s *Store) CreateExploration(goal, desc string) (*Exploration, error) {
	now := NowUTC()
	res, err := s.db.Exec(`INSERT INTO explorations (description, goal, status, created_at, updated_at)
		VALUES (?,?,?,?,?)`, desc, goal, "open", SqlTime(now), SqlTime(now))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Exploration{ID: id, Description: desc, Goal: goal, Status: "open", CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) GetExploration(id int64) (*Exploration, error) {
	row := s.db.QueryRow(`SELECT id, description, goal, status, created_at, updated_at FROM explorations WHERE id=?`, id)
	var e Exploration
	var c, u any
	if err := row.Scan(&e.ID, &e.Description, &e.Goal, &e.Status, &c, &u); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	e.CreatedAt, e.UpdatedAt = parseDBTime(c), parseDBTime(u)
	return &e, nil
}

func (s *Store) SetExplorationStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE explorations SET status=?, updated_at=? WHERE id=?`, status, SqlNow(), id)
	return err
}

// ── nodes ────────────────────────────────────────────────────────────────────

func (s *Store) CreateNode(n *ExplorationNode) error {
	if n.Payload == "" {
		n.Payload = "{}"
	}
	if n.State == "" {
		n.State = "open"
	}
	now := NowUTC()
	n.CreatedAt, n.UpdatedAt = now, now
	res, err := s.db.Exec(`INSERT INTO exploration_nodes
		(exploration_id, kind, payload, priority, state, origin, owner, blocked_reason, delete_reason, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		n.ExplorationID, n.Kind, n.Payload, n.Priority, n.State, n.Origin, n.Owner,
		n.BlockedReason, n.DeleteReason, SqlTime(now), SqlTime(now))
	if err != nil {
		return err
	}
	n.ID, _ = res.LastInsertId()
	return nil
}

func scanNode(row interface{ Scan(...any) error }) (*ExplorationNode, error) {
	var n ExplorationNode
	var origin, owner, blocked, del sql.NullString
	var c, u, comp any
	if err := row.Scan(&n.ID, &n.ExplorationID, &n.Kind, &n.Payload, &n.Priority, &n.State,
		&origin, &owner, &blocked, &del, &c, &u, &comp); err != nil {
		return nil, err
	}
	n.Origin, n.Owner, n.BlockedReason, n.DeleteReason = origin.String, owner.String, blocked.String, del.String
	n.CreatedAt, n.UpdatedAt, n.CompletedAt = parseDBTime(c), parseDBTime(u), parseDBTime(comp)
	return &n, nil
}

const nodeCols = `id, exploration_id, kind, payload, priority, state, origin, owner, blocked_reason, delete_reason, created_at, updated_at, completed_at`

func (s *Store) GetNode(id int64) (*ExplorationNode, error) {
	n, err := scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM exploration_nodes WHERE id=?`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return n, nil
}

// ListNodes returns an exploration's nodes, optionally filtered by kind (empty = all).
func (s *Store) ListNodes(explorationID int64, kind string) ([]ExplorationNode, error) {
	q := `SELECT ` + nodeCols + ` FROM exploration_nodes WHERE exploration_id=?`
	args := []any{explorationID}
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	q += ` ORDER BY id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExplorationNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func (s *Store) SetNodeState(id int64, state, reason string) error {
	now := NowUTC()
	done := ""
	if state == IntentDone || state == IntentStopped || state == IntentExhausted {
		done = SqlTime(now).(string)
	}
	if done != "" {
		_, err := s.db.Exec(`UPDATE exploration_nodes SET state=?, blocked_reason=?, updated_at=?, completed_at=? WHERE id=?`,
			state, reason, SqlTime(now), done, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE exploration_nodes SET state=?, blocked_reason=?, updated_at=? WHERE id=?`,
		state, reason, SqlTime(now), id)
	return err
}

func (s *Store) SetNodePayload(id int64, payload string) error {
	_, err := s.db.Exec(`UPDATE exploration_nodes SET payload=?, updated_at=? WHERE id=?`, payload, SqlNow(), id)
	return err
}

func (s *Store) SetNodeOwner(id int64, owner string) error {
	_, err := s.db.Exec(`UPDATE exploration_nodes SET owner=?, updated_at=? WHERE id=?`, owner, SqlNow(), id)
	return err
}

// ClaimNextIntent atomically picks the highest-priority open intent and marks it
// running + owned by worker. Returns ErrNotFound when the frontier is empty.
// Serialized by the single-writer SQLite connection.
func (s *Store) ClaimNextIntent(explorationID int64, worker string) (*ExplorationNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT `+nodeCols+` FROM exploration_nodes
		WHERE exploration_id=? AND kind='intent' AND state='open'
		ORDER BY priority DESC, id ASC LIMIT 1`, explorationID)
	n, err := scanNode(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	now := NowUTC()
	if _, err := s.db.Exec(`UPDATE exploration_nodes SET state='running', owner=?, updated_at=? WHERE id=?`,
		worker, SqlTime(now), n.ID); err != nil {
		return nil, err
	}
	n.State, n.Owner, n.UpdatedAt = IntentRunning, worker, now
	return n, nil
}

// CountOpenIntents reports how many intents are still claimable.
func (s *Store) CountOpenIntents(explorationID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM exploration_nodes
		WHERE exploration_id=? AND kind='intent' AND state IN ('open','running')`, explorationID).Scan(&n)
	return n, err
}

// ── edges ────────────────────────────────────────────────────────────────────

func (s *Store) AddEdge(explorationID, src, dst int64, rel string) error {
	if src == dst {
		return errors.New("edge cannot be self-referential")
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO exploration_edges (exploration_id, src_id, dst_id, rel, created_at)
		VALUES (?,?,?,?,?)`, explorationID, src, dst, rel, SqlNow())
	return err
}

func (s *Store) ListEdges(explorationID int64) ([]ExplorationEdge, error) {
	rows, err := s.db.Query(`SELECT exploration_id, src_id, dst_id, rel, created_at FROM exploration_edges WHERE exploration_id=? ORDER BY created_at`, explorationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExplorationEdge
	for rows.Next() {
		var e ExplorationEdge
		var c any
		if err := rows.Scan(&e.ExplorationID, &e.SrcID, &e.DstID, &e.Rel, &c); err != nil {
			return nil, err
		}
		e.CreatedAt = parseDBTime(c)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── anchors (connect exploration ↔ asset graph) ──────────────────────────────

func (s *Store) AddAnchor(nodeID, assetID int64) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO exploration_anchors (node_id, asset_id) VALUES (?,?)`, nodeID, assetID)
	return err
}

func (s *Store) ListAnchorsForNode(nodeID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT asset_id FROM exploration_anchors WHERE node_id=?`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CoveredAssetIDs returns the distinct asset ids that any node in the exploration
// anchors to — i.e. assets this task has actually probed (drives coverage).
func (s *Store) CoveredAssetIDs(explorationID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT DISTINCT a.asset_id FROM exploration_anchors a
		JOIN exploration_nodes n ON n.id = a.node_id
		WHERE n.exploration_id=?`, explorationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ── activity (per-step worker traces) ────────────────────────────────────────

func (s *Store) AppendActivity(a *Activity) error {
	if a.Metadata == "" {
		a.Metadata = "{}"
	}
	a.CreatedAt = NowUTC()
	res, err := s.db.Exec(`INSERT INTO activity
		(exploration_id, node_id, worker, kind, tool, tool_use_id, is_error, summary, detail, metadata,
		 input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ExplorationID, nullZero(a.NodeID), a.Worker, a.Kind, a.Tool, a.ToolUseID, a.IsError,
		a.Summary, a.Detail, a.Metadata, a.InputTokens, a.OutputTokens, a.CacheReadTokens,
		a.CacheWriteTokens, SqlTime(a.CreatedAt))
	if err != nil {
		return err
	}
	a.ID, _ = res.LastInsertId()
	return nil
}

func scanActivity(row interface{ Scan(...any) error }) (*Activity, error) {
	var a Activity
	var node sql.NullInt64
	var worker, kind, tool, tuid, summary, detail sql.NullString
	var it, ot, crt, cwt sql.NullInt64
	var c any
	if err := row.Scan(&a.ID, &a.ExplorationID, &node, &worker, &kind, &tool, &tuid, &a.IsError,
		&summary, &detail, &a.Metadata, &it, &ot, &crt, &cwt, &c); err != nil {
		return nil, err
	}
	a.NodeID = node.Int64
	a.Worker, a.Kind, a.Tool, a.ToolUseID = worker.String, kind.String, tool.String, tuid.String
	a.Summary, a.Detail = summary.String, detail.String
	a.InputTokens, a.OutputTokens = int(it.Int64), int(ot.Int64)
	a.CacheReadTokens, a.CacheWriteTokens = int(crt.Int64), int(cwt.Int64)
	a.CreatedAt = parseDBTime(c)
	return &a, nil
}

const activityCols = `id, exploration_id, node_id, worker, kind, tool, tool_use_id, is_error, summary, detail, metadata, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, created_at`

// ListActivity returns an exploration's steps, optionally scoped to one node.
func (s *Store) ListActivity(explorationID, nodeID int64, limit int) ([]Activity, error) {
	q := `SELECT ` + activityCols + ` FROM activity WHERE exploration_id=?`
	args := []any{explorationID}
	if nodeID > 0 {
		q += ` AND node_id=?`
		args = append(args, nodeID)
	}
	q += ` ORDER BY id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		a, err := scanActivity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// SearchActivity keyword-searches other workers' steps in a task, excluding the
// caller's own intent node (process-level info exchange between workers).
func (s *Store) SearchActivity(explorationID, excludeNodeID int64, q string, limit int) ([]Activity, error) {
	like := "%" + strings.ToLower(q) + "%"
	if limit <= 0 {
		limit = 30
	}
	rows, err := s.db.Query(`SELECT `+activityCols+` FROM activity
		WHERE exploration_id=? AND (node_id IS NULL OR node_id<>?)
		  AND (LOWER(summary) LIKE ? OR LOWER(detail) LIKE ?)
		ORDER BY id DESC LIMIT ?`,
		explorationID, excludeNodeID, like, like, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		a, err := scanActivity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// ── tasks ────────────────────────────────────────────────────────────────────

const taskCols = `id, name, description, goal, exploration_id, status, paused, queued, queued_at,
	queue_mode, llm_profile_id, active_llm_profile_id, company_id, parent_ref, timeout_seconds,
	plan_heartbeat_seconds, coverage_enabled, max_workers, pinned_at, first_run_at, deadline_at,
	archived_at, deleted_at, completed_at, created_at, updated_at`

func scanTask(row interface{ Scan(...any) error }) (*Task, error) {
	var t Task
	var queued, llm, active, company sql.NullInt64
	var qmode, pref sql.NullString
	var qat, pin, frun, dl, arch, del, comp, c, u any
	if err := row.Scan(&t.ID, &t.Name, &t.Description, &t.Goal, &t.ExplorationID, &t.Status,
		&t.Paused, &queued, &qat, &qmode, &llm, &active, &company, &pref, &t.TimeoutSeconds,
		&t.PlanHeartbeatSeconds, &t.CoverageEnabled, &t.MaxWorkers, &pin, &frun, &dl, &arch, &del,
		&comp, &c, &u); err != nil {
		return nil, err
	}
	t.Queued = queued.Int64 != 0
	t.LLMProfileID, t.ActiveLLMProfileID, t.CompanyID = llm.Int64, active.Int64, company.Int64
	t.QueueMode, t.ParentRef = qmode.String, pref.String
	t.QueuedAt, t.PinnedAt, t.FirstRunAt = parseDBTime(qat), parseDBTime(pin), parseDBTime(frun)
	t.DeadlineAt, t.ArchivedAt, t.DeletedAt, t.CompletedAt = parseDBTime(dl), parseDBTime(arch), parseDBTime(del), parseDBTime(comp)
	t.CreatedAt, t.UpdatedAt = parseDBTime(c), parseDBTime(u)
	return &t, nil
}

// CreateTask creates an exploration + a begin/goal node + the task row.
func (s *Store) CreateTask(t *Task) error {
	if t.MaxWorkers <= 0 {
		t.MaxWorkers = 3
	}
	if t.PlanHeartbeatSeconds <= 0 {
		t.PlanHeartbeatSeconds = 300
	}
	expl, err := s.CreateExploration(t.Goal, t.Description)
	if err != nil {
		return err
	}
	t.ExplorationID = expl.ID
	// seed a goal node so the planner has a root to reason from
	_ = s.CreateNode(&ExplorationNode{ExplorationID: expl.ID, Kind: NodeGoal, State: "open",
		Payload: `{"goal":` + jsonQuote(t.Goal) + `}`, Origin: "task"})
	now := NowUTC()
	t.CreatedAt, t.UpdatedAt = now, now
	if t.Status == "" {
		t.Status = "created"
	}
	res, err := s.db.Exec(`INSERT INTO tasks
		(name, description, goal, exploration_id, status, paused, queued, queue_mode, llm_profile_id,
		 active_llm_profile_id, company_id, parent_ref, timeout_seconds, plan_heartbeat_seconds,
		 coverage_enabled, max_workers, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.Name, t.Description, t.Goal, t.ExplorationID, t.Status, t.Paused, t.Queued, t.QueueMode,
		nullZero(t.LLMProfileID), nullZero(t.ActiveLLMProfileID), nullZero(t.CompanyID), t.ParentRef,
		t.TimeoutSeconds, t.PlanHeartbeatSeconds, t.CoverageEnabled, t.MaxWorkers, SqlTime(now), SqlTime(now))
	if err != nil {
		return err
	}
	t.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) GetTask(id int64) (*Task, error) {
	t, err := scanTask(s.db.QueryRow(`SELECT `+taskCols+` FROM tasks WHERE id=? AND deleted_at IS NULL`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

func (s *Store) ListTasks(status string) ([]Task, error) {
	q := `SELECT ` + taskCols + ` FROM tasks WHERE deleted_at IS NULL`
	args := []any{}
	if status != "" {
		q += ` AND status=?`
		args = append(args, status)
	}
	q += ` ORDER BY (pinned_at IS NOT NULL) DESC, id DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *Store) SetTaskStatus(id int64, status string) error {
	now := NowUTC()
	done := ""
	if status == "done" || status == "failed" || status == "timeout" {
		done = SqlTime(now).(string)
	}
	if done != "" {
		_, err := s.db.Exec(`UPDATE tasks SET status=?, completed_at=?, updated_at=? WHERE id=?`, status, done, SqlTime(now), id)
		return err
	}
	if status == "running" {
		_, err := s.db.Exec(`UPDATE tasks SET status=?, first_run_at=COALESCE(first_run_at, ?), updated_at=? WHERE id=?`,
			status, SqlTime(now), SqlTime(now), id)
		return err
	}
	_, err := s.db.Exec(`UPDATE tasks SET status=?, updated_at=? WHERE id=?`, status, SqlTime(now), id)
	return err
}

func (s *Store) SetTaskPaused(id int64, paused bool) error {
	_, err := s.db.Exec(`UPDATE tasks SET paused=?, updated_at=? WHERE id=?`, paused, SqlNow(), id)
	return err
}

func (s *Store) SetTaskActiveLLM(id, profileID int64) error {
	_, err := s.db.Exec(`UPDATE tasks SET active_llm_profile_id=?, updated_at=? WHERE id=?`, nullZero(profileID), SqlNow(), id)
	return err
}

func (s *Store) DeleteTask(id int64) error {
	_, err := s.db.Exec(`UPDATE tasks SET deleted_at=?, updated_at=? WHERE id=?`, SqlNow(), SqlNow(), id)
	return err
}

// ── finding retests ──────────────────────────────────────────────────────────

func (s *Store) CreateRetest(r *FindingRetest) error {
	now := NowUTC()
	r.CreatedAt, r.UpdatedAt = now, now
	if r.Status == "" {
		r.Status = "running"
	}
	res, err := s.db.Exec(`INSERT INTO finding_retests
		(finding_id, task_id, status, conclusion, fix_version, conditions, notes, evidence, session_ref, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		r.FindingID, nullZero(r.TaskID), r.Status, r.Conclusion, r.FixVersion, r.Conditions,
		r.Notes, r.Evidence, r.SessionRef, SqlTime(now), SqlTime(now))
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) ListRetests(findingID int64) ([]FindingRetest, error) {
	rows, err := s.db.Query(`SELECT id, finding_id, task_id, status, conclusion, fix_version, conditions,
		notes, evidence, session_ref, created_at, updated_at FROM finding_retests WHERE finding_id=? ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRetest
	for rows.Next() {
		var r FindingRetest
		var task sql.NullInt64
		var concl, fix, cond, notes, ev, sess sql.NullString
		var c, u any
		if err := rows.Scan(&r.ID, &r.FindingID, &task, &r.Status, &concl, &fix, &cond, &notes, &ev, &sess, &c, &u); err != nil {
			return nil, err
		}
		r.TaskID = task.Int64
		r.Conclusion, r.FixVersion, r.Conditions = concl.String, fix.String, cond.String
		r.Notes, r.Evidence, r.SessionRef = notes.String, ev.String, sess.String
		r.CreatedAt, r.UpdatedAt = parseDBTime(c), parseDBTime(u)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpdateRetest(id int64, status, conclusion, evidence string) error {
	_, err := s.db.Exec(`UPDATE finding_retests SET status=?, conclusion=?, evidence=?, updated_at=? WHERE id=?`,
		status, conclusion, evidence, SqlNow(), id)
	return err
}

// ── asset-graph bridge ───────────────────────────────────────────────────────

// AssetIDByValue returns the id of an asset by (type, value), or 0 if absent.
func (s *Store) AssetIDByValue(typ, value string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM assets WHERE type=? AND value=?`, typ, value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// UpsertAssetGetID upserts an asset and returns its id (new or existing).
func (s *Store) UpsertAssetGetID(a *Asset) (int64, error) {
	if err := s.UpsertAsset(a); err != nil {
		return 0, err
	}
	if a.ID != 0 {
		return a.ID, nil
	}
	return s.AssetIDByValue(a.Type, a.Value)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func nullZero(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// jsonQuote returns a JSON-encoded string literal (including surrounding quotes).
func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
