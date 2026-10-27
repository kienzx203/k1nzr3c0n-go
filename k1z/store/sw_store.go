// ScopeWeaver parity features — agent role configs, side-questions
// (human-in-the-loop), and asset-enrichment helpers. Additive.
package store

import (
	"database/sql"
	"errors"
	"time"
)

const swSchema = `
CREATE TABLE IF NOT EXISTS agent_configs (
	id             INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	role           TEXT NOT NULL UNIQUE,       -- goals|planner|worker|mainagent|retester
	name           TEXT NOT NULL DEFAULT '',
	prompt         TEXT NOT NULL DEFAULT '',   -- '' = built-in default
	llm_profile_id INTEGER NOT NULL DEFAULT 0, -- 0 = use task/global
	max_steps      INTEGER NOT NULL DEFAULT 0, -- 0 = engine default (run budget)
	tools          TEXT NOT NULL DEFAULT '',   -- JSON array of allowed tools; '' = all
	enabled        BOOLEAN NOT NULL DEFAULT 1,
	created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS side_questions (
	id             INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	exploration_id INTEGER NOT NULL,
	node_id        INTEGER,
	worker         TEXT,
	question       TEXT NOT NULL,
	answer         TEXT,
	status         TEXT NOT NULL DEFAULT 'pending', -- pending|answered|skipped
	created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
	answered_at    DATETIME
);
CREATE INDEX IF NOT EXISTS ix_side_q_expl ON side_questions (exploration_id);
CREATE INDEX IF NOT EXISTS ix_side_q_status ON side_questions (status);
`

// ── agent role configs ───────────────────────────────────────────────────────

type AgentConfig struct {
	ID           int64
	Role         string
	Name         string
	Description  string
	Kind         string // engine | assistant
	Prompt       string
	LLMProfileID int64
	MaxSteps     int
	Tools        string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// SeedAgentConfigs inserts the built-in agent roles (engine roles) and the
// built-in chat assistant agents (Auto + Penetration testing) once.
func (s *Store) SeedAgentConfigs() {
	// idempotent column migrations for existing DBs
	for _, q := range []string{
		`ALTER TABLE agent_configs ADD COLUMN description TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent_configs ADD COLUMN kind TEXT NOT NULL DEFAULT 'engine'`,
	} {
		_, _ = s.db.Exec(q)
	}
	defaults := []struct {
		role, name, kind, desc string
		steps                  int
	}{
		{"goals", "Goal decomposition", "engine", "Break a penetration-testing objective into independent, verifiable subgoals.", 10},
		{"planner", "Planner", "engine", "Review the situation and goals, adding exploration intents only for genuinely uncovered directions.", 14},
		{"worker", "Worker", "engine", "Claim and execute one intent, write facts and vulnerabilities back to the graph, then stop.", 18},
		{"mainagent", "Main agent", "engine", "Human interface: observe progress and turn user intent into hints or high-priority intents.", 12},
		{"retester", "Vulnerability retester", "engine", "Confirm whether a previously reported vulnerability is still reproducible.", 16},
		// chat assistant agents (selectable in the AI Agent chat)
		{"auto", "Auto", "assistant", "Platform assistant: manage tasks (create, inspect, pause, hint) and assets, and create or edit skills, custom tools, and MCP servers.", 24},
		{"pentest", "Penetration testing", "assistant", "Independent penetration-testing agent: handles reconnaissance, attack-surface discovery, exploitation, verification, and wrap-up with its own planning, execution, and adversarial validation.", 24},
	}
	for _, d := range defaults {
		_, _ = s.db.insertIgnore(`INSERT OR IGNORE INTO agent_configs (role, name, kind, description, max_steps, enabled, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?)`, d.role, d.name, d.kind, d.desc, d.steps, true, SqlNow(), SqlNow())
		// keep built-in name/description fresh without clobbering user edits to prompt/llm
		_, _ = s.db.Exec(`UPDATE agent_configs SET name=?, kind=?, description=? WHERE role=? AND (description='' OR description IS NULL)`,
			d.name, d.kind, d.desc, d.role)
	}
}

// ListChatAgents returns the selectable chat assistant agents.
func (s *Store) ListChatAgents() ([]AgentConfig, error) {
	rows, err := s.db.Query(`SELECT `+agentCfgCols+`, description, kind FROM agent_configs WHERE kind='assistant' AND enabled = ? ORDER BY role`, true)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentConfig
	for rows.Next() {
		var a AgentConfig
		var llm sql.NullInt64
		var c, u any
		if err := rows.Scan(&a.ID, &a.Role, &a.Name, &a.Prompt, &llm, &a.MaxSteps, &a.Tools, &a.Enabled, &c, &u, &a.Description, &a.Kind); err != nil {
			return nil, err
		}
		a.LLMProfileID = llm.Int64
		a.CreatedAt, a.UpdatedAt = parseDBTime(c), parseDBTime(u)
		out = append(out, a)
	}
	return out, rows.Err()
}

func scanAgentCfg(row interface{ Scan(...any) error }) (*AgentConfig, error) {
	var a AgentConfig
	var llm sql.NullInt64
	var c, u any
	if err := row.Scan(&a.ID, &a.Role, &a.Name, &a.Prompt, &llm, &a.MaxSteps, &a.Tools, &a.Enabled, &c, &u); err != nil {
		return nil, err
	}
	a.LLMProfileID = llm.Int64
	a.CreatedAt, a.UpdatedAt = parseDBTime(c), parseDBTime(u)
	return &a, nil
}

const agentCfgCols = `id, role, name, prompt, llm_profile_id, max_steps, tools, enabled, created_at, updated_at`

func (s *Store) GetAgentConfig(role string) (*AgentConfig, error) {
	a, err := scanAgentCfg(s.db.QueryRow(`SELECT `+agentCfgCols+` FROM agent_configs WHERE role=?`, role))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return a, nil
}

func (s *Store) ListAgentConfigs() ([]AgentConfig, error) {
	rows, err := s.db.Query(`SELECT ` + agentCfgCols + `, COALESCE(description,''), COALESCE(kind,'engine') FROM agent_configs ORDER BY (kind='assistant') DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentConfig
	for rows.Next() {
		var a AgentConfig
		var llm sql.NullInt64
		var c, u any
		if err := rows.Scan(&a.ID, &a.Role, &a.Name, &a.Prompt, &llm, &a.MaxSteps, &a.Tools, &a.Enabled, &c, &u, &a.Description, &a.Kind); err != nil {
			return nil, err
		}
		a.LLMProfileID = llm.Int64
		a.CreatedAt, a.UpdatedAt = parseDBTime(c), parseDBTime(u)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAgentConfig(role, prompt string, llmProfileID int64, maxSteps int, tools string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE agent_configs SET prompt=?, llm_profile_id=?, max_steps=?, tools=?, enabled=?, updated_at=? WHERE role=?`,
		prompt, llmProfileID, maxSteps, tools, enabled, SqlNow(), role)
	return err
}

// ── side-questions (human-in-the-loop) ───────────────────────────────────────

type SideQuestion struct {
	ID            int64
	ExplorationID int64
	NodeID        int64
	Worker        string
	Question      string
	Answer        string
	Status        string
	CreatedAt     time.Time
	AnsweredAt    time.Time
}

func (s *Store) CreateSideQuestion(explID, nodeID int64, worker, question string) (int64, error) {
	return s.db.insertReturningID(`INSERT INTO side_questions (exploration_id, node_id, worker, question, status, created_at)
		VALUES (?,?,?,?,?,?)`, explID, nullZero(nodeID), worker, question, "pending", SqlNow())
}

func (s *Store) AnswerSideQuestion(id int64, answer string) error {
	_, err := s.db.Exec(`UPDATE side_questions SET answer=?, status='answered', answered_at=? WHERE id=?`,
		answer, SqlNow(), id)
	return err
}

func (s *Store) SkipSideQuestion(id int64) error {
	_, err := s.db.Exec(`UPDATE side_questions SET status='skipped', answered_at=? WHERE id=?`, SqlNow(), id)
	return err
}

func scanSideQ(row interface{ Scan(...any) error }) (*SideQuestion, error) {
	var q SideQuestion
	var node sql.NullInt64
	var worker, ans sql.NullString
	var c, a any
	if err := row.Scan(&q.ID, &q.ExplorationID, &node, &worker, &q.Question, &ans, &q.Status, &c, &a); err != nil {
		return nil, err
	}
	q.NodeID, q.Worker, q.Answer = node.Int64, worker.String, ans.String
	q.CreatedAt, q.AnsweredAt = parseDBTime(c), parseDBTime(a)
	return &q, nil
}

const sideQCols = `id, exploration_id, node_id, worker, question, answer, status, created_at, answered_at`

func (s *Store) GetSideQuestion(id int64) (*SideQuestion, error) {
	q, err := scanSideQ(s.db.QueryRow(`SELECT `+sideQCols+` FROM side_questions WHERE id=?`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return q, nil
}

// ListSideQuestions returns a task's questions; onlyPending filters to pending.
func (s *Store) ListSideQuestions(explID int64, onlyPending bool) ([]SideQuestion, error) {
	q := `SELECT ` + sideQCols + ` FROM side_questions WHERE exploration_id=?`
	args := []any{explID}
	if onlyPending {
		q += ` AND status='pending'`
	}
	q += ` ORDER BY id DESC`
	return s.querySideQ(q, args...)
}

// ListPendingSideQuestions returns all pending questions across tasks.
func (s *Store) ListPendingSideQuestions() ([]SideQuestion, error) {
	return s.querySideQ(`SELECT ` + sideQCols + ` FROM side_questions WHERE status='pending' ORDER BY id DESC`)
}

func (s *Store) querySideQ(q string, args ...any) ([]SideQuestion, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SideQuestion
	for rows.Next() {
		sq, err := scanSideQ(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sq)
	}
	return out, rows.Err()
}

// ── asset enrichment ─────────────────────────────────────────────────────────

// UpdateAssetMeta replaces an asset's meta JSON.
func (s *Store) UpdateAssetMeta(id int64, meta string) error {
	_, err := s.db.Exec(`UPDATE assets SET meta=? WHERE id=?`, meta, id)
	return err
}

// ListAssetsForEnrich returns assets whose meta has not been marked enriched.
func (s *Store) ListAssetsForEnrich(limit int) ([]Asset, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, company_id, type, value, meta, source, created_at FROM assets
		WHERE meta NOT LIKE '%"enriched"%' ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		var cid sql.NullInt64
		var c any
		if err := rows.Scan(&a.ID, &cid, &a.Type, &a.Value, &a.Meta, &a.Source, &c); err != nil {
			return nil, err
		}
		if cid.Valid {
			v := cid.Int64
			a.CompanyID = &v
		}
		a.CreatedAt = parseDBTime(c)
		out = append(out, a)
	}
	return out, rows.Err()
}
