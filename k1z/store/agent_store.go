package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

// ── AI agent layer (ported concepts from ScopeWeaver) ────────────────────────

// LLMProfile is one configured LLM provider (GLM/Z.ai, OpenAI-compatible).
type LLMProfile struct {
	ID          int64
	Name        string
	BaseURL     string // e.g. https://api.z.ai/api/paas/v4
	APIKey      string
	Model       string // e.g. glm-4.7
	Temperature float64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Conversation is one agent chat thread.
type Conversation struct {
	ID          int64
	Title       string
	AgentKey    string // "recon-agent"
	PinnedAt    time.Time
	TotalTokens int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ChatRole: user | assistant | tool
type ChatMessage struct {
	ID             int64
	ConversationID int64
	Role           string
	Content        string
	ToolCalls      string // JSON array (assistant tool_calls), "" if none
	ToolCallID     string // for role=tool
	CreatedAt      time.Time
}

// Company groups assets by organization (ScopeWeaver company scope).
type Company struct {
	ID        int64
	Name      string
	Notes     *string
	CreatedAt time.Time
}

// Asset is one graph node: domain/subdomain/ip/port/site/endpoint.
type Asset struct {
	ID        int64
	CompanyID *int64
	Type      string // domain|subdomain|ip|port|site|endpoint
	Value     string // the hostname/ip/url
	Meta      string // JSON: title, tech, status_code...
	Source    string // run id / agent / manual
	CreatedAt time.Time
}

// TrafficPair is one captured HTTP request/response (recording proxy).
type TrafficPair struct {
	ID         int64
	RunID      *string // optional run linkage
	Host       string
	Method     string
	Path       string
	StatusCode int
	Request    string // full request head + body (capped)
	Response   string // full response head + body (capped)
	FindingID  *int64 // evidence binding
	CreatedAt  time.Time
}

// schema extension, applied by Open()
const agentSchema = `
CREATE TABLE IF NOT EXISTS llm_profiles (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name VARCHAR(128) NOT NULL UNIQUE,
	base_url TEXT NOT NULL,
	api_key TEXT NOT NULL,
	model VARCHAR(128) NOT NULL,
	temperature REAL DEFAULT 0.2,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS conversations (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	title VARCHAR(256) NOT NULL DEFAULT 'New chat',
	agent_key VARCHAR(64) NOT NULL DEFAULT 'recon-agent',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS chat_messages (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	conversation_id INTEGER NOT NULL,
	role VARCHAR(20) NOT NULL,
	content TEXT NOT NULL DEFAULT '',
	tool_calls TEXT NOT NULL DEFAULT '',
	tool_call_id VARCHAR(64) NOT NULL DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_chat_messages_conv ON chat_messages (conversation_id);
CREATE TABLE IF NOT EXISTS companies (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name VARCHAR(256) NOT NULL UNIQUE,
	notes TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assets (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	company_id INTEGER,
	type VARCHAR(20) NOT NULL,
	value VARCHAR(512) NOT NULL,
	meta TEXT NOT NULL DEFAULT '{}',
	source VARCHAR(64) NOT NULL DEFAULT 'manual',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_assets_company ON assets (company_id);
CREATE INDEX IF NOT EXISTS ix_assets_value ON assets (value);
CREATE TABLE IF NOT EXISTS traffic (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	run_id VARCHAR(16),
	host VARCHAR(512) NOT NULL,
	method VARCHAR(10) NOT NULL DEFAULT 'GET',
	path TEXT NOT NULL DEFAULT '/',
	status_code INTEGER,
	request TEXT NOT NULL DEFAULT '',
	response TEXT NOT NULL DEFAULT '',
	finding_id INTEGER,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_traffic_host ON traffic (host);
CREATE INDEX IF NOT EXISTS ix_traffic_finding ON traffic (finding_id);
CREATE TABLE IF NOT EXISTS traffic_rules (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	pattern VARCHAR(512) NOT NULL,
	action VARCHAR(10) NOT NULL DEFAULT 'block',
	enabled BOOLEAN DEFAULT 1,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS mcp_servers (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name VARCHAR(128) NOT NULL UNIQUE,
	command VARCHAR(512) NOT NULL,
	args TEXT NOT NULL DEFAULT '[]',
	enabled BOOLEAN DEFAULT 1,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS pending_approvals (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	method VARCHAR(10) NOT NULL,
	host VARCHAR(512) NOT NULL,
	path TEXT NOT NULL DEFAULT '/',
	dump TEXT NOT NULL DEFAULT '',
	decision VARCHAR(10),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	decided_at DATETIME
);
CREATE TABLE IF NOT EXISTS agent_rules (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	tool_pattern VARCHAR(128) NOT NULL,
	input_pattern VARCHAR(512) NOT NULL DEFAULT '',
	action VARCHAR(10) NOT NULL DEFAULT 'ask',
	enabled BOOLEAN DEFAULT 1,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS agent_audit (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	tool VARCHAR(64) NOT NULL,
	args TEXT NOT NULL DEFAULT '',
	result TEXT NOT NULL DEFAULT '',
	blocked INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notify_settings (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT CHECK (id = 1),
	webhook_url TEXT NOT NULL DEFAULT '',
	username TEXT NOT NULL DEFAULT 'k1nzr3c0n'
);
INSERT OR IGNORE INTO notify_settings (id, webhook_url, username) VALUES (1, '', 'k1nzr3c0n');
CREATE TABLE IF NOT EXISTS llm_usage (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	profile_id INTEGER,
	conversation_id INTEGER,
	prompt_tokens INTEGER NOT NULL DEFAULT 0,
	completion_tokens INTEGER NOT NULL DEFAULT 0,
	total_tokens INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_llm_usage_conv ON llm_usage (conversation_id);
`

// ── llm profiles ─────────────────────────────────────────────────────────────

// CreateLLMProfile upserts by name: re-submitting an existing name updates
// its credentials instead of failing the UNIQUE constraint.
func (s *Store) CreateLLMProfile(p *LLMProfile) error {
	now := NowUTC()
	p.CreatedAt, p.UpdatedAt = now, now
	id, err := s.db.insertReturningID(`INSERT INTO llm_profiles (name, base_url, api_key, model, temperature, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
		  base_url=excluded.base_url, api_key=excluded.api_key,
		  model=excluded.model, temperature=excluded.temperature,
		  updated_at=excluded.updated_at`,
		p.Name, p.BaseURL, p.APIKey, p.Model, p.Temperature, SqlTime(now), SqlTime(now))
	if err != nil {
		return err
	}
	if id > 0 {
		p.ID = id
		return nil
	}
	// upsert-hit: fetch the existing row id
	row := s.db.QueryRow(`SELECT id FROM llm_profiles WHERE name=?`, p.Name)
	_ = row.Scan(&p.ID)
	return nil
}

func (s *Store) UpdateLLMProfile(p *LLMProfile) error {
	p.UpdatedAt = NowUTC()
	_, err := s.db.Exec(`UPDATE llm_profiles SET name=?, base_url=?, api_key=?, model=?, temperature=?, updated_at=? WHERE id=?`,
		p.Name, p.BaseURL, p.APIKey, p.Model, p.Temperature, SqlTime(p.UpdatedAt), p.ID)
	return err
}

func (s *Store) DeleteLLMProfile(id int64) error {
	_, err := s.db.Exec(`DELETE FROM llm_profiles WHERE id=?`, id)
	return err
}

func (s *Store) GetLLMProfile(id int64) (*LLMProfile, error) {
	row := s.db.QueryRow(`SELECT id, name, base_url, api_key, model, temperature, created_at, updated_at FROM llm_profiles WHERE id=?`, id)
	var p LLMProfile
	var c, u any
	if err := row.Scan(&p.ID, &p.Name, &p.BaseURL, &p.APIKey, &p.Model, &p.Temperature, &c, &u); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.CreatedAt = parseDBTime(c)
	p.UpdatedAt = parseDBTime(u)
	return &p, nil
}

// ListLLMProfiles returns profiles with keys masked.
func (s *Store) ListLLMProfiles() ([]LLMProfile, error) {
	rows, err := s.db.Query(`SELECT id, name, base_url, api_key, model, temperature, created_at, updated_at FROM llm_profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LLMProfile
	for rows.Next() {
		var p LLMProfile
		var c, u any
		if err := rows.Scan(&p.ID, &p.Name, &p.BaseURL, &p.APIKey, &p.Model, &p.Temperature, &c, &u); err != nil {
			return nil, err
		}
		p.CreatedAt = parseDBTime(c)
		p.UpdatedAt = parseDBTime(u)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── conversations ────────────────────────────────────────────────────────────

func (s *Store) CreateConversation(title, agentKey string) (*Conversation, error) {
	if title == "" {
		title = "New chat"
	}
	if agentKey == "" {
		agentKey = "recon-agent"
	}
	id, err := s.db.insertReturningID(`INSERT INTO conversations (title, agent_key, created_at, updated_at) VALUES (?,?,?,?)`,
		title, agentKey, SqlNow(), SqlNow())
	if err != nil {
		return nil, err
	}
	return &Conversation{ID: id, Title: title, AgentKey: agentKey, CreatedAt: NowUTC(), UpdatedAt: NowUTC()}, nil
}

func (s *Store) ListConversations() ([]Conversation, error) {
	rows, err := s.db.Query(`SELECT id, title, agent_key, pinned_at, total_tokens, created_at, updated_at
		FROM conversations ORDER BY (pinned_at IS NOT NULL) DESC, updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Conversation
	for rows.Next() {
		var c Conversation
		var pin, ct, ut any
		var tok sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Title, &c.AgentKey, &pin, &tok, &ct, &ut); err != nil {
			return nil, err
		}
		c.PinnedAt = parseDBTime(pin)
		c.TotalTokens = int(tok.Int64)
		c.CreatedAt = parseDBTime(ct)
		c.UpdatedAt = parseDBTime(ut)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetConversationPinned pins/unpins a conversation.
func (s *Store) SetConversationPinned(id int64, pinned bool) error {
	if pinned {
		_, err := s.db.Exec(`UPDATE conversations SET pinned_at=? WHERE id=?`, SqlNow(), id)
		return err
	}
	_, err := s.db.Exec(`UPDATE conversations SET pinned_at=NULL WHERE id=?`, id)
	return err
}

// RenameConversation updates the title.
func (s *Store) RenameConversation(id int64, title string) error {
	if title == "" {
		return nil
	}
	_, err := s.db.Exec(`UPDATE conversations SET title=?, updated_at=? WHERE id=?`, title, SqlNow(), id)
	return err
}

// DeleteConversationsBatch removes several conversations and their messages.
func (s *Store) DeleteConversationsBatch(ids []int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if _, err := s.db.Exec(`DELETE FROM chat_messages WHERE conversation_id=?`, id); err != nil {
			return err
		}
		if _, err := s.db.Exec(`DELETE FROM conversations WHERE id=?`, id); err != nil {
			return err
		}
	}
	return nil
}

// AddConversationTokens accumulates a turn's token usage onto the conversation.
func (s *Store) AddConversationTokens(id int64, tokens int) {
	if tokens <= 0 {
		return
	}
	_, _ = s.db.Exec(`UPDATE conversations SET total_tokens = COALESCE(total_tokens,0) + ? WHERE id=?`, tokens, id)
}

func (s *Store) DeleteConversation(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM chat_messages WHERE conversation_id=?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM conversations WHERE id=?`, id)
	return err
}

func (s *Store) TouchConversation(id int64) {
	_, _ = s.db.Exec(`UPDATE conversations SET updated_at=? WHERE id=?`, SqlNow(), id)
}

// ── chat messages ────────────────────────────────────────────────────────────

func (s *Store) InsertChatMessage(m *ChatMessage) error {
	m.CreatedAt = NowUTC()
	id, err := s.db.insertReturningID(`INSERT INTO chat_messages (conversation_id, role, content, tool_calls, tool_call_id, created_at)
		VALUES (?,?,?,?,?,?)`, m.ConversationID, m.Role, m.Content, m.ToolCalls, m.ToolCallID, SqlTime(m.CreatedAt))
	if err != nil {
		return err
	}
	m.ID = id
	s.TouchConversation(m.ConversationID)
	return nil
}

func (s *Store) ListChatMessages(conversationID int64) ([]ChatMessage, error) {
	rows, err := s.db.Query(`SELECT id, conversation_id, role, content, tool_calls, tool_call_id, created_at
		FROM chat_messages WHERE conversation_id=? ORDER BY id ASC`, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChatMessage
	for rows.Next() {
		var m ChatMessage
		var ct any
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content, &m.ToolCalls, &m.ToolCallID, &ct); err != nil {
			return nil, err
		}
		m.CreatedAt = parseDBTime(ct)
		out = append(out, m)
	}
	return out, rows.Err()
}

// ── companies + assets ───────────────────────────────────────────────────────

func (s *Store) UpsertCompany(name string, notes *string) (*Company, error) {
	existing, err := s.db.Query(`SELECT id FROM companies WHERE name=?`, name)
	if err == nil {
		defer existing.Close()
		if existing.Next() {
			var id int64
			_ = existing.Scan(&id)
			return &Company{ID: id, Name: name}, nil
		}
	}
	id, err := s.db.insertReturningID(`INSERT INTO companies (name, notes, created_at) VALUES (?,?,?)`, name, notes, SqlNow())
	if err != nil {
		return nil, err
	}
	return &Company{ID: id, Name: name, Notes: notes, CreatedAt: NowUTC()}, nil
}

func (s *Store) ListCompanies() ([]Company, error) {
	rows, err := s.db.Query(`SELECT id, name, notes, created_at FROM companies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Company
	for rows.Next() {
		var c Company
		var ct any
		if err := rows.Scan(&c.ID, &c.Name, &c.Notes, &ct); err != nil {
			return nil, err
		}
		c.CreatedAt = parseDBTime(ct)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteCompany(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`UPDATE assets SET company_id=NULL WHERE company_id=?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM companies WHERE id=?`, id)
	return err
}

// UpsertAsset inserts the asset unless (type, value) already exists; meta merged.
func (s *Store) UpsertAsset(a *Asset) error {
	if a.Meta == "" {
		a.Meta = "{}"
	}
	if a.Source == "" {
		a.Source = "manual"
	}
	existing, err := s.db.Query(`SELECT id, meta FROM assets WHERE type=? AND value=?`, a.Type, a.Value)
	if err != nil {
		return err
	}
	defer existing.Close()
	if existing.Next() {
		var id int64
		var meta string
		_ = existing.Scan(&id, &meta)
		if a.CompanyID != nil {
			_, _ = s.db.Exec(`UPDATE assets SET company_id=? WHERE id=?`, *a.CompanyID, id)
		}
		return nil // dedupe
	}
	a.CreatedAt = NowUTC()
	id, err := s.db.insertReturningID(`INSERT INTO assets (company_id, type, value, meta, source, created_at) VALUES (?,?,?,?,?,?)`,
		a.CompanyID, a.Type, a.Value, a.Meta, a.Source, SqlTime(a.CreatedAt))
	if err != nil {
		return err
	}
	a.ID = id
	return nil
}

type GraphAssetFilter struct {
	CompanyID int64
	Type      string
	Q         string
	Limit     int
}

func (s *Store) ListAssetsGraph(f GraphAssetFilter) ([]Asset, error) {
	where, args := "1=1", []any{}
	if f.CompanyID > 0 {
		where += " AND company_id=?"
		args = append(args, f.CompanyID)
	}
	if f.Type != "" {
		where += " AND type=?"
		args = append(args, f.Type)
	}
	if f.Q != "" {
		where += " AND value LIKE ?"
		args = append(args, "%"+f.Q+"%")
	}
	limit := f.Limit
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT id, company_id, type, value, meta, source, created_at FROM assets WHERE `+where+` ORDER BY id DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		var ct any
		if err := rows.Scan(&a.ID, &a.CompanyID, &a.Type, &a.Value, &a.Meta, &a.Source, &ct); err != nil {
			return nil, err
		}
		a.CreatedAt = parseDBTime(ct)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAsset(id int64) error {
	_, err := s.db.Exec(`DELETE FROM assets WHERE id=?`, id)
	return err
}

// ── traffic ──────────────────────────────────────────────────────────────────

func (s *Store) InsertTraffic(t *TrafficPair) error {
	t.CreatedAt = NowUTC()
	id, err := s.db.insertReturningID(`INSERT INTO traffic (run_id, host, method, path, status_code, request, response, finding_id, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, t.RunID, t.Host, t.Method, t.Path, t.StatusCode, t.Request, t.Response, t.FindingID, SqlTime(t.CreatedAt))
	if err != nil {
		return err
	}
	t.ID = id
	return nil
}

func (s *Store) ListTraffic(host string, limit int) ([]TrafficPair, error) {
	where, args := "1=1", []any{}
	if host != "" {
		where += " AND host LIKE ?"
		args = append(args, "%"+host+"%")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, run_id, host, method, path, status_code, request, response, finding_id, created_at
		FROM traffic WHERE `+where+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficPair
	for rows.Next() {
		var t TrafficPair
		var ct any
		if err := rows.Scan(&t.ID, &t.RunID, &t.Host, &t.Method, &t.Path, &t.StatusCode, &t.Request, &t.Response, &t.FindingID, &ct); err != nil {
			return nil, err
		}
		t.CreatedAt = parseDBTime(ct)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTraffic(id int64) (*TrafficPair, error) {
	row := s.db.QueryRow(`SELECT id, run_id, host, method, path, status_code, request, response, finding_id, created_at FROM traffic WHERE id=?`, id)
	var t TrafficPair
	var ct any
	if err := row.Scan(&t.ID, &t.RunID, &t.Host, &t.Method, &t.Path, &t.StatusCode, &t.Request, &t.Response, &t.FindingID, &ct); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt = parseDBTime(ct)
	return &t, nil
}

// BindTrafficEvidence attaches a captured pair to a finding as evidence.
func (s *Store) BindTrafficEvidence(trafficID, findingID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE traffic SET finding_id=? WHERE id=?`, findingID, trafficID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

var _ = strings.TrimSpace

// InsertLLMUsage records one turn's token usage.
func (s *Store) InsertLLMUsage(profileID, conversationID int64, prompt, completion, total int) error {
	_, err := s.db.Exec(`INSERT INTO llm_usage (profile_id, conversation_id, prompt_tokens, completion_tokens, total_tokens, created_at)
		VALUES (?,?,?,?,?,?)`, profileID, conversationID, prompt, completion, total, SqlNow())
	return err
}

// LLMUsageSummary aggregates usage over all turns.
type LLMUsageSummary struct {
	Turns            int64 `json:"turns"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

func (s *Store) LLMUsageTotals() (LLMUsageSummary, error) {
	var u LLMUsageSummary
	err := s.db.QueryRow(`SELECT count(*), COALESCE(SUM(prompt_tokens),0),
		COALESCE(SUM(completion_tokens),0), COALESCE(SUM(total_tokens),0) FROM llm_usage`).
		Scan(&u.Turns, &u.PromptTokens, &u.CompletionTokens, &u.TotalTokens)
	return u, err
}

// TrafficRule blocks or flags hosts matching a substring pattern.
type TrafficRule struct {
	ID      int64  `json:"id"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // block | flag
	Enabled bool   `json:"enabled"`
}

func (s *Store) ListTrafficRules() ([]TrafficRule, error) {
	rows, err := s.db.Query(`SELECT id, pattern, action, enabled FROM traffic_rules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficRule
	for rows.Next() {
		var r TrafficRule
		if err := rows.Scan(&r.ID, &r.Pattern, &r.Action, &r.Enabled); err == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

func (s *Store) CreateTrafficRule(pattern, action string) error {
	switch action {
	case "flag", "hold", "block":
	default:
		action = "block"
	}
	_, err := s.db.Exec(`INSERT INTO traffic_rules (pattern, action, enabled, created_at) VALUES (?,?,?,?)`,
		pattern, action, true, SqlNow())
	return err
}

func (s *Store) DeleteTrafficRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM traffic_rules WHERE id=?`, id)
	return err
}

// MatchTrafficRule returns (matched rule, true) for a host — first enabled hit wins.
func (s *Store) MatchTrafficRule(host string) (TrafficRule, bool) {
	rules, err := s.ListTrafficRules()
	if err != nil {
		return TrafficRule{}, false
	}
	for _, r := range rules {
		if r.Enabled && strings.Contains(strings.ToLower(host), strings.ToLower(r.Pattern)) {
			return r, true
		}
	}
	return TrafficRule{}, false
}

// MCPServer is one configured stdio MCP server.
type MCPServer struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Enabled bool     `json:"enabled"`
}

func (s *Store) CreateMCP(m MCPServer) (int64, error) {
	args, _ := json.Marshal(m.Args)
	id, err := s.db.insertReturningID(`INSERT INTO mcp_servers (name, command, args, enabled, created_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET command=excluded.command, args=excluded.args, enabled=excluded.enabled`,
		m.Name, m.Command, string(args), m.Enabled, SqlNow())
	if err != nil {
		return 0, err
	}
	if id > 0 {
		return id, nil
	}
	_ = s.db.QueryRow(`SELECT id FROM mcp_servers WHERE name=?`, m.Name).Scan(&id)
	return id, nil
}

func (s *Store) ListMCP() ([]MCPServer, error) {
	rows, err := s.db.Query(`SELECT id, name, command, args, enabled FROM mcp_servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPServer
	for rows.Next() {
		var m MCPServer
		var argsJSON string
		if err := rows.Scan(&m.ID, &m.Name, &m.Command, &argsJSON, &m.Enabled); err == nil {
			_ = json.Unmarshal([]byte(argsJSON), &m.Args)
			out = append(out, m)
		}
	}
	return out, rows.Err()
}

func (s *Store) DeleteMCP(id int64) error {
	_, err := s.db.Exec(`DELETE FROM mcp_servers WHERE id=?`, id)
	return err
}

// PendingApproval is one held request awaiting an approve/deny decision.
type PendingApproval struct {
	ID        int64     `json:"id"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Dump      string    `json:"dump"`
	Decision  *string   `json:"decision"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) InsertPendingApproval(method, host, path, dump string) (int64, error) {
	id, err := s.db.insertReturningID(`INSERT INTO pending_approvals (method, host, path, dump, created_at) VALUES (?,?,?,?,?)`,
		method, host, path, dump, SqlNow())
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) SetApprovalDecision(id int64, decision string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE pending_approvals SET decision=?, decided_at=? WHERE id=?`, decision, SqlNow(), id)
	return err
}

// GetApproval fetches one approval row (poll for decision).
func (s *Store) GetApproval(id int64) (*PendingApproval, error) {
	row := s.db.QueryRow(`SELECT id, method, host, path, dump, decision, created_at FROM pending_approvals WHERE id=?`, id)
	var a PendingApproval
	var dec sql.NullString
	var ct any
	if err := row.Scan(&a.ID, &a.Method, &a.Host, &a.Path, &a.Dump, &dec, &ct); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if dec.Valid {
		a.Decision = &dec.String
	}
	a.CreatedAt = parseDBTime(ct)
	return &a, nil
}

func (s *Store) ListPendingApprovals(onlyPending bool) ([]PendingApproval, error) {
	q := `SELECT id, method, host, path, dump, decision, created_at FROM pending_approvals`
	if onlyPending {
		q += ` WHERE decision IS NULL`
	}
	q += ` ORDER BY id DESC LIMIT 200`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingApproval
	for rows.Next() {
		var a PendingApproval
		var dec sql.NullString
		var ct any
		if err := rows.Scan(&a.ID, &a.Method, &a.Host, &a.Path, &a.Dump, &dec, &ct); err == nil {
			if dec.Valid {
				a.Decision = &dec.String
			}
			a.CreatedAt = parseDBTime(ct)
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

// AgentRule gates agent tool calls: allow | deny | ask.
type AgentRule struct {
	ID           int64  `json:"id"`
	ToolPattern  string `json:"tool_pattern"`
	InputPattern string `json:"input_pattern"`
	Action       string `json:"action"`
	Enabled      bool   `json:"enabled"`
}

func (s *Store) ListAgentRules() ([]AgentRule, error) {
	rows, err := s.db.Query(`SELECT id, tool_pattern, input_pattern, action, enabled FROM agent_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentRule
	for rows.Next() {
		var r AgentRule
		if err := rows.Scan(&r.ID, &r.ToolPattern, &r.InputPattern, &r.Action, &r.Enabled); err == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

func (s *Store) CreateAgentRule(toolPat, inputPat, action string) error {
	switch action {
	case "allow", "deny", "ask":
	default:
		action = "ask"
	}
	_, err := s.db.Exec(`INSERT INTO agent_rules (tool_pattern, input_pattern, action, enabled, created_at) VALUES (?,?,?,?,?)`,
		toolPat, inputPat, action, true, SqlNow())
	return err
}

func (s *Store) DeleteAgentRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM agent_rules WHERE id=?`, id)
	return err
}

// MatchAgentRule returns the first enabled rule matching a tool call.
func (s *Store) MatchAgentRule(tool, input string) (AgentRule, bool) {
	rules, err := s.ListAgentRules()
	if err != nil {
		return AgentRule{}, false
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if !matchPattern(r.ToolPattern, tool) {
			continue
		}
		if r.InputPattern != "" && !matchPattern(r.InputPattern, input) {
			continue
		}
		return r, true
	}
	return AgentRule{}, false
}

// matchPattern: empty matches all; "re:" prefix = regex; else substring.
func matchPattern(pat, s string) bool {
	if pat == "" || pat == "*" {
		return true
	}
	if strings.HasPrefix(pat, "re:") {
		if re, err := regexp.Compile("(?i)" + strings.TrimPrefix(pat, "re:")); err == nil {
			return re.MatchString(s)
		}
		return false
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(pat))
}

// InsertAgentAudit records one tool call (blocked=1 when a rule denied it).
func (s *Store) InsertAgentAudit(tool, args, result string, blocked bool) error {
	b := 0
	if blocked {
		b = 1
	}
	_, err := s.db.Exec(`INSERT INTO agent_audit (tool, args, result, blocked, created_at) VALUES (?,?,?,?,?)`,
		tool, truncateStr(args, 2000), truncateStr(result, 2000), b, SqlNow())
	return err
}

func (s *Store) ListAgentAudit(limit int) ([]map[string]any, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, tool, args, result, blocked, created_at FROM agent_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, blocked int64
		var tool, args, result string
		var ct any
		if err := rows.Scan(&id, &tool, &args, &result, &blocked, &ct); err == nil {
			out = append(out, map[string]any{"id": id, "tool": tool, "args": args, "result": result,
				"blocked": blocked == 1, "created_at": parseDBTime(ct)})
		}
	}
	return out, rows.Err()
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// UntestedAssets lists graph assets never seen in any finding host.
func (s *Store) UntestedAssets(limit int) ([]Asset, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, company_id, type, value, meta, source, created_at FROM assets
		WHERE value NOT IN (SELECT DISTINCT host FROM findings)
		ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		var ct any
		if err := rows.Scan(&a.ID, &a.CompanyID, &a.Type, &a.Value, &a.Meta, &a.Source, &ct); err == nil {
			a.CreatedAt = parseDBTime(ct)
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

// NotifySettings is the single-row webhook configuration.
type NotifySettings struct {
	WebhookURL string `json:"webhook_url"`
	Username   string `json:"username"`
}

func (s *Store) GetNotifySettings() NotifySettings {
	var n NotifySettings
	_ = s.db.QueryRow(`SELECT webhook_url, username FROM notify_settings WHERE id=1`).Scan(&n.WebhookURL, &n.Username)
	return n
}

func (s *Store) SetNotifySettings(n NotifySettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE notify_settings SET webhook_url=?, username=? WHERE id=1`, n.WebhookURL, n.Username)
	return err
}

// ListLLMUsageRows returns recent usage turns (newest first).
type LLMUsageRow struct {
	ID               int64     `json:"id"`
	ProfileID        int64     `json:"profile_id"`
	ConversationID   int64     `json:"conversation_id"`
	PromptTokens     int64     `json:"prompt_tokens"`
	CompletionTokens int64     `json:"completion_tokens"`
	TotalTokens      int64     `json:"total_tokens"`
	CreatedAt        time.Time `json:"created_at"`
}

func (s *Store) ListLLMUsageRows(limit int) ([]LLMUsageRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, profile_id, conversation_id, prompt_tokens, completion_tokens, total_tokens, created_at
		FROM llm_usage ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LLMUsageRow{}
	for rows.Next() {
		var u LLMUsageRow
		var ct any
		if err := rows.Scan(&u.ID, &u.ProfileID, &u.ConversationID, &u.PromptTokens, &u.CompletionTokens, &u.TotalTokens, &ct); err == nil {
			u.CreatedAt = parseDBTime(ct)
			out = append(out, u)
		}
	}
	return out, rows.Err()
}
