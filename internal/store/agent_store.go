package store

import (
	"database/sql"
	"errors"
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
	ID        int64
	Title     string
	AgentKey  string // "recon-agent"
	CreatedAt time.Time
	UpdatedAt time.Time
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
`

// ── llm profiles ─────────────────────────────────────────────────────────────

func (s *Store) CreateLLMProfile(p *LLMProfile) error {
	p.CreatedAt = NowUTC()
	p.UpdatedAt = p.CreatedAt
	res, err := s.db.Exec(`INSERT INTO llm_profiles (name, base_url, api_key, model, temperature, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?)`, p.Name, p.BaseURL, p.APIKey, p.Model, p.Temperature, SqlTime(p.CreatedAt), SqlTime(p.UpdatedAt))
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
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
	res, err := s.db.Exec(`INSERT INTO conversations (title, agent_key, created_at, updated_at) VALUES (?,?,?,?)`,
		title, agentKey, SqlNow(), SqlNow())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Conversation{ID: id, Title: title, AgentKey: agentKey, CreatedAt: NowUTC(), UpdatedAt: NowUTC()}, nil
}

func (s *Store) ListConversations() ([]Conversation, error) {
	rows, err := s.db.Query(`SELECT id, title, agent_key, created_at, updated_at FROM conversations ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Conversation
	for rows.Next() {
		var c Conversation
		var ct, ut any
		if err := rows.Scan(&c.ID, &c.Title, &c.AgentKey, &ct, &ut); err != nil {
			return nil, err
		}
		c.CreatedAt = parseDBTime(ct)
		c.UpdatedAt = parseDBTime(ut)
		out = append(out, c)
	}
	return out, rows.Err()
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
	res, err := s.db.Exec(`INSERT INTO chat_messages (conversation_id, role, content, tool_calls, tool_call_id, created_at)
		VALUES (?,?,?,?,?,?)`, m.ConversationID, m.Role, m.Content, m.ToolCalls, m.ToolCallID, SqlTime(m.CreatedAt))
	if err != nil {
		return err
	}
	m.ID, _ = res.LastInsertId()
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
	res, err := s.db.Exec(`INSERT INTO companies (name, notes, created_at) VALUES (?,?,?)`, name, notes, SqlNow())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
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
	res, err := s.db.Exec(`INSERT INTO assets (company_id, type, value, meta, source, created_at) VALUES (?,?,?,?,?,?)`,
		a.CompanyID, a.Type, a.Value, a.Meta, a.Source, SqlTime(a.CreatedAt))
	if err != nil {
		return err
	}
	a.ID, _ = res.LastInsertId()
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
	res, err := s.db.Exec(`INSERT INTO traffic (run_id, host, method, path, status_code, request, response, finding_id, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, t.RunID, t.Host, t.Method, t.Path, t.StatusCode, t.Request, t.Response, t.FindingID, SqlTime(t.CreatedAt))
	if err != nil {
		return err
	}
	t.ID, _ = res.LastInsertId()
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
