// Skill usage ledger (ScopeWeaver parity) — one row per load_skill invocation,
// powering the Skill library overview (calls, ranking, unused, unmatched). Additive.
package store

import "time"

const skillSchema = `
CREATE TABLE IF NOT EXISTS skill_usage (
	id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	skill      TEXT NOT NULL,
	agent_key  TEXT,
	task_id    INTEGER,
	session_id TEXT,
	args_len   INTEGER NOT NULL DEFAULT 0,
	found      BOOLEAN NOT NULL DEFAULT 1,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_skill_usage_skill ON skill_usage (skill);
CREATE INDEX IF NOT EXISTS ix_skill_usage_found ON skill_usage (found);
`

type SkillStat struct {
	Skill    string
	Calls    int
	Agents   []string
	LastUsed time.Time
}

type SkillCall struct {
	ID        int64
	Skill     string
	AgentKey  string
	SessionID string
	Found     bool
	CreatedAt time.Time
}

// InsertSkillUsage appends one ledger row (best-effort).
func (s *Store) InsertSkillUsage(skill, agentKey, sessionID string, argsLen int, found bool) {
	_, _ = s.db.Exec(`INSERT INTO skill_usage (skill, agent_key, session_id, args_len, found, created_at)
		VALUES (?,?,?,?,?,?)`, skill, nullStr(agentKey), nullStr(sessionID), argsLen, found, SqlNow())
}

func nullStr(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// SkillStats aggregates resolved (found=1) calls grouped by skill, most-used first.
func (s *Store) SkillStats() ([]SkillStat, error) {
	rows, err := s.db.Query(`SELECT skill, COUNT(*) AS n,
		GROUP_CONCAT(DISTINCT COALESCE(agent_key,'')) AS agents, MAX(created_at) AS last
		FROM skill_usage WHERE found=1 GROUP BY skill ORDER BY n DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkillStat
	for rows.Next() {
		var st SkillStat
		var agents string
		var last any
		if err := rows.Scan(&st.Skill, &st.Calls, &agents, &last); err != nil {
			return nil, err
		}
		for _, a := range splitNonEmpty(agents) {
			st.Agents = append(st.Agents, a)
		}
		st.LastUsed = parseDBTime(last)
		out = append(out, st)
	}
	return out, rows.Err()
}

// MissingSkillStats aggregates unmatched (found=0) calls grouped by named skill.
func (s *Store) MissingSkillStats() ([]SkillStat, error) {
	rows, err := s.db.Query(`SELECT skill, COUNT(*) n, MAX(created_at) last
		FROM skill_usage WHERE found=0 GROUP BY skill ORDER BY n DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkillStat
	for rows.Next() {
		var st SkillStat
		var last any
		if err := rows.Scan(&st.Skill, &st.Calls, &last); err != nil {
			return nil, err
		}
		st.LastUsed = parseDBTime(last)
		out = append(out, st)
	}
	return out, rows.Err()
}

// RecentSkillCalls returns the most recent calls; skill="" = all skills.
func (s *Store) RecentSkillCalls(skill string, limit int) ([]SkillCall, error) {
	if limit <= 0 {
		limit = 20
	}
	q := `SELECT id, skill, COALESCE(agent_key,''), COALESCE(session_id,''), found, created_at FROM skill_usage`
	args := []any{}
	if skill != "" {
		q += ` WHERE skill=?`
		args = append(args, skill)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkillCall
	for rows.Next() {
		var c SkillCall
		var created any
		if err := rows.Scan(&c.ID, &c.Skill, &c.AgentKey, &c.SessionID, &c.Found, &created); err != nil {
			return nil, err
		}
		c.CreatedAt = parseDBTime(created)
		out = append(out, c)
	}
	return out, rows.Err()
}

// TotalSkillCalls counts all resolved skill invocations.
func (s *Store) TotalSkillCalls() int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM skill_usage WHERE found=1`).Scan(&n)
	return n
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range splitComma(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	out = append(out, cur)
	return out
}
