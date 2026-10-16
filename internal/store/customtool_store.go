// Custom tools (ScopeWeaver parity) — user-defined command/script/http tools
// with a JSON-Schema parameter spec, exposed to the chat agent. Additive.
package store

import (
	"database/sql"
	"errors"
	"time"
)

const customToolSchema = `
CREATE TABLE IF NOT EXISTS custom_tools (
	key         TEXT NOT NULL PRIMARY KEY,
	description TEXT NOT NULL DEFAULT '',
	kind        TEXT NOT NULL DEFAULT 'command',  -- command | script | http
	schema      TEXT NOT NULL DEFAULT '{}',        -- JSON Schema for params
	exec        TEXT NOT NULL DEFAULT '{}',        -- JSON: {command} or {method,url,headers}
	enabled     BOOLEAN NOT NULL DEFAULT 1,
	created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

type CustomTool struct {
	Key         string
	Description string
	Kind        string
	Schema      string
	Exec        string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (s *Store) UpsertCustomTool(t *CustomTool) error {
	if t.Schema == "" {
		t.Schema = "{}"
	}
	if t.Exec == "" {
		t.Exec = "{}"
	}
	if t.Kind == "" {
		t.Kind = "command"
	}
	_, err := s.db.Exec(`INSERT INTO custom_tools (key, description, kind, schema, exec, enabled, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET description=excluded.description, kind=excluded.kind,
		  schema=excluded.schema, exec=excluded.exec, enabled=excluded.enabled, updated_at=excluded.updated_at`,
		t.Key, t.Description, t.Kind, t.Schema, t.Exec, t.Enabled, SqlNow(), SqlNow())
	return err
}

func (s *Store) DeleteCustomTool(key string) error {
	_, err := s.db.Exec(`DELETE FROM custom_tools WHERE key=?`, key)
	return err
}

func scanCustomTool(row interface{ Scan(...any) error }) (*CustomTool, error) {
	var t CustomTool
	var c, u any
	if err := row.Scan(&t.Key, &t.Description, &t.Kind, &t.Schema, &t.Exec, &t.Enabled, &c, &u); err != nil {
		return nil, err
	}
	t.CreatedAt, t.UpdatedAt = parseDBTime(c), parseDBTime(u)
	return &t, nil
}

func (s *Store) GetCustomTool(key string) (*CustomTool, error) {
	t, err := scanCustomTool(s.db.QueryRow(`SELECT key, description, kind, schema, exec, enabled, created_at, updated_at FROM custom_tools WHERE key=?`, key))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

func (s *Store) ListCustomTools() ([]CustomTool, error) {
	rows, err := s.db.Query(`SELECT key, description, kind, schema, exec, enabled, created_at, updated_at FROM custom_tools ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomTool
	for rows.Next() {
		t, err := scanCustomTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}
