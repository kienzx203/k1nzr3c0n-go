// ScopeWeaver parity — task categories, task templates, task archive/restore,
// and a generic key/value settings table. Additive.
package store

import (
	"database/sql"
	"errors"
	"time"
)

const sw2Schema = `
CREATE TABLE IF NOT EXISTS task_categories (
	id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL UNIQUE,
	color      TEXT NOT NULL DEFAULT '#5b9bff',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS task_templates (
	id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	goal        TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	max_workers INTEGER NOT NULL DEFAULT 3,
	created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT NOT NULL PRIMARY KEY,
	value TEXT NOT NULL DEFAULT ''
);
`

// ── settings (key/value) ─────────────────────────────────────────────────────

func (s *Store) GetSetting(key, def string) string {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ── task categories ──────────────────────────────────────────────────────────

type TaskCategory struct {
	ID        int64
	Name      string
	Color     string
	CreatedAt time.Time
}

func (s *Store) CreateCategory(name, color string) (*TaskCategory, error) {
	if color == "" {
		color = "#5b9bff"
	}
	res, err := s.db.Exec(`INSERT INTO task_categories (name, color, created_at) VALUES (?,?,?)
		ON CONFLICT(name) DO UPDATE SET color=excluded.color`, name, color, SqlNow())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if id == 0 {
		_ = s.db.QueryRow(`SELECT id FROM task_categories WHERE name=?`, name).Scan(&id)
	}
	return &TaskCategory{ID: id, Name: name, Color: color, CreatedAt: NowUTC()}, nil
}

func (s *Store) ListCategories() ([]TaskCategory, error) {
	rows, err := s.db.Query(`SELECT id, name, color, created_at FROM task_categories ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskCategory
	for rows.Next() {
		var c TaskCategory
		var t any
		if err := rows.Scan(&c.ID, &c.Name, &c.Color, &t); err != nil {
			return nil, err
		}
		c.CreatedAt = parseDBTime(t)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteCategory(id int64) error {
	_, _ = s.db.Exec(`UPDATE tasks SET category_id=NULL WHERE category_id=?`, id)
	_, err := s.db.Exec(`DELETE FROM task_categories WHERE id=?`, id)
	return err
}

func (s *Store) SetTaskCategory(taskID, categoryID int64) error {
	_, err := s.db.Exec(`UPDATE tasks SET category_id=?, updated_at=? WHERE id=?`, nullZero(categoryID), SqlNow(), taskID)
	return err
}

// ── task templates ───────────────────────────────────────────────────────────

type TaskTemplate struct {
	ID          int64
	Name        string
	Goal        string
	Description string
	MaxWorkers  int
	CreatedAt   time.Time
}

func (s *Store) CreateTemplate(t *TaskTemplate) error {
	if t.MaxWorkers <= 0 {
		t.MaxWorkers = 3
	}
	t.CreatedAt = NowUTC()
	res, err := s.db.Exec(`INSERT INTO task_templates (name, goal, description, max_workers, created_at)
		VALUES (?,?,?,?,?)`, t.Name, t.Goal, t.Description, t.MaxWorkers, SqlTime(t.CreatedAt))
	if err != nil {
		return err
	}
	t.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) ListTemplates() ([]TaskTemplate, error) {
	rows, err := s.db.Query(`SELECT id, name, goal, description, max_workers, created_at FROM task_templates ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskTemplate
	for rows.Next() {
		var t TaskTemplate
		var c any
		if err := rows.Scan(&t.ID, &t.Name, &t.Goal, &t.Description, &t.MaxWorkers, &c); err != nil {
			return nil, err
		}
		t.CreatedAt = parseDBTime(c)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTemplate(id int64) (*TaskTemplate, error) {
	var t TaskTemplate
	var c any
	err := s.db.QueryRow(`SELECT id, name, goal, description, max_workers, created_at FROM task_templates WHERE id=?`, id).
		Scan(&t.ID, &t.Name, &t.Goal, &t.Description, &t.MaxWorkers, &c)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt = parseDBTime(c)
	return &t, nil
}

func (s *Store) DeleteTemplate(id int64) error {
	_, err := s.db.Exec(`DELETE FROM task_templates WHERE id=?`, id)
	return err
}

// ── task archive / restore ───────────────────────────────────────────────────

func (s *Store) ArchiveTask(id int64) error {
	_, err := s.db.Exec(`UPDATE tasks SET archived_at=?, updated_at=? WHERE id=?`, SqlNow(), SqlNow(), id)
	return err
}

func (s *Store) RestoreTask(id int64) error {
	_, err := s.db.Exec(`UPDATE tasks SET archived_at=NULL, updated_at=? WHERE id=?`, SqlNow(), id)
	return err
}

// ListTasksFiltered lists tasks with archive control. archived=false hides
// archived tasks (default view); archived=true returns only archived ones.
func (s *Store) ListTasksFiltered(status string, archived bool) ([]Task, error) {
	q := `SELECT ` + taskCols + ` FROM tasks WHERE deleted_at IS NULL`
	if archived {
		q += ` AND archived_at IS NOT NULL`
	} else {
		q += ` AND archived_at IS NULL`
	}
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

// TaskCategoryID reads a task's category id (0 = none).
func (s *Store) TaskCategoryID(taskID int64) int64 {
	var id sql.NullInt64
	_ = s.db.QueryRow(`SELECT category_id FROM tasks WHERE id=?`, taskID).Scan(&id)
	return id.Int64
}
