package store

import "strings"

// Mention is one @-mention candidate (asset / finding / task) for the chat input.
type Mention struct {
	Kind  string `json:"kind"`  // asset | finding | task
	ID    int64  `json:"id"`
	Label string `json:"label"` // the token text
	Sub   string `json:"sub"`   // secondary line
}

// SearchMentions returns @-mention candidates matching q. kind filters to one
// type ("asset"|"finding"|"task"); empty searches all three.
func (s *Store) SearchMentions(q, kind string, limit int) ([]Mention, error) {
	if limit <= 0 {
		limit = 8
	}
	like := "%" + strings.ToLower(q) + "%"
	out := []Mention{}

	if kind == "" || kind == "asset" {
		rows, err := s.db.Query(`SELECT id, type, value FROM assets WHERE LOWER(value) LIKE ? ORDER BY id DESC LIMIT ?`, like, limit)
		if err == nil {
			for rows.Next() {
				var id int64
				var typ, val string
				if rows.Scan(&id, &typ, &val) == nil {
					out = append(out, Mention{Kind: "asset", ID: id, Label: val, Sub: typ})
				}
			}
			rows.Close()
		}
	}
	if kind == "" || kind == "finding" {
		rows, err := s.db.Query(`SELECT id, COALESCE(title,''), host, COALESCE(severity,'') FROM findings
			WHERE LOWER(COALESCE(title,'')) LIKE ? OR LOWER(host) LIKE ? ORDER BY id DESC LIMIT ?`, like, like, limit)
		if err == nil {
			for rows.Next() {
				var id int64
				var title, host, sev string
				if rows.Scan(&id, &title, &host, &sev) == nil {
					label := title
					if label == "" {
						label = host
					}
					out = append(out, Mention{Kind: "finding", ID: id, Label: label, Sub: sev + " · " + host})
				}
			}
			rows.Close()
		}
	}
	if kind == "" || kind == "task" {
		rows, err := s.db.Query(`SELECT id, name, goal FROM tasks WHERE deleted_at IS NULL
			AND (LOWER(name) LIKE ? OR LOWER(goal) LIKE ?) ORDER BY id DESC LIMIT ?`, like, like, limit)
		if err == nil {
			for rows.Next() {
				var id int64
				var name, goal string
				if rows.Scan(&id, &name, &goal) == nil {
					label := name
					if label == "" {
						label = goal
					}
					out = append(out, Mention{Kind: "task", ID: id, Label: label, Sub: goal})
				}
			}
			rows.Close()
		}
	}
	return out, nil
}
