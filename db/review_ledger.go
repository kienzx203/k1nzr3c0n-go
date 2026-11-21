package db

// Review-coverage ledger: the engine-tracked denominator that makes "no function /
// endpoint missed" enforceable rather than trusted to the agent's memory. Every unit
// (function from the SAST inventory, endpoint from the route extractor) is seeded here;
// the worker marks each reviewed with a verdict; the planner's completion gate reads
// coverage from here.

import (
	"context"
	"strconv"
	"strings"
)

// ReviewUnit is one reviewable code unit seeded into the ledger.
type ReviewUnit struct {
	Kind    string // "function" | "endpoint"
	UnitKey string // stable id (file:line:label)
	Label   string
	File    string
	Line    int
}

// ReviewCoverageResult is the coverage snapshot the planner gate reads.
type ReviewCoverageResult struct {
	Total         int               `json:"total"`
	Reviewed      int               `json:"reviewed"`
	Pending       int               `json:"pending"`
	Vulnerable    int               `json:"vulnerable"`
	ByKind        map[string][2]int `json:"by_kind"` // kind -> [reviewed,total]
	PendingSample []string          `json:"pending_sample"`
}

// SeedReviewUnits bulk-inserts units for a task (idempotent: existing units keep their
// review state). Returns how many NEW units were inserted.
func (d *DB) SeedReviewUnits(ctx context.Context, taskID int64, units []ReviewUnit) (int, error) {
	inserted := 0
	for _, u := range units {
		if u.UnitKey == "" {
			continue
		}
		res, err := d.ExecContext(ctx,
			`INSERT INTO task_review_units(task_id,kind,unit_key,label,file,line)
			 VALUES($1,$2,$3,$4,$5,$6)
			 ON CONFLICT (task_id,kind,unit_key) DO NOTHING`,
			taskID, u.Kind, u.UnitKey, u.Label, u.File, u.Line)
		if err != nil {
			return inserted, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	return inserted, nil
}

// MarkReviewUnit records that a unit was reviewed: sets the verdict, appends the checked
// classes, and stores a note. Matches by exact unit_key, else by a label/file substring so
// the agent can reference a unit by its name without the precise key.
func (d *DB) MarkReviewUnit(ctx context.Context, taskID int64, ref string, classes []string, verdict, note string) (int64, error) {
	ref = strings.TrimSpace(ref)
	if verdict == "" {
		verdict = "reviewed"
	}
	cls := strings.Join(classes, ",")
	// exact key first
	res, err := d.ExecContext(ctx,
		`UPDATE task_review_units
		   SET verdict=$3, classes_reviewed=$4, note=$5, updated_at=now()
		 WHERE task_id=$1 AND unit_key=$2`,
		taskID, ref, verdict, cls, note)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return n, nil
	}
	// fall back to a label/file match (the agent referenced a name, not the key)
	res, err = d.ExecContext(ctx,
		`UPDATE task_review_units
		   SET verdict=$3, classes_reviewed=$4, note=$5, updated_at=now()
		 WHERE task_id=$1 AND (label ILIKE '%'||$2||'%' OR unit_key ILIKE '%'||$2||'%' OR file ILIKE '%'||$2||'%')
		   AND verdict='pending'`,
		taskID, ref, verdict, cls, note)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ReviewCoverage returns the coverage snapshot for a task's review ledger.
func (d *DB) ReviewCoverage(ctx context.Context, taskID int64) (*ReviewCoverageResult, error) {
	r := &ReviewCoverageResult{ByKind: map[string][2]int{}}
	rows, err := d.QueryContext(ctx,
		`SELECT kind,
		        COUNT(*),
		        COUNT(*) FILTER (WHERE verdict<>'pending'),
		        COUNT(*) FILTER (WHERE verdict='vulnerable')
		   FROM task_review_units WHERE task_id=$1 GROUP BY kind`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var total, reviewed, vuln int
		if err := rows.Scan(&kind, &total, &reviewed, &vuln); err != nil {
			return nil, err
		}
		r.Total += total
		r.Reviewed += reviewed
		r.Vulnerable += vuln
		r.ByKind[kind] = [2]int{reviewed, total}
	}
	r.Pending = r.Total - r.Reviewed
	// a sample of still-pending units so the planner can name what to dispatch
	prows, err := d.QueryContext(ctx,
		`SELECT kind, COALESCE(NULLIF(label,''), unit_key), file, line
		   FROM task_review_units WHERE task_id=$1 AND verdict='pending'
		 ORDER BY kind, file, line LIMIT 40`, taskID)
	if err == nil {
		defer prows.Close()
		for prows.Next() {
			var kind, label, file string
			var line int
			if prows.Scan(&kind, &label, &file, &line) == nil {
				loc := file
				if line > 0 {
					loc = file + ":" + strconv.Itoa(line)
				}
				r.PendingSample = append(r.PendingSample, kind+" "+label+" ("+loc+")")
			}
		}
	}
	return r, nil
}
