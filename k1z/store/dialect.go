package store

// Dialect support lets the k1z store run on either SQLite (the default, and the
// format of the original Python k1nzr3c0n.db) or PostgreSQL (shared with the
// ARTEX half of the binary). The two differ in three ways the rest of the package
// must not care about:
//
//   - placeholders: SQLite uses `?`, PostgreSQL uses `$1,$2,…`.
//   - auto-increment inserts: SQLite exposes the new row id via
//     sql.Result.LastInsertId(); the pgx database/sql driver does NOT, so a
//     PostgreSQL insert must append `RETURNING id` and scan it.
//   - DDL: column types and a few constructs (AUTOINCREMENT, CURRENT_TIMESTAMP
//     defaults, `INSERT OR IGNORE`) spell differently.
//
// The xdb wrapper hides the first two behind the exact *sql.DB method surface the
// store already calls (Exec/Query/QueryRow, with Begin/Close promoted), so for
// SQLite nothing changes and the PostgreSQL path is a per-connection dialect flag.
// DDL translation lives in translateSchema (schema_pg.go).

import (
	"database/sql"
	"strings"
)

type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

// pgSchemaName is the PostgreSQL schema the k1z tables live in, kept separate
// from the ARTEX half's tables in the same database. It is created at init and
// pinned as the connection search_path by the PostgreSQL open path.
const pgSchemaName = "k1z"

// rebind converts `?` placeholders to the dialect's form. For SQLite it is the
// identity. For PostgreSQL each `?` becomes `$1`, `$2`, … in order, while any `?`
// inside a single-quoted SQL string literal is left untouched.
func (d dialect) rebind(q string) string {
	if d != dialectPostgres || !strings.ContainsRune(q, '?') {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n := 0
	inStr := false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '\'':
			inStr = !inStr
			b.WriteByte(c)
		case c == '?' && !inStr:
			n++
			b.WriteByte('$')
			b.WriteString(itoa(n))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// itoa avoids a strconv import for the tiny positive integers rebind produces.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// xdb wraps *sql.DB and rebinds every query to the active dialect. It embeds the
// handle so Begin/Close/Conn/SetMaxOpenConns and friends are promoted unchanged;
// only the three query methods the store uses are overridden to rebind.
type xdb struct {
	*sql.DB
	dia dialect
}

func (x *xdb) Exec(query string, args ...any) (sql.Result, error) {
	return x.DB.Exec(x.dia.rebind(query), args...)
}

func (x *xdb) Query(query string, args ...any) (*sql.Rows, error) {
	return x.DB.Query(x.dia.rebind(query), args...)
}

func (x *xdb) QueryRow(query string, args ...any) *sql.Row {
	return x.DB.QueryRow(x.dia.rebind(query), args...)
}

// insertReturningID runs an INSERT and returns the new auto-increment id in a
// dialect-correct way: LastInsertId() on SQLite, `RETURNING id` on PostgreSQL
// (where the pgx driver cannot report LastInsertId). The caller passes the INSERT
// WITHOUT a trailing `RETURNING` clause; the id column must be named `id`.
func (x *xdb) insertReturningID(query string, args ...any) (int64, error) {
	if x.dia == dialectPostgres {
		var id int64
		err := x.DB.QueryRow(x.dia.rebind(query)+" RETURNING id", args...).Scan(&id)
		return id, err
	}
	res, err := x.DB.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
