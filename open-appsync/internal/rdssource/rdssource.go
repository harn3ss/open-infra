// Package rdssource is the "RDS/Aurora" data source: it runs SQL statements against a relational
// database and returns rows as JSON, behind the same neutral datasource.Store contract as the
// DynamoDB/HTTP/Lambda sources. It mirrors AppSync's RDS data source shape — the request mapping emits
//
//	{"version":"2018-05-29","statements":["SELECT ... WHERE id = :ID"],"variableMap":{":ID":"123"}}
//
// and the result is a JSON array with one entry per statement, each a list of row objects — so a
// response template can read $ctx.result[0] for the first statement's rows.
//
// Named parameters (:name) from variableMap are rewritten to the driver's positional placeholders, so a
// value is always bound as a parameter, never interpolated into SQL (no injection). This first cut
// targets PostgreSQL/Aurora-PostgreSQL ($N placeholders); a MySQL dialect (? placeholders) is a small
// addition on the same seam.
//
// Fidelity note: byte-exact equivalence with a live AppSync RDS Data API trip is a separate future item;
// this implements the call-and-return contract and is unit-proven against a mock DB with zero AWS.
package rdssource

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"

	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" database/sql driver
)

const maxRowsPerStatement = 10000 // bound a runaway result set

// Store runs SQL over a *sql.DB using a dialect's placeholder style.
type Store struct {
	db          *sql.DB
	placeholder func(i int) string // 1-based → driver placeholder, e.g. postgres "$1"
}

var _ datasource.Store = (*Store)(nil)

func postgresPlaceholder(i int) string { return "$" + strconv.Itoa(i) }

// New builds a Store over an existing *sql.DB (tests inject a mock). Defaults to the PostgreSQL dialect.
func New(db *sql.DB) *Store {
	return &Store{db: db, placeholder: postgresPlaceholder}
}

// NewPostgres opens a PostgreSQL/Aurora-PostgreSQL connection from a DSN (e.g.
// "postgres://user:pass@host:5432/db?sslmode=require") and returns a Store over it.
func NewPostgres(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("rdssource: open postgres: %w", err)
	}
	return New(db), nil
}

// Close closes the underlying pool (engine shutdown).
func (s *Store) Close() error { return s.db.Close() }

// Execute runs each statement with the request's variableMap and returns [statement][row] as JSON.
func (s *Store) Execute(ctx context.Context, op runtime.Operation) (any, error) {
	statements, err := toStringSlice(op["statements"])
	if err != nil {
		return nil, fmt.Errorf("rdssource: %w", err)
	}
	if len(statements) == 0 {
		return nil, fmt.Errorf("rdssource: no statements")
	}
	varMap, _ := op["variableMap"].(map[string]any)

	results := make([]any, 0, len(statements))
	for i, stmt := range statements {
		query, args := rewriteNamedParams(stmt, varMap, s.placeholder)
		rowsJSON, err := s.query(ctx, query, args)
		if err != nil {
			return nil, fmt.Errorf("rdssource: statement %d: %w", i, err)
		}
		results = append(results, rowsJSON)
	}
	return results, nil
}

func (s *Store) query(ctx context.Context, query string, args []any) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		if len(out) >= maxRowsPerStatement {
			return nil, fmt.Errorf("result set exceeds %d rows", maxRowsPerStatement)
		}
		cells := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range cells {
			ptrs[i] = &cells[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			row[c] = normalize(cells[i])
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// normalize turns driver cell values into clean JSON: raw bytes become strings, everything else passes.
func normalize(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

var namedParam = regexp.MustCompile(`:([A-Za-z_][A-Za-z0-9_]*)`)

// rewriteNamedParams replaces each :name occurrence with a positional placeholder and collects the bound
// argument from variableMap (keyed as ":name" or "name"). A name absent from variableMap binds NULL. Each
// occurrence binds a parameter in order (a repeated :name binds again — simple and safe).
func rewriteNamedParams(stmt string, varMap map[string]any, placeholder func(int) string) (string, []any) {
	var args []any
	out := namedParam.ReplaceAllStringFunc(stmt, func(tok string) string {
		name := tok[1:]
		val, ok := varMap[tok] // ":name"
		if !ok {
			val = varMap[name] // "name"
		}
		args = append(args, val)
		return placeholder(len(args))
	})
	return out, args
}

func toStringSlice(v any) ([]string, error) {
	switch t := v.(type) {
	case []string:
		return t, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("statements must be strings")
			}
			out = append(out, s)
		}
		return out, nil
	case string:
		return []string{t}, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("statements must be a string or list of strings")
	}
}
