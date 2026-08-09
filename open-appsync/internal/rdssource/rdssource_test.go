package rdssource

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

func newMock(t *testing.T) (*Store, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(db), mock
}

// Named params (:ID) are rewritten to positional placeholders and bound as arguments (never
// interpolated), and rows come back as [statement][row] JSON.
func TestRDS_NamedParamsAndRows(t *testing.T) {
	s, mock := newMock(t)
	mock.ExpectQuery(`SELECT id, name FROM todos WHERE id = $1`).
		WithArgs("7").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow("7", "Ada"))

	res, err := s.Execute(context.Background(), runtime.Operation{
		"version":     "2018-05-29",
		"statements":  []any{"SELECT id, name FROM todos WHERE id = :ID"},
		"variableMap": map[string]any{":ID": "7"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := []any{[]map[string]any{{"id": "7", "name": "Ada"}}}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("result = %#v, want %#v", res, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// Multiple statements → one result set each, in order.
func TestRDS_MultipleStatements(t *testing.T) {
	s, mock := newMock(t)
	mock.ExpectQuery(`SELECT 1 AS a`).WillReturnRows(sqlmock.NewRows([]string{"a"}).AddRow(int64(1)))
	mock.ExpectQuery(`SELECT 2 AS b`).WillReturnRows(sqlmock.NewRows([]string{"b"}).AddRow(int64(2)))

	res, err := s.Execute(context.Background(), runtime.Operation{
		"statements": []any{"SELECT 1 AS a", "SELECT 2 AS b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	list := res.([]any)
	if len(list) != 2 {
		t.Fatalf("want 2 result sets, got %d", len(list))
	}
	if list[0].([]map[string]any)[0]["a"] != int64(1) || list[1].([]map[string]any)[0]["b"] != int64(2) {
		t.Errorf("result = %#v", res)
	}
}

// A name absent from variableMap binds NULL (not interpolated, not an error).
func TestRDS_MissingParamBindsNull(t *testing.T) {
	s, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO t (a, b) VALUES ($1, $2)`).
		WithArgs("x", nil).
		WillReturnRows(sqlmock.NewRows([]string{"ok"}).AddRow(true))
	_, err := s.Execute(context.Background(), runtime.Operation{
		"statements":  []any{"INSERT INTO t (a, b) VALUES (:A, :B)"},
		"variableMap": map[string]any{":A": "x"}, // :B missing → NULL
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// A statement error surfaces (the resolver fails), it is not swallowed.
func TestRDS_StatementErrorSurfaces(t *testing.T) {
	s, mock := newMock(t)
	mock.ExpectQuery(`SELECT boom`).WillReturnError(errors.New("syntax error"))
	if _, err := s.Execute(context.Background(), runtime.Operation{"statements": []any{"SELECT boom"}}); err == nil {
		t.Fatal("a statement error must surface")
	}
}

// rewriteNamedParams unit: order + repeated names + no-params passthrough.
func TestRewriteNamedParams(t *testing.T) {
	q, args := rewriteNamedParams("SELECT * FROM t WHERE a=:X AND b=:Y AND c=:X",
		map[string]any{":X": 1, ":Y": 2}, postgresPlaceholder)
	if q != "SELECT * FROM t WHERE a=$1 AND b=$2 AND c=$3" {
		t.Errorf("query = %q", q)
	}
	if !reflect.DeepEqual(args, []any{1, 2, 1}) {
		t.Errorf("args = %v, want [1 2 1]", args)
	}
	if q2, a2 := rewriteNamedParams("SELECT 1", nil, postgresPlaceholder); q2 != "SELECT 1" || len(a2) != 0 {
		t.Errorf("no-params: q=%q args=%v", q2, a2)
	}
}
