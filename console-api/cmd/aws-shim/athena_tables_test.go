package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

const payrollIOPlan = `{"inputTableColumnInfos":[{"table":{"catalog":"iceberg","schemaTable":{"schema":"sales","table":"orders"}}},` +
	`{"table":{"catalog":"iceberg","schemaTable":{"schema":"hr","table":"payroll"}}}],` +
	`"outputTable":{"catalog":"iceberg","schemaTable":{"schema":"sales","table":"report"}}}`

func TestAthena_TableChecksFromTheIOPlan(t *testing.T) {
	tables, err := parseIOPlan(payrollIOPlan)
	if err != nil {
		t.Fatal(err)
	}
	got := athenaTableChecks(tables, true, "iceberg")
	want := [][2]string{{"glue:GetTable", "sales/orders"}, {"glue:GetTable", "hr/payroll"}, {"glue:UpdateTable", "sales/report"}}
	if len(got) != len(want) {
		t.Fatalf("checks = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("checks = %v, want %v", got, want)
		}
	}
	// No plan, or a table in a catalog the shim does not front: any table.
	if c := athenaTableChecks(nil, false, "iceberg"); len(c) != 1 || c[0][1] != anyResource {
		t.Fatalf("an unplanned statement must be checked on Table::*, got %v", c)
	}
	if c := athenaTableChecks([]athenaTable{{Catalog: "system", Schema: "runtime", Table: "queries"}}, true, "iceberg"); c[0][1] != anyResource {
		t.Fatalf("a table outside the fronted catalog must be checked on Table::*, got %v", c)
	}
}

// ioTrino answers EXPLAIN (TYPE IO) with a plan and any other statement with a row, recording what ran.
type ioTrino struct {
	srv  *httptest.Server
	mu   sync.Mutex
	sqls []string
}

func newIOTrino(plan string) *ioTrino {
	ft := &ioTrino{}
	ft.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ft.mu.Lock()
		ft.sqls = append(ft.sqls, string(b))
		ft.mu.Unlock()
		row := []any{"x"}
		if strings.HasPrefix(string(b), "EXPLAIN (TYPE IO") {
			row = []any{plan}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "q", "columns": []map[string]any{{"name": "c", "type": "varchar"}},
			"data": [][]any{row}, "stats": map[string]any{"state": "FINISHED"}})
	}))
	return ft
}

// A query is authorized on every table it reads or writes, not on its WorkGroup alone: a User denied
// glue:GetTable on one table it joins cannot run it, and the query never reaches Trino.
func TestAthena_QueryIsAuthorizedOnItsTables(t *testing.T) {
	ft := newIOTrino(payrollIOPlan)
	defer ft.srv.Close()
	h := &athenaHandler{logger: discardLogger(), catalog: "iceberg", authz: userPolicy(
		dpAllow([]string{"athena:*", "glue:*"}, "*"),
		dpDeny([]string{"glue:GetTable"}, "Table::hr/payroll"))}
	run := func(claims iam.Claims) athenaExecSnapshot {
		store := newAthenaExecStore(time.Hour, discardLogger())
		ex := &athenaExec{Id: "ex", State: "QUEUED", SubmittedAt: time.Now()}
		store.put(ex)
		r := httptest.NewRequest("POST", "http://shim/", nil)
		store.runExec(context.Background(), ex, newTrinoClient(ft.srv.URL), athenaStartParams{
			Query: "INSERT INTO sales.report SELECT * FROM sales.orders JOIN hr.payroll USING (id)", Catalog: "iceberg", User: claims.Sub,
			Authorize: h.tableAuthorizer(context.Background(), claims, r)})
		return ex.snapshot()
	}
	s := run(testUser)
	if s.State != "FAILED" || !strings.Contains(s.StateReason, "AccessDenied") || !strings.Contains(s.StateReason, "hr/payroll") {
		t.Fatalf("a query joining a denied table: state %s (%q), want FAILED AccessDenied on hr/payroll", s.State, s.StateReason)
	}
	ft.mu.Lock()
	for _, q := range ft.sqls {
		if !strings.HasPrefix(q, "EXPLAIN") {
			t.Errorf("the denied query reached Trino: %q", q)
		}
	}
	ft.sqls = nil
	ft.mu.Unlock()

	// An ungoverned User (no policy names it) keeps RBAC as its authority: the query runs.
	if s := run(iam.Claims{Sub: "other"}); s.State != "SUCCEEDED" {
		t.Fatalf("an ungoverned User's query: state %s (%q), want SUCCEEDED", s.State, s.StateReason)
	}
}
