package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

// A document may carry more than one named operation; operationName picks which runs (GraphQL-over-HTTP).
func TestOperationName_SelectsAmongMany(t *testing.T) {
	e := New(map[string]resolver.Resolver{}, WithSchema(mustParse(t)))
	doc := `query A { __type(name: "Todo") { name } }
	        query B { __type(name: "Priority") { name } }`

	a := e.ExecuteOp(context.Background(), doc, "A", nil)
	if len(a.Errors) != 0 {
		t.Fatalf("A errored: %+v", a.Errors)
	}
	if got := a.Data["__type"].(map[string]any)["name"]; got != "Todo" {
		t.Errorf("op A selected wrong: %v", got)
	}
	b := e.ExecuteOp(context.Background(), doc, "B", nil)
	if got := b.Data["__type"].(map[string]any)["name"]; got != "Priority" {
		t.Errorf("op B selected wrong: %v", got)
	}

	// No operationName on a multi-operation document is ambiguous → error.
	if res := e.ExecuteOp(context.Background(), doc, "", nil); len(res.Errors) == 0 {
		t.Error("multi-operation document without operationName should error")
	}
	// An unknown operationName → error.
	if res := e.ExecuteOp(context.Background(), doc, "Nope", nil); len(res.Errors) == 0 {
		t.Error("unknown operationName should error")
	}
}

// A single-operation document is unaffected: Execute (no name) and a matching name both run it.
func TestOperationName_SingleOperationUnaffected(t *testing.T) {
	e := New(map[string]resolver.Resolver{}, WithSchema(mustParse(t)))
	q := `query Only { __type(name: "Todo") { name } }`
	if res := e.Execute(context.Background(), q, nil); len(res.Errors) != 0 {
		t.Fatalf("plain Execute errored: %+v", res.Errors)
	}
	if res := e.ExecuteOp(context.Background(), q, "Only", nil); res.Data["__type"].(map[string]any)["name"] != "Todo" {
		t.Errorf("named select of the sole op failed: %+v", res)
	}
}
