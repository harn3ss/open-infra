package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

// flattenSelections is the fragment expander. These white-box tests pin the structural expansion plus
// the two failure modes that must not reach the executor: an unknown fragment and a fragment cycle.

func TestFlatten_NamedSpreadExpands(t *testing.T) {
	frags := map[string]fragmentDef{
		"F": {name: "F", typeCondition: "Todo", selections: []selection{{name: "id"}, {name: "name"}}},
	}
	in := []selection{{name: "getTodo", selections: []selection{{fragmentSpread: "F"}, {name: "age"}}}}
	out, err := flattenSelections(in, frags, nil, nil, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	got := fieldNames(out[0].selections)
	want := []string{"id", "name", "age"}
	if !equalStrings(got, want) {
		t.Errorf("expanded fields = %v, want %v", got, want)
	}
}

func TestFlatten_InlineFragmentExpands(t *testing.T) {
	in := []selection{{name: "getTodo", selections: []selection{
		{inline: true, typeCondition: "Todo", selections: []selection{{name: "id"}}},
		{inline: true, selections: []selection{{name: "name"}}}, // untyped inline
	}}}
	out, err := flattenSelections(in, nil, nil, nil, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if got := fieldNames(out[0].selections); !equalStrings(got, []string{"id", "name"}) {
		t.Errorf("inline expanded = %v", got)
	}
}

func TestFlatten_UnknownFragmentErrors(t *testing.T) {
	in := []selection{{name: "x", selections: []selection{{fragmentSpread: "Nope"}}}}
	if _, err := flattenSelections(in, map[string]fragmentDef{}, nil, nil, map[string]bool{}); err == nil {
		t.Fatal("expected an unknown-fragment error")
	}
}

func TestFlatten_CycleDetected(t *testing.T) {
	// A → B → A : must be rejected, not recurse forever.
	frags := map[string]fragmentDef{
		"A": {name: "A", selections: []selection{{fragmentSpread: "B"}}},
		"B": {name: "B", selections: []selection{{fragmentSpread: "A"}}},
	}
	in := []selection{{name: "x", selections: []selection{{fragmentSpread: "A"}}}}
	if _, err := flattenSelections(in, frags, nil, nil, map[string]bool{}); err == nil {
		t.Fatal("expected a fragment-cycle error")
	}
}

func TestFlatten_SiblingReuseIsNotACycle(t *testing.T) {
	// The same fragment used twice as siblings is fine (not a cycle).
	frags := map[string]fragmentDef{"F": {name: "F", selections: []selection{{name: "id"}}}}
	in := []selection{{name: "x", selections: []selection{{fragmentSpread: "F"}, {fragmentSpread: "F"}}}}
	out, err := flattenSelections(in, frags, nil, nil, map[string]bool{})
	if err != nil {
		t.Fatalf("sibling reuse should not error: %v", err)
	}
	if got := fieldNames(out[0].selections); !equalStrings(got, []string{"id", "id"}) {
		t.Errorf("sibling reuse = %v", got)
	}
}

func TestFlatten_TypeConditionMustExistWhenSchemaPresent(t *testing.T) {
	s := mustParse(t)
	frags := map[string]fragmentDef{"F": {name: "F", typeCondition: "Ghost", selections: []selection{{name: "id"}}}}
	in := []selection{{name: "x", selections: []selection{{fragmentSpread: "F"}}}}
	if _, err := flattenSelections(in, frags, s, nil, map[string]bool{}); err == nil {
		t.Fatal("expected error: type condition on a non-existent type")
	}
	// A condition on a real type is accepted...
	frags["F"] = fragmentDef{name: "F", typeCondition: "Todo", selections: []selection{{name: "id"}}}
	if _, err := flattenSelections(in, frags, s, nil, map[string]bool{}); err != nil {
		t.Errorf("real type condition should be accepted: %v", err)
	}
	// ...and a condition on an introspection meta-type is always valid.
	frags["F"] = fragmentDef{name: "F", typeCondition: "__Type", selections: []selection{{name: "kind"}}}
	if _, err := flattenSelections(in, frags, s, nil, map[string]bool{}); err != nil {
		t.Errorf("__Type condition should be valid: %v", err)
	}
}

// TestFragments_ResolveEndToEnd drives named + inline fragments through the full executor via the
// introspection path (no resolvers needed) — a normal query that happens to select meta-fields.
func TestFragments_ResolveEndToEnd(t *testing.T) {
	e := New(map[string]resolver.Resolver{}, WithSchema(mustParse(t)))

	// Named fragment spread.
	q := `{ __schema { queryType { ...QT } } }
	      fragment QT on __Type { name kind }`
	res := e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("named-fragment query errored: %+v", res.Errors)
	}
	qt := res.Data["__schema"].(map[string]any)["queryType"].(map[string]any)
	if qt["name"] != "Query" || qt["kind"] != kindObject {
		t.Errorf("named fragment result = %+v", qt)
	}

	// Inline fragment.
	q = `{ __type(name: "Todo") { ... on __Type { name kind } } }`
	res = e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("inline-fragment query errored: %+v", res.Errors)
	}
	typ := res.Data["__type"].(map[string]any)
	if typ["name"] != "Todo" || typ["kind"] != kindObject {
		t.Errorf("inline fragment result = %+v", typ)
	}
}

func fieldNames(sels []selection) []string {
	out := make([]string, len(sels))
	for i, s := range sels {
		out[i] = s.name
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
