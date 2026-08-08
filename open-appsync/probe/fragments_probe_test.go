package probe

import (
	"context"
	"testing"
)

// A real DATA query (not just introspection) driving named + inline fragments against the VTL resolvers
// and DynamoDB-style store — the "fragments resolve in a normal query" graduation bar, end-to-end.
func TestFragmentsProbe_NamedAndInlineInDataQuery(t *testing.T) {
	e := newGraphQLEngine()
	id := "11111111-2222-4333-8444-555555555555" // pinned autoId

	if res := e.Execute(context.Background(), `mutation { createTodo(input: { name: "Ada", age: 36 }) { id } }`, nil); len(res.Errors) != 0 {
		t.Fatalf("seed mutation errored: %+v", res.Errors)
	}

	// Named fragment on the getTodo selection set.
	named := `query($id: ID!) { getTodo(id: $id) { ...Fields } }
	          fragment Fields on Todo { id name age }`
	res := e.Execute(context.Background(), named, map[string]any{"id": id})
	if len(res.Errors) != 0 {
		t.Fatalf("named-fragment data query errored: %+v", res.Errors)
	}
	got := res.Data["getTodo"].(map[string]any)
	if got["id"] != id || got["name"] != "Ada" || got["age"].(float64) != 36 {
		t.Fatalf("named fragment projection = %v", got)
	}

	// Inline fragment mixing a direct field with an inline-fragment field.
	inline := `query($id: ID!) { getTodo(id: $id) { id ... on Todo { name age } } }`
	res = e.Execute(context.Background(), inline, map[string]any{"id": id})
	if len(res.Errors) != 0 {
		t.Fatalf("inline-fragment data query errored: %+v", res.Errors)
	}
	got = res.Data["getTodo"].(map[string]any)
	if got["id"] != id || got["name"] != "Ada" || got["age"].(float64) != 36 {
		t.Fatalf("inline fragment projection = %v", got)
	}
}
