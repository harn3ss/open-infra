package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

const polySDL = `
interface Node { id: ID! }
type Dog implements Node { id: ID! bark: String! }
type Cat implements Node { id: ID! meow: String! }
union Animal = Dog | Cat
type Query {
  node(id: ID!): Node
  animals: [Animal!]!
}
`

func polyEngine(t *testing.T, results map[string]any) *Engine {
	t.Helper()
	schema, err := ParseSchema(polySDL)
	if err != nil {
		t.Fatal(err)
	}
	resolvers := map[string]resolver.Resolver{}
	for field, res := range results {
		resolvers["Query."+field] = resolver.Resolver{Runtime: stubRuntime{}, Source: stubStore{result: res}}
	}
	return New(resolvers, WithSchema(schema))
}

// An interface field: inline fragments dispatch on the object's concrete type (from __typename), and
// __typename resolves to the concrete type. The non-matching fragment's fields must NOT appear.
func TestPolymorphic_InterfaceDispatch(t *testing.T) {
	e := polyEngine(t, map[string]any{
		"node": map[string]any{"__typename": "Dog", "id": "d1", "bark": "woof", "meow": "should-not-leak"},
	})
	q := `{ node(id:"d1") { id __typename ... on Dog { bark } ... on Cat { meow } ... on Node { id } } }`
	res := e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errored: %+v", res.Errors)
	}
	node := res.Data["node"].(map[string]any)
	if node["__typename"] != "Dog" || node["id"] != "d1" || node["bark"] != "woof" {
		t.Errorf("Dog fields wrong: %v", node)
	}
	if _, leaked := node["meow"]; leaked {
		t.Errorf("Cat's meow leaked onto a Dog: %v", node) // the whole point of type-conditional dispatch
	}
}

// A union field over a list: each element resolves its own concrete type independently.
func TestPolymorphic_UnionListPerElement(t *testing.T) {
	e := polyEngine(t, map[string]any{
		"animals": []any{
			map[string]any{"__typename": "Dog", "id": "d1", "bark": "woof"},
			map[string]any{"__typename": "Cat", "id": "c1", "meow": "mrow"},
		},
	})
	q := `{ animals { __typename ... on Dog { bark } ... on Cat { meow } } }`
	res := e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errored: %+v", res.Errors)
	}
	list := res.Data["animals"].([]any)
	dog := list[0].(map[string]any)
	cat := list[1].(map[string]any)
	if dog["__typename"] != "Dog" || dog["bark"] != "woof" {
		t.Errorf("dog element wrong: %v", dog)
	}
	if _, leaked := dog["meow"]; leaked {
		t.Errorf("meow leaked onto dog element: %v", dog)
	}
	if cat["__typename"] != "Cat" || cat["meow"] != "mrow" {
		t.Errorf("cat element wrong: %v", cat)
	}
	if _, leaked := cat["bark"]; leaked {
		t.Errorf("bark leaked onto cat element: %v", cat)
	}
}

// A named fragment with a type condition dispatches the same way as an inline fragment.
func TestPolymorphic_NamedFragmentDispatch(t *testing.T) {
	e := polyEngine(t, map[string]any{
		"node": map[string]any{"__typename": "Cat", "id": "c1", "meow": "mrow"},
	})
	q := `{ node(id:"c1") { __typename ...D ...C } }
	      fragment D on Dog { bark }
	      fragment C on Cat { meow }`
	res := e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errored: %+v", res.Errors)
	}
	node := res.Data["node"].(map[string]any)
	if node["meow"] != "mrow" {
		t.Errorf("Cat fragment should apply: %v", node)
	}
	if _, leaked := node["bark"]; leaked {
		t.Errorf("Dog fragment should not apply to a Cat: %v", node)
	}
}

// Without a __typename hint on an abstract field, dispatch is lenient (fields are not silently dropped).
func TestPolymorphic_NoHintIsLenient(t *testing.T) {
	e := polyEngine(t, map[string]any{
		"node": map[string]any{"id": "x1", "bark": "woof"}, // no __typename
	})
	q := `{ node(id:"x1") { id ... on Dog { bark } } }`
	res := e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errored: %+v", res.Errors)
	}
	node := res.Data["node"].(map[string]any)
	if node["bark"] != "woof" { // lenient: included because concrete type is unknown
		t.Errorf("no-hint dispatch should be lenient: %v", node)
	}
}
