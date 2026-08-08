package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

const nestedSDL = `
type Author { id: ID! name: String! }
type Tag { label: String! }
type Post { id: ID! title: String! author: Author! tags: [Tag!] }
type Query { getPost(id: ID!): Post }
`

// stubRuntime/stubStore return a fixed value so a resolver can serve a nested object without VTL.
type stubStore struct{ result any }

func (s stubStore) Execute(context.Context, runtime.Operation) (any, error) { return s.result, nil }

type stubRuntime struct{}

func (stubRuntime) RenderRequest(map[string]any) (runtime.Operation, error) {
	return runtime.Operation{}, nil
}
func (stubRuntime) RenderResponse(ctx map[string]any) (any, error) { return ctx["result"], nil }

// TestTypename_NestedResolvesConcreteType is the graduation bar: __typename resolves to the concrete
// type at each of 2–3 nesting levels (root, nested object, list element), threaded from the type graph.
func TestTypename_NestedResolvesConcreteType(t *testing.T) {
	schema, err := ParseSchema(nestedSDL)
	if err != nil {
		t.Fatal(err)
	}
	post := map[string]any{
		"id": "p1", "title": "Hi",
		"author": map[string]any{"id": "a1", "name": "Ada"},
		"tags":   []any{map[string]any{"label": "x"}},
	}
	resolvers := map[string]resolver.Resolver{
		"Query.getPost": {Runtime: stubRuntime{}, Source: stubStore{result: post}},
	}
	e := New(resolvers, WithSchema(schema))

	q := `{ getPost(id: "p1") { __typename id author { __typename name } tags { __typename label } } }`
	res := e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("query errored: %+v", res.Errors)
	}
	gp := res.Data["getPost"].(map[string]any)
	if gp["__typename"] != "Post" { // level 1
		t.Errorf("getPost.__typename = %v, want Post", gp["__typename"])
	}
	if au := gp["author"].(map[string]any); au["__typename"] != "Author" { // level 2 (nested object)
		t.Errorf("author.__typename = %v, want Author", au["__typename"])
	}
	if tags := gp["tags"].([]any); tags[0].(map[string]any)["__typename"] != "Tag" { // level 2 (list element)
		t.Errorf("tags[0].__typename = %v, want Tag", tags[0])
	}
}

// TestTypename_RootStillWorks: the root __typename remains the root operation type.
func TestTypename_RootStillWorks(t *testing.T) {
	e := New(map[string]resolver.Resolver{}, WithSchema(mustParse(t)))
	if res := e.Execute(context.Background(), `{ __typename }`, nil); res.Data["__typename"] != "Query" {
		t.Errorf("root __typename = %v, want Query", res.Data["__typename"])
	}
}

// TestTypename_NoSchemaResolvesNull: without a schema there's no type to name, so a nested __typename is
// null rather than a guess (root still works — it's the operation type, not schema-derived).
func TestTypename_NoSchemaResolvesNull(t *testing.T) {
	post := map[string]any{"id": "p1", "author": map[string]any{"id": "a1"}}
	resolvers := map[string]resolver.Resolver{
		"Query.getPost": {Runtime: stubRuntime{}, Source: stubStore{result: post}},
	}
	e := New(resolvers) // no WithSchema
	res := e.Execute(context.Background(), `{ getPost(id:"p1") { __typename id } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %+v", res.Errors)
	}
	if gp := res.Data["getPost"].(map[string]any); gp["__typename"] != nil {
		t.Errorf("nested __typename without schema = %v, want nil", gp["__typename"])
	}
}
