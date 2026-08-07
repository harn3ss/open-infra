package probe

import (
	"context"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// The top-of-the-stack probe: a REAL GraphQL query/mutation string drives the VTL resolvers against
// the DynamoDB-style data source and returns the {data} an AppSync client expects. This closes the
// slice-1 loop — schema (field→resolver) intake, execution, resolver lifecycle, $util, data source —
// all exercised by an actual GraphQL operation.

func newGraphQLEngine() *graphql.Engine {
	store := dynamodb.NewMemStore()
	e := engine() // pinned autoId/time
	resp := "$util.toJson($ctx.result)"
	resolvers := map[string]resolver.Resolver{
		"Mutation.createTodo": {Runtime: vtlruntime.New(e, mustCorpus("putitem.request.vtl"), resp), Source: store},
		"Query.getTodo":       {Runtime: vtlruntime.New(e, mustCorpus("getitem.request.vtl"), resp), Source: store},
	}
	return graphql.New(resolvers)
}

// mustCorpus reads a corpus template outside a *testing.T (used in the engine builder).
func mustCorpus(name string) string {
	b, err := corpus.ReadFile("corpus/" + name)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestGraphQLProbe_MutationThenQuery(t *testing.T) {
	e := newGraphQLEngine()
	id := "11111111-2222-4333-8444-555555555555" // pinned autoId

	// A real mutation string — inline object argument + selection set.
	mut := `mutation { createTodo(input: { name: "Ada", age: 36 }) { id name age } }`
	res := e.Execute(context.Background(), mut, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("mutation errors: %+v", res.Errors)
	}
	wantCreate := map[string]any{"createTodo": map[string]any{"id": id, "name": "Ada", "age": float64(36)}}
	if !reflect.DeepEqual(res.Data, wantCreate) {
		t.Fatalf("createTodo data not faithful:\n got %v\nwant %v", res.Data, wantCreate)
	}

	// A real query with a $variable + a narrower selection set (only id + name).
	q := `query GetTodo($id: ID!) { getTodo(id: $id) { id name } }`
	res = e.Execute(context.Background(), q, map[string]any{"id": id})
	if len(res.Errors) != 0 {
		t.Fatalf("query errors: %+v", res.Errors)
	}
	// Selection set narrows the projection to id + name (age dropped) — faithful field selection.
	want := map[string]any{"getTodo": map[string]any{"id": id, "name": "Ada"}}
	if !reflect.DeepEqual(res.Data, want) {
		t.Fatalf("getTodo selection not faithful:\n got %v\nwant %v", res.Data, want)
	}
}

// A resolver-thrown $util.error surfaces as a GraphQL error entry (with errorType), data null.
func TestGraphQLProbe_ValidationErrorEntry(t *testing.T) {
	store := dynamodb.NewMemStore()
	e := graphql.New(map[string]resolver.Resolver{
		"Mutation.createTodo": {Runtime: vtlruntime.New(engine(), mustCorpus("validate.request.vtl"), "$util.toJson($ctx.result)"), Source: store},
	})
	res := e.Execute(context.Background(), `mutation { createTodo(input: {}) { id } }`, nil)
	if len(res.Errors) != 1 || res.Errors[0].ErrorType != "BadRequest" {
		t.Fatalf("expected one BadRequest error, got %+v", res.Errors)
	}
	if res.Data["createTodo"] != nil {
		t.Fatalf("errored field must be null, got %v", res.Data["createTodo"])
	}
}

// An unknown field is a GraphQL error, not a silent empty — honest about what's implemented.
func TestGraphQLProbe_UnknownField(t *testing.T) {
	res := newGraphQLEngine().Execute(context.Background(), `query { listAllTheThings { id } }`, nil)
	if len(res.Errors) != 1 {
		t.Fatalf("expected one error for the unknown field, got %+v", res.Errors)
	}
}
