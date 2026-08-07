package probe

import (
	"context"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// vtlResolver builds a resolver whose appsync-vtl runtime uses the given (deterministic) engine and
// the named corpus request/response templates — the same wiring server.Load does.
func vtlResolver(t *testing.T, e *vtl.Engine, req, resp string, src datasource.Store) resolver.Resolver {
	t.Helper()
	return resolver.Resolver{
		Runtime: vtlruntime.New(e, mustTemplate(t, req), mustTemplate(t, resp)),
		Source:  src,
	}
}

// End-to-end resolver probe (slice 1's headline): a REAL AppSync VTL resolver (request + response
// mapping templates, straight from the corpus) runs the full request→execute→response cycle against
// a DynamoDB-style data source and returns the GraphQL result AWS would. This is the "one resolver,
// one data source, proven end-to-end" bar from the handoff — with an in-memory store so it's
// deterministic; the same resolver runs unchanged against the FerretDB binding (piece 3).

// mutation runs a resolver for a create (PutItem) and query runs one for a read (GetItem), sharing
// the store — proving a written item reads back through faithful marshalling both ways.
func TestResolverProbe_PutThenGet(t *testing.T) {
	e := engine() // pinned autoId/time
	store := dynamodb.NewMemStore()

	createTodo := vtlResolver(t, e, "putitem.request.vtl", "response.vtl", store)
	getTodo := vtlResolver(t, e, "getitem.request.vtl", "response.vtl", store)

	// createTodo(input: {name:"Ada", age:36}) → the written item, id from $util.autoId().
	created, err := createTodo.Resolve(context.Background(), map[string]any{
		"args": map[string]any{"input": map[string]any{"name": "Ada", "age": float64(36)}},
	})
	if err != nil {
		t.Fatalf("createTodo: %v", err)
	}
	id := "11111111-2222-4333-8444-555555555555"
	wantCreated := map[string]any{"id": id, "name": "Ada", "age": float64(36)}
	if !reflect.DeepEqual(created, wantCreated) {
		t.Fatalf("createTodo result not faithful:\n got %v\nwant %v", created, wantCreated)
	}

	// getTodo(id) → the same item, read back through fromDynamoDB un-marshalling.
	got, err := getTodo.Resolve(context.Background(), map[string]any{"args": map[string]any{"id": id}})
	if err != nil {
		t.Fatalf("getTodo: %v", err)
	}
	if !reflect.DeepEqual(got, wantCreated) {
		t.Fatalf("getTodo round-trip not faithful:\n got %v\nwant %v", got, wantCreated)
	}
}

// A read miss returns null (AppSync GetItem semantics), and the response template passes it through.
func TestResolverProbe_GetMissingIsNull(t *testing.T) {
	getTodo := vtlResolver(t, engine(), "getitem.request.vtl", "response.vtl", dynamodb.NewMemStore())
	got, err := getTodo.Resolve(context.Background(), map[string]any{"args": map[string]any{"id": "nope"}})
	if err != nil {
		t.Fatalf("getTodo: %v", err)
	}
	if got != nil {
		t.Fatalf("missing item should resolve to null, got %v", got)
	}
}

// The validation resolver aborts the whole field with $util.error() before any data-source write —
// proving the resolver contract surfaces a thrown error instead of running the operation.
func TestResolverProbe_ValidationAborts(t *testing.T) {
	store := dynamodb.NewMemStore()
	create := vtlResolver(t, engine(), "validate.request.vtl", "response.vtl", store)
	_, err := create.Resolve(context.Background(), map[string]any{"args": map[string]any{"input": map[string]any{}}})
	if err == nil {
		t.Fatal("expected the validation resolver to abort with an error")
	}
	// Nothing was written.
	scan, _ := store.Execute(context.Background(), map[string]any{"operation": "Scan"})
	if items := scan.(map[string]any)["items"].([]any); len(items) != 0 {
		t.Fatalf("a rejected mutation must not write; store has %d items", len(items))
	}
}
