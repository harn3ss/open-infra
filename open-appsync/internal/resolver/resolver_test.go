package resolver_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// This is the "no backstage pass" test: a SECOND runtime — one that is not VTL and lives outside
// internal/vtlruntime — implements runtime.Runtime and drives the resolver lifecycle through the exact
// same public interface, with no backstage pass. If VTL needed a shortcut this stranger can't take,
// the seam would be theatre; that this trivial runtime runs end-to-end proves the extension point is
// genuine. (The interface stays internal/changeable until a REAL second tenant lands — this only
// proves it is implementable, which is the honesty bar for the interface, not the stability claim.)

// staticRuntime is a deliberately trivial runtime: In → a fixed neutral Operation built from $ctx
// (ignoring templates entirely), Out → the data-source result passed straight through. It shares
// nothing with VTL.
type staticRuntime struct{ op runtime.Operation }

func (s staticRuntime) RenderRequest(ctx map[string]any) (runtime.Operation, error) {
	return s.op, nil
}
func (s staticRuntime) RenderResponse(ctx map[string]any) (any, error) {
	return ctx["result"], nil // identity response
}

func TestResolver_DrivesAnyRuntime_NoBackstagePass(t *testing.T) {
	store := dynamodb.NewMemStore()
	// Seed a row directly so a Scan has something to return.
	if _, err := store.Execute(context.Background(), runtime.Operation{
		"operation":       "PutItem",
		"key":             map[string]any{"id": map[string]any{"S": "1"}},
		"attributeValues": map[string]any{"name": map[string]any{"S": "Ada"}},
	}); err != nil {
		t.Fatal(err)
	}

	r := resolver.Resolver{
		Runtime: staticRuntime{op: runtime.Operation{"operation": "Scan"}},
		Source:  store,
	}
	got, err := r.Resolve(context.Background(), map[string]any{"args": map[string]any{}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The lifecycle executed the stranger's Operation and handed its result back through the stranger's
	// response phase — no VTL involved anywhere.
	m, ok := got.(map[string]any)
	if !ok || m["scannedCount"].(float64) != 1 {
		t.Fatalf("second-runtime resolve not faithful: %v", got)
	}
	items := m["items"].([]any)
	want := map[string]any{"id": "1", "name": "Ada"}
	if len(items) != 1 || !reflect.DeepEqual(items[0], want) {
		t.Fatalf("scan item not faithful:\n got %v\nwant %v", items, want)
	}
}

// A runtime's request-phase error aborts before the data source is touched (the "Error" term).
type failingRuntime struct{}

func (failingRuntime) RenderRequest(map[string]any) (runtime.Operation, error) {
	return nil, errors.New("boom")
}
func (failingRuntime) RenderResponse(map[string]any) (any, error) { return nil, nil }

func TestResolver_RequestErrorSkipsDataSource(t *testing.T) {
	r := resolver.Resolver{Runtime: failingRuntime{}, Source: dynamodb.NewMemStore()}
	if _, err := r.Resolve(context.Background(), map[string]any{}); err == nil {
		t.Fatal("a request-phase error must abort the resolver")
	}
}
