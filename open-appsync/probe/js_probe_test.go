package probe

import (
	"context"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/jsruntime"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// The SECOND-tenant proof: a real, non-VTL, production-shaped runtime — AppSync-style
// JavaScript resolvers on a goja sandbox — runs through the EXACT same lifecycle and executor as VTL,
// with no backstage pass. This is what earns the interface-stability claim. It also proves the sandbox
// denies ambient capability (prove the "no").

// Compile-time proof: the JS runtime satisfies the same step contract as VTL, no shortcut.
var _ runtime.Runtime = (*jsruntime.Runtime)(nil)

func mustJS(t *testing.T, src string) *jsruntime.Runtime {
	t.Helper()
	rt, err := jsruntime.New(engine().Util(), src) // shares the pinned autoId provider
	if err != nil {
		t.Fatalf("compile JS: %v", err)
	}
	return rt
}

const jsPut = `
function request(ctx) {
  return {
    operation: 'PutItem',
    key: { id: util.dynamodb.toDynamoDB(util.autoId()) },
    attributeValues: util.dynamodb.toMapValues({ name: ctx.args.name, age: ctx.args.age })
  };
}
function response(ctx) { return ctx.result; }
`

const jsGet = `
function request(ctx) {
  return { operation: 'GetItem', key: { id: util.dynamodb.toDynamoDB(ctx.args.id) } };
}
function response(ctx) { return ctx.result; }
`

// A JS mutation then a JS query run end-to-end through the GraphQL executor — the same path VTL takes.
func TestJSProbe_PutThenGet(t *testing.T) {
	store := dynamodb.NewMemStore()
	id := "11111111-2222-4333-8444-555555555555" // pinned autoId

	e := graphql.New(map[string]resolver.Resolver{
		"Mutation.createTodo": {Runtime: mustJS(t, jsPut), Source: store},
		"Query.getTodo":       {Runtime: mustJS(t, jsGet), Source: store},
	})

	res := e.Execute(context.Background(), `mutation { createTodo(name: "Ada", age: 36) { id name age } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("js mutation errors: %+v", res.Errors)
	}
	want := map[string]any{"createTodo": map[string]any{"id": id, "name": "Ada", "age": float64(36)}}
	if !reflect.DeepEqual(res.Data, want) {
		t.Fatalf("js createTodo not faithful:\n got %v\nwant %v", res.Data, want)
	}

	res = e.Execute(context.Background(), `query { getTodo(id: "`+id+`") { id name } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("js query errors: %+v", res.Errors)
	}
	got := map[string]any{"getTodo": map[string]any{"id": id, "name": "Ada"}}
	if !reflect.DeepEqual(res.Data, got) {
		t.Fatalf("js getTodo not faithful:\n got %v\nwant %v", res.Data, got)
	}
}

// A JS runtime and a VTL runtime coexist in the same registry and both resolve — the seam is shared,
// not VTL-privileged.
func TestJSProbe_CoexistsWithVTL(t *testing.T) {
	store := dynamodb.NewMemStore()
	e := graphql.New(map[string]resolver.Resolver{
		"Mutation.createTodo": {Runtime: mustJS(t, jsPut), Source: store},                                                                         // JS
		"Query.getTodo":       {Runtime: vtlruntime.New(engine(), mustCorpus("getitem.request.vtl"), "$util.toJson($ctx.result)"), Source: store}, // VTL
	})
	id := "11111111-2222-4333-8444-555555555555"
	if r := e.Execute(context.Background(), `mutation { createTodo(name:"Ada", age:36) { id } }`, nil); len(r.Errors) != 0 {
		t.Fatalf("js create errors: %+v", r.Errors)
	}
	if r := e.Execute(context.Background(), `query { getTodo(id:"`+id+`") { name } }`, nil); len(r.Errors) != 0 {
		t.Fatalf("vtl get (of a js-written item) errors: %+v", r.Errors)
	}
}

// SANDBOX NEGATIVE (prove the "no"): a resolver reaching for ambient capability fails closed — goja
// has no require/process/fetch, so the reference errors and no data source is ever touched.
func TestJSProbe_SandboxDeniesAmbientCapability(t *testing.T) {
	store := dynamodb.NewMemStore()
	for _, attempt := range []string{
		`function request(ctx){ var fs = require('fs'); return {operation:'Scan'}; } function response(ctx){ return ctx.result; }`,
		`function request(ctx){ return {payload: process.env}; } function response(ctx){ return ctx.result; }`,
		`function request(ctx){ fetch('http://169.254.169.254/'); return {operation:'Scan'}; } function response(ctx){ return ctx.result; }`,
	} {
		r := resolver.Resolver{Runtime: mustJS(t, attempt), Source: store}
		_, err := r.Resolve(context.Background(), map[string]any{"args": map[string]any{}})
		if err == nil {
			t.Fatalf("a resolver reaching for ambient capability must fail closed:\n%s", attempt)
		}
	}
	// Nothing was ever executed against the store.
	scan, _ := store.Execute(context.Background(), runtime.Operation{"operation": "Scan"})
	if n := len(scan.(map[string]any)["items"].([]any)); n != 0 {
		t.Fatalf("a sandbox-denied resolver must not reach the data source; store has %d items", n)
	}
}

// util.error in JS surfaces as a resolver error with its errorType (the AppSync error shape).
func TestJSProbe_UtilErrorSurfaces(t *testing.T) {
	src := `function request(ctx){ util.error('name is required','BadRequest'); return {operation:'Scan'}; }
	        function response(ctx){ return ctx.result; }`
	e := graphql.New(map[string]resolver.Resolver{
		"Mutation.createTodo": {Runtime: mustJS(t, src), Source: dynamodb.NewMemStore()},
	})
	res := e.Execute(context.Background(), `mutation { createTodo(name:"") { id } }`, nil)
	if len(res.Errors) != 1 || res.Errors[0].ErrorType != "BadRequest" {
		t.Fatalf("expected a surfaced BadRequest from util.error, got %+v", res.Errors)
	}
}

// A no-Operation JS step (request returns nothing) skips the data source — the loosened Out term holds
// for JS exactly as for VTL, so JS can be a pipeline before-step too.
func TestJSProbe_NoOperationStep(t *testing.T) {
	rt := mustJS(t, `function request(ctx){ ctx.stash.tag = 'x'; } function response(ctx){ return ctx.result; }`)
	op, err := rt.RenderRequest(map[string]any{"stash": map[string]any{}, "args": map[string]any{}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if op != nil {
		t.Fatalf("a request() returning nothing must emit no Operation, got %v", op)
	}
}
