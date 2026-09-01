package probe

import (
	"context"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// The pipeline lifecycle probe: a resolver runs before -> 2 functions -> after end-to-end,
// with $ctx.stash threaded from the before-step into a function and $ctx.prev.result carried from one
// function to the next and into the after-step. The before-step emits NO Operation — the direct proof
// that the loosened Out term is real (a step may transform $ctx without calling a data source).

func step(e *vtl.Engine, req, resp string) *vtlruntime.Runtime { return vtlruntime.New(e, req, resp) }

func TestPipelineProbe_BeforeFunctionsAfter(t *testing.T) {
	e := engine() // pinned autoId
	store := dynamodb.NewMemStore()
	id := "11111111-2222-4333-8444-555555555555"

	// before: put args.tag into the shared stash; renders nothing -> no Operation.
	before := step(e, `#set($d = $ctx.stash.put("tag", $ctx.args.tag))`, "")

	// fn1: PutItem using args.name + stash.tag; its response becomes $ctx.prev.result.
	fn1 := resolver.Function{
		Runtime: step(e,
			`{"operation":"PutItem","key":{"id":$util.dynamodb.toDynamoDBJson($util.autoId())},`+
				`"attributeValues":$util.dynamodb.toMapValuesJson({"name":$ctx.args.name,"tag":$ctx.stash.tag})}`,
			`$util.toJson($ctx.result)`),
		Source: store,
	}
	// fn2: GetItem by the id produced by fn1 ($ctx.prev.result.id); response becomes $ctx.prev.result.
	fn2 := resolver.Function{
		Runtime: step(e,
			`{"operation":"GetItem","key":{"id":$util.dynamodb.toDynamoDBJson($ctx.prev.result.id)}}`,
			`$util.toJson($ctx.result)`),
		Source: store,
	}
	// after: shape the final value from the last function's result.
	after := step(e, "", `$util.toJson($ctx.prev.result)`)

	r := resolver.Resolver{Pipeline: &resolver.Pipeline{
		Before:    before,
		Functions: []resolver.Function{fn1, fn2},
		After:     after,
	}}

	got, err := r.Resolve(context.Background(), map[string]any{
		"args": map[string]any{"name": "Ada", "tag": "work"},
	})
	if err != nil {
		t.Fatalf("pipeline resolve: %v", err)
	}
	want := map[string]any{"id": id, "name": "Ada", "tag": "work"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pipeline result not faithful:\n got %v\nwant %v", got, want)
	}
}

// The direct proof of the loosened Out term: the before-step's request phase returns a nil Operation,
// so the lifecycle calls no data source for it.
func TestPipelineProbe_BeforeEmitsNoOperation(t *testing.T) {
	before := step(engine(), `#set($d = $ctx.stash.put("tag", "x"))`, "")
	op, err := before.RenderRequest(map[string]any{"stash": map[string]any{}, "args": map[string]any{}})
	if err != nil {
		t.Fatalf("before render: %v", err)
	}
	if op != nil {
		t.Fatalf("a before-step must emit no Operation, got %v", op)
	}
}

// An abort in the before-step ($util.error) stops the pipeline before any function runs.
func TestPipelineProbe_BeforeAbort(t *testing.T) {
	e := engine()
	store := dynamodb.NewMemStore()
	r := resolver.Resolver{Pipeline: &resolver.Pipeline{
		Before: step(e, `$util.error("no", "BadRequest")`, ""),
		Functions: []resolver.Function{{
			Runtime: step(e, `{"operation":"PutItem","key":{"id":$util.dynamodb.toDynamoDBJson($util.autoId())},"attributeValues":$util.dynamodb.toMapValuesJson($ctx.args)}`, `$util.toJson($ctx.result)`),
			Source:  store,
		}},
	}}
	if _, err := r.Resolve(context.Background(), map[string]any{"args": map[string]any{"x": "y"}}); err == nil {
		t.Fatal("before abort must fail the pipeline")
	}
	scan, _ := store.Execute(context.Background(), map[string]any{"operation": "Scan"})
	if n := len(scan.(map[string]any)["items"].([]any)); n != 0 {
		t.Fatalf("an aborted pipeline must not run its functions; store has %d items", n)
	}
}
