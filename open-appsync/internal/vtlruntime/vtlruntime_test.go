package vtlruntime_test

import (
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

func pinned() *vtl.Engine {
	e := vtl.New()
	e.Util().AutoID = func() string { return "fixed-id" }
	return e
}

// The VTL tenant implements the runtime.Runtime contract (assignment is the compile-time proof).
var _ runtime.Runtime = (*vtlruntime.Runtime)(nil)
var _ runtime.Validator = (*vtlruntime.Runtime)(nil)

func TestVTLRuntime_RequestEmitsNeutralOperation(t *testing.T) {
	rt := vtlruntime.New(pinned(),
		`{"operation":"GetItem","key":{"id":$util.dynamodb.toDynamoDBJson($ctx.args.id)}}`,
		`$util.toJson($ctx.result)`)

	op, err := rt.RenderRequest(map[string]any{"args": map[string]any{"id": "123"}})
	if err != nil {
		t.Fatal(err)
	}
	want := runtime.Operation{"operation": "GetItem", "key": map[string]any{"id": map[string]any{"S": "123"}}}
	if !reflect.DeepEqual(op, want) {
		t.Fatalf("request op not faithful:\n got %v\nwant %v", op, want)
	}
}

func TestVTLRuntime_ResponsePassesResultThrough(t *testing.T) {
	rt := vtlruntime.New(pinned(), `{}`, `$util.toJson($ctx.result)`)
	result := map[string]any{"id": "1", "name": "Ada"}
	got, err := rt.RenderResponse(map[string]any{"result": result})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, result) {
		t.Fatalf("response not faithful:\n got %v\nwant %v", got, result)
	}
}

// Validate is the fail-closed hook: a well-formed template passes, a structurally broken one (an
// unterminated #if) is rejected so the engine refuses to serve it.
func TestVTLRuntime_Validate(t *testing.T) {
	if err := vtlruntime.New(pinned(), `{"operation":"Scan"}`, `$util.toJson($ctx.result)`).Validate(); err != nil {
		t.Fatalf("well-formed templates should validate: %v", err)
	}
	broken := vtlruntime.New(pinned(), "#if($ctx.args.x)\n{}\n", `$util.toJson($ctx.result)`) // no #end
	if err := broken.Validate(); err == nil {
		t.Fatal("a malformed template (#if without #end) must fail validation")
	}
}
