package directlambda

import (
	"errors"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

func fieldCtx() map[string]any {
	args := map[string]any{"id": "p1"}
	return map[string]any{
		"args": args, "arguments": args,
		"identity": map[string]any{"username": "ada", "groups": []any{"readers"}},
		"source":   map[string]any{"id": "parent"},
		"request":  map[string]any{"headers": map[string]any{"x-custom": "v"}},
		"info":     map[string]any{"fieldName": "author", "parentTypeName": "Post"},
	}
}

// No request template: the Context is the payload of an Invoke, under AWS's names, with prev null and an
// empty stash outside a pipeline.
func TestRequest_SendsTheContextAsAnInvoke(t *testing.T) {
	op, err := New(nil, nil, false).RenderRequest(fieldCtx())
	if err != nil {
		t.Fatal(err)
	}
	if op["operation"] != "Invoke" || op["version"] != "2018-05-29" {
		t.Fatalf("op = %v, want a 2018-05-29 Invoke", op)
	}
	ev := op["payload"].(map[string]any)
	want := map[string]any{
		"arguments": map[string]any{"id": "p1"},
		"identity":  map[string]any{"username": "ada", "groups": []any{"readers"}},
		"source":    map[string]any{"id": "parent"},
		"request":   map[string]any{"headers": map[string]any{"x-custom": "v"}},
		"info":      map[string]any{"fieldName": "author", "parentTypeName": "Post"},
		"prev":      nil,
		"stash":     map[string]any{},
	}
	if !reflect.DeepEqual(ev, want) {
		t.Errorf("event =\n %v\nwant\n %v", ev, want)
	}
}

// With batching on, the same Context goes out as a BatchInvoke (the lifecycle merges the batch).
func TestRequest_BatchingSendsABatchInvoke(t *testing.T) {
	op, _ := New(nil, nil, true).RenderRequest(fieldCtx())
	if op["operation"] != "BatchInvoke" {
		t.Errorf("operation = %v, want BatchInvoke", op["operation"])
	}
}

// An anonymous caller's identity is null, as AppSync's API_KEY mode gives it.
func TestEvent_AnonymousIdentityIsNull(t *testing.T) {
	ctx := fieldCtx()
	ctx["identity"] = map[string]any{"username": "", "groups": []any{}}
	if ev := Event(ctx); ev["identity"] != nil {
		t.Errorf("identity = %v, want null", ev["identity"])
	}
}

// No response template: the result is the value.
func TestResponse_ReturnsTheResult(t *testing.T) {
	ctx := fieldCtx()
	ctx["result"] = map[string]any{"statusCode": float64(500), "data": "kept"}
	got, err := New(nil, nil, false).RenderResponse(ctx)
	if err != nil || !reflect.DeepEqual(got, ctx["result"]) {
		t.Errorf("got %v, %v; want the whole result", got, err)
	}
}

// Batched default response: an item's data is the value; an item with an errorMessage is the field's
// error with its errorType and data; a null item is a null value.
func TestResponse_BatchedItems(t *testing.T) {
	rt := New(nil, nil, true)
	ok := map[string]any{"result": map[string]any{"data": map[string]any{"id": "a"}}}
	if got, err := rt.RenderResponse(ok); err != nil || !reflect.DeepEqual(got, map[string]any{"id": "a"}) {
		t.Errorf("data item: got %v, %v", got, err)
	}
	bad := map[string]any{"result": map[string]any{"data": []any{"partial"}, "errorMessage": "Not found", "errorType": "ERROR"}}
	_, err := rt.RenderResponse(bad)
	var te *vtl.ThrowError
	if !errors.As(err, &te) || te.Message != "Not found" || te.ErrorType != "ERROR" || !reflect.DeepEqual(te.Data, []any{"partial"}) {
		t.Errorf("error item: got %v", err)
	}
	if got, err := rt.RenderResponse(map[string]any{"result": nil}); got != nil || err != nil {
		t.Errorf("null item: got %v, %v; want null", got, err)
	}
	empty := map[string]any{"result": map[string]any{"data": "x", "errorMessage": ""}}
	if got, err := rt.RenderResponse(empty); got != "x" || err != nil {
		t.Errorf("an empty errorMessage is no error: got %v, %v", got, err)
	}
}

// A template the resolver gives runs as written; only the missing phase is direct.
func TestHalfDirect_TemplatePhaseRunsAsWritten(t *testing.T) {
	eng := vtl.New()
	req := vtlruntime.New(eng, `{"version":"2018-05-29","operation":"Invoke","payload":{"only":$util.toJson($ctx.args.id)}}`, "")
	rt := New(req, nil, false)
	op, err := rt.RenderRequest(fieldCtx())
	if err != nil || !reflect.DeepEqual(op["payload"], map[string]any{"only": "p1"}) {
		t.Fatalf("request = %v, %v; want the template's payload", op, err)
	}
	resp := vtlruntime.New(eng, "", `$util.toJson($ctx.result.x)`)
	ctx := fieldCtx()
	ctx["result"] = map[string]any{"x": "shaped"}
	if got, err := New(nil, resp, false).RenderResponse(ctx); got != "shaped" || err != nil {
		t.Errorf("response = %v, %v; want the template's value", got, err)
	}
	if err := New(vtlruntime.New(eng, "#if($x)", ""), nil, false).Validate(); err == nil {
		t.Error("a malformed template must fail validation")
	}
}
