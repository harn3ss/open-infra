package vtl

import (
	"errors"
	"testing"
	"time"
)

// fixedEngine returns an engine with pinned $util.autoId/time so output is byte-deterministic.
func fixedEngine() *Engine {
	e := New()
	e.util.AutoID = func() string { return "00000000-0000-4000-8000-000000000000" }
	e.util.Now = func() time.Time { return time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC) }
	return e
}

func render(t *testing.T, tmpl string, ctx map[string]any) string {
	t.Helper()
	out, err := fixedEngine().Render(tmpl, ctx)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	return out
}

func TestToDynamoDB_TypedShapes(t *testing.T) {
	// The fidelity-critical conversion; shapes are AWS-documented ground truth.
	cases := map[any]string{}
	_ = cases
	got := map[string]string{
		"string": jsonString(toDynamoDB("hello")),
		"int":    jsonString(toDynamoDB(float64(5))),
		"float":  jsonString(toDynamoDB(3.5)),
		"bool":   jsonString(toDynamoDB(true)),
		"null":   jsonString(toDynamoDB(nil)),
		"list":   jsonString(toDynamoDB([]any{"a", float64(1)})),
		"map":    jsonString(toDynamoDB(map[string]any{"id": "a", "n": float64(2)})),
	}
	want := map[string]string{
		"string": `{"S":"hello"}`,
		"int":    `{"N":5}`,
		"float":  `{"N":3.5}`,
		"bool":   `{"BOOL":true}`,
		"null":   `{"NULL":null}`,
		"list":   `{"L":[{"S":"a"},{"N":1}]}`,
		"map":    `{"M":{"id":{"S":"a"},"n":{"N":2}}}`,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("toDynamoDB %s = %s, want %s", k, got[k], w)
		}
	}
}

func TestRender_UtilToJson(t *testing.T) {
	out := render(t, `$util.toJson($ctx.result)`, map[string]any{"result": map[string]any{"id": "x", "n": float64(1)}})
	if out != `{"id":"x","n":1}` {
		t.Fatalf("got %q", out)
	}
}

func TestRender_UtilDynamoDBJson(t *testing.T) {
	out := render(t, `$util.dynamodb.toDynamoDBJson($ctx.args.id)`, map[string]any{"args": map[string]any{"id": "123"}})
	if out != `{"S":"123"}` {
		t.Fatalf("got %q", out)
	}
}

func TestRender_IfNotNull(t *testing.T) {
	tmpl := `#if(!$util.isNull($ctx.args.opt))has:$ctx.args.opt#{else}absent#end`
	if out := render(t, tmpl, map[string]any{"args": map[string]any{"opt": "v"}}); out != "has:v" {
		t.Fatalf("got %q", out)
	}
	if out := render(t, tmpl, map[string]any{"args": map[string]any{}}); out != "absent" {
		t.Fatalf("got %q", out)
	}
}

func TestRender_AutoIdDeterministic(t *testing.T) {
	out := render(t, `$util.autoId()`, map[string]any{})
	if out != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("got %q", out)
	}
}

func TestRender_UtilErrorThrows(t *testing.T) {
	_, err := fixedEngine().Render(`#if($util.isNull($ctx.args.id))$util.error("id required","BadRequest")#end`,
		map[string]any{"args": map[string]any{}})
	var te *ThrowError
	if !errors.As(err, &te) {
		t.Fatalf("expected *ThrowError, got %v", err)
	}
	if te.Message != "id required" || te.ErrorType != "BadRequest" {
		t.Fatalf("bad ThrowError: %+v", te)
	}
}
