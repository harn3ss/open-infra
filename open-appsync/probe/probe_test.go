// Package probe is open-appsync's compatibility probe: it runs canonical AWS
// AppSync resolver mapping templates through the engine and asserts the output matches AWS's
// DOCUMENTED behavior. The ground truth is AWS's published resolver-template semantics (a live diff
// against real AWS AppSync needs an AWS account — the very thing open-appsync frees teams from), the
// same discipline as anchoring SigV4 on AWS's published test vectors. Expected values are asserted
// as JSON-semantic equality (structure + typed values), which is the fidelity that matters for a
// DynamoDB resolver — not Velocity whitespace.
//
// This is slice 1's probe: it proves the VTL engine + $util execute real templates faithfully with
// the request/response mapping. Wiring the templates to an actual FerretDB data source and
// the GraphQL executor (pieces 1/4) are the next rungs; until this probe is green open-appsync does
// not count as proven.
package probe

import (
	"embed"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

//go:embed corpus/*.vtl
var corpus embed.FS

func mustTemplate(t *testing.T, name string) string {
	t.Helper()
	b, err := corpus.ReadFile("corpus/" + name)
	if err != nil {
		t.Fatalf("read corpus %s: %v", name, err)
	}
	return string(b)
}

// engine returns a VTL engine with pinned autoId/time so output is deterministic.
func engine() *vtl.Engine {
	e := vtl.New()
	e.Util().AutoID = func() string { return "11111111-2222-4333-8444-555555555555" }
	e.Util().Now = func() time.Time { return time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC) }
	return e
}

// renderJSON renders a template and parses the output as JSON (resolver mapping templates emit a
// JSON document). A parse failure is a real fidelity failure — the template must produce valid JSON.
func renderJSON(t *testing.T, name string, ctx map[string]any) any {
	t.Helper()
	out, err := engine().Render(mustTemplate(t, name), ctx)
	if err != nil {
		t.Fatalf("%s: render error: %v", name, err)
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%s: output is not valid JSON: %v\n---\n%s", name, err, out)
	}
	return v
}

func asJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("bad expected JSON: %v", err)
	}
	return v
}

func TestProbe_GetItemRequest(t *testing.T) {
	got := renderJSON(t, "getitem.request.vtl", map[string]any{"args": map[string]any{"id": "123"}})
	want := asJSON(t, `{"version":"2018-05-29","operation":"GetItem","key":{"id":{"S":"123"}}}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetItem request not faithful:\n got %v\nwant %v", got, want)
	}
}

func TestProbe_PutItemRequest(t *testing.T) {
	ctx := map[string]any{"args": map[string]any{"input": map[string]any{"name": "Ada", "age": float64(36)}}}
	got := renderJSON(t, "putitem.request.vtl", ctx)
	want := asJSON(t, `{
	  "version":"2018-05-29","operation":"PutItem",
	  "key":{"id":{"S":"11111111-2222-4333-8444-555555555555"}},
	  "attributeValues":{"name":{"S":"Ada"},"age":{"N":"36"}}
	}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PutItem request not faithful:\n got %v\nwant %v", got, want)
	}
}

func TestProbe_ResponseTemplate(t *testing.T) {
	result := map[string]any{"id": "123", "name": "Ada", "age": float64(36)}
	got := renderJSON(t, "response.vtl", map[string]any{"result": result})
	if !reflect.DeepEqual(got, result) {
		t.Fatalf("response template not faithful:\n got %v\nwant %v", got, result)
	}
}

// TestProbe_ValidateRejects proves the resolver-thrown-error path: a validation template that calls
// $util.error aborts with the AppSync error shape (message + errorType) instead of producing an op.
func TestProbe_ValidateRejects(t *testing.T) {
	_, err := engine().Render(mustTemplate(t, "validate.request.vtl"),
		map[string]any{"args": map[string]any{"input": map[string]any{}}})
	var te *vtl.ThrowError
	if !errors.As(err, &te) {
		t.Fatalf("expected a $util.error ThrowError, got %v", err)
	}
	if te.Message != "name is required" || te.ErrorType != "BadRequest" {
		t.Fatalf("wrong error shape: %+v", te)
	}
}

// TestProbe_ValidatePasses: with a valid input the same template produces the PutItem operation.
func TestProbe_ValidatePasses(t *testing.T) {
	ctx := map[string]any{"args": map[string]any{"input": map[string]any{"name": "Ada"}}}
	got := renderJSON(t, "validate.request.vtl", ctx)
	m, ok := got.(map[string]any)
	if !ok || m["operation"] != "PutItem" {
		t.Fatalf("valid input should yield a PutItem op, got %v", got)
	}
}
