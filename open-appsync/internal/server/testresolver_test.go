package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The test-resolver endpoint: POST a resolver + a sample $ctx, get back the neutral
// request Operation and — when a sample result is supplied — the response value, with no deploy and
// no data source. This is the authoring-with-feedback loop.
func post(t *testing.T, body string) TestResolverResponse {
	t.Helper()
	w := httptest.NewRecorder()
	TestResolverHandler()(w, httptest.NewRequest(http.MethodPost, "/test-resolver", strings.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out TestResolverResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad response JSON: %v (%s)", err, w.Body.String())
	}
	return out
}

func TestTestResolver_RequestAndResponse(t *testing.T) {
	out := post(t, `{
	  "request": "{\"operation\":\"GetItem\",\"key\":{\"id\":$util.dynamodb.toDynamoDBJson($ctx.args.id)}}",
	  "response": "$util.toJson($ctx.result)",
	  "context": {"args": {"id": "123"}},
	  "result": {"id": "123", "name": "Ada"}
	}`)
	if out.Error != "" {
		t.Fatalf("unexpected error: %+v", out)
	}
	op := out.RequestOp.(map[string]any)
	if op["operation"] != "GetItem" {
		t.Fatalf("request op not shown faithfully: %v", op)
	}
	key := op["key"].(map[string]any)["id"].(map[string]any)
	if key["S"] != "123" {
		t.Fatalf("key not marshalled: %v", key)
	}
	resp := out.Response.(map[string]any)
	if resp["name"] != "Ada" {
		t.Fatalf("response phase not shown: %v", resp)
	}
}

// Without a sample result, only the request phase runs (the response is not rendered).
func TestTestResolver_RequestOnly(t *testing.T) {
	out := post(t, `{
	  "request": "{\"operation\":\"Scan\"}",
	  "response": "$util.toJson($ctx.result)",
	  "context": {"args": {}}
	}`)
	if out.Error != "" || out.Response != nil {
		t.Fatalf("expected request-only, got %+v", out)
	}
	if out.RequestOp.(map[string]any)["operation"] != "Scan" {
		t.Fatalf("request op wrong: %v", out.RequestOp)
	}
}

// A $util.error surfaces with its errorType — the feedback that makes authoring not blind.
func TestTestResolver_SurfacesValidationError(t *testing.T) {
	out := post(t, `{
	  "request": "#if($util.isNullOrEmpty($ctx.args.name))$util.error(\"name is required\",\"BadRequest\")#end\n{\"operation\":\"Scan\"}",
	  "response": "$util.toJson($ctx.result)",
	  "context": {"args": {}}
	}`)
	if out.ErrorType != "BadRequest" || out.Error != "name is required" {
		t.Fatalf("expected a surfaced BadRequest, got %+v", out)
	}
}
