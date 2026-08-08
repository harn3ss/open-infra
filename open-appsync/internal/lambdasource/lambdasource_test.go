package lambdasource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Green-light-one: the caller works with zero AWS. An httptest server stands in for a kind: Function;
// the Store must send the invoke `payload` and return the function's JSON response as the result.
func TestLambdaSource_InvokesWithPayload(t *testing.T) {
	var gotBody map[string]any
	fn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		// Echo an author derived from the payload — like a real function reading its event.
		id, _ := gotBody["id"].(string)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "name": "Ada"})
	}))
	defer fn.Close()

	s := New(fn.URL)
	op := runtime.Operation{
		"version":   "2018-05-29",
		"operation": "Invoke",
		"payload":   map[string]any{"id": "a1", "field": "author"},
	}
	res, err := s.Execute(context.Background(), op)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// The function received the payload (not the whole envelope).
	if gotBody["id"] != "a1" || gotBody["field"] != "author" || gotBody["operation"] != nil {
		t.Errorf("function received %v, want just the payload", gotBody)
	}
	m, ok := res.(map[string]any)
	if !ok || m["name"] != "Ada" || m["id"] != "a1" {
		t.Errorf("result = %v, want the function's JSON response", res)
	}
}

// A function error (non-2xx) is surfaced as an invocation error.
func TestLambdaSource_FunctionErrorSurfaces(t *testing.T) {
	fn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errorMessage":"boom"}`, http.StatusInternalServerError)
	}))
	defer fn.Close()
	if _, err := New(fn.URL).Execute(context.Background(), runtime.Operation{"payload": map[string]any{}}); err == nil {
		t.Error("a non-2xx function response should be an error")
	}
}

// BatchInvoke is explicitly not supported yet (fails loud rather than silently mis-invoking).
func TestLambdaSource_BatchInvokeUnsupported(t *testing.T) {
	if _, err := New("http://unused").Execute(context.Background(), runtime.Operation{"operation": "BatchInvoke"}); err == nil {
		t.Error("BatchInvoke should return a not-supported error")
	}
}
