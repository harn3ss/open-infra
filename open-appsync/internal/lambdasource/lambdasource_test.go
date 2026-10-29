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

// directRuntime stands in for the REAL runtime in direct-invoke mode: it always answers HTTP 200 with
// the handler's RAW return value as the body, and signals a THROWN handler error via the
// X-Amz-Function-Error header (it never proxy-maps a {statusCode,...} return). This is the contract the
// node/python/.NET bootstraps implement when X-Openinfra-Invoke: direct is set; the earlier stub
// returned JSON directly with no such contract, so it could not catch the proxy-mapping mismatch.
func directRuntime(t *testing.T, ret map[string]any, thrown bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Openinfra-Invoke") != "direct" {
			t.Errorf("caller did not request direct-invoke (X-Openinfra-Invoke=%q)", r.Header.Get("X-Openinfra-Invoke"))
		}
		if thrown {
			w.Header().Set("X-Amz-Function-Error", "Unhandled")
		}
		w.WriteHeader(http.StatusOK) // direct mode is ALWAYS 200; the header carries the error signal
		_ = json.NewEncoder(w).Encode(ret)
	}))
}

// The #331/#332 case: a handler that returns { statusCode, message, data } with NO body must come back
// as the WHOLE object (under proxy mapping it reached the resolver as null / only body).
func TestLambdaSource_RawReturn_FullObject(t *testing.T) {
	ret := map[string]any{"statusCode": float64(200), "message": "ok", "data": map[string]any{"name": "Ada"}}
	fn := directRuntime(t, ret, false)
	defer fn.Close()
	res, err := New(fn.URL).Execute(context.Background(), runtime.Operation{"payload": map[string]any{"id": "a1"}})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	m, ok := res.(map[string]any)
	if !ok || m["message"] != "ok" || m["data"] == nil || m["statusCode"] != float64(200) {
		t.Errorf("result = %v, want the full returned object (not null / not just body)", res)
	}
}

// Issue point 2: a handler that CATCHES an error and RETURNS { statusCode: 500, ... } is ordinary data,
// not a resolver error (only a THROWN error is a failure).
func TestLambdaSource_Returned500_IsData(t *testing.T) {
	ret := map[string]any{"statusCode": float64(500), "message": "handled"}
	fn := directRuntime(t, ret, false)
	defer fn.Close()
	res, err := New(fn.URL).Execute(context.Background(), runtime.Operation{"payload": map[string]any{}})
	if err != nil {
		t.Fatalf("a returned statusCode:500 is data, not an error: %v", err)
	}
	if m, ok := res.(map[string]any); !ok || m["message"] != "handled" {
		t.Errorf("result = %v, want the returned object as data", res)
	}
}

// A THROWN handler error (X-Amz-Function-Error) is the one thing that is a resolver failure.
func TestLambdaSource_ThrownError_IsFailure(t *testing.T) {
	fn := directRuntime(t, map[string]any{"errorType": "Error", "errorMessage": "boom"}, true)
	defer fn.Close()
	if _, err := New(fn.URL).Execute(context.Background(), runtime.Operation{"payload": map[string]any{}}); err == nil {
		t.Error("a thrown handler error (X-Amz-Function-Error) should be a resolver error")
	}
}
