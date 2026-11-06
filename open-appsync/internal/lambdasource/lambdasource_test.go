package lambdasource

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// batchFn is a direct-invoke function that records the event it got and answers with reply(event).
func batchFn(t *testing.T, calls *[]any, reply func(event any) any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Openinfra-Invoke") != "direct" {
			t.Errorf("BatchInvoke must use direct-invoke (X-Openinfra-Invoke=%q)", r.Header.Get("X-Openinfra-Invoke"))
		}
		b, _ := io.ReadAll(r.Body)
		var ev any
		_ = json.Unmarshal(b, &ev)
		*calls = append(*calls, ev)
		_ = json.NewEncoder(w).Encode(reply(ev))
	}))
}

func batchOp(payload any) runtime.Operation {
	return runtime.Operation{"version": "2018-05-29", "operation": "BatchInvoke", "payload": payload}
}

// AppSync's BatchInvoke: the payloads of the batch are merged into ONE list, the function is invoked
// once with it, and the returned list's elements are the items' results in order.
func TestLambdaSource_ExecuteBatch_OneInvocationOfThePayloadList(t *testing.T) {
	var calls []any
	fn := batchFn(t, &calls, func(ev any) any {
		var out []any
		for _, p := range ev.([]any) {
			out = append(out, map[string]any{"echo": p.(map[string]any)["id"]})
		}
		return out
	})
	defer fn.Close()
	res, err := New(fn.URL).ExecuteBatch(context.Background(), []runtime.Operation{
		batchOp(map[string]any{"id": "a"}), batchOp(map[string]any{"id": "b"}), batchOp(map[string]any{"id": "c"}),
	})
	if err != nil {
		t.Fatalf("ExecuteBatch: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("a batch is ONE invocation, got %d", len(calls))
	}
	if ev, ok := calls[0].([]any); !ok || len(ev) != 3 || ev[1].(map[string]any)["id"] != "b" {
		t.Errorf("the function must receive the list of payloads, got %v", calls[0])
	}
	for i, want := range []string{"a", "b", "c"} {
		if res[i].(map[string]any)["echo"] != want {
			t.Errorf("result %d = %v, want echo %s (in order)", i, res[i], want)
		}
	}
}

// A BatchInvoke document run on its own is a batch of one: the function still receives a list.
func TestLambdaSource_ExecuteBatchInvokeIsABatchOfOne(t *testing.T) {
	var calls []any
	fn := batchFn(t, &calls, func(ev any) any { return []any{map[string]any{"n": float64(len(ev.([]any)))}} })
	defer fn.Close()
	res, err := New(fn.URL).Execute(context.Background(), batchOp(map[string]any{"id": "a"}))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.(map[string]any)["n"] != float64(1) {
		t.Errorf("result = %v, want the single item of a one-element batch", res)
	}
}

// A response that cannot be matched back to the batch fails it: a list of the wrong length, or no list.
func TestLambdaSource_ExecuteBatch_ResponseMismatchFails(t *testing.T) {
	ops := []runtime.Operation{batchOp(1), batchOp(2), batchOp(3)}
	for name, reply := range map[string]any{
		"short list": []any{"x", "y"},
		"long list":  []any{"x", "y", "z", "w"},
		"not a list": map[string]any{"data": "x"},
	} {
		var calls []any
		fn := batchFn(t, &calls, func(any) any { return reply })
		_, err := New(fn.URL).ExecuteBatch(context.Background(), ops)
		fn.Close()
		var be *BatchResponseError
		if !errors.As(err, &be) {
			t.Errorf("%s: want a BatchResponseError, got %v", name, err)
			continue
		}
		msg, typ, _ := be.AppSyncError()
		if typ != BatchResponseMismatch || !strings.Contains(msg, "batch of 3") && !strings.Contains(msg, "list of 3") {
			t.Errorf("%s: error = %q (%s), want the size mismatch named", name, msg, typ)
		}
	}
}

// Null items are valid in a batch response (the item's $ctx.result is null).
func TestLambdaSource_ExecuteBatch_NullItemsAreValid(t *testing.T) {
	var calls []any
	fn := batchFn(t, &calls, func(any) any { return []any{nil, "b"} })
	defer fn.Close()
	res, err := New(fn.URL).ExecuteBatch(context.Background(), []runtime.Operation{batchOp(1), batchOp(2)})
	if err != nil || res[0] != nil || res[1] != "b" {
		t.Fatalf("got %v, %v; want [nil b]", res, err)
	}
}

// A thrown error is the function's errorType/errorMessage on the field — what AppSync shows — and fails
// every item of a batch.
func TestLambdaSource_ThrownError_CarriesLambdaErrorTypeAndMessage(t *testing.T) {
	fn := directRuntime(t, map[string]any{"errorType": "CustomException", "errorMessage": "Custom message"}, true)
	defer fn.Close()
	_, err := New(fn.URL).Execute(context.Background(), runtime.Operation{"payload": map[string]any{}})
	var fe *FunctionError
	if !errors.As(err, &fe) {
		t.Fatalf("want a FunctionError, got %v", err)
	}
	if msg, typ, _ := fe.AppSyncError(); msg != "Custom message" || typ != "CustomException" {
		t.Errorf("AppSyncError = (%q, %q), want (Custom message, CustomException)", msg, typ)
	}
	if _, err := New(fn.URL).ExecuteBatch(context.Background(), []runtime.Operation{batchOp(1), batchOp(2)}); !errors.As(err, &fe) {
		t.Errorf("a thrown error must fail the whole batch, got %v", err)
	}
}

// An error thrown with no errorType is "Lambda:<X-Amz-Function-Error>"; an UnauthorizedException's
// message is AppSync's fixed one, not the function's.
func TestLambdaSource_FunctionErrorShapes(t *testing.T) {
	cases := []struct {
		body              string
		wantMsg, wantType string
	}{
		{`{"errorMessage":"I fail. Always."}`, "I fail. Always.", "Lambda:Unhandled"},
		{`"bare string"`, "bare string", "Lambda:Unhandled"},
		{`{"errorType":"UnauthorizedException","errorMessage":"go away"}`, "You are not authorized to make this call.", "UnauthorizedException"},
	}
	for _, c := range cases {
		fe := functionError("Unhandled", []byte(c.body))
		if msg, typ, _ := fe.AppSyncError(); msg != c.wantMsg || typ != c.wantType {
			t.Errorf("%s: AppSyncError = (%q, %q), want (%q, %q)", c.body, msg, typ, c.wantMsg, c.wantType)
		}
	}
}

// Fail closed on a request this source does not serve: an asynchronous (Event) invoke, or an operation
// that is not Lambda's. The function is never called.
func TestLambdaSource_UnsupportedRequestsFailClosed(t *testing.T) {
	var calls []any
	fn := batchFn(t, &calls, func(any) any { return nil })
	defer fn.Close()
	for name, op := range map[string]runtime.Operation{
		"Event invoke":       {"operation": "Invoke", "invocationType": "Event", "payload": 1},
		"Event batch":        {"operation": "BatchInvoke", "invocationType": "Event", "payload": 1},
		"unknown operation":  {"operation": "GetItem", "payload": 1},
		"unknown invocation": {"operation": "Invoke", "invocationType": "DryRun", "payload": 1},
	} {
		_, err := New(fn.URL).Execute(context.Background(), op)
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
		if name == "Event invoke" && (err == nil || !strings.Contains(err.Error(), "invocationType Event")) {
			t.Errorf("%s: the error must name the unsupported feature, got %v", name, err)
		}
	}
	if len(calls) != 0 {
		t.Errorf("a refused request must not reach the function (%d calls)", len(calls))
	}
	if _, err := New(fn.URL).Execute(context.Background(), runtime.Operation{"operation": "Invoke", "invocationType": "RequestResponse", "payload": 1}); err != nil {
		t.Errorf("RequestResponse is the synchronous invoke and is served: %v", err)
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
