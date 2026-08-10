package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// DryRun validates permissions without invoking: an authorized caller gets 204 and the function is
// never called (the handler returns before any upstream request).
func TestLambda_DryRun_204(t *testing.T) {
	// svcSuffix points nowhere reachable — if DryRun wrongly invoked, the test would still pass on 204
	// only because the branch returns first; correctness is that we get 204 with no body.
	h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
	req := httptest.NewRequest("POST", "http://lambda/2015-03-31/functions/hello/invocations", nil)
	req.Header.Set("X-Amz-Invocation-Type", "DryRun")
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "u"}, "r-1")
	if w.Code != http.StatusNoContent {
		t.Fatalf("DryRun status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Errorf("DryRun must have an empty body, got %q", w.Body.String())
	}
}

// DryRun is NOT an authorization bypass: the SAR still runs, so a denied caller gets 403.
func TestLambda_DryRun_StillAuthorized(t *testing.T) {
	h := newLambdaHandler(csWithSAR(false), "default", "svc.invalid", nil, discardLogger())
	req := httptest.NewRequest("POST", "http://lambda/2015-03-31/functions/hello/invocations", nil)
	req.Header.Set("X-Amz-Invocation-Type", "DryRun")
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "u"}, "r-1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("denied DryRun status = %d, want 403 (DryRun must still enforce auth)", w.Code)
	}
}

// Event (async) invocation with no event bus configured is refused honestly (503), not silently dropped.
func TestLambda_EventWithoutBus_503(t *testing.T) {
	h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger()) // async == nil
	req := httptest.NewRequest("POST", "http://lambda/2015-03-31/functions/hello/invocations", nil)
	req.Header.Set("X-Amz-Invocation-Type", "Event")
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "u"}, "r-1")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("Event without a bus = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("x-amzn-errortype"); got != "ServiceException" {
		t.Errorf("errortype = %q, want ServiceException", got)
	}
}
