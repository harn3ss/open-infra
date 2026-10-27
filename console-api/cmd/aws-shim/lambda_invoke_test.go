package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// csWithPodQuota is csWithSAR plus a function-concurrency-quota ResourceQuota in `default` whose
// count/pods used/hard are as given — the tenant concurrency cap the throttle check reads.
func csWithPodQuota(t *testing.T, used, hard string) *fake.Clientset {
	t.Helper()
	cs := csWithSAR(true)
	q := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "function-concurrency-quota", Namespace: "default"},
		Status: corev1.ResourceQuotaStatus{
			Hard: corev1.ResourceList{corev1.ResourceName("count/pods"): resource.MustParse(hard)},
			Used: corev1.ResourceList{corev1.ResourceName("count/pods"): resource.MustParse(used)},
		},
	}
	if err := cs.Tracker().Add(q); err != nil {
		t.Fatalf("seed quota: %v", err)
	}
	return cs
}

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

// At the tenant concurrency cap (count/pods used >= hard), a synchronous invoke is throttled at the
// front door with 429 TooManyRequestsException + a Retry-After — never forwarded into Knative to queue
// and time out into a 503. This is the AWS-correct surfacing of the quota (the documented 503→429 fix).
func TestLambda_ConcurrencyCap_429(t *testing.T) {
	h := newLambdaHandler(csWithPodQuota(t, "150", "150"), "default", "svc.invalid", nil, discardLogger())
	req := httptest.NewRequest("POST", "http://lambda/2015-03-31/functions/hello/invocations", nil)
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "u"}, "r-1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("at-cap invoke status = %d, want 429; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("x-amzn-errortype"); got != "TooManyRequestsException" {
		t.Errorf("errortype = %q, want TooManyRequestsException", got)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Errorf("a throttle response must carry a Retry-After hint for the caller's back-off")
	}
}

// Below the cap the sync path is NOT throttled: it proceeds to forward. Here the upstream is
// unreachable (svc.invalid), so the handler returns ResourceNotFoundException (404) — which proves the
// request passed the throttle gate rather than being rejected with 429.
func TestLambda_UnderCap_NotThrottled(t *testing.T) {
	h := newLambdaHandler(csWithPodQuota(t, "3", "150"), "default", "svc.invalid", nil, discardLogger())
	req := httptest.NewRequest("POST", "http://lambda/2015-03-31/functions/hello/invocations", nil)
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "u"}, "r-1")
	if w.Code == http.StatusTooManyRequests {
		t.Fatalf("under-cap invoke must not be throttled, got 429; body=%s", w.Body.String())
	}
}
