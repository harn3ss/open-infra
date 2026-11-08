package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func fnClaimWithTimeout(ns, name string, secs int64) *unstructured.Unstructured {
	spec := map[string]any{"image": "ghcr.io/me/fn:1"}
	if secs > 0 {
		spec["timeout"] = secs
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Function",
		"metadata": map[string]any{"name": name, "namespace": ns}, "spec": spec}}
}

func timeoutsFor(objs ...runtime.Object) *fnTimeouts {
	return newFnTimeouts(dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{functionClaimGVR: "FunctionList"}, objs...))
}

// A function's timeout is its spec.timeout, clamped to Lambda's 900 s, or Knative's 300 s when unset.
func TestFnTimeouts_TheFunctionsOwn(t *testing.T) {
	ts := timeoutsFor(fnClaimWithTimeout("default", "slow", 120), fnClaimWithTimeout("default", "plain", 0), fnClaimWithTimeout("default", "huge", 5000))
	ctx := context.Background()
	for name, want := range map[string]time.Duration{"slow": 120 * time.Second, "plain": defaultFunctionTimeout, "huge": maxFunctionTimeout, "missing": defaultFunctionTimeout} {
		if got := ts.of(ctx, "default", name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	var nilTS *fnTimeouts
	if nilTS.of(ctx, "default", "x") != defaultFunctionTimeout {
		t.Error("no reader: the default")
	}
}

func timeoutHandler(t *testing.T, up http.HandlerFunc, secs int64) *lambdaHandler {
	t.Helper()
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	h := newLambdaHandler(csWithSAR(true), "default", "svc.cluster.local", nil, discardLogger())
	h.client = &http.Client{Transport: toServer{u}}
	h.timeouts = timeoutsFor(fnClaimWithTimeout("default", "fn", secs))
	h.coldStart = 0
	return h
}

func invokeFn(h *lambdaHandler) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "http://lambda/2015-03-31/functions/fn/invocations", io.NopCloser(strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "u"}, "req-1")
	return w
}

// An invoke waits for the function's own timeout, not a fixed one: a function that takes longer than a
// short default but less than its Timeout returns its result.
func TestLambda_InvokeWaitsForTheFunctionsTimeout(t *testing.T) {
	h := timeoutHandler(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"done":true}`))
	}, 3)
	w := invokeFn(h)
	if w.Code != http.StatusOK || w.Header().Get("X-Amz-Function-Error") != "" || !strings.Contains(w.Body.String(), `"done":true`) {
		t.Fatalf("a function within its timeout must return its result: %d %q %s", w.Code, w.Header().Get("X-Amz-Function-Error"), w.Body.String())
	}
}

// A function that outlives its timeout ends with Lambda's timeout error: 200, a function error, and
// Sandbox.Timedout "Task timed out after N.NN seconds" — not ResourceNotFoundException.
func TestLambda_InvokePastTheTimeoutIsTaskTimedOut(t *testing.T) {
	release := make(chan struct{})
	h := timeoutHandler(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, 1)
	defer close(release)
	start := time.Now()
	w := invokeFn(h)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("the invoke must end at the function's timeout, took %v", el)
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusOK || w.Header().Get("X-Amz-Function-Error") != "Unhandled" || body["errorType"] != "Sandbox.Timedout" ||
		!strings.Contains(body["errorMessage"], "Task timed out after 1.00 seconds") || !strings.Contains(body["errorMessage"], "req-1") {
		t.Fatalf("a timed-out invoke must be Lambda's timeout error: %d %q %s", w.Code, w.Header().Get("X-Amz-Function-Error"), w.Body.String())
	}
}

// Knative ends a request at the revision's timeout with a 504 the function never answered: that too is the
// function's timeout. A 504 the function itself sent with its error header is its own error.
func TestLambda_KnativesTimeoutIsTaskTimedOut(t *testing.T) {
	h := timeoutHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.Write([]byte("activator request timeout"))
	}, 30)
	w := invokeFn(h)
	if !strings.Contains(w.Body.String(), "Task timed out after 30.00 seconds") || w.Header().Get("X-Amz-Function-Error") != "Unhandled" {
		t.Fatalf("Knative's 504 is the function's timeout: %d %s", w.Code, w.Body.String())
	}
	h = timeoutHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Function-Error", "Unhandled")
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.Write([]byte(`{"errorMessage":"upstream said no"}`))
	}, 30)
	if w := invokeFn(h); !strings.Contains(w.Body.String(), "upstream said no") {
		t.Fatalf("a function's own error passes through: %s", w.Body.String())
	}
}
