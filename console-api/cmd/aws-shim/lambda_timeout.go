// A Lambda function's timeout, as an invoke waits for it (#372).
//
// AWS runs a function up to its Timeout (1–900 s), counted once its runtime is initialised, and past it
// ends the invocation with a function error: "Task timed out after N.NN seconds". Here the function's
// runtime enforces its spec.timeout (300 s when unset) from the invoke's arrival, and answers a 504 at it
// (#413). Knative's revision deadline, which counts the wait for an instance started from zero, is the
// timeout plus invokeColdStartAllowance (function-composition.yaml), and so is the invoke's own wait. Past
// it, or on either 504 (the runtime's, or Knative's at its deadline), a synchronous invoke answers AWS's
// timeout error; an asynchronous delivery counts it a failed attempt, retried as AWS retries one.
package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

const (
	// defaultFunctionTimeout is a function's timeout when spec.timeout is unset: Knative's revision timeout.
	defaultFunctionTimeout = 300 * time.Second
	// maxFunctionTimeout is Lambda's, and the Function XRD's, ceiling.
	maxFunctionTimeout = 900 * time.Second
	// invokeColdStartAllowance is added to a function's timeout: scaling it from zero comes first.
	invokeColdStartAllowance = 90 * time.Second
	// fnTimeoutCacheTTL is how long a function's timeout is remembered.
	fnTimeoutCacheTTL = time.Minute
)

// fnTimeouts reads functions' spec.timeout, remembered briefly.
type fnTimeouts struct {
	dyn dynamic.Interface
	now func() time.Time

	mu    sync.Mutex
	cache map[string]fnTimeoutEntry
}

type fnTimeoutEntry struct {
	d  time.Duration
	at time.Time
}

func newFnTimeouts(dyn dynamic.Interface) *fnTimeouts {
	return &fnTimeouts{dyn: dyn, cache: map[string]fnTimeoutEntry{}}
}

func (t *fnTimeouts) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// of is function ns/name's timeout: its spec.timeout, clamped to 1–900 s, or the default when it is
// unset or the function cannot be read.
func (t *fnTimeouts) of(ctx context.Context, ns, name string) time.Duration {
	if t == nil || t.dyn == nil {
		return defaultFunctionTimeout
	}
	key := ns + "/" + name
	t.mu.Lock()
	if e, ok := t.cache[key]; ok && t.clock().Sub(e.at) < fnTimeoutCacheTTL {
		t.mu.Unlock()
		return e.d
	}
	t.mu.Unlock()
	d := defaultFunctionTimeout
	if claim, err := t.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{}); err == nil {
		if secs, found, _ := unstructured.NestedInt64(claim.Object, "spec", "timeout"); found && secs > 0 {
			d = time.Duration(secs) * time.Second
			if d > maxFunctionTimeout {
				d = maxFunctionTimeout
			}
		}
	}
	t.mu.Lock()
	if len(t.cache) > fnLocatorCacheMax {
		t.cache = map[string]fnTimeoutEntry{}
	}
	t.cache[key] = fnTimeoutEntry{d: d, at: t.clock()}
	t.mu.Unlock()
	return d
}

// forget drops function ns/name's remembered timeout (its configuration just changed).
func (t *fnTimeouts) forget(ns, name string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.cache, ns+"/"+name)
	t.mu.Unlock()
}

// writeTaskTimedOut answers a synchronous invoke the function did not finish within its timeout, as
// Lambda answers one: 200, a function error, and the Sandbox.Timedout payload.
func writeTaskTimedOut(w http.ResponseWriter, requestID string, timeout time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Amz-Function-Error", "Unhandled")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"errorType":"Sandbox.Timedout","errorMessage":"RequestId: %s Error: Task timed out after %.2f seconds"}`,
		requestID, timeout.Seconds())
}
