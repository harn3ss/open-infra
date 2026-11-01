package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const testCFNNamespace = "open-infra-cfn"

func fnClaim(ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Function",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     map[string]any{"runtime": "nodejs20.x"},
	}}
}

// fnDyn is a fake cluster holding the given kind: Function claims (and Services, which are not functions).
func fnDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		functionClaimGVR:                      "FunctionList",
		{Version: "v1", Resource: "services"}: "ServiceList",
	}, objs...)
}

func TestFnLocator_FindsTheNamespaceThatHasTheFunction(t *testing.T) {
	ctx := context.Background()
	l := newFnLocator(fnDyn(fnClaim(testCFNNamespace, "stack-fn"), fnClaim("default", "api-fn")), discardLogger(), "default", testCFNNamespace)
	if got := l.namespaceOf(ctx, "stack-fn", "default"); got != testCFNNamespace {
		t.Errorf("a stack's function resolves to %q, want %q", got, testCFNNamespace)
	}
	if got := l.namespaceOf(ctx, "api-fn", "default"); got != "default" {
		t.Errorf("a Lambda-API function resolves to %q, want default", got)
	}
	if got := l.namespaceOf(ctx, "nowhere", "default"); got != "default" {
		t.Errorf("an unknown function resolves to %q, want the fallback", got)
	}
}

// A Kubernetes Service (an application) of the same name is not a function: only a kind: Function counts.
func TestFnLocator_AServiceIsNotAFunction(t *testing.T) {
	svc := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": "webapp", "namespace": testCFNNamespace}}}
	l := newFnLocator(fnDyn(svc), discardLogger(), "default", testCFNNamespace)
	if got := l.namespaceOf(context.Background(), "webapp", "default"); got != "default" {
		t.Errorf("a Service named like the function routed the invoke to %q", got)
	}
}

// A name in both namespaces resolves to the first (the Lambda API's) — the order is the precedence.
func TestFnLocator_CollisionResolvesToTheFirstNamespace(t *testing.T) {
	l := newFnLocator(fnDyn(fnClaim(testCFNNamespace, "dup"), fnClaim("default", "dup")), discardLogger(), "default", testCFNNamespace)
	if got := l.namespaceOf(context.Background(), "dup", "default"); got != "default" {
		t.Errorf("collision resolved to %q, want default (the first namespace)", got)
	}
}

// Answers are remembered (a found one for a minute, a miss briefly), forget drops one, and the cache is
// bounded.
func TestFnLocator_CachesAndForgets(t *testing.T) {
	ctx := context.Background()
	dyn := fnDyn(fnClaim(testCFNNamespace, "f"))
	l := newFnLocator(dyn, discardLogger(), "default", testCFNNamespace)
	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }
	if got := l.namespaceOf(ctx, "f", "default"); got != testCFNNamespace {
		t.Fatalf("first lookup = %q", got)
	}
	_ = dyn.Tracker().Delete(functionClaimGVR, testCFNNamespace, "f")
	if got := l.namespaceOf(ctx, "f", "default"); got != testCFNNamespace {
		t.Errorf("within the TTL the answer must be the remembered one, got %q", got)
	}
	now = now.Add(2 * time.Minute)
	if got := l.namespaceOf(ctx, "f", "default"); got != "default" {
		t.Errorf("after the TTL the function (now gone) must fall back, got %q", got)
	}
	// A remembered miss is short-lived and forget drops it at once.
	_ = dyn.Tracker().Create(functionClaimGVR, fnClaim(testCFNNamespace, "f"), testCFNNamespace)
	if got := l.namespaceOf(ctx, "f", "default"); got != "default" {
		t.Errorf("a remembered miss = %q, want the fallback", got)
	}
	l.forget("f")
	if got := l.namespaceOf(ctx, "f", "default"); got != testCFNNamespace {
		t.Errorf("after forget the function must be found, got %q", got)
	}
	for i := 0; i < fnLocatorCacheMax+10; i++ {
		l.namespaceOf(ctx, "n"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+time.Duration(i).String(), "default")
	}
	if n := len(l.cache); n > fnLocatorCacheMax {
		t.Errorf("cache holds %d entries, want at most %d", n, fnLocatorCacheMax)
	}
}

// A namespace the shim cannot read is skipped; with the function found elsewhere it still resolves, and
// with it found nowhere the answer is the fallback and nothing is remembered.
func TestFnLocator_UnreadableNamespace(t *testing.T) {
	ctx := context.Background()
	dyn := fnDyn(fnClaim(testCFNNamespace, "f"))
	forbidden := true
	dyn.PrependReactor("get", "functions", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == "default" && forbidden {
			return true, nil, apierrors.NewForbidden(functionClaimGVR.GroupResource(), "x", nil)
		}
		return false, nil, nil
	})
	l := newFnLocator(dyn, discardLogger(), "default", testCFNNamespace)
	if got := l.namespaceOf(ctx, "f", "default"); got != testCFNNamespace {
		t.Errorf("found past an unreadable namespace = %q, want %q", got, testCFNNamespace)
	}
	if got := l.namespaceOf(ctx, "g", "default"); got != "default" {
		t.Errorf("not found with a namespace unreadable = %q, want the fallback", got)
	}
	if _, cached := l.cache["g"]; cached {
		t.Error("an answer with a namespace unreadable must not be remembered")
	}
}

func TestFnLocator_NilAndUnconfiguredFallBack(t *testing.T) {
	var l *fnLocator
	if got := l.namespaceOf(context.Background(), "f", "default"); got != "default" {
		t.Errorf("nil locator = %q", got)
	}
	l.forget("f") // nil-safe
	if got, err := l.elsewhere(context.Background(), "f", "default"); got != "" || err != nil {
		t.Errorf("nil locator elsewhere = %q, %v", got, err)
	}
}

func TestFnLocator_Elsewhere(t *testing.T) {
	ctx := context.Background()
	l := newFnLocator(fnDyn(fnClaim("default", "taken")), discardLogger(), "default", testCFNNamespace)
	if got, err := l.elsewhere(ctx, "taken", testCFNNamespace); err != nil || got != "default" {
		t.Errorf("elsewhere(taken) = %q, %v; want default", got, err)
	}
	if got, _ := l.elsewhere(ctx, "taken", "default"); got != "" {
		t.Errorf("the namespace asked about is not elsewhere, got %q", got)
	}
	if got, _ := l.elsewhere(ctx, "free", testCFNNamespace); got != "" {
		t.Errorf("elsewhere(free) = %q", got)
	}
}

// parseInvokePath accepts a function ARN, a partial ARN and a name, each with an optional qualifier.
func TestParseInvokePath_ARNForms(t *testing.T) {
	cases := map[string][2]string{
		"hello":      {"hello", ""},
		"hello:live": {"hello", "live"},
		"arn:aws:lambda:us-east-1:000000000000:function:hello":      {"hello", ""},
		"arn:aws:lambda:us-east-1:000000000000:function:hello:live": {"hello", "live"},
		"000000000000:function:hello":                               {"hello", ""},
	}
	for in, want := range cases {
		r := httptest.NewRequest(http.MethodPost, "http://lambda/2015-03-31/functions/"+strings.ReplaceAll(in, ":", "%3A")+"/invocations", nil)
		name, q, ok := parseInvokePath(r)
		if !ok || name != want[0] || q != want[1] {
			t.Errorf("parseInvokePath(%q) = %q, %q, %v; want %q, %q", in, name, q, ok, want[0], want[1])
		}
	}
}

// captureTransport records the host each upstream request goes to and answers 200 {}.
type captureTransport struct {
	mu    sync.Mutex
	hosts []string
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.hosts = append(c.hosts, r.URL.Host)
	c.mu.Unlock()
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	_, _ = rec.WriteString("{}")
	return rec.Result(), nil
}

// A Lambda Invoke of a stack's function (by name or by the Arn its stack reports) reaches it in the stack
// namespace, and is authorized there: a caller who may invoke functions only in the Lambda API's
// namespace is refused.
func TestLambda_InvokeReachesAStackFunction(t *testing.T) {
	var checkedNS []string
	allowIn := func(ns string) func(a *authzv1.ResourceAttributes) bool {
		return func(a *authzv1.ResourceAttributes) bool {
			checkedNS = append(checkedNS, a.Namespace)
			return a.Namespace == ns
		}
	}
	for _, path := range []string{"stack-fn", "arn%3Aaws%3Alambda%3Aus-east-1%3A000000000000%3Afunction%3Astack-fn"} {
		ct := &captureTransport{}
		h := newLambdaHandler(csWithSARFunc(allowIn(testCFNNamespace)), "default", "svc.cluster.local", nil, discardLogger())
		h.client = &http.Client{Transport: ct}
		h.fns = newFnLocator(fnDyn(fnClaim(testCFNNamespace, "stack-fn")), discardLogger(), "default", testCFNNamespace)
		w := httptest.NewRecorder()
		h.serve(w, httptest.NewRequest(http.MethodPost, "http://lambda/2015-03-31/functions/"+path+"/invocations", strings.NewReader("{}")), iam.Claims{Sub: "u"}, "r-1")
		if w.Code != http.StatusOK {
			t.Fatalf("invoke %s = %d %s", path, w.Code, w.Body.String())
		}
		if len(ct.hosts) != 1 || ct.hosts[0] != "stack-fn."+testCFNNamespace+".svc.cluster.local" {
			t.Errorf("invoke %s went to %v, want the stack namespace's address", path, ct.hosts)
		}
	}
	// Only invoke rights in the Lambda API's namespace: refused for the stack's function.
	h := newLambdaHandler(csWithSARFunc(allowIn("default")), "default", "svc.cluster.local", nil, discardLogger())
	h.client = &http.Client{Transport: &captureTransport{}}
	h.fns = newFnLocator(fnDyn(fnClaim(testCFNNamespace, "stack-fn")), discardLogger(), "default", testCFNNamespace)
	w := httptest.NewRecorder()
	h.serve(w, httptest.NewRequest(http.MethodPost, "http://lambda/2015-03-31/functions/stack-fn/invocations", strings.NewReader("{}")), iam.Claims{Sub: "u"}, "r-2")
	if w.Code != http.StatusForbidden {
		t.Errorf("invoke without rights in the function's namespace = %d, want 403", w.Code)
	}
	if checkedNS[len(checkedNS)-1] != testCFNNamespace {
		t.Errorf("authorization was checked in %q, want the function's namespace", checkedNS[len(checkedNS)-1])
	}
}

// An EventBridge Lambda target and an API Gateway integration are authorized where the function lives.
func TestFunctionTargets_AuthorizedWhereTheFunctionLives(t *testing.T) {
	ctx := context.Background()
	var seen []string
	cs := csWithSARFunc(func(a *authzv1.ResourceAttributes) bool {
		if a.Resource == "functions" {
			seen = append(seen, a.Namespace+"/"+a.Name)
		}
		return true
	})
	fns := newFnLocator(fnDyn(fnClaim(testCFNNamespace, "stack-fn")), discardLogger(), "default", testCFNNamespace)
	eb := newEBHandler(cs, "default", "default", "000000000000", "us-east-1", nil, nil, nil, discardLogger())
	eb.fns = fns
	req := httptest.NewRequest(http.MethodPost, "http://x/", nil)
	if reason, ok := eb.authorizeTarget(ctx, req, iam.Claims{Sub: "u"}, "lambda", "arn:aws:lambda:us-east-1:000000000000:function:stack-fn", ""); !ok {
		t.Fatalf("authorizeTarget: %s", reason)
	}
	gw := newAPIGWHandler(cs, "default", "000000000000", "us-east-1", "default", "svc.cluster.local", "http://x", nil, discardLogger())
	gw.fns = fns
	if reason, ok := gw.authorizeIntegrationTarget(ctx, req, iam.Claims{Sub: "u"}, "stack-fn"); !ok {
		t.Fatalf("authorizeIntegrationTarget: %s", reason)
	}
	v1 := newAPIGWV1Handler(cs, "default", "default", "svc.cluster.local", "", nil, nil, discardLogger())
	v1.fns = fns
	if got := v1.fnNamespace(ctx, "stack-fn"); got != testCFNNamespace {
		t.Errorf("REST v1 integration namespace = %q", got)
	}
	for _, s := range seen {
		if s != testCFNNamespace+"/stack-fn" {
			t.Errorf("a function target was authorized as %s, want %s/stack-fn", s, testCFNNamespace)
		}
	}
	if len(seen) != 2 {
		t.Errorf("function checks = %v, want one per target", seen)
	}
}

// A stack may not create a function whose name a function outside it already has (a name is unique, as
// on AWS); a free name is created, and the locator then finds it at once.
func TestCFNCreate_FunctionNameUnique(t *testing.T) {
	ctx := context.Background()
	dyn := fnDyn(fnClaim("default", "taken"))
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Group: "openinfra.dev", Version: "v1"}})
	mapper.Add(schema.GroupVersionKind{Group: "openinfra.dev", Version: "v1", Kind: "Function"}, meta.RESTScopeNamespace)
	door := &cfnDoorway{fns: newFnLocator(dyn, discardLogger(), "default", testCFNNamespace)}
	ap := &impersonatingApplier{caller: dyn, shim: dyn, mapper: mapper, ns: testCFNNamespace, door: door}
	manifest := func(name string) []byte {
		return []byte("apiVersion: openinfra.dev/v1\nkind: Function\nmetadata:\n  name: " + name + "\nspec:\n  runtime: nodejs20.x\n")
	}
	if _, err := ap.Create(ctx, manifest("taken")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("creating a function whose name another namespace has: err = %v, want a refusal", err)
	}
	if _, err := dyn.Tracker().Get(functionClaimGVR, testCFNNamespace, "taken"); err == nil {
		t.Error("the refused function must not be created")
	}
	// A remembered miss for the new name is dropped when the stack creates it.
	if got := door.fns.namespaceOf(ctx, "fresh", "default"); got != "default" {
		t.Fatalf("before create = %q", got)
	}
	created, err := ap.Create(ctx, manifest("fresh"))
	if err != nil || !created {
		t.Fatalf("create fresh = %v, %v", created, err)
	}
	if got := door.fns.namespaceOf(ctx, "fresh", "default"); got != testCFNNamespace {
		t.Errorf("after create = %q, want the stack namespace", got)
	}
}
