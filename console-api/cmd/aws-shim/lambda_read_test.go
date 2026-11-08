package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// readFn is a Function claim with the fields the read operations map.
func readFn(ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Function",
		"metadata": map[string]any{"name": name, "namespace": ns, "creationTimestamp": "2026-10-27T04:19:39Z"},
		"spec": map[string]any{
			"code":    map[string]any{"runtime": "nodejs20", "handler": "index.handler", "source": map[string]any{"bucket": "code", "key": "fn.zip"}},
			"memory":  "1Gi",
			"timeout": int64(600),
			"env":     []any{map[string]any{"name": "STAGE", "value": "dev"}},
			"aliases": []any{map[string]any{"name": "live", "functionVersion": "$LATEST"}},
		},
		"status": map[string]any{"conditions": []any{
			map[string]any{"type": "Synced", "status": "True"},
			map[string]any{"type": "Ready", "status": "True"},
		}},
	}}
}

func readLambda(allow func(a *authzv1.ResourceAttributes) bool, objs ...runtime.Object) *lambdaHandler {
	h := newLambdaHandler(csWithSARFunc(allow), "default", "svc.cluster.local", nil, discardLogger())
	h.account, h.region = "000000000000", "us-east-1"
	h.fns = newFnLocator(fnDyn(objs...), discardLogger(), "default", testCFNNamespace)
	return h
}

func lambdaGet(h *lambdaHandler, path string, claims iam.Claims) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.serve(w, httptest.NewRequest(http.MethodGet, "http://lambda"+path, nil), claims, "r-1")
	return w
}

func TestLambdaGetFunction_StackFunction(t *testing.T) {
	var checked []string
	h := readLambda(func(a *authzv1.ResourceAttributes) bool {
		checked = append(checked, a.Verb+" "+a.Resource+" "+a.Namespace+"/"+a.Name)
		return true
	}, readFn(testCFNNamespace, "orders"))
	for _, path := range []string{"/2015-03-31/functions/orders",
		"/2015-03-31/functions/arn%3Aaws%3Alambda%3Aus-east-1%3A000000000000%3Afunction%3Aorders"} {
		w := lambdaGet(h, path, iam.Claims{Sub: "u"})
		if w.Code != http.StatusOK {
			t.Fatalf("GetFunction %s = %d %s", path, w.Code, w.Body.String())
		}
		var out struct {
			Configuration map[string]any
			Code          map[string]any
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		c := out.Configuration
		if c["FunctionName"] != "orders" || c["FunctionArn"] != "arn:aws:lambda:us-east-1:000000000000:function:orders" ||
			c["Runtime"] != "nodejs20.x" || c["Handler"] != "index.handler" || c["PackageType"] != "Zip" ||
			c["MemorySize"] != float64(1024) || c["Timeout"] != float64(600) || c["State"] != "Active" ||
			c["LastModified"] != "2026-10-27T04:19:39.000+0000" || c["Version"] != "$LATEST" {
			t.Errorf("configuration = %v", c)
		}
		if env, _ := c["Environment"].(map[string]any); env == nil || env["Variables"].(map[string]any)["STAGE"] != "dev" {
			t.Errorf("environment = %v", c["Environment"])
		}
		if out.Code["RepositoryType"] != "S3" {
			t.Errorf("code = %v", out.Code)
		}
	}
	if len(checked) == 0 || checked[len(checked)-1] != "get functions "+testCFNNamespace+"/orders" {
		t.Errorf("GetFunction was authorized as %v, want get on the function where it lives", checked)
	}

	// GetFunctionConfiguration answers the configuration itself; a qualifier must be an alias it has.
	w := lambdaGet(h, "/2015-03-31/functions/orders/configuration?Qualifier=live", iam.Claims{Sub: "u"})
	var c map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &c)
	if w.Code != http.StatusOK || c["FunctionArn"] != "arn:aws:lambda:us-east-1:000000000000:function:orders:live" {
		t.Errorf("GetFunctionConfiguration (alias) = %d %s", w.Code, w.Body.String())
	}
	if w := lambdaGet(h, "/2015-03-31/functions/orders:canary/configuration", iam.Claims{Sub: "u"}); w.Code != http.StatusNotFound {
		t.Errorf("an alias the function lacks = %d, want 404", w.Code)
	}
}

func TestLambdaGetFunction_ImageFunction(t *testing.T) {
	fn := fnClaim("default", "web")
	fn.Object["spec"] = map[string]any{"image": "registry/web:1", "reservedConcurrency": int64(5)}
	h := readLambda(allowAll, fn)
	w := lambdaGet(h, "/2015-03-31/functions/web", iam.Claims{Sub: "u"})
	var out map[string]map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || out["Configuration"]["PackageType"] != "Image" || out["Code"]["ImageUri"] != "registry/web:1" ||
		out["Concurrency"]["ReservedConcurrentExecutions"] != float64(5) || out["Configuration"]["Timeout"] != float64(300) {
		t.Errorf("GetFunction (image) = %d %s", w.Code, w.Body.String())
	}
}

// A function's execution role is its Role: a role name as its ARN in the function's account, a role ARN as
// given; a function with no role has no Role.
func TestLambdaGetFunction_Role(t *testing.T) {
	named, arn, none := fnClaim("default", "named"), fnClaim("default", "byarn"), fnClaim("default", "none")
	named.Object["spec"] = map[string]any{"image": "registry/web:1", "role": "orders-reader"}
	arn.Object["spec"] = map[string]any{"image": "registry/web:1", "role": "arn:aws:iam::000000000000:role/service-role/Reader"}
	none.Object["spec"] = map[string]any{"image": "registry/web:1"}
	h := readLambda(allowAll, named, arn, none)
	for fn, want := range map[string]any{
		"named": "arn:aws:iam::000000000000:role/orders-reader",
		"byarn": "arn:aws:iam::000000000000:role/service-role/Reader",
		"none":  nil,
	} {
		w := lambdaGet(h, "/2015-03-31/functions/"+fn+"/configuration", iam.Claims{Sub: "u"})
		var c map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &c)
		if w.Code != http.StatusOK || c["Role"] != want {
			t.Errorf("%s: Role = %v (%d), want %v", fn, c["Role"], w.Code, want)
		}
	}
}

func TestLambdaGetFunction_NotFound(t *testing.T) {
	h := readLambda(allowAll, readFn("default", "orders"))
	for _, path := range []string{"/2015-03-31/functions/missing", "/2015-03-31/functions/missing/configuration", "/2015-03-31/functions/missing/policy"} {
		w := lambdaGet(h, path, iam.Claims{Sub: "u"})
		if w.Code != http.StatusNotFound || w.Header().Get("x-amzn-errortype") != "ResourceNotFoundException" {
			t.Errorf("%s = %d %s, want 404 ResourceNotFoundException", path, w.Code, w.Header().Get("x-amzn-errortype"))
		}
	}
	if w := lambdaGet(h, "/2015-03-31/functions/Bad.Name", iam.Claims{Sub: "u"}); w.Code != http.StatusBadRequest {
		t.Errorf("an invalid name = %d, want 400", w.Code)
	}
}

func TestLambdaGetFunction_Denied(t *testing.T) {
	// RBAC: no get on functions where it lives.
	h := readLambda(func(a *authzv1.ResourceAttributes) bool { return a.Namespace == "default" }, readFn(testCFNNamespace, "orders"))
	for _, path := range []string{"/2015-03-31/functions/orders", "/2015-03-31/functions/orders/configuration", "/2015-03-31/functions/orders/policy"} {
		if w := lambdaGet(h, path, iam.Claims{Sub: "u"}); w.Code != http.StatusForbidden || w.Header().Get("x-amzn-errortype") != "AccessDeniedException" {
			t.Errorf("%s without get = %d %s", path, w.Code, w.Body.String())
		}
	}
	// Data plane: a policy denying lambda:GetFunction on the function.
	h = readLambda(allowAll, readFn("default", "orders"))
	h.authz = userPolicy(dpAllow([]string{"lambda:*"}, "*"), dpDeny([]string{"lambda:GetFunction"}, "Function::orders"))
	if w := lambdaGet(h, "/2015-03-31/functions/orders", testUser); w.Code != http.StatusForbidden {
		t.Errorf("GetFunction under a Deny = %d", w.Code)
	}
	if w := lambdaGet(h, "/2015-03-31/functions/orders/configuration", testUser); w.Code != http.StatusOK {
		t.Errorf("GetFunctionConfiguration (not denied) = %d %s", w.Code, w.Body.String())
	}
	// An assumed role with no grant reads nothing.
	h.authz = roleChecker()
	if w := lambdaGet(h, "/2015-03-31/functions/orders", ecrRoleClaims()); w.Code != http.StatusForbidden {
		t.Errorf("an assumed role with no policy = %d", w.Code)
	}
}

// A function has no resource policy: GetPolicy answers as AWS does for a function with none, once the
// caller may read it.
func TestLambdaGetPolicy_NoPolicy(t *testing.T) {
	h := readLambda(allowAll, readFn("default", "orders"))
	w := lambdaGet(h, "/2015-03-31/functions/orders/policy", iam.Claims{Sub: "u"})
	if w.Code != http.StatusNotFound || w.Header().Get("x-amzn-errortype") != "ResourceNotFoundException" ||
		!strings.Contains(w.Body.String(), "The resource you requested does not exist.") {
		t.Errorf("GetPolicy = %d %s %s", w.Code, w.Header().Get("x-amzn-errortype"), w.Body.String())
	}
	h.authz = userPolicy(dpAllow([]string{"lambda:*"}, "*"), dpDeny([]string{"lambda:GetPolicy"}, "Function::orders"))
	if w := lambdaGet(h, "/2015-03-31/functions/orders/policy", testUser); w.Code != http.StatusForbidden {
		t.Errorf("GetPolicy under a Deny = %d", w.Code)
	}
}

// pagedFnDyn is a fake cluster whose function lists honor Limit and Continue (the fake client ignores
// both), counting the most items any one list returned.
func pagedFnDyn(t *testing.T, maxSeen *int, objs ...*unstructured.Unstructured) *dynamicfake.FakeDynamicClient {
	t.Helper()
	var ro []runtime.Object
	for _, o := range objs {
		ro = append(ro, o)
	}
	d := fnDyn(ro...)
	d.PrependReactor("list", "functions", func(a k8stesting.Action) (bool, runtime.Object, error) {
		la := a.(k8stesting.ListActionImpl)
		var names []string
		byName := map[string]*unstructured.Unstructured{}
		for _, o := range objs {
			if o.GetNamespace() == la.Namespace {
				names = append(names, o.GetName())
				byName[o.GetName()] = o
			}
		}
		sort.Strings(names)
		start := 0
		if c := la.ListOptions.Continue; c != "" {
			start, _ = strconv.Atoi(c)
		}
		end := len(names)
		if l := int(la.ListOptions.Limit); l > 0 && start+l < end {
			end = start + l
		}
		list := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "FunctionList"}}
		for _, n := range names[start:end] {
			list.Items = append(list.Items, *byName[n].DeepCopy())
		}
		if end < len(names) {
			list.SetContinue(strconv.Itoa(end))
		}
		if len(list.Items) > *maxSeen {
			*maxSeen = len(list.Items)
		}
		return true, list, nil
	})
	return d
}

func listAll(t *testing.T, h *lambdaHandler, claims iam.Claims, maxItems string) ([]string, int) {
	t.Helper()
	var names []string
	marker, pages := "", 0
	for {
		q := "?MaxItems=" + maxItems
		if marker != "" {
			q += "&Marker=" + marker
		}
		w := lambdaGet(h, "/2015-03-31/functions/"+q, claims)
		if w.Code != http.StatusOK {
			t.Fatalf("ListFunctions = %d %s", w.Code, w.Body.String())
		}
		var out struct {
			Functions  []map[string]any
			NextMarker string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, f := range out.Functions {
			names = append(names, f["FunctionName"].(string))
		}
		if out.NextMarker == "" {
			return names, pages
		}
		marker = out.NextMarker
		if pages > 100 {
			t.Fatal("ListFunctions never ended")
		}
	}
}

func TestLambdaListFunctions_PagesAcrossNamespaces(t *testing.T) {
	var objs []*unstructured.Unstructured
	for i := 0; i < 7; i++ {
		objs = append(objs, readFn("default", fmt.Sprintf("api-%d", i)))
	}
	for i := 0; i < 5; i++ {
		objs = append(objs, readFn(testCFNNamespace, fmt.Sprintf("stack-%d", i)))
	}
	maxSeen := 0
	h := readLambda(allowAll)
	h.fns = newFnLocator(pagedFnDyn(t, &maxSeen, objs...), discardLogger(), "default", testCFNNamespace)
	names, pages := listAll(t, h, iam.Claims{Sub: "u"}, "3")
	if len(names) != 12 || pages != 4 {
		t.Errorf("listed %d functions in %d pages, want 12 in 4: %v", len(names), pages, names)
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Errorf("%s listed twice", n)
		}
		seen[n] = true
	}
	if maxSeen > 3 {
		t.Errorf("one list read %d claims, want at most the page size", maxSeen)
	}
	// MaxItems above AWS's page maximum still reads at most 50 claims a page.
	objs = nil
	for i := 0; i < 120; i++ {
		objs = append(objs, readFn("default", fmt.Sprintf("fn-%03d", i)))
	}
	maxSeen = 0
	h.fns = newFnLocator(pagedFnDyn(t, &maxSeen, objs...), discardLogger(), "default", testCFNNamespace)
	if names, pages := listAll(t, h, iam.Claims{Sub: "u"}, "1000"); len(names) != 120 || pages != 3 || maxSeen > lambdaListMax {
		t.Errorf("listed %d in %d pages (largest read %d)", len(names), pages, maxSeen)
	}
}

// A namespace the caller may not list is not listed; a caller who may list none is refused.
func TestLambdaListFunctions_OnlyWhatTheCallerMayList(t *testing.T) {
	objs := []*unstructured.Unstructured{readFn("default", "api-fn"), readFn(testCFNNamespace, "stack-fn")}
	maxSeen := 0
	h := readLambda(func(a *authzv1.ResourceAttributes) bool { return a.Namespace == testCFNNamespace })
	h.fns = newFnLocator(pagedFnDyn(t, &maxSeen, objs...), discardLogger(), "default", testCFNNamespace)
	if names, _ := listAll(t, h, iam.Claims{Sub: "u"}, "50"); len(names) != 1 || names[0] != "stack-fn" {
		t.Errorf("listed %v, want only the namespace the caller may list", names)
	}
	h.cs = csWithSAR(false)
	if w := lambdaGet(h, "/2015-03-31/functions/", iam.Claims{Sub: "u"}); w.Code != http.StatusForbidden {
		t.Errorf("ListFunctions with no list rights = %d", w.Code)
	}
	// An assumed role needs lambda:ListFunctions on "*".
	h.cs = csWithSAR(true)
	h.authz = roleChecker(dpAllow([]string{"lambda:GetFunction"}, "Function::stack-fn"))
	if w := lambdaGet(h, "/2015-03-31/functions/", ecrRoleClaims()); w.Code != http.StatusForbidden {
		t.Errorf("ListFunctions by a role granted one function = %d", w.Code)
	}
	h.authz = roleChecker(dpAllow([]string{"lambda:ListFunctions"}, "*"))
	if w := lambdaGet(h, "/2015-03-31/functions", ecrRoleClaims()); w.Code != http.StatusOK {
		t.Errorf("ListFunctions by a role granted it = %d %s", w.Code, w.Body.String())
	}
	if w := lambdaGet(h, "/2015-03-31/functions/?Marker=bogus", ecrRoleClaims()); w.Code != http.StatusBadRequest {
		t.Errorf("a bad Marker = %d", w.Code)
	}
}
