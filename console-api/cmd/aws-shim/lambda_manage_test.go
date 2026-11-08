package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const lmAccount = "123456789012"

// lmRoles resolves roles by name (the IAM home) and by "<ns>/<name>".
type lmRoles map[string]resolvedRole

func (f lmRoles) Resolve(_ context.Context, name string) (resolvedRole, bool) {
	r, ok := f[name]
	return r, ok
}
func (f lmRoles) ResolveIn(_ context.Context, ns, name string) (resolvedRole, bool) {
	r, ok := f[ns+"/"+name]
	return r, ok
}

func lmRole(name string) string { return "arn:aws:iam::" + lmAccount + ":role/" + name }

func manageFixture(t *testing.T, authz *dataplaneauthz.Checker, objs ...runtime.Object) (*lambdaHandler, *dynamicfake.FakeDynamicClient, *blobS3) {
	t.Helper()
	f := newBlobS3()
	f.buckets[lambdaCodeBucket], f.buckets["deploy"] = true, true
	dyn := fnDyn(objs...)
	h := newLambdaHandler(csWithSAR(true), "default", "svc.invalid", nil, discardLogger())
	h.fns = newFnLocator(dyn, discardLogger(), "default", testCFNNamespace)
	h.authz = authz
	h.account, h.region = lmAccount, "us-east-1"
	h.timeouts = newFnTimeouts(dyn)
	h.roles = lmRoles{
		"exec":       {trust: []string{"Service::" + lambdaService}},
		"states":     {trust: []string{"Service::states.amazonaws.com"}},
		"conditions": {trust: []string{"Service::" + lambdaService}, trustDoc: `{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"1"}}}]}`},
	}
	h.pkgDoor = &cfnDoorway{s3: allowAllSAR(), authz: authz, packages: &packageStore{mc: blobMinio(t, f)}}
	return h, dyn, f
}

func lambdaReq(method, path string, body any) *http.Request {
	var b []byte
	switch v := body.(type) {
	case nil:
	case string:
		b = []byte(v)
	default:
		b, _ = json.Marshal(v)
	}
	return httptest.NewRequest(method, "http://shim"+path, strings.NewReader(string(b)))
}

func zipB64(t *testing.T, files map[string]string) (string, []byte) {
	z := testZip(t, files)
	return base64.StdEncoding.EncodeToString(z), z
}

func lmCreateBody(t *testing.T, extra map[string]any) map[string]any {
	code, _ := zipB64(t, map[string]string{"index.js": "exports.handler = async () => 1;\n"})
	b := map[string]any{"FunctionName": "orders", "Runtime": "nodejs20.x", "Handler": "index.handler",
		"Role": lmRole("exec"), "Code": map[string]any{"ZipFile": code}}
	for k, v := range extra {
		if v == nil {
			delete(b, k)
		} else {
			b[k] = v
		}
	}
	return b
}

func getClaim(t *testing.T, dyn *dynamicfake.FakeDynamicClient, ns, name string) *unstructured.Unstructured {
	t.Helper()
	obj, err := dyn.Resource(functionClaimGVR).Namespace(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("function %s/%s: %v", ns, name, err)
	}
	return obj
}

// CreateFunction with a .zip makes the kind: Function Lambda would run: its runtime, handler, role, timeout,
// memory and variables, and the package stored by its SHA-256, which the answer reports as CodeSha256.
func TestCreateFunction_Zip(t *testing.T) {
	h, dyn, f := manageFixture(t, nil)
	code, raw := zipB64(t, map[string]string{"index.js": "exports.handler = async () => 1;\n"})
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, map[string]any{
		"Code": map[string]any{"ZipFile": code}, "Timeout": 30, "MemorySize": 256, "Description": "orders api",
		"Environment": map[string]any{"Variables": map[string]any{"STAGE": "prod"}},
		"Publish":     false, "Architectures": []any{"x86_64"},
	})), testUser)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateFunction: %d %s", w.Code, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	sum := shaOf(raw)
	rawSum, _ := hex.DecodeString(sum)
	if out["FunctionName"] != "orders" || out["Runtime"] != "nodejs20.x" || out["Handler"] != "index.handler" ||
		out["Role"] != lmRole("exec") || out["Timeout"] != float64(30) || out["MemorySize"] != float64(256) ||
		out["CodeSha256"] != base64.StdEncoding.EncodeToString(rawSum) || out["Description"] != "orders api" ||
		out["FunctionArn"] != "arn:aws:lambda:us-east-1:"+lmAccount+":function:orders" {
		t.Fatalf("the answer must be the function's configuration: %s", w.Body)
	}
	obj := getClaim(t, dyn, "default", "orders")
	if got, _, _ := unstructured.NestedString(obj.Object, "spec", "code", "source", "package", "sha256"); got != sum {
		t.Fatalf("the Function must name its stored package: %v", obj.Object["spec"])
	}
	if rt, _, _ := unstructured.NestedString(obj.Object, "spec", "code", "runtime"); rt != "nodejs20" {
		t.Errorf("runtime: %q", rt)
	}
	if env, _, _ := unstructured.NestedSlice(obj.Object, "spec", "env"); len(env) != 1 {
		t.Errorf("env: %v", env)
	}
	if _, ok := f.objects[lambdaCodeBucket+"/"+packageKey("default", sum)]; !ok {
		t.Fatal("the package must be stored")
	}
	// The same name again is AWS's conflict.
	w = serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, nil)), testUser)
	if w.Code != http.StatusConflict || !isDenied(w, "ResourceConflictException") || !strings.Contains(w.Body.String(), "Function already exist: orders") {
		t.Fatalf("a second CreateFunction of the name must conflict: %d %s", w.Code, w.Body)
	}
}

// A name a stack's function already has in the account conflicts too: a name is unique in its account.
func TestCreateFunction_NameUniqueInTheAccount(t *testing.T) {
	h, _, _ := manageFixture(t, nil, fnClaim(testCFNNamespace, "orders"))
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, nil)), testUser)
	if w.Code != http.StatusConflict {
		t.Fatalf("a name a stack's function has must conflict: %d %s", w.Code, w.Body)
	}
}

// An image function names its image, and takes no runtime or handler.
func TestCreateFunction_Image(t *testing.T) {
	h, dyn, _ := manageFixture(t, nil)
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", map[string]any{"FunctionName": "img", "PackageType": "Image",
		"Role": lmRole("exec"), "Code": map[string]any{"ImageUri": "registry.example/fn:1"}}), testUser)
	if w.Code != http.StatusCreated {
		t.Fatalf("image CreateFunction: %d %s", w.Code, w.Body)
	}
	if img, _, _ := unstructured.NestedString(getClaim(t, dyn, "default", "img").Object, "spec", "image"); img != "registry.example/fn:1" {
		t.Fatalf("image: %q", img)
	}
	w = serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", map[string]any{"FunctionName": "img2", "PackageType": "Image",
		"Runtime": "nodejs20.x", "Role": lmRole("exec"), "Code": map[string]any{"ImageUri": "registry.example/fn:1"}}), testUser)
	if !isDenied(w, "InvalidParameterValueException") {
		t.Fatalf("an image function takes no Runtime: %d %s", w.Code, w.Body)
	}
}

// The execution role is checked as Lambda checks it: required, a role ARN of the caller's account, one the
// caller may pass, and one Lambda can assume.
func TestCreateFunction_ExecutionRole(t *testing.T) {
	cases := []struct {
		name, role, code, text string
	}{
		{"missing", "", "ValidationException", "Member must not be null"},
		{"not an ARN", "exec", "ValidationException", "regular expression pattern"},
		{"another account's", "arn:aws:iam::999999999999:role/exec", "AccessDeniedException", "Cross-account pass role is not allowed."},
		{"does not trust Lambda", lmRole("states"), "InvalidParameterValueException", "cannot be assumed by Lambda"},
		{"trust with conditions", lmRole("conditions"), "InvalidParameterValueException", "has conditions"},
		{"no such role", lmRole("nobody"), "InvalidParameterValueException", "cannot be assumed by Lambda"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, dyn, _ := manageFixture(t, nil)
			extra := map[string]any{"Role": tc.role}
			if tc.role == "" {
				extra["Role"] = nil
			}
			w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, extra)), testUser)
			if !isDenied(w, tc.code) || !strings.Contains(w.Body.String(), tc.text) {
				t.Fatalf("want %s %q: %d %s", tc.code, tc.text, w.Code, w.Body)
			}
			if _, err := dyn.Resource(functionClaimGVR).Namespace("default").Get(context.Background(), "orders", metav1.GetOptions{}); err == nil {
				t.Fatal("a refused CreateFunction must create nothing")
			}
		})
	}
}

// iam:PassRole is the caller's: a principal allowed lambda:CreateFunction but not iam:PassRole on the role is
// refused, and one allowed both creates the function.
func TestCreateFunction_PassRoleIsTheCallers(t *testing.T) {
	onlyCreate := checkerInMode(t, "enforce", userDoc(dpAllow([]string{"lambda:CreateFunction"}, "*")))
	h, dyn, _ := manageFixture(t, onlyCreate)
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, nil)), testUser)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "iam:PassRole") {
		t.Fatalf("CreateFunction without iam:PassRole must be refused: %d %s", w.Code, w.Body)
	}
	if _, err := dyn.Resource(functionClaimGVR).Namespace("default").Get(context.Background(), "orders", metav1.GetOptions{}); err == nil {
		t.Fatal("nothing may be created without iam:PassRole")
	}
	both := checkerInMode(t, "enforce", userDoc(dpAllow([]string{"lambda:CreateFunction"}, "*"), dpAllow([]string{"iam:PassRole"}, "Role::exec")))
	h, _, _ = manageFixture(t, both)
	if w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, nil)), testUser); w.Code != http.StatusCreated {
		t.Fatalf("with iam:PassRole on the role CreateFunction succeeds: %d %s", w.Code, w.Body)
	}
}

// What a Function cannot carry refuses, naming the field; Lambda's defaults are accepted.
func TestCreateFunction_RefusesWhatItCannotCarry(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"Layers":         {"Layers": []any{"arn:aws:lambda:us-east-1:1:layer:x:1"}},
		"Architectures":  {"Architectures": []any{"arm64"}},
		"VpcConfig":      {"VpcConfig": map[string]any{"SubnetIds": []any{"subnet-1"}}},
		"Tags":           {"Tags": map[string]any{"team": "a"}},
		"unknown member": {"Frobnicate": true},
		"runtime":        {"Runtime": "ruby3.3"},
		"timeout":        {"Timeout": 901},
		"memory":         {"MemorySize": 64},
		"reserved env":   {"Environment": map[string]any{"Variables": map[string]any{"AWS_ENDPOINT_URL": "http://elsewhere"}}},
		"platform env":   {"Environment": map[string]any{"Variables": map[string]any{"OPENINFRA_CODE_URL": "http://elsewhere"}}},
		"quoted value":   {"Environment": map[string]any{"Variables": map[string]any{"XX": `a", valueFrom: {`}}},
		"env name":       {"Environment": map[string]any{"Variables": map[string]any{"1BAD": "x"}}},
		"handler":        {"Handler": "index.handler; rm -rf"},
		"name":           {"FunctionName": "Orders_API"},
		"not a zip":      {"Code": map[string]any{"ZipFile": base64.StdEncoding.EncodeToString([]byte("not a zip"))}},
		"two sources":    {"Code": map[string]any{"ZipFile": "UEs=", "S3Bucket": "deploy", "S3Key": "k"}},
	} {
		t.Run(name, func(t *testing.T) {
			h, dyn, _ := manageFixture(t, nil)
			w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, extra)), testUser)
			if w.Code != http.StatusBadRequest || !(isDenied(w, "InvalidParameterValueException") || isDenied(w, "ValidationException")) {
				t.Fatalf("must refuse: %d %s", w.Code, w.Body)
			}
			if l, _ := dyn.Resource(functionClaimGVR).Namespace("default").List(context.Background(), metav1.ListOptions{}); len(l.Items) != 0 {
				t.Fatal("a refused CreateFunction must create nothing")
			}
		})
	}
	h, _, _ := manageFixture(t, nil)
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, map[string]any{
		"TracingConfig": map[string]any{"Mode": "PassThrough"}, "EphemeralStorage": map[string]any{"Size": 512}})), testUser)
	if w.Code != http.StatusCreated {
		t.Fatalf("Lambda's defaults are accepted: %d %s", w.Code, w.Body)
	}
}

// A .zip in S3 is read as the caller may read it; one the caller may not read is refused with S3's denial.
func TestCreateFunction_S3PackageIsReadAsTheCaller(t *testing.T) {
	authz := checkerInMode(t, "enforce", userDoc(dpAllow([]string{"lambda:CreateFunction", "iam:PassRole"}, "*"),
		dpAllow([]string{"s3:GetObject"}, "Bucket::deploy/pkg/*")))
	h, dyn, f := manageFixture(t, authz)
	z := testZip(t, map[string]string{"app.py": "def handler(e, c): return 1\n"})
	f.objects["deploy/pkg/app.zip"], f.objects["deploy/other/app.zip"] = z, z
	body := lmCreateBody(t, map[string]any{"Runtime": "python3.12", "Handler": "app.handler",
		"Code": map[string]any{"S3Bucket": "deploy", "S3Key": "other/app.zip"}})
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", body), testUser)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Your access has been denied by S3") {
		t.Fatalf("a package the caller may not read must be refused: %d %s", w.Code, w.Body)
	}
	body["Code"] = map[string]any{"S3Bucket": "deploy", "S3Key": "pkg/app.zip"}
	if w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", body), testUser); w.Code != http.StatusCreated {
		t.Fatalf("a granted package: %d %s", w.Code, w.Body)
	}
	if o, _, _ := unstructured.NestedString(getClaim(t, dyn, "default", "orders").Object, "spec", "code", "source", "package", "origin"); o != "s3://deploy/pkg/app.zip" {
		t.Fatalf("origin: %q", o)
	}
}

func zipFunction(ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Function",
		"metadata": map[string]any{"name": name, "namespace": ns, "resourceVersion": "7"},
		"spec": map[string]any{"role": lmRole("exec"), "timeout": int64(10), "env": []any{map[string]any{"name": "A", "value": "1"}},
			"code": map[string]any{"runtime": "nodejs20", "handler": "index.handler",
				"source": map[string]any{"package": map[string]any{"sha256": strings.Repeat("a", 64), "size": int64(10)}}}}}}
}

// UpdateFunctionConfiguration changes what it names (Environment replacing the variables, as on AWS) and
// leaves the rest; a stale RevisionId is refused.
func TestUpdateFunctionConfiguration(t *testing.T) {
	h, dyn, _ := manageFixture(t, nil, zipFunction(testCFNNamespace, "orders"))
	w := serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/configuration", map[string]any{
		"Timeout": 120, "Runtime": "python3.12", "Environment": map[string]any{"Variables": map[string]any{"BB": "2"}}}), testUser)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"LastUpdateStatus":"InProgress"`) {
		t.Fatalf("UpdateFunctionConfiguration: %d %s", w.Code, w.Body)
	}
	obj := getClaim(t, dyn, testCFNNamespace, "orders")
	spec := obj.Object["spec"].(map[string]any)
	env, _ := spec["env"].([]any)
	if to, _ := jsonInt(spec["timeout"]); to != 120 || len(env) != 1 || env[0].(map[string]any)["name"] != "BB" {
		t.Fatalf("timeout and env must change: %v", spec)
	}
	if rt, _, _ := unstructured.NestedString(obj.Object, "spec", "code", "runtime"); rt != "python3.12" {
		t.Errorf("runtime: %q", rt)
	}
	if h, _, _ := unstructured.NestedString(obj.Object, "spec", "code", "handler"); h != "index.handler" {
		t.Errorf("an unnamed handler is kept: %q", h)
	}
	w = serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/configuration", map[string]any{"Timeout": 5, "RevisionId": "1"}), testUser)
	if w.Code != http.StatusPreconditionFailed || !isDenied(w, "PreconditionFailedException") {
		t.Fatalf("a stale RevisionId: %d %s", w.Code, w.Body)
	}
	w = serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/configuration", map[string]any{"Role": lmRole("states")}), testUser)
	if !strings.Contains(w.Body.String(), "cannot be assumed by Lambda") {
		t.Fatalf("a new role is checked as at create: %d %s", w.Code, w.Body)
	}
	w = serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/missing/configuration", map[string]any{"Timeout": 5}), testUser)
	if w.Code != http.StatusNotFound || !isDenied(w, "ResourceNotFoundException") {
		t.Fatalf("a missing function: %d %s", w.Code, w.Body)
	}
}

// UpdateFunctionCode stores the new package and names it; an image function takes only an image.
func TestUpdateFunctionCode(t *testing.T) {
	img := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Function",
		"metadata": map[string]any{"name": "img", "namespace": "default"}, "spec": map[string]any{"image": "registry.example/fn:1"}}}
	h, dyn, _ := manageFixture(t, nil, zipFunction("default", "orders"), img)
	code, raw := zipB64(t, map[string]string{"index.js": "exports.handler = async () => 2;\n"})
	w := serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/code", map[string]any{"ZipFile": code}), testUser)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateFunctionCode: %d %s", w.Code, w.Body)
	}
	if got, _, _ := unstructured.NestedString(getClaim(t, dyn, "default", "orders").Object, "spec", "code", "source", "package", "sha256"); got != shaOf(raw) {
		t.Fatalf("the Function must name the new package: %s", got)
	}
	w = serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/code", map[string]any{"ImageUri": "registry.example/fn:2"}), testUser)
	if !strings.Contains(w.Body.String(), "packageType Zip") {
		t.Fatalf("a zip function takes no image: %d %s", w.Code, w.Body)
	}
	w = serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/img/code", map[string]any{"ZipFile": code}), testUser)
	if !strings.Contains(w.Body.String(), "packageType Image") {
		t.Fatalf("an image function takes only an image: %d %s", w.Code, w.Body)
	}
	w = serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/img/code", map[string]any{"ImageUri": "registry.example/fn:2"}), testUser)
	if img, _, _ := unstructured.NestedString(getClaim(t, dyn, "default", "img").Object, "spec", "image"); w.Code != http.StatusOK || img != "registry.example/fn:2" {
		t.Fatalf("image update: %d %s %q", w.Code, w.Body, img)
	}
}

// DeleteFunction removes the function; a missing one is ResourceNotFoundException; a version it does not
// have is not found, and $LATEST is not deleted alone (lambda_versions_test.go deletes a version).
func TestDeleteFunction(t *testing.T) {
	h, dyn, _ := manageFixture(t, nil, zipFunction("default", "orders"))
	w := serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders?Qualifier=1", nil), testUser)
	if w.Code != http.StatusNotFound {
		t.Fatalf("a delete of a version the function lacks: %d %s", w.Code, w.Body)
	}
	w = serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders?Qualifier=$LATEST", nil), testUser)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a delete of $LATEST alone: %d %s", w.Code, w.Body)
	}
	w = serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/arn:aws:lambda:us-east-1:"+lmAccount+":function:orders", nil), testUser)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DeleteFunction: %d %s", w.Code, w.Body)
	}
	if _, err := dyn.Resource(functionClaimGVR).Namespace("default").Get(context.Background(), "orders", metav1.GetOptions{}); err == nil {
		t.Fatal("the function must be gone")
	}
	if w := serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders", nil), testUser); w.Code != http.StatusNotFound {
		t.Fatalf("a missing function: %d %s", w.Code, w.Body)
	}
}

// Each operation is refused to a principal whose policy does not allow it, before anything is written.
func TestLambdaWrites_DeniedWithoutPolicy(t *testing.T) {
	authz := checkerInMode(t, "enforce")
	h, dyn, _ := manageFixture(t, authz, zipFunction("default", "orders"))
	for _, req := range []*http.Request{
		lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, map[string]any{"FunctionName": "other"})),
		lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/code", map[string]any{"ZipFile": "UEs="}),
		lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/configuration", map[string]any{"Timeout": 5}),
		lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders", nil),
	} {
		w := serveWith(h, req, iam.Claims{Sub: "tester"})
		if w.Code != http.StatusForbidden || !isDenied(w, "AccessDeniedException") {
			t.Errorf("%s %s: %d %s", req.Method, req.URL.Path, w.Code, w.Body)
		}
	}
	obj := getClaim(t, dyn, "default", "orders")
	if to, _ := jsonInt(obj.Object["spec"].(map[string]any)["timeout"]); to != 10 {
		t.Fatal("a refused update must change nothing")
	}
}

// AWSLambda_FullAccess passes a role to Lambda alone (iam:PassRole where iam:PassedToService is
// lambda.amazonaws.com): with it and lambda:CreateFunction, CreateFunction may name a role; the same grant
// does not pass a role to another service.
func TestCreateFunction_PassedToServiceLambda(t *testing.T) {
	pass, unsupported, err := policyengine.ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*",
	  "Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}]}`)
	if err != nil || len(unsupported) > 0 {
		t.Fatalf("import: %v %v", err, unsupported)
	}
	authz := checkerInMode(t, "enforce", userDoc(append(pass, dpAllow([]string{"lambda:CreateFunction"}, "*"))...))
	h, _, _ := manageFixture(t, authz)
	if w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, nil)), testUser); w.Code != http.StatusCreated {
		t.Fatalf("PassRole to Lambda must allow CreateFunction to name a role: %d %s", w.Code, w.Body)
	}
	r := httptest.NewRequest(http.MethodPost, "http://shim/", nil)
	if ok, _ := callerMayPassRole(r.Context(), csWithSAR(true), authz, testUser, "default", "exec", "states.amazonaws.com", r); ok {
		t.Fatal("PassRole to Lambda must not pass a role to Step Functions")
	}
	if ok, _ := callerMayPassRole(r.Context(), csWithSAR(true), authz, testUser, "default", "exec", lambdaService, r); !ok {
		t.Fatal("PassRole to Lambda passes a role to Lambda")
	}
}
