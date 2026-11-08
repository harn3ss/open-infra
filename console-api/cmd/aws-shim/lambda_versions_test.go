package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
)

// knativeService is a function's Knative Service whose latest created revision is created and whose latest
// ready one is ready, at generation gen (observed).
func knativeService(ns, name, ready, created string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "serving.knative.dev/v1", "kind": "Service",
		"metadata": map[string]any{"name": name, "namespace": ns, "generation": int64(2)},
		"status":   map[string]any{"observedGeneration": int64(2), "latestReadyRevisionName": ready, "latestCreatedRevisionName": created}}}
}

// revisionMeta is a Knative revision's metadata, created at t.
func revisionMeta(ns, name string, t time.Time) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{
		TypeMeta:   metav1.TypeMeta{APIVersion: "serving.knative.dev/v1", Kind: "Revision"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, CreationTimestamp: metav1.NewTime(t)},
	}
}

func versionsFixture(t *testing.T, revisions []*metav1.PartialObjectMetadata, objs ...runtime.Object) (*lambdaHandler, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	h, dyn, _ := manageFixture(t, nil, objs...)
	scheme := runtime.NewScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	metas := make([]runtime.Object, 0, len(revisions))
	for _, r := range revisions {
		metas = append(metas, r)
	}
	h.meta = metadatafake.NewSimpleMetadataClient(scheme, metas...)
	return h, dyn
}

func updatedAt(fn *unstructured.Unstructured, t time.Time) *unstructured.Unstructured {
	fn.SetAnnotations(map[string]string{fnUpdatedAtAnnotation: t.UTC().Format(time.RFC3339Nano)})
	return fn
}

func decodeJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not JSON: %s", b)
	}
	return m
}

// PublishVersion publishes the revision the function's latest change runs, with the configuration it has,
// as version 1; publishing again with nothing changed answers with version 1, as Lambda does; a change
// still rolling out is ResourceConflictException.
func TestPublishVersion_FromTheSettledRevision(t *testing.T) {
	changed := time.Now().Add(-time.Minute)
	h, dyn := versionsFixture(t,
		[]*metav1.PartialObjectMetadata{revisionMeta("default", "orders-00002", changed.Add(2*time.Second))},
		updatedAt(zipFunction("default", "orders"), changed), knativeService("default", "orders", "orders-00002", "orders-00002"))

	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/versions", map[string]any{"Description": "first"}), testUser)
	c := decodeJSON(t, w.Body.Bytes())
	if w.Code != http.StatusCreated || c["Version"] != "1" || c["Description"] != "first" ||
		c["FunctionArn"] != "arn:aws:lambda:us-east-1:"+lmAccount+":function:orders:1" || c["Timeout"] != float64(10) {
		t.Fatalf("PublishVersion: %d %s", w.Code, w.Body)
	}
	vs := versionsOf(getClaim(t, dyn, "default", "orders"))
	if len(vs) != 1 || vs[0].Revision != "orders-00002" || vs[0].Configuration == "" {
		t.Fatalf("the version must pin the settled revision: %+v", vs)
	}

	w = serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/versions", map[string]any{}), testUser)
	if c := decodeJSON(t, w.Body.Bytes()); w.Code != http.StatusCreated || c["Version"] != "1" {
		t.Fatalf("an unchanged function publishes no new version: %d %s", w.Code, w.Body)
	}
	if vs := versionsOf(getClaim(t, dyn, "default", "orders")); len(vs) != 1 {
		t.Fatalf("an unchanged function publishes no new version: %+v", vs)
	}

	w = serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/versions", map[string]any{"CodeSha256": "nope"}), testUser)
	if w.Code != http.StatusBadRequest || !isDenied(w, "InvalidParameterValueException") {
		t.Fatalf("a CodeSha256 that is not $LATEST's: %d %s", w.Code, w.Body)
	}
}

func TestPublishVersion_RefusesAChangeStillRollingOut(t *testing.T) {
	changed := time.Now().Add(-time.Minute)
	for name, tc := range map[string]struct {
		ready, created string
		revCreated     time.Time
	}{
		"a newer revision is not ready":          {"orders-00001", "orders-00002", changed.Add(time.Second)},
		"the ready revision predates the change": {"orders-00001", "orders-00001", changed.Add(-time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			h, dyn := versionsFixture(t,
				[]*metav1.PartialObjectMetadata{revisionMeta("default", tc.ready, tc.revCreated)},
				updatedAt(zipFunction("default", "orders"), changed), knativeService("default", "orders", tc.ready, tc.created))
			w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/versions", nil), testUser)
			if w.Code != http.StatusConflict || !isDenied(w, "ResourceConflictException") {
				t.Fatalf("an update in progress: %d %s", w.Code, w.Body)
			}
			if vs := versionsOf(getClaim(t, dyn, "default", "orders")); len(vs) != 0 {
				t.Fatalf("nothing may be published: %+v", vs)
			}
		})
	}
}

// A function with versions and an alias: a version's read is its own configuration, an alias's its
// version's with the alias's ARN; ListVersionsByFunction lists $LATEST first.
func versionedFunction() *unstructured.Unstructured {
	fn := zipFunction("default", "orders")
	cfg1, _ := json.Marshal(map[string]any{"FunctionName": "orders", "Timeout": 3, "Version": "1", "Runtime": "nodejs20.x"})
	cfg2, _ := json.Marshal(map[string]any{"FunctionName": "orders", "Timeout": 4, "Version": "2", "Runtime": "nodejs20.x"})
	fn.Object["spec"].(map[string]any)["versions"] = []any{
		map[string]any{"version": "1", "revision": "orders-00001", "configuration": string(cfg1), "published": "2026-11-01T00:00:00.000+0000"},
		map[string]any{"version": "2", "revision": "orders-00002", "configuration": string(cfg2)},
	}
	fn.Object["spec"].(map[string]any)["aliases"] = []any{
		map[string]any{"name": "live", "functionVersion": "1"},
	}
	return fn
}

func TestQualifiedReads(t *testing.T) {
	h, _ := versionsFixture(t, nil, versionedFunction())
	w := serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/configuration?Qualifier=1", nil), testUser)
	c := decodeJSON(t, w.Body.Bytes())
	if w.Code != http.StatusOK || c["Version"] != "1" || c["Timeout"] != float64(3) || c["LastModified"] != "2026-11-01T00:00:00.000+0000" ||
		!strings.HasSuffix(c["FunctionArn"].(string), ":function:orders:1") {
		t.Fatalf("a version's configuration: %d %s", w.Code, w.Body)
	}
	w = serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders:live", nil), testUser)
	cfg, _ := decodeJSON(t, w.Body.Bytes())["Configuration"].(map[string]any)
	if w.Code != http.StatusOK || cfg["Version"] != "1" || !strings.HasSuffix(cfg["FunctionArn"].(string), ":function:orders:live") {
		t.Fatalf("an alias's function: %d %s", w.Code, w.Body)
	}
	if w := serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/configuration?Qualifier=9", nil), testUser); w.Code != http.StatusNotFound {
		t.Fatalf("a version the function lacks: %d %s", w.Code, w.Body)
	}
	w = serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/versions", nil), testUser)
	var list struct{ Versions []map[string]any }
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if w.Code != http.StatusOK || len(list.Versions) != 3 || list.Versions[0]["Version"] != "$LATEST" || list.Versions[2]["Version"] != "2" {
		t.Fatalf("ListVersionsByFunction: %d %s", w.Code, w.Body)
	}
}

// Invoking a version or an alias runs that version, at its traffic tag, and says which version ran.
func TestInvoke_AVersionOrAliasRunsThatVersion(t *testing.T) {
	h, _ := versionsFixture(t, nil, versionedFunction())
	ct := &captureTransport{}
	h.client = &http.Client{Transport: ct}
	for _, tc := range []struct{ path, host, version string }{
		{"/2015-03-31/functions/orders:2/invocations", "v2-orders.default.svc.invalid", "2"},
		{"/2015-03-31/functions/orders:live/invocations", "v1-orders.default.svc.invalid", "1"},
		{"/2015-03-31/functions/orders/invocations?Qualifier=$LATEST", "orders.default.svc.invalid", "$LATEST"},
		{"/2015-03-31/functions/orders/invocations", "orders.default.svc.invalid", "$LATEST"},
	} {
		ct.hosts = nil
		w := serveWith(h, lambdaReq(http.MethodPost, tc.path, `{}`), testUser)
		if w.Code != http.StatusOK || len(ct.hosts) != 1 || ct.hosts[0] != tc.host || w.Header().Get("X-Amz-Executed-Version") != tc.version {
			t.Errorf("%s: %d %v executed=%q, want %s", tc.path, w.Code, ct.hosts, w.Header().Get("X-Amz-Executed-Version"), tc.host)
		}
	}
	ct.hosts = nil
	if w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders:canary/invocations", `{}`), testUser); w.Code != http.StatusNotFound || len(ct.hosts) != 0 {
		t.Errorf("an alias the function lacks: %d %v", w.Code, ct.hosts)
	}
}

// Aliases: one names a published version (or $LATEST) and may route a share to one other version; a
// version an alias names cannot be deleted; deleting the alias frees it.
func TestAliases(t *testing.T) {
	h, dyn := versionsFixture(t, nil, versionedFunction())
	post := func(body map[string]any) *httpResult {
		return result(serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders/aliases", body), testUser))
	}
	if r := post(map[string]any{"Name": "beta", "FunctionVersion": "9"}); r.code != http.StatusNotFound {
		t.Fatalf("an alias of a version the function lacks: %d %s", r.code, r.body)
	}
	if r := post(map[string]any{"Name": "live", "FunctionVersion": "2"}); r.code != http.StatusConflict {
		t.Fatalf("an alias that exists: %d %s", r.code, r.body)
	}
	if r := post(map[string]any{"Name": "12", "FunctionVersion": "2"}); r.code != http.StatusBadRequest {
		t.Fatalf("an all-digit alias name: %d %s", r.code, r.body)
	}
	if r := post(map[string]any{"Name": "beta", "FunctionVersion": "$LATEST",
		"RoutingConfig": map[string]any{"AdditionalVersionWeights": map[string]any{"2": 0.1}}}); r.code != http.StatusBadRequest {
		t.Fatalf("a weighted alias of $LATEST: %d %s", r.code, r.body)
	}
	r := post(map[string]any{"Name": "beta", "FunctionVersion": "2", "Description": "next"})
	if r.code != http.StatusCreated || r.json["AliasArn"] != "arn:aws:lambda:us-east-1:"+lmAccount+":function:orders:beta" || r.json["FunctionVersion"] != "2" {
		t.Fatalf("CreateAlias: %d %s", r.code, r.body)
	}

	r = result(serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/aliases/live", map[string]any{
		"RoutingConfig": map[string]any{"AdditionalVersionWeights": map[string]any{"2": 0.25}}}), testUser))
	if rc, _ := r.json["RoutingConfig"].(map[string]any); r.code != http.StatusOK || rc == nil || r.json["FunctionVersion"] != "1" {
		t.Fatalf("UpdateAlias: %d %s", r.code, r.body)
	}
	r = result(serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/aliases?FunctionVersion=1", nil), testUser))
	if as, _ := r.json["Aliases"].([]any); r.code != http.StatusOK || len(as) != 1 {
		t.Fatalf("ListAliases of version 1: %d %s", r.code, r.body)
	}

	for _, v := range []string{"1", "2"} {
		w := serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders?Qualifier="+v, nil), testUser)
		if w.Code != http.StatusConflict {
			t.Fatalf("version %s, which an alias names, must not be deleted: %d %s", v, w.Code, w.Body)
		}
	}
	if w := serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders?Qualifier=live", nil), testUser); w.Code != http.StatusBadRequest {
		t.Fatalf("an alias is not deleted by DeleteFunction: %d %s", w.Code, w.Body)
	}
	for _, a := range []string{"beta", "live"} {
		if w := serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders/aliases/"+a, nil), testUser); w.Code != http.StatusNoContent {
			t.Fatalf("DeleteAlias %s: %d %s", a, w.Code, w.Body)
		}
	}
	if w := serveWith(h, lambdaReq(http.MethodDelete, "/2015-03-31/functions/orders?Qualifier=2", nil), testUser); w.Code != http.StatusNoContent {
		t.Fatalf("DeleteFunction of version 2: %d %s", w.Code, w.Body)
	}
	fn := getClaim(t, dyn, "default", "orders")
	if vs := versionsOf(fn); len(vs) != 1 || vs[0].Version != "1" || len(aliasesOf(fn)) != 0 {
		t.Fatalf("after the deletes: %+v %+v", vs, aliasesOf(fn))
	}
	// The next version is numbered after the highest ever kept, never reusing one still published.
	if n := nextVersion(versionsOf(fn)); n != "2" {
		t.Fatalf("next version = %s", n)
	}
}

// Publish on CreateFunction answers with version 1 at once; it is invoked as Pending until the function
// has rolled out, then its revision is filled.
func TestCreateFunction_PublishRecordsVersion1(t *testing.T) {
	h, dyn := versionsFixture(t, nil)
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, map[string]any{"Publish": true})), testUser)
	c := decodeJSON(t, w.Body.Bytes())
	if w.Code != http.StatusCreated || c["Version"] != "1" || !strings.HasSuffix(c["FunctionArn"].(string), ":function:orders:1") {
		t.Fatalf("CreateFunction with Publish: %d %s", w.Code, w.Body)
	}
	fn := getClaim(t, dyn, "default", "orders")
	if vs := versionsOf(fn); len(vs) != 1 || vs[0].Revision != "" || fn.GetAnnotations()[fnUpdatedAtAnnotation] == "" {
		t.Fatalf("a pending version 1 and the change stamped: %+v %v", vs, fn.GetAnnotations())
	}
	if w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/orders:1/invocations", `{}`), testUser); w.Code != http.StatusConflict {
		t.Fatalf("a pending version is not invoked: %d %s", w.Code, w.Body)
	}
	// The function rolls out: its first revision is ready, created after the change.
	ks := knativeService("default", "orders", "orders-00001", "orders-00001")
	if _, err := dyn.Resource(knativeServiceGVR).Namespace("default").Create(context.Background(), ks, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	_ = metav1.AddMetaToScheme(scheme)
	h.meta = metadatafake.NewSimpleMetadataClient(scheme, revisionMeta("default", "orders-00001", time.Now().Add(time.Minute)))
	w = serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/configuration?Qualifier=1", nil), testUser)
	if c := decodeJSON(t, w.Body.Bytes()); w.Code != http.StatusOK || c["State"] != "Active" {
		t.Fatalf("the rolled-out version: %d %s", w.Code, w.Body)
	}
	if vs := versionsOf(getClaim(t, dyn, "default", "orders")); vs[0].Revision != "orders-00001" {
		t.Fatalf("the version's revision must be filled: %+v", vs)
	}
}

// A version is addressed as v<version>-<name>; a name too long for that has no published versions.
func TestPublishVersion_RefusesANameTooLongForAVersionAddress(t *testing.T) {
	name := "f" + strings.Repeat("x", 59) + "z" // 61 characters: v1-<name> is 64
	h, _ := versionsFixture(t,
		[]*metav1.PartialObjectMetadata{revisionMeta("default", name+"-1", time.Now())},
		zipFunction("default", name), knativeService("default", name, name+"-1", name+"-1"))
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions/"+name+"/versions", nil), testUser)
	if w.Code != http.StatusBadRequest || !isDenied(w, "InvalidParameterValueException") {
		t.Fatalf("a name too long for a version: %d %s", w.Code, w.Body)
	}
}

type httpResult struct {
	code int
	body string
	json map[string]any
}

func result(w interface {
	Result() *http.Response
}) *httpResult {
	resp := w.Result()
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	r := &httpResult{code: resp.StatusCode, body: b.String()}
	_ = json.Unmarshal([]byte(r.body), &r.json)
	return r
}
