package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

const (
	cfTestDist  = "E1A2B3C4D5E6F7"
	cfTestStack = "web"
	cfTestSite  = "web-cdn"
)

// cfFixture is a CloudFront front door over one stack whose distribution is the StaticSite web-cdn, with
// the site's status port served by a test server (synced = the start time of its last successful sync;
// 0 = the site does not answer).
type cfFixture struct {
	h      *cloudFrontHandler
	door   *cfnDoorway
	dyn    *dynamicfake.FakeDynamicClient
	synced atomic.Int64
	now    time.Time
	sars   []authzv1.ResourceAttributes
}

func newCFFixture(t *testing.T, allow func(a *authzv1.ResourceAttributes) bool) *cfFixture {
	t.Helper()
	f := &cfFixture{now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	gvrs := map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "secrets"}:    "SecretList",
		{Version: "v1", Resource: "configmaps"}: "ConfigMapList",
	}
	f.dyn = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrs)
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(act ktesting.Action) (bool, runtime.Object, error) {
		sar := act.(ktesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		f.sars = append(f.sars, *sar.Spec.ResourceAttributes)
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allow(sar.Spec.ResourceAttributes)}}, nil
	})
	f.door = &cfnDoorway{shimDyn: f.dyn, ns: opsNS, recNS: shimNS, cs: cs, authzNS: "default", logger: discardLogger()}
	f.seedStack(t, cfTestStack, cfn.StackResource{LogicalID: "Cdn", APIVersion: "openinfra.dev/v1", Kind: "StaticSite",
		Name: cfTestSite, Type: cloudFrontDistributionType, PhysicalID: cfTestDist})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+opsNS+"/"+cfTestSite {
			http.NotFound(w, r)
			return
		}
		v := f.synced.Load()
		if v == 0 {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "%d\n", v)
	}))
	t.Cleanup(srv.Close)
	f.h = newCloudFrontHandler(f.door, discardLogger())
	f.h.statusURL = func(ns, site string) string { return srv.URL + "/" + ns + "/" + site }
	f.h.now = func() time.Time { return f.now }
	n := 0
	f.h.newID = func() string { n++; return fmt.Sprintf("ITEST%09d", n) }
	return f
}

func (f *cfFixture) seedStack(t *testing.T, name string, res ...cfn.StackResource) {
	t.Helper()
	rec := cfn.StackRecord{Name: name, Namespace: opsNS, Status: "CREATE_COMPLETE", Resources: res}
	data, _ := json.Marshal(rec)
	obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": map[string]any{"name": "cfn-stack-" + name, "namespace": shimNS,
			"labels": map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": name}},
		"data": map[string]any{"stack.json": base64.StdEncoding.EncodeToString(data)}}}
	if _, err := f.dyn.Resource(secretGVR).Namespace(shimNS).Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

var cfUser = iam.Claims{Sub: "deployer", Groups: []string{"openinfra:powerusers", "openinfra:users"}}

func allowAll(*authzv1.ResourceAttributes) bool { return true }

// do sends one request to the front door as claims.
func (f *cfFixture) do(claims iam.Claims, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://shim.test"+path, strings.NewReader(body))
	w := httptest.NewRecorder()
	f.h.serve(w, r, claims, "req-1")
	return w
}

func cfBatch(ref string, paths ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><InvalidationBatch xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">`)
	fmt.Fprintf(&b, "<Paths><Quantity>%d</Quantity><Items>", len(paths))
	for _, p := range paths {
		b.WriteString("<Path>" + p + "</Path>")
	}
	b.WriteString("</Items></Paths><CallerReference>" + ref + "</CallerReference></InvalidationBatch>")
	return b.String()
}

// cfInvOut is the response shape a client parses (namespace-agnostic, as botocore reads it).
type cfInvOut struct {
	XMLName    xml.Name `xml:"Invalidation"`
	ID         string   `xml:"Id"`
	Status     string   `xml:"Status"`
	CreateTime string   `xml:"CreateTime"`
	Batch      struct {
		Paths struct {
			Quantity int      `xml:"Quantity"`
			Items    []string `xml:"Items>Path"`
		} `xml:"Paths"`
		CallerReference string `xml:"CallerReference"`
	} `xml:"InvalidationBatch"`
}

type cfErrOut struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

func cfInv(t *testing.T, w *httptest.ResponseRecorder, wantStatus int) cfInvOut {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status %d, want %d: %s", w.Code, wantStatus, w.Body.String())
	}
	var out cfInvOut
	if err := xml.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not an Invalidation: %v\n%s", err, w.Body.String())
	}
	return out
}

func cfErr(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantCode string) cfErrOut {
	t.Helper()
	var out cfErrOut
	if err := xml.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not CloudFront's error shape: %v\n%s", err, w.Body.String())
	}
	if w.Code != wantStatus || out.Error.Code != wantCode {
		t.Fatalf("got %d %s (%s), want %d %s", w.Code, out.Error.Code, out.Error.Message, wantStatus, wantCode)
	}
	if out.RequestID != "req-1" || !strings.Contains(w.Body.String(), cloudFrontXMLNS) {
		t.Fatalf("error lacks the request id or CloudFront's namespace: %s", w.Body.String())
	}
	return out
}

const invPath = "/2020-05-31/distribution/" + cfTestDist + "/invalidation"

// The deploy flow: create-invalidation answers InProgress at once; get-invalidation (what `wait
// invalidation-completed` polls) stays InProgress until the site reports a sync that started after the
// invalidation, then answers Completed — and keeps answering it.
func TestCloudFront_InvalidationCompletesAfterTheSiteSyncs(t *testing.T) {
	f := newCFFixture(t, allowAll)
	created := f.now
	f.synced.Store(created.Unix() - 10) // the site's last sync was before the upload

	w := f.do(cfUser, http.MethodPost, invPath, cfBatch("cli-1", "/*"))
	inv := cfInv(t, w, http.StatusCreated)
	if inv.ID != "ITEST000000001" || inv.Status != "InProgress" || inv.Batch.CallerReference != "cli-1" ||
		inv.Batch.Paths.Quantity != 1 || len(inv.Batch.Paths.Items) != 1 || inv.Batch.Paths.Items[0] != "/*" {
		t.Fatalf("CreateInvalidation answered %+v", inv)
	}
	if inv.CreateTime != "2026-11-01T12:00:00.000Z" {
		t.Errorf("CreateTime %q, want ISO-8601 with milliseconds", inv.CreateTime)
	}
	if loc := w.Header().Get("Location"); loc != "http://shim.test"+invPath+"/"+inv.ID {
		t.Errorf("Location %q", loc)
	}

	get := func() cfInvOut {
		return cfInv(t, f.do(cfUser, http.MethodGet, invPath+"/"+inv.ID, ""), http.StatusOK)
	}
	f.now = created.Add(20 * time.Second)
	if s := get().Status; s != "InProgress" {
		t.Fatalf("before the site has synced since the invalidation: %s, want InProgress", s)
	}
	// A sync that began in the same second the invalidation was created (it may have listed the bucket
	// before the upload landed) does not count.
	f.synced.Store(created.Unix())
	if s := get().Status; s != "InProgress" {
		t.Fatalf("a sync started with the invalidation counted: %s", s)
	}
	f.synced.Store(created.Unix() + 30)
	if s := get().Status; s != "Completed" {
		t.Fatalf("after a later sync: %s, want Completed", s)
	}
	// Completed is recorded: it no longer depends on the site answering.
	f.synced.Store(0)
	if s := get().Status; s != "Completed" {
		t.Fatalf("Completed was not kept: %s", s)
	}
}

// A site that does not answer its status port (starting, or from before the port) keeps the invalidation
// InProgress — never Completed on a timer.
func TestCloudFront_UnreachableSiteStaysInProgress(t *testing.T) {
	f := newCFFixture(t, allowAll)
	inv := cfInv(t, f.do(cfUser, http.MethodPost, invPath, cfBatch("r", "/index.html")), http.StatusCreated)
	f.now = f.now.Add(time.Hour)
	if s := cfInv(t, f.do(cfUser, http.MethodGet, invPath+"/"+inv.ID, ""), http.StatusOK).Status; s != "InProgress" {
		t.Fatalf("got %s with no answer from the site, want InProgress", s)
	}
}

// CallerReference: the same request again answers the first invalidation; the same reference with
// other paths is refused, as on AWS.
func TestCloudFront_CallerReferenceIdempotency(t *testing.T) {
	f := newCFFixture(t, allowAll)
	a := cfInv(t, f.do(cfUser, http.MethodPost, invPath, cfBatch("ref-1", "/a", "/b")), http.StatusCreated)
	b := cfInv(t, f.do(cfUser, http.MethodPost, invPath, cfBatch("ref-1", "/b", "/a")), http.StatusCreated)
	if a.ID != b.ID {
		t.Fatalf("the same request created a second invalidation (%s, %s)", a.ID, b.ID)
	}
	cfErr(t, f.do(cfUser, http.MethodPost, invPath, cfBatch("ref-1", "/c")), http.StatusConflict, "InvalidationBatchAlreadyExists")
	c := cfInv(t, f.do(cfUser, http.MethodPost, invPath, cfBatch("ref-2", "/a")), http.StatusCreated)
	if c.ID == a.ID {
		t.Fatal("a new CallerReference must create a new invalidation")
	}
}

func TestCloudFront_RequestValidation(t *testing.T) {
	f := newCFFixture(t, allowAll)
	for _, tc := range []struct {
		name, body string
		status     int
		code       string
	}{
		{"no body", "", http.StatusBadRequest, "MissingBody"},
		{"not XML", "<InvalidationBatch><Paths>", http.StatusBadRequest, "MalformedXML"},
		{"no caller reference", strings.Replace(cfBatch("x", "/a"), "<CallerReference>x</CallerReference>", "", 1), http.StatusBadRequest, "InvalidArgument"},
		{"quantity mismatch", strings.Replace(cfBatch("x", "/a"), "<Quantity>1</Quantity>", "<Quantity>2</Quantity>", 1), http.StatusBadRequest, "InconsistentQuantities"},
		{"no quantity", strings.Replace(cfBatch("x", "/a"), "<Quantity>1</Quantity>", "", 1), http.StatusBadRequest, "InvalidArgument"},
		{"no paths", cfBatch("x"), http.StatusBadRequest, "InvalidArgument"},
		{"relative path", cfBatch("x", "index.html"), http.StatusBadRequest, "InvalidArgument"},
		{"inner wildcard", cfBatch("x", "/a*/b"), http.StatusBadRequest, "InvalidArgument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfErr(t, f.do(cfUser, http.MethodPost, invPath, tc.body), tc.status, tc.code)
		})
	}
	many := make([]string, cfMaxPaths+1)
	for i := range many {
		many[i] = fmt.Sprintf("/p%d", i)
	}
	cfErr(t, f.do(cfUser, http.MethodPost, invPath, cfBatch("x", many...)), http.StatusRequestEntityTooLarge, "BatchTooLarge")
	if list, _ := f.h.load(context.Background(), &cfDistribution{id: cfTestDist, stack: cfTestStack}); len(list) != 0 {
		t.Fatalf("a refused request recorded an invalidation: %v", list)
	}
}

func TestCloudFront_UnknownDistributionAndInvalidation(t *testing.T) {
	f := newCFFixture(t, allowAll)
	cfErr(t, f.do(cfUser, http.MethodPost, "/2020-05-31/distribution/E0000000000000/invalidation", cfBatch("x", "/*")),
		http.StatusNotFound, "NoSuchDistribution")
	cfErr(t, f.do(cfUser, http.MethodGet, "/2020-05-31/distribution/lower-case/invalidation", ""), http.StatusNotFound, "NoSuchDistribution")
	cfErr(t, f.do(cfUser, http.MethodGet, invPath+"/INOPE", ""), http.StatusNotFound, "NoSuchInvalidation")
	// A distribution of a stack that has not completed has no id yet; another stack's resources are not it.
	f.seedStack(t, "other", cfn.StackResource{LogicalID: "Q", Kind: "Queue", Name: "q", Type: "AWS::SQS::Queue", PhysicalID: "E9999999999999"})
	cfErr(t, f.do(cfUser, http.MethodGet, "/2020-05-31/distribution/E9999999999999/invalidation", ""), http.StatusNotFound, "NoSuchDistribution")
}

// Operations other than the invalidation calls are an honest 501 in CloudFront's own error shape.
func TestCloudFront_OtherOperationsAre501(t *testing.T) {
	f := newCFFixture(t, allowAll)
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/2020-05-31/distribution/" + cfTestDist},
		{http.MethodGet, "/2020-05-31/distribution"},
		{http.MethodPut, "/2020-05-31/distribution/" + cfTestDist + "/config"},
		{http.MethodDelete, invPath + "/IABC"},
	} {
		e := cfErr(t, f.do(cfUser, p.method, p.path, ""), http.StatusNotImplemented, "NotImplemented")
		if !strings.Contains(e.Error.Message, "CreateInvalidation") {
			t.Errorf("%s %s: the 501 should name what is served: %s", p.method, p.path, e.Error.Message)
		}
	}
}

// A User is authorized on the distribution's StaticSite in its namespace: update to create an
// invalidation, get to read them. A reader can read but not create; a caller with no rights there gets
// AccessDenied, and nothing is recorded.
func TestCloudFront_UserAuthorizedOnTheStaticSite(t *testing.T) {
	f := newCFFixture(t, func(a *authzv1.ResourceAttributes) bool { return a.Verb == "get" })
	cfErr(t, f.do(cfUser, http.MethodPost, invPath, cfBatch("x", "/*")), http.StatusForbidden, "AccessDenied")
	if len(f.sars) != 1 {
		t.Fatalf("want one access review, got %d", len(f.sars))
	}
	got := f.sars[0]
	if got.Verb != "update" || got.Group != "openinfra.dev" || got.Resource != "staticsites" || got.Namespace != opsNS || got.Name != cfTestSite {
		t.Fatalf("CreateInvalidation was checked as %+v, want update staticsites %s/%s", got, opsNS, cfTestSite)
	}
	if list, _ := f.h.load(context.Background(), &cfDistribution{id: cfTestDist, stack: cfTestStack}); len(list) != 0 {
		t.Fatalf("a denied request recorded an invalidation: %v", list)
	}
	w := f.do(cfUser, http.MethodGet, invPath, "")
	if w.Code != http.StatusOK {
		t.Fatalf("a reader's ListInvalidations: %d %s", w.Code, w.Body.String())
	}
	if f.sars[1].Verb != "get" || f.sars[1].Name != cfTestSite {
		t.Fatalf("ListInvalidations was checked as %+v", f.sars[1])
	}

	none := newCFFixture(t, func(*authzv1.ResourceAttributes) bool { return false })
	cfErr(t, none.do(cfUser, http.MethodGet, invPath+"/IANY", ""), http.StatusForbidden, "AccessDenied")
}

// An assumed role's authority is its data-plane policy, default-deny: no policy, no invalidation; a grant
// of cloudfront:CreateInvalidation on another distribution does not reach this one; a grant on this one does.
func TestCloudFront_AssumedRoleNeedsAGrantOnTheDistribution(t *testing.T) {
	role := iam.Claims{Sub: "assumed-role/" + ecrTestRole + "/ci", Groups: []string{"openinfra:users"}, AssumedRole: ecrTestRole}
	f := newCFFixture(t, func(*authzv1.ResourceAttributes) bool { return false }) // RBAC is not a role's authority
	f.door.authz = roleChecker()
	cfErr(t, f.do(role, http.MethodPost, invPath, cfBatch("x", "/*")), http.StatusForbidden, "AccessDenied")

	f.door.authz = roleChecker(dpAllow([]string{"cloudfront:CreateInvalidation"}, "Distribution::E0THER0000000"))
	cfErr(t, f.do(role, http.MethodPost, invPath, cfBatch("x", "/*")), http.StatusForbidden, "AccessDenied")

	f.door.authz = roleChecker(dpAllow([]string{"cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"}, "Distribution::"+cfTestDist))
	inv := cfInv(t, f.do(role, http.MethodPost, invPath, cfBatch("x", "/*")), http.StatusCreated)
	cfInv(t, f.do(role, http.MethodGet, invPath+"/"+inv.ID, ""), http.StatusOK)
	cfErr(t, f.do(role, http.MethodGet, invPath, ""), http.StatusForbidden, "AccessDenied") // ListInvalidations not granted
	if len(f.sars) != 0 {
		t.Fatalf("an assumed role was put through RBAC: %v", f.sars)
	}
}

// ListInvalidations: newest first, paged by Marker/MaxItems, statuses settled like GetInvalidation's.
func TestCloudFront_ListInvalidations(t *testing.T) {
	f := newCFFixture(t, allowAll)
	t0 := f.now
	var ids []string
	for i := 0; i < 3; i++ {
		f.now = t0.Add(time.Duration(i) * time.Minute)
		ids = append(ids, cfInv(t, f.do(cfUser, http.MethodPost, invPath, cfBatch(fmt.Sprint("r", i), "/*")), http.StatusCreated).ID)
	}
	f.synced.Store(t0.Add(90 * time.Second).Unix()) // synced after the first two, before the third

	type listOut struct {
		Marker      string `xml:"Marker"`
		NextMarker  string `xml:"NextMarker"`
		MaxItems    int    `xml:"MaxItems"`
		IsTruncated bool   `xml:"IsTruncated"`
		Quantity    int    `xml:"Quantity"`
		Items       []struct {
			ID     string `xml:"Id"`
			Status string `xml:"Status"`
		} `xml:"Items>InvalidationSummary"`
	}
	listOf := func(f *cfFixture, q string) listOut {
		w := f.do(cfUser, http.MethodGet, invPath+q, "")
		if w.Code != http.StatusOK {
			t.Fatalf("ListInvalidations%s: %d %s", q, w.Code, w.Body.String())
		}
		var out listOut
		if err := xml.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	list := func(q string) listOut { return listOf(f, q) }
	all := list("")
	if all.Quantity != 3 || all.IsTruncated || all.MaxItems != 100 || len(all.Items) != 3 {
		t.Fatalf("list: %+v", all)
	}
	if all.Items[0].ID != ids[2] || all.Items[2].ID != ids[0] {
		t.Fatalf("not newest first: %+v", all.Items)
	}
	if all.Items[0].Status != "InProgress" || all.Items[1].Status != "Completed" || all.Items[2].Status != "Completed" {
		t.Fatalf("statuses: %+v", all.Items)
	}
	p1 := list("?MaxItems=2")
	if !p1.IsTruncated || p1.NextMarker != ids[1] || p1.Quantity != 2 {
		t.Fatalf("page 1: %+v", p1)
	}
	p2 := list("?MaxItems=2&Marker=" + p1.NextMarker)
	if p2.IsTruncated || p2.Quantity != 1 || p2.Items[0].ID != ids[0] || p2.Marker != ids[1] {
		t.Fatalf("page 2: %+v", p2)
	}
	cfErr(t, f.do(cfUser, http.MethodGet, invPath+"?MaxItems=0", ""), http.StatusBadRequest, "InvalidArgument")

	if e := listOf(newCFFixture(t, allowAll), ""); e.Quantity != 0 || e.IsTruncated || len(e.Items) != 0 {
		t.Fatalf("empty list: %+v", e)
	}
}

// The invalidations are the stack's records: deleting the stack removes them.
func TestCloudFront_StackDeleteRemovesInvalidations(t *testing.T) {
	f := newCFFixture(t, allowAll)
	cfInv(t, f.do(cfUser, http.MethodPost, invPath, cfBatch("x", "/*")), http.StatusCreated)
	sec := f.dyn.Resource(secretGVR).Namespace(shimNS)
	if _, err := sec.Get(context.Background(), invalidationsRecordName(cfTestStack), metav1.GetOptions{}); err != nil {
		t.Fatalf("no invalidations record: %v", err)
	}
	f.door.deleteStackSide(context.Background(), cfTestStack)
	if _, err := sec.Get(context.Background(), invalidationsRecordName(cfTestStack), metav1.GetOptions{}); err == nil {
		t.Fatal("the stack's invalidations outlived it")
	}
}

// Keeping history is bounded: the oldest beyond cfMaxKept are forgotten.
func TestCloudFront_HistoryIsBounded(t *testing.T) {
	f := newCFFixture(t, allowAll)
	for i := 0; i < cfMaxKept+5; i++ {
		f.now = f.now.Add(time.Second)
		cfInv(t, f.do(cfUser, http.MethodPost, invPath, cfBatch(fmt.Sprint("r", i), "/*")), http.StatusCreated)
	}
	list, err := f.h.load(context.Background(), &cfDistribution{id: cfTestDist, stack: cfTestStack})
	if err != nil || len(list) != cfMaxKept || list[0].CallerReference != "r5" {
		t.Fatalf("kept %d (first %q), want the newest %d", len(list), list[0].CallerReference, cfMaxKept)
	}
}

func TestCloudFront_AuthFailureShape(t *testing.T) {
	w := httptest.NewRecorder()
	(&cloudFrontHandler{}).authFailure(w, nil, "req-1")
	cfErr(t, w, http.StatusForbidden, "SignatureDoesNotMatch")
}

func TestCloudFront_StatusURL(t *testing.T) {
	h := newCloudFrontHandler(&cfnDoorway{svcSuffix: "svc.cluster.local"}, discardLogger())
	if got := h.statusURL("open-infra-cfn", "web-cdn"); got != "http://web-cdn-site.open-infra-cfn.svc.cluster.local:8081/synced" {
		t.Fatalf("statusURL %q", got)
	}
	if id := newInvalidationID(); len(id) != 14 || id[0] != 'I' || strings.ToUpper(id) != id {
		t.Fatalf("invalidation id %q is not in AWS's shape", id)
	}
}
