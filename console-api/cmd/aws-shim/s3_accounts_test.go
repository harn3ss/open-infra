package main

// Each account's S3 buckets are its own: a bucket belongs to the account of the kind: Bucket claim that
// made it (a claim naming a bucket that existed before it made nothing), ListBuckets lists the caller's
// account's alone, a request is decided in the bucket's account with its policy, and bucket names stay
// global.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// s3Directory is a namespace → account directory: the member account owns memberHome, every other
// namespace is the management account's.
type s3Directory struct{ members bool }

func (d s3Directory) AccountOf(ns string) string {
	if ns == memberHome {
		return testMember
	}
	return awsidentity.Current().AccountID
}

func (d s3Directory) Accounts() []string {
	if !d.members {
		return []string{awsidentity.Current().AccountID}
	}
	return []string{awsidentity.Current().AccountID, testMember}
}

// datedS3 is fakeS3 with ListBuckets: each bucket's creation time is when it first appeared.
type datedS3 struct {
	*fakeS3
	cmu     sync.Mutex
	created map[string]time.Time
}

func (d *datedS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.Trim(r.URL.Path, "/") == "" {
		d.fakeS3.mu.Lock()
		names := make([]string, 0, len(d.buckets))
		for b := range d.buckets {
			names = append(names, b)
		}
		d.fakeS3.mu.Unlock()
		slices.Sort(names)
		var sb strings.Builder
		sb.WriteString(`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>x</ID></Owner><Buckets>`)
		d.cmu.Lock()
		for _, b := range names {
			if _, ok := d.created[b]; !ok {
				d.created[b] = time.Now()
			}
			sb.WriteString(`<Bucket><Name>` + b + `</Name><CreationDate>` + d.created[b].UTC().Format(iso8601Millis) + `</CreationDate></Bucket>`)
		}
		d.cmu.Unlock()
		sb.WriteString(`</Buckets></ListAllMyBucketsResult>`)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(sb.String()))
		return
	}
	d.fakeS3.ServeHTTP(w, r)
}

func (d *datedS3) add(bucket string, at time.Time) {
	d.fakeS3.mu.Lock()
	d.buckets[bucket] = true
	d.fakeS3.mu.Unlock()
	d.cmu.Lock()
	d.created[bucket] = at
	d.cmu.Unlock()
}

// xbucket is a kind: Bucket claim's composite, created at at, for bucket.
func xbucket(name, ns, claim, bucket string, at time.Time) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "XBucket",
		"metadata": map[string]any{"name": name, "creationTimestamp": at.UTC().Format(time.RFC3339), "labels": map[string]any{
			"crossplane.io/claim-namespace": ns, "crossplane.io/claim-name": claim}},
		"spec":   map[string]any{"bucketName": bucket},
		"status": map[string]any{"bucket": bucket},
	}}
}

func bucketClaimObj(ns, name, bucket string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Bucket",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     map[string]any{"bucketName": bucket},
	}}
}

// s3AccountsFixture: the management account's mgmt-data (its claim made it), the member account's
// team-data (likewise), a StaticSite's site-x (no kind: Bucket made it, though the member names it in a
// claim of its own) and the management account's assets (the member's later claim names it too).
func s3AccountsFixture(t *testing.T) (*s3Handler, *datedS3, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	f := &datedS3{fakeS3: newFakeS3(), created: map[string]time.Time{}}
	f.add("mgmt-data", base.Add(10*time.Second))
	f.add("team-data", base.Add(20*time.Second))
	f.add("site-x", base)
	f.add("assets", base)
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{xbucketListGVR: "XBucketList", bucketListGVR: "BucketList"},
		xbucket("x-mgmt", "open-infra-s3", "mgmt-data", "mgmt-data", base.Add(5*time.Second)),
		bucketClaimObj("open-infra-s3", "mgmt-data", "mgmt-data"),
		xbucket("x-team", memberHome, "team-data", "team-data", base.Add(15*time.Second)),
		bucketClaimObj(memberHome, "team-data", "team-data"),
		xbucket("x-assets", "open-infra-s3", "assets", "assets", base.Add(-time.Minute)),
		xbucket("x-squat-assets", memberHome, "assets", "assets", base.Add(time.Minute)),
		bucketClaimObj(memberHome, "assets", "assets"),
		xbucket("x-squat-site", memberHome, "site-x", "site-x", base.Add(time.Minute)),
	)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	mc, err := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4("a", "b", ""), Region: "us-east-1", BucketLookup: minio.BucketLookupPath})
	if err != nil {
		t.Fatal(err)
	}
	h := &s3Handler{mc: mc, cs: csWithSAR(true), logger: discardLogger(), dyn: dyn, bucketNS: "open-infra-s3",
		callerDyn: func(string, []string) (dynamic.Interface, error) { return dyn, nil },
		authz:     doorAccountsAuthz(t), accounts: s3Directory{members: true},
		createWait: 3 * time.Second, createPoll: 20 * time.Millisecond}
	return h, f, dyn
}

var (
	s3Alice = iam.Claims{Sub: "alice"}
	s3Bob   = iam.Claims{Sub: "bob", Account: testMember}
)

func s3Req(ctx context.Context, method, path string) *http.Request {
	return httptest.NewRequest(method, path, nil).WithContext(ctx)
}

func TestS3Accounts_ABucketIsTheAccountsWhoseClaimMadeIt(t *testing.T) {
	h, _, _ := s3AccountsFixture(t)
	ctx := context.Background()
	mgmt := awsidentity.Current().AccountID
	for bucket, want := range map[string]string{
		"mgmt-data": mgmt, "team-data": testMember,
		"site-x": mgmt, // a StaticSite's: the member's claim came after the bucket and made nothing
		"assets": mgmt, // the management account's claim made it; the member's later claim did not
		"velero": mgmt, // a platform bucket
	} {
		if got := h.bucketOwner(ctx, bucket); got != want {
			t.Errorf("owner of %s = %q, want %q", bucket, got, want)
		}
	}
}

func TestS3Accounts_EachAccountReachesItsOwnBuckets(t *testing.T) {
	h, _, _ := s3AccountsFixture(t)
	mctx := memberCtx()
	get := func(b string) s3op { return s3op{kind: "get", bucket: b, key: "k"} }
	put := func(b string) s3op { return s3op{kind: "put", bucket: b, key: "k", write: true} }

	// The member account: its own bucket, by its identity policy alone.
	if !h.allowed(s3Req(mctx, "GET", "/team-data/k"), s3Bob, get("team-data")) || !h.allowed(s3Req(mctx, "PUT", "/team-data/k"), s3Bob, put("team-data")) {
		t.Fatal("the member account's principal must reach its own bucket")
	}
	// Never the management account's (no bucket policy lets it across), a StaticSite's, or a platform bucket.
	for _, b := range []string{"mgmt-data", "assets", "site-x", "velero"} {
		if h.allowed(s3Req(mctx, "GET", "/"+b+"/k"), s3Bob, get(b)) {
			t.Errorf("a member account's principal reached %s", b)
		}
	}
	// The management account: its own, never the member account's.
	ctx := context.Background()
	if !h.allowed(s3Req(ctx, "GET", "/mgmt-data/k"), s3Alice, get("mgmt-data")) || !h.allowed(s3Req(ctx, "GET", "/site-x/k"), s3Alice, get("site-x")) {
		t.Fatal("the management account's principal must reach its own buckets")
	}
	if h.allowed(s3Req(ctx, "GET", "/team-data/k"), s3Alice, get("team-data")) || h.allowed(s3Req(ctx, "PUT", "/team-data/k"), s3Alice, put("team-data")) {
		t.Fatal("the management account's principal reached a member account's bucket")
	}
}

// Across accounts both must allow: the caller's identity policy and the bucket's policy.
func TestS3Accounts_ABucketPolicyLetsAnotherAccountIn(t *testing.T) {
	h, f, _ := s3AccountsFixture(t)
	mgmt := awsidentity.Current().AccountID
	f.fakeS3.mu.Lock()
	f.policies["team-data"] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + mgmt +
		`:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::team-data/*"}]}`
	f.fakeS3.mu.Unlock()
	ctx := context.Background()
	if !h.allowed(s3Req(ctx, "GET", "/team-data/k"), s3Alice, s3op{kind: "get", bucket: "team-data", key: "k"}) {
		t.Fatal("the member account's bucket policy lets the management account read")
	}
	if h.allowed(s3Req(ctx, "PUT", "/team-data/k"), s3Alice, s3op{kind: "put", bucket: "team-data", key: "k", write: true}) {
		t.Fatal("the bucket policy grants reads alone")
	}
	// A policy naming another account lets nobody else in.
	f.fakeS3.mu.Lock()
	f.policies["mgmt-data"] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::955555555555:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::mgmt-data/*"}]}`
	f.fakeS3.mu.Unlock()
	if h.allowed(s3Req(memberCtx(), "GET", "/mgmt-data/k"), s3Bob, s3op{kind: "get", bucket: "mgmt-data", key: "k"}) {
		t.Fatal("a bucket policy for another account let the member account in")
	}
}

func TestS3Accounts_ListBucketsListsTheCallersAccountsAlone(t *testing.T) {
	h, _, _ := s3AccountsFixture(t)
	list := func(ctx context.Context, c iam.Claims) string {
		w := httptest.NewRecorder()
		h.serve(w, s3Req(ctx, "GET", "/"), c, "r")
		if w.Code != 200 {
			t.Fatalf("ListBuckets = %d %s", w.Code, w.Body)
		}
		return w.Body.String()
	}
	body := list(memberCtx(), s3Bob)
	if !strings.Contains(body, "<Name>team-data</Name>") || strings.Count(body, "<Name>") != 1 || !strings.Contains(body, "<ID>"+testMember+"</ID>") {
		t.Fatalf("the member account lists its own bucket alone, as its owner: %s", body)
	}
	body = list(context.Background(), s3Alice)
	for _, b := range []string{"mgmt-data", "site-x", "assets"} {
		if !strings.Contains(body, "<Name>"+b+"</Name>") {
			t.Errorf("the management account's listing misses %s", b)
		}
	}
	if strings.Contains(body, "team-data") || !strings.Contains(body, "<ID>open-infra</ID>") {
		t.Fatalf("the management account's listing: %s", body)
	}
}

func TestS3Accounts_CreateBucketInTheMembersHome(t *testing.T) {
	h, f, dyn := s3AccountsFixture(t)
	mctx := memberCtx()
	create := func(ctx context.Context, c iam.Claims, b string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.createBucket(w, s3Req(ctx, "PUT", "/"+b), c, s3op{kind: "create-bucket", bucket: b, write: true}, "r")
		return w
	}
	// Names are global: the management account's, a StaticSite's, and the one the member's own (later)
	// claim names but did not make, are all taken.
	for _, b := range []string{"mgmt-data", "site-x", "assets"} {
		if w := create(mctx, s3Bob, b); w.Code == 200 || !strings.Contains(w.Body.String(), "BucketAlreadyExists") {
			t.Errorf("member CreateBucket %s = %d %s, want BucketAlreadyExists", b, w.Code, w.Body)
		}
	}
	if w := create(context.Background(), s3Alice, "team-data"); w.Code == 200 || !strings.Contains(w.Body.String(), "BucketAlreadyExists") {
		t.Fatalf("the management account took the member account's bucket name: %d %s", w.Code, w.Body)
	}
	// A new bucket: its claim in the member's home; once the platform has made it, it is the member's.
	go func() {
		for i := 0; i < 200; i++ {
			if _, err := dyn.Resource(bucketListGVR).Namespace(memberHome).Get(context.Background(), "team-new", metav1.GetOptions{}); err == nil {
				_, _ = dyn.Resource(xbucketListGVR).Create(context.Background(),
					xbucket("x-team-new", memberHome, "team-new", "team-new", time.Now().Add(-2*time.Second)), metav1.CreateOptions{})
				f.add("team-new", time.Now())
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if w := create(mctx, s3Bob, "team-new"); w.Code != 200 {
		t.Fatalf("member CreateBucket team-new = %d %s", w.Code, w.Body)
	}
	if _, err := dyn.Resource(bucketListGVR).Namespace("open-infra-s3").Get(context.Background(), "team-new", metav1.GetOptions{}); err == nil {
		t.Fatal("a member account's bucket claim was made in the management account's namespace")
	}
	if !h.allowed(s3Req(mctx, "PUT", "/team-new/k"), s3Bob, s3op{kind: "put", bucket: "team-new", key: "k", write: true}) {
		t.Fatal("the member account's new bucket is its own at once")
	}
	if h.allowed(s3Req(context.Background(), "GET", "/team-new/k"), s3Alice, s3op{kind: "get", bucket: "team-new", key: "k"}) {
		t.Fatal("the management account reached the member account's new bucket")
	}
	// Re-creating its own bucket answers 200, as AWS does in us-east-1.
	if w := create(mctx, s3Bob, "team-new"); w.Code != 200 {
		t.Fatalf("member re-CreateBucket of its own = %d %s", w.Code, w.Body)
	}
}

func TestS3Accounts_DeleteBucketByItsOwnAccountAlone(t *testing.T) {
	h, f, dyn := s3AccountsFixture(t)
	del := func(ctx context.Context, c iam.Claims, b string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.deleteBucket(w, s3Req(ctx, "DELETE", "/"+b), c, s3op{kind: "delete-bucket", bucket: b, write: true}, "r")
		return w
	}
	if w := del(memberCtx(), s3Bob, "mgmt-data"); w.Code != 403 {
		t.Fatalf("a member deleted the management account's bucket: %d %s", w.Code, w.Body)
	}
	if w := del(context.Background(), s3Alice, "team-data"); w.Code != 403 {
		t.Fatalf("the management account deleted a member account's bucket: %d %s", w.Code, w.Body)
	}
	if w := del(memberCtx(), s3Bob, "assets"); w.Code != 403 {
		t.Fatalf("a member deleted, through its own later claim, the management account's bucket: %d %s", w.Code, w.Body)
	}
	if _, err := dyn.Resource(bucketListGVR).Namespace("open-infra-s3").Get(context.Background(), "mgmt-data", metav1.GetOptions{}); err != nil {
		t.Fatal("the management account's claim is gone")
	}
	if w := del(memberCtx(), s3Bob, "team-data"); w.Code != 204 {
		t.Fatalf("the member deletes its own bucket: %d %s", w.Code, w.Body)
	}
	f.fakeS3.mu.Lock()
	removed := slices.Clone(f.removed)
	f.fakeS3.mu.Unlock()
	if len(removed) != 1 || removed[0] != "team-data" {
		t.Fatalf("removed %v", removed)
	}
}

// Until a member account exists nothing is looked up: every bucket is the management account's, exactly
// as before accounts.
func TestS3Accounts_NoMemberAccountsNothingChanges(t *testing.T) {
	h, _, dyn := s3AccountsFixture(t)
	h.accounts = s3Directory{members: false}
	dyn.ClearActions()
	w := httptest.NewRecorder()
	h.serve(w, s3Req(context.Background(), "GET", "/"), s3Alice, "r")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<Name>team-data</Name>") {
		t.Fatalf("ListBuckets = %d %s", w.Code, w.Body)
	}
	if !h.allowed(s3Req(context.Background(), "GET", "/team-data/k"), s3Alice, s3op{kind: "get", bucket: "team-data", key: "k"}) {
		t.Fatal("without member accounts every bucket is the management account's")
	}
	for _, a := range dyn.Actions() {
		if a.GetResource().Resource == "xbuckets" {
			t.Fatalf("looked up the buckets' claims without a member account: %v", a)
		}
	}
}

// x-amz-expected-bucket-owner (and x-amz-source-expected-bucket-owner for a copy's source): the request is
// refused when the bucket's owner is not the account it names, and is unchanged without the header.
func TestS3Accounts_ExpectedBucketOwner(t *testing.T) {
	h, _, _ := s3AccountsFixture(t)
	mgmt := awsidentity.Current().AccountID
	get := func(b string) s3op { return s3op{kind: "get", bucket: b, key: "k"} }
	req := func(header, value string) *http.Request {
		r := s3Req(context.Background(), "GET", "/x/k")
		if header != "" {
			r.Header.Set(header, value)
		}
		return r
	}
	for _, c := range []struct {
		name, header, value, bucket string
		op                          s3op
		want                        bool
	}{
		{"no header", "", "", "team-data", get("team-data"), true},
		{"the owner", "x-amz-expected-bucket-owner", testMember, "team-data", get("team-data"), true},
		{"the management account's own", "x-amz-expected-bucket-owner", mgmt, "mgmt-data", get("mgmt-data"), true},
		{"another account", "x-amz-expected-bucket-owner", mgmt, "team-data", get("team-data"), false},
		{"another account (member expected)", "x-amz-expected-bucket-owner", testMember, "mgmt-data", get("mgmt-data"), false},
		{"copy source owner", "x-amz-source-expected-bucket-owner", testMember, "team-data", get("team-data"), true},
		{"copy source another account", "x-amz-source-expected-bucket-owner", testMember, "assets", get("assets"), false},
		{"create-bucket takes none", "x-amz-expected-bucket-owner", testMember, "new-one", s3op{kind: "create-bucket", bucket: "new-one", write: true}, true},
	} {
		header := c.header
		if header == "" {
			header = "x-amz-expected-bucket-owner"
		}
		if got := h.expectedOwner(req(c.header, c.value), header, c.op); got != c.want {
			t.Errorf("%s: expectedOwner = %v, want %v", c.name, got, c.want)
		}
	}
}

// CreateBucket is decided in the caller's own account: the bucket it makes is the caller's. Before it
// exists no claim names it, so deciding it by the name's owner would decide a member's create across
// accounts and deny it.
func TestS3Accounts_CreateBucketIsDecidedInTheCallersAccount(t *testing.T) {
	h, _, _ := s3AccountsFixture(t)
	create := s3op{kind: "create-bucket", bucket: "brand-new", write: true}
	if !h.allowed(s3Req(memberCtx(), "PUT", "/brand-new"), s3Bob, create) {
		t.Fatal("a member account's principal must be allowed to create a bucket in its own account")
	}
	if !h.allowed(s3Req(context.Background(), "PUT", "/brand-new"), s3Alice, create) {
		t.Fatal("the management account's principal must be allowed to create a bucket")
	}
}
