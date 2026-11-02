package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestS3BucketNameRules(t *testing.T) {
	for name, want := range map[string]bool{
		"my-bucket": true, "a.b.c": true, "abc": true, strings.Repeat("a", 63): true,
		"ab": false, strings.Repeat("a", 64): false, "My-Bucket": false, "-abc": false, "abc-": false,
		"a..b": false, "192.168.1.1": false, "xn--abc": false, "sthree-x": false, "amzn-s3-demo-x": false,
		"abc-s3alias": false, "abc--ol-s3": false, "abc.mrap": false, "abc--x-s3": false, "abc--table-s3": false,
		"under_score": false,
	} {
		if got := validS3BucketName(name); got != want {
			t.Errorf("validS3BucketName(%q) = %v, want %v", name, got, want)
		}
	}
}

// The claim name is the bucket name when it fits; a dotted or long name is shortened with a hash, so it
// stays a valid, unique Kubernetes name whose setup Job name fits a label value.
func TestBucketClaimName(t *testing.T) {
	if got := bucketClaimName("app-artifacts"); got != "app-artifacts" {
		t.Errorf("a short name must be kept: %q", got)
	}
	long := strings.Repeat("a", 30) + "." + strings.Repeat("b", 30)
	a, b := bucketClaimName(long), bucketClaimName(strings.Replace(long, ".", "-", 1))
	for _, n := range []string{a, b, bucketClaimName("x.y")} {
		if len(n) > maxBucketClaimName || !fnNameRE.MatchString(n) || len(n+"-bucket-0123456789") > 63 {
			t.Errorf("claim name %q is not a valid short name", n)
		}
	}
	if a == b {
		t.Errorf("two bucket names map to one claim name %q", a)
	}
}

func TestS3CreateBucketDecodes(t *testing.T) {
	op, ok := decodeTarget(http.MethodPut, "new-bucket", "", url.Values{})
	if !ok || op.kind != "create-bucket" || !op.write || op.action() != "s3:CreateBucket" {
		t.Fatalf("PUT /new-bucket decodes to %+v %v", op, ok)
	}
	h := &s3Handler{vhostSuffixes: []string{"s3.example.test"}}
	r := httptest.NewRequest(http.MethodPut, "/", nil)
	r.Host = "new-bucket.s3.example.test"
	if op, ok := h.decode(r); !ok || op.kind != "create-bucket" || op.bucket != "new-bucket" {
		t.Fatalf("virtual-hosted PUT / decodes to %+v %v", op, ok)
	}
}

func TestS3CreateBucketRequestChecks(t *testing.T) {
	cases := []struct {
		name, body string
		hdr        map[string]string
		want       string
	}{
		{"plain", "", nil, ""},
		{"private acl", "", map[string]string{"x-amz-acl": "private"}, ""},
		{"public acl", "", map[string]string{"x-amz-acl": "public-read"}, "InvalidBucketAclWithObjectOwnership"},
		{"a grant", "", map[string]string{"x-amz-grant-read": "uri=x"}, "InvalidBucketAclWithObjectOwnership"},
		{"enforced ownership", "", map[string]string{"x-amz-object-ownership": "BucketOwnerEnforced"}, ""},
		{"object writer", "", map[string]string{"x-amz-object-ownership": "ObjectWriter"}, "InvalidArgument"},
		{"object lock", "", map[string]string{"x-amz-bucket-object-lock-enabled": "true"}, "NotImplemented"},
		{"empty constraint", `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></CreateBucketConfiguration>`, nil, ""},
		{"explicit us-east-1", `<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>`, nil, "InvalidLocationConstraint"},
		{"another region", `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`, nil, "IllegalLocationConstraintException"},
		{"directory bucket", `<CreateBucketConfiguration><Location><Name>use1-az4</Name></Location></CreateBucketConfiguration>`, nil, "NotImplemented"},
		{"not xml", `{`, nil, "MalformedXML"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPut, "/b", strings.NewReader(c.body))
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		if got, _, _ := createBucketRequestError(r); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// createFixture is deleteBucketFixture plus the account-wide bucket namespace, and a short wait.
func createFixture(t *testing.T) (*s3Handler, *fakeS3, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	h, f, d := deleteBucketFixture(t)
	dyn := d.(*dynamicfake.FakeDynamicClient)
	h.bucketNS = "open-infra-s3"
	h.createWait, h.createPoll = 3*time.Second, 20*time.Millisecond
	return h, f, dyn
}

// setupFinishes plays the platform's part: once the claim exists, the bucket appears in MinIO and the
// claim reports ready.
func setupFinishes(t *testing.T, f *fakeS3, dyn dynamic.Interface, ns, name, bucket string) {
	go func() {
		for i := 0; i < 200; i++ {
			cur, err := dyn.Resource(bucketListGVR).Namespace(ns).Get(context.Background(), name, metav1.GetOptions{})
			if err == nil {
				f.mu.Lock()
				f.buckets[bucket] = true
				f.mu.Unlock()
				_ = unstructured.SetNestedField(cur.Object, true, "status", "ready")
				_, _ = dyn.Resource(bucketListGVR).Namespace(ns).Update(context.Background(), cur, metav1.UpdateOptions{})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

func createReq(bucket string) *http.Request {
	return httptest.NewRequest(http.MethodPut, "/"+bucket, nil)
}

func TestS3CreateBucket_MakesAClaimAsTheCallerAndAnswersWhenReady(t *testing.T) {
	h, f, dyn := createFixture(t)
	setupFinishes(t, f, dyn, "open-infra-s3", "app-artifacts", "app-artifacts")
	w := httptest.NewRecorder()
	h.createBucket(w, createReq("app-artifacts"), callerClaims(), s3op{kind: "create-bucket", bucket: "app-artifacts", write: true}, "r")
	if w.Code != 200 || w.Header().Get("Location") != "/app-artifacts" {
		t.Fatalf("CreateBucket = %d %s (Location %q), want 200 /app-artifacts", w.Code, w.Body, w.Header().Get("Location"))
	}
	c, err := dyn.Resource(bucketListGVR).Namespace("open-infra-s3").Get(context.Background(), "app-artifacts", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("no kind: Bucket claim: %v", err)
	}
	if b, _, _ := unstructured.NestedString(c.Object, "spec", "bucketName"); b != "app-artifacts" {
		t.Errorf("spec.bucketName = %q", b)
	}
	if by := c.GetAnnotations()["openinfra.dev/created-by"]; by != "User/alice" {
		t.Errorf("created-by = %q, want User/alice", by)
	}
	// Re-creating your own bucket in us-east-1 answers 200, as AWS does.
	w = httptest.NewRecorder()
	h.createBucket(w, createReq("app-artifacts"), callerClaims(), s3op{kind: "create-bucket", bucket: "app-artifacts", write: true}, "r")
	if w.Code != 200 {
		t.Fatalf("re-creating your own bucket = %d %s, want 200", w.Code, w.Body)
	}
}

func TestS3CreateBucket_NamesThatAreTaken(t *testing.T) {
	h, f, _ := createFixture(t)
	f.buckets["someone-elses"] = true // a bucket no kind: Bucket is
	for _, b := range []string{"velero", "someone-elses"} {
		w := httptest.NewRecorder()
		h.createBucket(w, createReq(b), callerClaims(), s3op{kind: "create-bucket", bucket: b, write: true}, "r")
		if w.Code != 409 || !strings.Contains(w.Body.String(), "BucketAlreadyExists") {
			t.Errorf("CreateBucket %s = %d %s, want 409 BucketAlreadyExists", b, w.Code, w.Body)
		}
	}
	w := httptest.NewRecorder()
	h.createBucket(w, createReq("Bad_Name"), callerClaims(), s3op{kind: "create-bucket", bucket: "Bad_Name", write: true}, "r")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "InvalidBucketName") {
		t.Errorf("an invalid name = %d %s, want 400 InvalidBucketName", w.Code, w.Body)
	}
}

// A stack's bucket the caller may read is theirs (200); one they may not read is someone else's (409).
func TestS3CreateBucket_ExistingClaim(t *testing.T) {
	h, f, dyn := createFixture(t)
	f.buckets["stack-data"] = true
	c, _ := dyn.Resource(bucketListGVR).Namespace("open-infra-cfn").Get(context.Background(), "stack-data", metav1.GetOptions{})
	_ = unstructured.SetNestedField(c.Object, true, "status", "ready")
	_, _ = dyn.Resource(bucketListGVR).Namespace("open-infra-cfn").Update(context.Background(), c, metav1.UpdateOptions{})
	w := httptest.NewRecorder()
	h.createBucket(w, createReq("stack-data"), callerClaims(), s3op{kind: "create-bucket", bucket: "stack-data", write: true}, "r")
	if w.Code != 200 {
		t.Fatalf("CreateBucket of your own stack's bucket = %d %s, want 200", w.Code, w.Body)
	}
	other := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{xbucketListGVR: "XBucketList", bucketListGVR: "BucketList"})
	other.PrependReactor("get", "buckets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "openinfra.dev", Resource: "buckets"}, "stack-data", nil)
	})
	h.callerDyn = func(string, []string) (dynamic.Interface, error) { return other, nil }
	w = httptest.NewRecorder()
	h.createBucket(w, createReq("stack-data"), callerClaims(), s3op{kind: "create-bucket", bucket: "stack-data", write: true}, "r")
	if w.Code != 409 || !strings.Contains(w.Body.String(), "BucketAlreadyExists") {
		t.Fatalf("CreateBucket of a bucket you may not read = %d %s, want 409 BucketAlreadyExists", w.Code, w.Body)
	}
}

// RBAC decides: a caller who may not create the claim gets AccessDenied, and nothing is made.
func TestS3CreateBucket_CallerMayNotCreateTheClaim(t *testing.T) {
	h, _, dyn := createFixture(t)
	dyn.PrependReactor("create", "buckets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "openinfra.dev", Resource: "buckets"}, "x", nil)
	})
	w := httptest.NewRecorder()
	h.createBucket(w, createReq("no-rights"), callerClaims(), s3op{kind: "create-bucket", bucket: "no-rights", write: true}, "r")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("CreateBucket without the right = %d %s, want 403 AccessDenied", w.Code, w.Body)
	}
}

// A setup that has not finished within the wait answers 503 (SDKs retry), not a false 200.
func TestS3CreateBucket_SlowSetupIsRetryable(t *testing.T) {
	h, _, _ := createFixture(t)
	h.createWait = 100 * time.Millisecond
	w := httptest.NewRecorder()
	h.createBucket(w, createReq("slow-bucket"), callerClaims(), s3op{kind: "create-bucket", bucket: "slow-bucket", write: true}, "r")
	if w.Code != 503 || !strings.Contains(w.Body.String(), "ServiceUnavailable") {
		t.Fatalf("a slow setup = %d %s, want 503 ServiceUnavailable", w.Code, w.Body)
	}
}

// A long or dotted bucket name gets a shortened claim name; the claim still names the exact bucket.
func TestS3CreateBucket_DottedName(t *testing.T) {
	h, f, dyn := createFixture(t)
	b := "logs.example.app-artifacts-for-the-long-name"
	setupFinishes(t, f, dyn, "open-infra-s3", bucketClaimName(b), b)
	w := httptest.NewRecorder()
	h.createBucket(w, createReq(b), callerClaims(), s3op{kind: "create-bucket", bucket: b, write: true}, "r")
	if w.Code != 200 {
		t.Fatalf("CreateBucket %s = %d %s", b, w.Code, w.Body)
	}
	c, err := dyn.Resource(bucketListGVR).Namespace("open-infra-s3").Get(context.Background(), bucketClaimName(b), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := unstructured.NestedString(c.Object, "spec", "bucketName"); got != b {
		t.Errorf("spec.bucketName = %q, want %q", got, b)
	}
}
