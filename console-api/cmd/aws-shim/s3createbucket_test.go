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
	lc := func(region string) string {
		return `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>` + region + `</LocationConstraint></CreateBucketConfiguration>`
	}
	cases := []struct {
		name, body string
		hdr        map[string]string
		signed     string // the request's signing region ("" = none, read as us-east-1)
		want       string
	}{
		{"plain", "", nil, "", ""},
		{"private acl", "", map[string]string{"x-amz-acl": "private"}, "", ""},
		{"public acl", "", map[string]string{"x-amz-acl": "public-read"}, "", "InvalidBucketAclWithObjectOwnership"},
		{"a grant", "", map[string]string{"x-amz-grant-read": "uri=x"}, "", "InvalidBucketAclWithObjectOwnership"},
		{"enforced ownership", "", map[string]string{"x-amz-object-ownership": "BucketOwnerEnforced"}, "", ""},
		{"object writer", "", map[string]string{"x-amz-object-ownership": "ObjectWriter"}, "", "InvalidArgument"},
		{"object lock", "", map[string]string{"x-amz-bucket-object-lock-enabled": "true"}, "", "NotImplemented"},
		{"empty constraint", `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></CreateBucketConfiguration>`, nil, "", ""},
		{"explicit us-east-1", lc("us-east-1"), nil, "us-east-1", "InvalidLocationConstraint"},
		{"another region, signed for us-east-1", lc("eu-west-1"), nil, "us-east-1", "IllegalLocationConstraintException"},
		{"another region, unsigned", lc("eu-west-1"), nil, "", "IllegalLocationConstraintException"},
		// `aws s3 mb` from a client configured for another region sends that region as the constraint.
		{"the signing region", lc("eu-west-1"), nil, "eu-west-1", ""},
		{"eu-west-1's legacy EU", lc("EU"), nil, "eu-west-1", ""},
		{"a third region", lc("ap-south-1"), nil, "eu-west-1", "IllegalLocationConstraintException"},
		{"us-east-1 from another region", lc("us-east-1"), nil, "eu-west-1", "IllegalLocationConstraintException"},
		{"no constraint, another region", "", nil, "eu-west-1", ""},
		{"directory bucket", `<CreateBucketConfiguration><Location><Name>use1-az4</Name></Location></CreateBucketConfiguration>`, nil, "", "NotImplemented"},
		{"not xml", `{`, nil, "", "MalformedXML"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPut, "/b", strings.NewReader(c.body))
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		if got, _, _ := createBucketRequestError(r, c.signed); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The signing region is read from the request's SigV4 scope: the Authorization header, or a pre-signed
// URL's X-Amz-Credential.
func TestRequestSigningRegion(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/b", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261102/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
	if got := requestSigningRegion(r); got != "eu-west-1" {
		t.Errorf("header-signed: %q", got)
	}
	r = httptest.NewRequest(http.MethodPut, "/b?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20261102%2Fap-south-1%2Fs3%2Faws4_request&X-Amz-Date=20261102T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=abc", nil)
	if got := requestSigningRegion(r); got != "ap-south-1" {
		t.Errorf("pre-signed: %q", got)
	}
	if got := requestSigningRegion(httptest.NewRequest(http.MethodPut, "/b", nil)); got != "" {
		t.Errorf("unsigned: %q", got)
	}
}

// With the platform's object encryption on, CreateBucket answers once the bucket exists and has its
// default encryption — the setup's later step (the claim's own credentials) is not waited for — and never
// before the encryption is set.
func TestS3CreateBucket_AnswersOnceTheBucketIsEncrypted(t *testing.T) {
	h, f, dyn := createFixture(t)
	h.encryptsNewBuckets = func() bool { return true }
	h.createWait = 2 * time.Second
	go func() {
		for i := 0; i < 300; i++ {
			if _, err := dyn.Resource(bucketListGVR).Namespace("open-infra-s3").Get(context.Background(), "fast-bucket", metav1.GetOptions{}); err == nil {
				f.mu.Lock()
				f.buckets["fast-bucket"] = true // created, not yet encrypted
				f.mu.Unlock()
				time.Sleep(200 * time.Millisecond)
				f.mu.Lock()
				f.encryption["fast-bucket"] = "AES256" // the setup's next step; the claim never reports ready here
				f.mu.Unlock()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	start := time.Now()
	w := httptest.NewRecorder()
	h.createBucket(w, createReq("fast-bucket"), callerClaims(), s3op{kind: "create-bucket", bucket: "fast-bucket", write: true}, "r")
	if w.Code != 200 {
		t.Fatalf("CreateBucket = %d %s, want 200 once the bucket is encrypted", w.Code, w.Body)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Errorf("answered after %v: before the bucket's default encryption was set", time.Since(start))
	}

	// Encryption off: the bucket existing is enough.
	h2, f2, dyn2 := createFixture(t)
	h2.encryptsNewBuckets = func() bool { return false }
	go func() {
		for i := 0; i < 300; i++ {
			if _, err := dyn2.Resource(bucketListGVR).Namespace("open-infra-s3").Get(context.Background(), "plain-bucket", metav1.GetOptions{}); err == nil {
				f2.mu.Lock()
				f2.buckets["plain-bucket"] = true
				f2.mu.Unlock()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	w = httptest.NewRecorder()
	h2.createBucket(w, createReq("plain-bucket"), callerClaims(), s3op{kind: "create-bucket", bucket: "plain-bucket", write: true}, "r")
	if w.Code != 200 {
		t.Fatalf("CreateBucket (encryption off) = %d %s, want 200 once the bucket exists", w.Code, w.Body)
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
