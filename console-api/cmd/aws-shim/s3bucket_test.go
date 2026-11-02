package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"time"
)

func TestS3Decode_Subresources(t *testing.T) {
	cases := []struct {
		method, url string
		ok          bool
		kind        string
		versionID   string
		write       bool
	}{
		{"GET", "/b?versioning", true, "get-bucket-versioning", "", false},
		{"PUT", "/b?versioning", true, "put-bucket-versioning", "", true},
		{"GET", "/b?versions&prefix=p", true, "list-object-versions", "", false},
		{"GET", "/b?tagging", true, "get-bucket-tagging", "", false},
		{"PUT", "/b?tagging", true, "put-bucket-tagging", "", true},
		{"DELETE", "/b?tagging", true, "delete-bucket-tagging", "", true},
		{"GET", "/b?location", true, "get-bucket-location", "", false},
		{"DELETE", "/b", true, "delete-bucket", "", true},
		{"GET", "/b?list-type=2&prefix=x", true, "list-objects", "", false},
		{"GET", "/b/k?versionId=v1", true, "get", "v1", false},
		{"HEAD", "/b/k?versionId=v1", true, "head", "v1", false},
		{"DELETE", "/b/k?versionId=v1", true, "delete", "v1", true},
		// a pre-signed URL's parameters (incl. the CLI's x-id) are not sub-resources
		{"GET", "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc&x-id=GetObject", true, "get", "", false},
		// sub-resources the shim does not serve are refused, never mistaken for a listing or a GET
		{"GET", "/b?acl", false, "", "", false},
		{"GET", "/b?policy", false, "", "", false},
		{"PUT", "/b?lifecycle", false, "", "", false},
		{"POST", "/b?delete", false, "", "", false},
		{"PUT", "/b/k?tagging", false, "", "", false},
		{"PUT", "/b/k?retention", false, "", "", false},
		{"GET", "/?acl", false, "", "", false},
	}
	h := &s3Handler{}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "https://s3.example.com"+c.url, nil)
		op, ok := h.decode(r)
		if ok != c.ok || (ok && (op.kind != c.kind || op.versionID != c.versionID || op.write != c.write || op.bucket != "b")) {
			t.Errorf("%s %s: decode = %+v ok=%v; want kind=%q version=%q write=%v ok=%v", c.method, c.url, op, ok, c.kind, c.versionID, c.write, c.ok)
		}
	}
	// virtual-hosted addressing decodes the same sub-resources
	hv := &s3Handler{vhostSuffixes: []string{"s3.example.com"}}
	r := httptest.NewRequest("GET", "https://b.s3.example.com/?versions", nil)
	r.Host = "b.s3.example.com"
	if op, ok := hv.decode(r); !ok || op.kind != "list-object-versions" || op.bucket != "b" {
		t.Errorf("vhost ?versions = %+v ok=%v", op, ok)
	}
	r = httptest.NewRequest("DELETE", "https://b.s3.example.com/", nil)
	r.Host = "b.s3.example.com"
	if op, ok := hv.decode(r); !ok || op.kind != "delete-bucket" {
		t.Errorf("vhost DELETE / = %+v ok=%v", op, ok)
	}
}

func TestS3OpAction(t *testing.T) {
	cases := map[s3op]string{
		{kind: "get"}:                        "s3:GetObject",
		{kind: "get", versionID: "v"}:        "s3:GetObjectVersion",
		{kind: "delete", versionID: "v"}:     "s3:DeleteObjectVersion",
		{kind: "get-bucket-versioning"}:      "s3:GetBucketVersioning",
		{kind: "put-bucket-versioning"}:      "s3:PutBucketVersioning",
		{kind: "list-object-versions"}:       "s3:ListBucketVersions",
		{kind: "get-bucket-tagging"}:         "s3:GetBucketTagging",
		{kind: "put-bucket-tagging"}:         "s3:PutBucketTagging",
		{kind: "delete-bucket-tagging"}:      "s3:PutBucketTagging",
		{kind: "get-bucket-location"}:        "s3:GetBucketLocation",
		{kind: "delete-bucket", write: true}: "s3:DeleteBucket",
		{kind: "list-objects"}:               "s3:ListBucket",
		{kind: "put", write: true}:           "s3:PutObject",
		{kind: "delete", write: true}:        "s3:DeleteObject",
		{kind: "list-buckets"}:               "s3:ListAllMyBuckets",
		{kind: "head-bucket"}:                "s3:ListBucket",
	}
	for op, want := range cases {
		if got := op.action(); got != want {
			t.Errorf("%+v action = %q, want %q", op, got, want)
		}
	}
}

// fakeS3 is a minimal S3 server for minio-go: one bucket's objects (with versions), its versioning
// status and tags. It answers only what the handlers under test send.
type fakeS3 struct {
	mu         sync.Mutex
	buckets    map[string]bool
	objects    map[string][]fakeVersion // bucket -> versions (newest last)
	versioning map[string]string
	tags       map[string]string // bucket -> raw Tagging XML ("" = none)
	encryption map[string]string // bucket -> default SSE algorithm ("" = none)
	removed    []string
}

type fakeVersion struct{ key, id string }

func newFakeS3() *fakeS3 {
	return &fakeS3{buckets: map[string]bool{}, objects: map[string][]fakeVersion{}, versioning: map[string]string{}, tags: map[string]string{}, encryption: map[string]string{}}
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(p, "/")
	q := r.URL.Query()
	_, hasVersioning := q["versioning"]
	_, hasVersions := q["versions"]
	_, hasTagging := q["tagging"]
	_, hasLocation := q["location"]
	_, hasEncryption := q["encryption"]
	notFound := func() {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<Error><Code>NoSuchBucket</Code><Message>no</Message></Error>`))
	}
	switch {
	case hasLocation:
		_, _ = w.Write([]byte(`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`))
	case !f.buckets[bucket]:
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		notFound()
	case key == "" && r.Method == http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case hasVersioning && r.Method == http.MethodGet:
		st := f.versioning[bucket]
		if st == "" {
			_, _ = w.Write([]byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></VersioningConfiguration>`))
			return
		}
		_, _ = w.Write([]byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>` + st + `</Status></VersioningConfiguration>`))
	case hasVersioning && r.Method == http.MethodPut:
		b := make([]byte, 512)
		n, _ := r.Body.Read(b)
		if strings.Contains(string(b[:n]), "Enabled") {
			f.versioning[bucket] = "Enabled"
		} else {
			f.versioning[bucket] = "Suspended"
		}
	case hasVersions:
		var sb strings.Builder
		sb.WriteString(`<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>` + bucket + `</Name><IsTruncated>false</IsTruncated>`)
		vs := f.objects[bucket]
		for i, v := range vs {
			latest := "false"
			if i == len(vs)-1 || vs[i+1].key != v.key {
				latest = "true"
			}
			sb.WriteString(`<Version><Key>` + v.key + `</Key><VersionId>` + v.id + `</VersionId><IsLatest>` + latest + `</IsLatest><LastModified>2026-11-01T00:00:00.000Z</LastModified><ETag>"e"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Version>`)
		}
		sb.WriteString(`</ListVersionsResult>`)
		_, _ = w.Write([]byte(sb.String()))
	case hasEncryption && r.Method == http.MethodGet:
		if f.encryption[bucket] == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>ServerSideEncryptionConfigurationNotFoundError</Code><Message>none</Message></Error>`))
			return
		}
		_, _ = w.Write([]byte(`<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>` + f.encryption[bucket] + `</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`))
	case hasTagging && r.Method == http.MethodGet:
		if f.tags[bucket] == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchTagSet</Code><Message>none</Message></Error>`))
			return
		}
		_, _ = w.Write([]byte(f.tags[bucket]))
	case hasTagging && r.Method == http.MethodPut:
		b := make([]byte, 8192)
		n, _ := r.Body.Read(b)
		f.tags[bucket] = string(b[:n])
	case hasTagging && r.Method == http.MethodDelete:
		f.tags[bucket] = ""
		w.WriteHeader(http.StatusNoContent)
	case key == "" && r.Method == http.MethodDelete:
		if len(f.objects[bucket]) > 0 {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`<Error><Code>BucketNotEmpty</Code><Message>not empty</Message></Error>`))
			return
		}
		delete(f.buckets, bucket)
		f.removed = append(f.removed, bucket)
		w.WriteHeader(http.StatusNoContent)
	case key != "" && r.Method == http.MethodPut:
		id := ""
		if f.versioning[bucket] == "Enabled" {
			id = "v" + string(rune('0'+len(f.objects[bucket])+1))
			w.Header().Set("x-amz-version-id", id)
		}
		f.objects[bucket] = append(f.objects[bucket], fakeVersion{key: key, id: id})
		w.Header().Set("ETag", `"e"`)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func fakeMinio(t *testing.T, f *fakeS3) *minio.Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	mc, err := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4("a", "b", ""), Region: "us-east-1", BucketLookup: minio.BucketLookupPath})
	if err != nil {
		t.Fatal(err)
	}
	return mc
}

func TestS3Versioning_VisibleThroughTheAPI(t *testing.T) {
	f := newFakeS3()
	f.buckets["data"] = true
	f.versioning["data"] = "Enabled" // the setup Job enabled it (claim versioning: true)
	h := &s3Handler{mc: fakeMinio(t, f), logger: discardLogger()}

	w := httptest.NewRecorder()
	h.getBucketVersioning(w, httptest.NewRequest("GET", "/data?versioning", nil), s3op{kind: "get-bucket-versioning", bucket: "data"}, "r1")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<Status>Enabled</Status>") || !strings.Contains(w.Body.String(), "VersioningConfiguration") {
		t.Fatalf("GetBucketVersioning = %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	h.putObject(w, httptest.NewRequest("PUT", "/data/k", strings.NewReader("x")), s3op{kind: "put", bucket: "data", key: "k", write: true}, "r2")
	if w.Code != 200 || w.Header().Get("x-amz-version-id") == "" {
		t.Fatalf("PutObject on a versioned bucket: %d, x-amz-version-id=%q", w.Code, w.Header().Get("x-amz-version-id"))
	}

	w = httptest.NewRecorder()
	h.listObjectVersions(w, httptest.NewRequest("GET", "/data?versions", nil), s3op{kind: "list-object-versions", bucket: "data"}, "r3")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<ListVersionsResult") || !strings.Contains(w.Body.String(), "<VersionId>v1</VersionId>") {
		t.Fatalf("ListObjectVersions = %d %s", w.Code, w.Body)
	}

	// a bucket whose versioning was never set: an empty document (no Status), as AWS returns
	f.buckets["plain"] = true
	w = httptest.NewRecorder()
	h.getBucketVersioning(w, httptest.NewRequest("GET", "/plain?versioning", nil), s3op{kind: "get-bucket-versioning", bucket: "plain"}, "r4")
	if w.Code != 200 || strings.Contains(w.Body.String(), "<Status>") {
		t.Fatalf("GetBucketVersioning (never set) = %d %s", w.Code, w.Body)
	}
}

func TestS3BucketTagging_RoundTrips(t *testing.T) {
	f := newFakeS3()
	f.buckets["data"] = true
	h := &s3Handler{mc: fakeMinio(t, f), logger: discardLogger()}

	w := httptest.NewRecorder()
	h.getBucketTagging(w, httptest.NewRequest("GET", "/data?tagging", nil), s3op{kind: "get-bucket-tagging", bucket: "data"}, "r")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "NoSuchTagSet") {
		t.Fatalf("GetBucketTagging (none) = %d %s, want 404 NoSuchTagSet", w.Code, w.Body)
	}
	body := `<Tagging><TagSet><Tag><Key>env</Key><Value>dev</Value></Tag><Tag><Key>team</Key><Value>a</Value></Tag></TagSet></Tagging>`
	w = httptest.NewRecorder()
	h.putBucketTagging(w, httptest.NewRequest("PUT", "/data?tagging", strings.NewReader(body)), s3op{kind: "put-bucket-tagging", bucket: "data", write: true}, "r")
	if w.Code != 204 {
		t.Fatalf("PutBucketTagging = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.getBucketTagging(w, httptest.NewRequest("GET", "/data?tagging", nil), s3op{kind: "get-bucket-tagging", bucket: "data"}, "r")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<Key>env</Key><Value>dev</Value>") || !strings.Contains(w.Body.String(), "<Key>team</Key><Value>a</Value>") {
		t.Fatalf("GetBucketTagging = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.deleteBucketTagging(w, httptest.NewRequest("DELETE", "/data?tagging", nil), s3op{kind: "delete-bucket-tagging", bucket: "data", write: true}, "r")
	if w.Code != 204 {
		t.Fatalf("DeleteBucketTagging = %d", w.Code)
	}
}

var (
	xbucketListGVR = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "xbuckets"}
	bucketListGVR  = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "buckets"}
)

func deleteBucketFixture(t *testing.T) (*s3Handler, *fakeS3, dynamic.Interface) {
	t.Helper()
	xr := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "XBucket",
		"metadata": map[string]any{"name": "data-x1", "labels": map[string]any{
			"crossplane.io/claim-namespace": "open-infra-cfn", "crossplane.io/claim-name": "stack-data"}},
		"status": map[string]any{"bucket": "stack-data"},
	}}
	claim := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Bucket",
		"metadata": map[string]any{"name": "stack-data", "namespace": "open-infra-cfn"},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{xbucketListGVR: "XBucketList", bucketListGVR: "BucketList"}, xr, claim)
	f := newFakeS3()
	h := &s3Handler{mc: fakeMinio(t, f), logger: discardLogger(), dyn: dyn,
		callerDyn: func(string, []string) (dynamic.Interface, error) { return dyn, nil }}
	return h, f, dyn
}

func callerClaims() iam.Claims {
	return iam.Claims{Sub: "alice", Groups: []string{"openinfra:powerusers"}}
}

func TestS3DeleteBucket_EmptyBucketDeletesItsClaimAndTheBucket(t *testing.T) {
	h, f, dyn := deleteBucketFixture(t)
	f.buckets["stack-data"] = true
	w := httptest.NewRecorder()
	h.deleteBucket(w, httptest.NewRequest("DELETE", "/stack-data", nil), callerClaims(), s3op{kind: "delete-bucket", bucket: "stack-data", write: true}, "r")
	if w.Code != 204 {
		t.Fatalf("DeleteBucket = %d %s, want 204", w.Code, w.Body)
	}
	if _, err := dyn.Resource(bucketListGVR).Namespace("open-infra-cfn").Get(context.Background(), "stack-data", metav1.GetOptions{}); err == nil {
		t.Error("the kind: Bucket claim still exists after DeleteBucket")
	}
	if len(f.removed) != 1 || f.removed[0] != "stack-data" {
		t.Errorf("MinIO bucket not removed: %v", f.removed)
	}
}

func TestS3DeleteBucket_NotEmptyIsRefusedAndKeepsTheClaim(t *testing.T) {
	h, f, dyn := deleteBucketFixture(t)
	f.buckets["stack-data"] = true
	f.objects["stack-data"] = []fakeVersion{{key: "k"}}
	w := httptest.NewRecorder()
	h.deleteBucket(w, httptest.NewRequest("DELETE", "/stack-data", nil), callerClaims(), s3op{kind: "delete-bucket", bucket: "stack-data", write: true}, "r")
	if w.Code != 409 || !strings.Contains(w.Body.String(), "BucketNotEmpty") {
		t.Fatalf("DeleteBucket (not empty) = %d %s, want 409 BucketNotEmpty", w.Code, w.Body)
	}
	if _, err := dyn.Resource(bucketListGVR).Namespace("open-infra-cfn").Get(context.Background(), "stack-data", metav1.GetOptions{}); err != nil {
		t.Errorf("the claim was deleted although the bucket is not empty: %v", err)
	}
}

func TestS3DeleteBucket_RefusesPlatformAndUnmanagedBuckets(t *testing.T) {
	h, f, _ := deleteBucketFixture(t)
	f.buckets["velero"] = true
	f.buckets["someone-elses"] = true // no kind: Bucket is this bucket
	for _, b := range []string{"velero", "someone-elses"} {
		w := httptest.NewRecorder()
		h.deleteBucket(w, httptest.NewRequest("DELETE", "/"+b, nil), callerClaims(), s3op{kind: "delete-bucket", bucket: b, write: true}, "r")
		if w.Code != 403 {
			t.Errorf("DeleteBucket %s = %d %s, want 403", b, w.Code, w.Body)
		}
	}
	if len(f.removed) != 0 {
		t.Errorf("buckets removed: %v", f.removed)
	}
	w := httptest.NewRecorder()
	h.deleteBucket(w, httptest.NewRequest("DELETE", "/nope", nil), callerClaims(), s3op{kind: "delete-bucket", bucket: "nope", write: true}, "r")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "NoSuchBucket") {
		t.Errorf("DeleteBucket of a missing bucket = %d %s, want 404 NoSuchBucket", w.Code, w.Body)
	}
}

// The S3 front door's platform-bucket list is the ownership script's.
func TestPlatformBucketsMatchOwnership(t *testing.T) {
	b, err := os.ReadFile("../../../platform/abstraction/provider-setup.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`PLATFORM_BUCKETS="([^"]*)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("PLATFORM_BUCKETS not found in provider-setup.yaml")
	}
	want := strings.Fields(string(m[1]))
	got := append([]string(nil), platformBuckets...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("platformBuckets = %v; provider-setup.yaml PLATFORM_BUCKETS = %v", got, want)
	}
}

// GetBucketEncryption answers the bucket's default encryption in S3's document, and a bucket with none
// answers ServerSideEncryptionConfigurationNotFoundError (404), the code SDKs key on.
func TestS3GetBucketEncryption(t *testing.T) {
	f := newFakeS3()
	f.buckets["enc"], f.buckets["plain"] = true, true
	f.encryption["enc"] = "AES256"
	h := &s3Handler{mc: fakeMinio(t, f), logger: discardLogger()}
	if op, ok := decodeTarget(http.MethodGet, "enc", "", url.Values{"encryption": {""}}); !ok || op.kind != "get-bucket-encryption" || op.action() != "s3:GetEncryptionConfiguration" {
		t.Fatalf("GET ?encryption decodes to %+v %v", op, ok)
	}
	w := httptest.NewRecorder()
	h.getBucketEncryption(w, httptest.NewRequest("GET", "/enc?encryption", nil), s3op{kind: "get-bucket-encryption", bucket: "enc"}, "r")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>") {
		t.Fatalf("GetBucketEncryption = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.getBucketEncryption(w, httptest.NewRequest("GET", "/plain?encryption", nil), s3op{kind: "get-bucket-encryption", bucket: "plain"}, "r")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "ServerSideEncryptionConfigurationNotFoundError") {
		t.Fatalf("GetBucketEncryption (none) = %d %s", w.Code, w.Body)
	}
}

// ListBuckets never sends the zero time: a bucket with no recorded creation time reports the epoch, so
// the AWS CLI's `aws s3 ls` (which fails the whole listing on year 0001) still lists every bucket.
func TestBucketCreationDate_NeverZero(t *testing.T) {
	if got := bucketCreationDate(time.Time{}); got != "1970-01-01T00:00:00.000Z" {
		t.Fatalf("zero time -> %q", got)
	}
	when := time.Date(2026, 11, 2, 1, 2, 3, 4e6, time.UTC)
	if got := bucketCreationDate(when); got != "2026-11-02T01:02:03.004Z" {
		t.Fatalf("a real time -> %q", got)
	}
}
