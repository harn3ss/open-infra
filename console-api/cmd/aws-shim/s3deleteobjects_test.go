package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// fakeMultiDeleteS3 is a minimal S3 server for minio-go's BucketExists and multi-object delete: buckets
// of keys, a versioned bucket answering a versionless delete with a delete marker, and keys whose
// delete fails. It records the keys each multi-delete named.
type fakeMultiDeleteS3 struct {
	mu        sync.Mutex
	buckets   map[string]map[string]bool // bucket -> keys
	versioned map[string]bool
	failing   map[string]string // key -> the S3 error code its delete answers
	asked     []string          // "key" or "key?versionId", per multi-delete entry received
	markers   int
}

func newFakeMultiDeleteS3() *fakeMultiDeleteS3 {
	return &fakeMultiDeleteS3{buckets: map[string]map[string]bool{}, versioned: map[string]bool{}, failing: map[string]string{}}
}

func (f *fakeMultiDeleteS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	keys, ok := f.buckets[bucket]
	switch {
	case key == "" && r.Method == http.MethodHead:
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case key == "" && r.Method == http.MethodPost && r.URL.Query().Has("delete"):
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchBucket</Code><Message>no</Message></Error>`))
			return
		}
		var in struct {
			Objects []struct {
				Key       string
				VersionID string `xml:"VersionId"`
			} `xml:"Object"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = xml.Unmarshal(body, &in)
		var sb strings.Builder
		sb.WriteString(`<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
		for _, o := range in.Objects {
			if o.VersionID != "" {
				f.asked = append(f.asked, o.Key+"?"+o.VersionID)
			} else {
				f.asked = append(f.asked, o.Key)
			}
			if code := f.failing[o.Key]; code != "" {
				sb.WriteString(`<Error><Key>` + o.Key + `</Key><VersionId>` + o.VersionID + `</VersionId><Code>` + code + `</Code><Message>m</Message></Error>`)
				continue
			}
			delete(keys, o.Key)
			switch {
			case o.VersionID != "":
				sb.WriteString(`<Deleted><Key>` + o.Key + `</Key><VersionId>` + o.VersionID + `</VersionId></Deleted>`)
			case f.versioned[bucket]:
				f.markers++
				sb.WriteString(fmt.Sprintf(`<Deleted><Key>%s</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>dm-%d</DeleteMarkerVersionId></Deleted>`, o.Key, f.markers))
			default:
				sb.WriteString(`<Deleted><Key>` + o.Key + `</Key></Deleted>`)
			}
		}
		sb.WriteString(`</DeleteResult>`)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(sb.String()))
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func multiDeleteMinio(t *testing.T, f *fakeMultiDeleteS3) *s3Handler {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	mc, err := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4("a", "b", ""), Region: "us-east-1", BucketLookup: minio.BucketLookupPath})
	if err != nil {
		t.Fatal(err)
	}
	return &s3Handler{mc: mc, logger: discardLogger()}
}

// countingSAR is a clientset whose SubjectAccessReviews answer allowed, counting them.
func countingSAR(allowed bool, n *int32) *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(n, 1)
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allowed}}, nil
	})
	return cs
}

type delObj struct{ key, version string }

func deleteDoc(quiet bool, objs ...delObj) string {
	var sb strings.Builder
	sb.WriteString(`<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for _, o := range objs {
		sb.WriteString(`<Object><Key>` + o.key + `</Key>`)
		if o.version != "" {
			sb.WriteString(`<VersionId>` + o.version + `</VersionId>`)
		}
		sb.WriteString(`</Object>`)
	}
	if quiet {
		sb.WriteString(`<Quiet>true</Quiet>`)
	}
	sb.WriteString(`</Delete>`)
	return sb.String()
}

func md5b64(s string) string {
	sum := md5.Sum([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// serveDelete sends DeleteObjects through the front door's serve, as the router does, as a User ("user")
// or the test's assumed role ("role"). It sends the document's Content-MD5 unless hdr sets it ("" drops it).
func serveDelete(h *s3Handler, as, bucket, doc string, hdr map[string]string) (*httptest.ResponseRecorder, deleteResult) {
	r := httptest.NewRequest("POST", "/"+bucket+"?delete", strings.NewReader(doc))
	if _, set := hdr["Content-MD5"]; !set {
		r.Header.Set("Content-MD5", md5b64(doc))
	}
	for k, v := range hdr {
		if v == "" {
			r.Header.Del(k)
			continue
		}
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	if as == "role" {
		h.serve(w, r, ecrRoleClaims(), "req-1")
	} else {
		h.serve(w, r, callerClaims(), "req-1")
	}
	var res deleteResult
	_ = xml.Unmarshal(w.Body.Bytes(), &res)
	return w, res
}

func TestS3Decode_DeleteObjects(t *testing.T) {
	h := &s3Handler{vhostSuffixes: []string{"s3.example.com"}}
	r := httptest.NewRequest("POST", "https://s3.example.com/b?delete", nil)
	if op, ok := h.decode(r); !ok || op.kind != "delete-objects" || op.bucket != "b" || !op.write {
		t.Errorf("POST /b?delete = %+v ok=%v", op, ok)
	}
	r = httptest.NewRequest("POST", "https://b.s3.example.com/?delete=", nil)
	r.Host = "b.s3.example.com"
	if op, ok := h.decode(r); !ok || op.kind != "delete-objects" || op.bucket != "b" {
		t.Errorf("vhost POST /?delete = %+v ok=%v", op, ok)
	}
	// a POST ?delete on a key is not DeleteObjects
	if _, ok := h.decode(httptest.NewRequest("POST", "https://s3.example.com/b/k?delete", nil)); ok {
		t.Error("POST /b/k?delete decoded as an operation")
	}
}

// Every key is deleted and listed, a missing key counts as deleted (as on S3), a versionless delete in a
// versioned bucket reports its delete marker, a key whose delete fails is that key's error — and a User's
// authorization runs once for the batch's one action, not once per key.
func TestS3DeleteObjects_DeletesEachKeyAndReportsIt(t *testing.T) {
	f := newFakeMultiDeleteS3()
	f.buckets["data"] = map[string]bool{"a.txt": true, "dir/b.txt": true, "stuck": true}
	f.failing["stuck"] = "InternalError"
	h := multiDeleteMinio(t, f)
	var sars int32
	h.cs = countingSAR(true, &sars)

	w, res := serveDelete(h, "user", "data", deleteDoc(false, delObj{"a.txt", ""}, delObj{"dir/b.txt", ""}, delObj{"never-there", ""}, delObj{"stuck", ""}), nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`) {
		t.Fatalf("DeleteObjects = %d %s", w.Code, w.Body)
	}
	got := map[string]bool{}
	for _, d := range res.Deleted {
		got[d.Key] = true
	}
	if len(res.Deleted) != 3 || !got["a.txt"] || !got["dir/b.txt"] || !got["never-there"] {
		t.Errorf("Deleted = %+v, want a.txt, dir/b.txt and never-there", res.Deleted)
	}
	if len(res.Errors) != 1 || res.Errors[0].Key != "stuck" || res.Errors[0].Code != "InternalError" {
		t.Errorf("Errors = %+v, want stuck's InternalError", res.Errors)
	}
	if len(f.buckets["data"]) != 1 || !f.buckets["data"]["stuck"] {
		t.Errorf("left in the bucket: %v", f.buckets["data"])
	}
	if sars != 1 {
		t.Errorf("%d SubjectAccessReviews for one batch of one action, want 1", sars)
	}

	// A versioned bucket: a versionless delete leaves a delete marker, a version delete names its version.
	f.buckets["ver"] = map[string]bool{"k": true}
	f.versioned["ver"] = true
	_, res = serveDelete(h, "user", "ver", deleteDoc(false, delObj{"k", ""}, delObj{"k", "v1"}), nil)
	if len(res.Deleted) != 2 {
		t.Fatalf("versioned Deleted = %+v", res.Deleted)
	}
	for _, d := range res.Deleted {
		switch d.VersionID {
		case "":
			if !d.DeleteMarker || d.DeleteMarkerVersionID == "" {
				t.Errorf("a versionless delete in a versioned bucket = %+v, want its delete marker", d)
			}
		case "v1":
			if d.DeleteMarker {
				t.Errorf("a version delete = %+v, want no delete marker", d)
			}
		default:
			t.Errorf("unexpected Deleted %+v", d)
		}
	}
	if !strings.Contains(fmt.Sprint(f.asked), "k?v1") {
		t.Errorf("MinIO was not asked for the version: %v", f.asked)
	}
}

// Quiet mode lists only the errors.
func TestS3DeleteObjects_Quiet(t *testing.T) {
	f := newFakeMultiDeleteS3()
	f.buckets["data"] = map[string]bool{"a": true, "b": true, "bad": true}
	f.failing["bad"] = "AccessDenied"
	h := multiDeleteMinio(t, f)
	var sars int32
	h.cs = countingSAR(true, &sars)
	w, res := serveDelete(h, "user", "data", deleteDoc(true, delObj{"a", ""}, delObj{"b", ""}, delObj{"bad", ""}), nil)
	if w.Code != 200 || len(res.Deleted) != 0 || len(res.Errors) != 1 || res.Errors[0].Key != "bad" || res.Errors[0].Code != "AccessDenied" {
		t.Fatalf("quiet DeleteObjects = %d %s", w.Code, w.Body)
	}
	if len(f.buckets["data"]) != 1 {
		t.Errorf("quiet mode did not delete: %v", f.buckets["data"])
	}
	// All deleted: an empty result.
	f.buckets["data"]["c"] = true
	_, res = serveDelete(h, "user", "data", deleteDoc(true, delObj{"c", ""}), nil)
	if len(res.Deleted) != 0 || len(res.Errors) != 0 {
		t.Errorf("quiet, all deleted = %+v", res)
	}
}

// Each key is authorized as AWS does: an assumed role allowed s3:DeleteObject but not
// s3:DeleteObjectVersion deletes the plain key, and the versioned entry is that key's AccessDenied (with
// its version) — never sent to MinIO. A role with no grant at all gets a 200 with every key denied.
func TestS3DeleteObjects_AuthorizedPerKey(t *testing.T) {
	f := newFakeMultiDeleteS3()
	f.buckets["data"] = map[string]bool{"plain": true, "old": true}
	h := multiDeleteMinio(t, f)
	h.authz = roleChecker(dpAllow([]string{"s3:DeleteObject"}, "Bucket::data"))

	w, res := serveDelete(h, "role", "data", deleteDoc(false, delObj{"plain", ""}, delObj{"old", "v7"}), nil)
	if w.Code != 200 {
		t.Fatalf("DeleteObjects = %d %s", w.Code, w.Body)
	}
	if len(res.Deleted) != 1 || res.Deleted[0].Key != "plain" {
		t.Errorf("Deleted = %+v, want plain", res.Deleted)
	}
	if len(res.Errors) != 1 || res.Errors[0].Key != "old" || res.Errors[0].VersionID != "v7" || res.Errors[0].Code != "AccessDenied" || res.Errors[0].Message != "Access Denied" {
		t.Errorf("Errors = %+v, want old v7 AccessDenied", res.Errors)
	}
	if fmt.Sprint(f.asked) != "[plain]" {
		t.Errorf("MinIO was asked to delete %v, want only plain", f.asked)
	}

	// Another bucket: nothing allowed there.
	f.buckets["other"] = map[string]bool{"x": true, "y": true}
	f.asked = nil
	w, res = serveDelete(h, "role", "other", deleteDoc(false, delObj{"x", ""}, delObj{"y", ""}), nil)
	if w.Code != 200 || len(res.Deleted) != 0 || len(res.Errors) != 2 || res.Errors[0].Code != "AccessDenied" || res.Errors[1].Code != "AccessDenied" {
		t.Fatalf("DeleteObjects with no grant = %d %s, want 200 with two AccessDenied", w.Code, w.Body)
	}
	if len(f.asked) != 0 || len(f.buckets["other"]) != 2 {
		t.Errorf("a denied batch reached MinIO: asked %v, left %v", f.asked, f.buckets["other"])
	}

	// A User whose coarse grant does not allow deleting: every key is denied, one review for the batch.
	var sars int32
	h.cs = countingSAR(false, &sars)
	_, res = serveDelete(h, "user", "data", deleteDoc(false, delObj{"a", ""}, delObj{"b", ""}, delObj{"c", ""}), nil)
	if len(res.Errors) != 3 || len(res.Deleted) != 0 || sars != 1 {
		t.Errorf("a User without delete = %+v after %d reviews, want 3 AccessDenied after 1", res, sars)
	}
}

// The document is checked before anything is deleted: its digests, its shape, its size, and the bucket.
func TestS3DeleteObjects_RefusesABadRequest(t *testing.T) {
	f := newFakeMultiDeleteS3()
	f.buckets["data"] = map[string]bool{"k": true}
	h := multiDeleteMinio(t, f)
	var sars int32
	h.cs = countingSAR(true, &sars)
	doc := deleteDoc(false, delObj{"k", ""})
	crc := func(s string) string {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, crc32.ChecksumIEEE([]byte(s)))
		return base64.StdEncoding.EncodeToString(b)
	}

	many := make([]delObj, 1001)
	for i := range many {
		many[i] = delObj{"k" + strconv.Itoa(i), ""}
	}
	cases := []struct {
		name, bucket, doc string
		hdr               map[string]string
		status            int
		code              string
	}{
		{"a wrong Content-MD5", "data", doc, map[string]string{"Content-MD5": md5b64("something else")}, 400, "BadDigest"},
		{"a malformed Content-MD5", "data", doc, map[string]string{"Content-MD5": "not-base64!"}, 400, "InvalidDigest"},
		{"a wrong CRC32", "data", doc, map[string]string{"Content-MD5": "", "x-amz-checksum-crc32": crc("other")}, 400, "BadDigest"},
		{"a malformed CRC32", "data", doc, map[string]string{"Content-MD5": "", "x-amz-checksum-crc32": "AAAA"}, 400, "InvalidRequest"},
		{"unparsable XML", "data", "<Delete><Object>", nil, 400, "MalformedXML"},
		{"no objects", "data", deleteDoc(false), nil, 400, "MalformedXML"},
		{"more than 1000 objects", "data", deleteDoc(false, many...), nil, 400, "MalformedXML"},
		{"an empty key", "data", deleteDoc(false, delObj{"", ""}), nil, 400, "MalformedXML"},
		{"a missing bucket", "nope", doc, nil, 404, "NoSuchBucket"},
	}
	for _, c := range cases {
		w, _ := serveDelete(h, "user", c.bucket, c.doc, c.hdr)
		if w.Code != c.status || !strings.Contains(w.Body.String(), "<Code>"+c.code+"</Code>") {
			t.Errorf("%s = %d %s, want %d %s", c.name, w.Code, w.Body, c.status, c.code)
		}
	}
	if len(f.asked) != 0 || !f.buckets["data"]["k"] {
		t.Fatalf("a refused request deleted something: asked %v", f.asked)
	}

	// A correct CRC32 with no MD5 (the newer SDKs' default) is accepted, and so is no digest at all.
	w, res := serveDelete(h, "user", "data", doc, map[string]string{"Content-MD5": "", "x-amz-checksum-crc32": crc(doc)})
	if w.Code != 200 || len(res.Deleted) != 1 {
		t.Errorf("DeleteObjects with a correct CRC32 = %d %s", w.Code, w.Body)
	}
	w, _ = serveDelete(h, "user", "data", doc, map[string]string{"Content-MD5": ""})
	if w.Code != 200 {
		t.Errorf("DeleteObjects with no digest = %d %s", w.Code, w.Body)
	}
}

// An aws-chunked request body (a trailing checksum) is read without its framing.
func TestS3DeleteObjects_AwsChunked(t *testing.T) {
	f := newFakeMultiDeleteS3()
	f.buckets["data"] = map[string]bool{"k1": true, "k2": true}
	h := multiDeleteMinio(t, f)
	var sars int32
	h.cs = countingSAR(true, &sars)
	doc := deleteDoc(false, delObj{"k1", ""}, delObj{"k2", ""})
	r := httptest.NewRequest("POST", "/data?delete", strings.NewReader(string(awsChunked([]byte(doc), 16))))
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	r.Header.Set("Content-Encoding", "aws-chunked")
	w := httptest.NewRecorder()
	h.serve(w, r, callerClaims(), "req-1")
	var res deleteResult
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &res) != nil || len(res.Deleted) != 2 {
		t.Fatalf("aws-chunked DeleteObjects = %d %s", w.Code, w.Body)
	}
}
