package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// blobS3 is a minimal S3 that keeps object bodies: buckets (HEAD/PUT) and objects (HEAD/GET/PUT, with an
// optional versionId), path-style.
type blobS3 struct {
	mu      sync.Mutex
	buckets map[string]bool
	objects map[string][]byte // "bucket/key[?v]" -> body
	puts    int
}

func newBlobS3() *blobS3 { return &blobS3{buckets: map[string]bool{}, objects: map[string][]byte{}} }

func (f *blobS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if _, ok := r.URL.Query()["location"]; ok {
		_, _ = w.Write([]byte(`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`))
		return
	}
	id := bucket + "/" + key
	if v := r.URL.Query().Get("versionId"); v != "" {
		id += "?" + v
	}
	switch {
	case key == "" && r.Method == http.MethodPut:
		f.buckets[bucket] = true
	case !f.buckets[bucket]:
		w.WriteHeader(http.StatusNotFound)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`))
		}
	case key == "" && r.Method == http.MethodHead:
	case r.Method == http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			b = decodeAWSChunked(b)
		}
		f.objects[id] = b
		f.puts++
		w.Header().Set("ETag", `"e"`)
	case r.Method == http.MethodHead || r.Method == http.MethodGet:
		b, ok := f.objects[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`))
			}
			return
		}
		w.Header().Set("ETag", `"e"`)
		w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 00:00:00 GMT")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

// decodeAWSChunked strips the aws-chunked framing (<hex size>;chunk-signature=…\r\n<data>\r\n …) minio-go
// uses to upload over plain HTTP.
func decodeAWSChunked(b []byte) []byte {
	var out []byte
	for len(b) > 0 {
		line, rest, ok := bytes.Cut(b, []byte("\r\n"))
		if !ok {
			break
		}
		sizeHex, _, _ := bytes.Cut(line, []byte(";"))
		n, err := strconv.ParseInt(string(sizeHex), 16, 64)
		if err != nil || n == 0 || int(n) > len(rest) {
			break
		}
		out = append(out, rest[:n]...)
		b = bytes.TrimPrefix(rest[n:], []byte("\r\n"))
	}
	return out
}

func blobMinio(t *testing.T, f *blobS3) *minio.Client {
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

func testZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, c)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func shaOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Inline code zips to the same bytes every time, so an unchanged stack stores and changes nothing.
func TestZipInline_SameCodeSameBytes(t *testing.T) {
	files := map[string]string{"index.js": "exports.handler = async () => 1;\n"}
	a, err := zipInline(files)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := zipInline(map[string]string{"index.js": "exports.handler = async () => 1;\n"})
	if !bytes.Equal(a, b) {
		t.Fatal("the same inline code must zip to the same bytes")
	}
	zr, err := zip.NewReader(bytes.NewReader(a), int64(len(a)))
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != "index.js" {
		t.Fatalf("the package must hold index.js: %v", err)
	}
	if c, _ := zipInline(map[string]string{"index.js": "exports.handler = async () => 2;\n"}); bytes.Equal(a, c) {
		t.Fatal("changed code must change the package")
	}
}

// A package that is not a zip, or that would unpack outside its directory, is refused.
func TestCheckPackage_Refusals(t *testing.T) {
	if err := checkPackage(testZip(t, map[string]string{"index.js": "x", "lib/a.js": "y"})); err != nil {
		t.Fatalf("a well-formed package: %v", err)
	}
	for name, body := range map[string][]byte{
		"not a zip":     []byte("hello"),
		"parent escape": testZip(t, map[string]string{"../evil.js": "x"}),
		"nested escape": testZip(t, map[string]string{"lib/../../evil.js": "x"}),
		"absolute":      testZip(t, map[string]string{"/etc/evil": "x"}),
	} {
		if err := checkPackage(body); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// The store keeps a package once under its namespace and SHA-256, making the bucket on first use.
func TestPackageStore_ContentAddressed(t *testing.T) {
	f := newBlobS3()
	s := &packageStore{mc: blobMinio(t, f)}
	body := testZip(t, map[string]string{"index.js": "x"})
	sp, err := s.put(context.Background(), "team-a", body)
	if err != nil {
		t.Fatal(err)
	}
	if sp.SHA256 != shaOf(body) || sp.Size != int64(len(body)) {
		t.Fatalf("stored package: %#v", sp)
	}
	if !f.buckets[lambdaCodeBucket] || !bytes.Equal(f.objects[lambdaCodeBucket+"/team-a/"+sp.SHA256+".zip"], body) {
		t.Fatalf("the package must be kept at %s/team-a/<sha>.zip", lambdaCodeBucket)
	}
	if _, err := s.put(context.Background(), "team-a", body); err != nil || f.puts != 1 {
		t.Fatalf("storing the same bytes again must be a no-op (puts=%d, %v)", f.puts, err)
	}
	if _, err := s.put(context.Background(), "team-a", []byte("not a zip")); err == nil {
		t.Fatal("a package that is not a zip must be refused")
	}
}

// An S3 package is read as the deploying caller may read it: a key the caller's policy grants is stored; one
// outside it is refused with Lambda's message, and nothing is stored; and the platform's own package bucket
// is no caller's to read, so another account's package cannot be copied through Code.S3Bucket.
func TestLambdaPackages_S3IsReadAsTheCaller(t *testing.T) {
	f := newBlobS3()
	f.buckets["deploy"], f.buckets[lambdaCodeBucket] = true, true
	good := testZip(t, map[string]string{"app.py": "def handler(e, c): return 1\n"})
	f.objects["deploy/pkg/hello.zip"] = good
	f.objects["deploy/secret/other.zip"] = good
	f.objects[lambdaCodeBucket+"/team-b/"+shaOf(good)+".zip"] = good
	store := &packageStore{mc: blobMinio(t, f)}
	h := &cfnDoorway{s3: allowAllSAR(), authz: roleChecker(dpAllow([]string{"s3:GetObject"}, "Bucket::deploy/pkg/*"))}
	p := &lambdaPackages{h: h, req: withCallerClaims(httptest.NewRequest(http.MethodPost, "/", nil), assumedApp), store: store}
	ctx := context.Background()

	sp, err := p.Store(ctx, "team-a", &cfn.CodePackage{S3Bucket: "deploy", S3Key: "pkg/hello.zip"})
	if err != nil || sp.SHA256 != shaOf(good) {
		t.Fatalf("a granted package must be stored: %v %#v", err, sp)
	}
	puts := f.puts
	_, err = p.Store(ctx, "team-a", &cfn.CodePackage{S3Bucket: "deploy", S3Key: "secret/other.zip"})
	var ue *cfn.UnauthorizedError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "Your access has been denied by S3") || !strings.Contains(err.Error(), "deploy/secret/other.zip") {
		t.Fatalf("a package outside the caller's grant must be refused as Lambda refuses it: %v", err)
	}
	if f.puts != puts {
		t.Fatal("a refused package must not be stored")
	}
	h.authz = userPolicy(dpAllow([]string{"s3:*"}, "*"))
	p.req = withCallerClaims(httptest.NewRequest(http.MethodPost, "/", nil), testUser)
	if _, err := p.Store(ctx, "team-a", &cfn.CodePackage{S3Bucket: lambdaCodeBucket, S3Key: "team-b/" + shaOf(good) + ".zip"}); !errors.As(err, &ue) {
		t.Fatalf("another account's stored package must not be readable through Code.S3Bucket: %v", err)
	}
	if _, err := p.Store(ctx, "team-a", &cfn.CodePackage{S3Bucket: "deploy", S3Key: "pkg/missing.zip"}); err == nil || !strings.Contains(err.Error(), "NoSuchKey") {
		t.Fatalf("a missing object must name NoSuchKey: %v", err)
	}
}

// fakeFnIdentities resolves tokens to functions.
type fakeFnIdentities map[string]functionIdentity

func (f fakeFnIdentities) functionOf(_ context.Context, token string) (functionIdentity, bool) {
	id, ok := f[token]
	return id, ok
}

func fnCodeFixture(t *testing.T) (*functionCodeHandler, []byte, []byte) {
	t.Helper()
	a := testZip(t, map[string]string{"index.js": "a"})
	b := testZip(t, map[string]string{"index.js": "b"})
	f := newBlobS3()
	f.buckets[lambdaCodeBucket] = true
	f.objects[lambdaCodeBucket+"/team/"+shaOf(a)+".zip"] = a
	f.objects[lambdaCodeBucket+"/team/"+shaOf(b)+".zip"] = b
	claim := func(name, sha string) *unstructured.Unstructured {
		src := map[string]any{"configMap": name + "-code"}
		if sha != "" {
			src = map[string]any{"package": map[string]any{"sha256": sha}}
		}
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Function",
			"metadata": map[string]any{"name": name, "namespace": "team"},
			"spec":     map[string]any{"code": map[string]any{"runtime": "nodejs22", "handler": "index.handler", "source": src}}}}
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{functionClaimGVR: "FunctionList"},
		claim("fa", shaOf(a)), claim("fb", shaOf(b)), claim("plain", ""))
	h := &functionCodeHandler{
		identities: fakeFnIdentities{
			"tok-a":     {namespace: "team", name: "fa"},
			"tok-b":     {namespace: "team", name: "fb"},
			"tok-plain": {namespace: "team", name: "plain"},
			"tok-susp":  {namespace: "team", name: "fa", suspended: true},
		},
		dyn: dyn, store: &packageStore{mc: blobMinio(t, f)}, logger: discardLogger(),
	}
	return h, a, b
}

func getFnCode(h *functionCodeHandler, token string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, functionCodePath, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rr := httptest.NewRecorder()
	h.serve(rr, req, "req")
	return rr
}

// A function's pod gets its own function's package and no other; anything else is refused.
func TestFunctionCode_OnlyTheFunctionsOwnPackage(t *testing.T) {
	h, a, b := fnCodeFixture(t)
	if rr := getFnCode(h, "tok-a"); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), a) || rr.Header().Get("X-Openinfra-Code-Sha256") != shaOf(a) {
		t.Fatalf("function fa's pod must get fa's package: %d", rr.Code)
	}
	if rr := getFnCode(h, "tok-b"); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), b) {
		t.Fatalf("function fb's pod must get fb's package, not fa's: %d", rr.Code)
	}
	for name, c := range map[string]struct {
		token string
		hdr   []string
		want  int
	}{
		"no token":          {"", nil, http.StatusUnauthorized},
		"not a function's":  {"tok-other", nil, http.StatusUnauthorized},
		"no stored package": {"tok-plain", nil, http.StatusNotFound},
		"suspended account": {"tok-susp", nil, http.StatusForbidden},
		"through a proxy":   {"tok-a", []string{"X-Forwarded-For", "203.0.113.9"}, http.StatusNotFound},
	} {
		if rr := getFnCode(h, c.token, c.hdr...); rr.Code != c.want || bytes.Equal(rr.Body.Bytes(), a) {
			t.Errorf("%s: got %d, want %d with no package", name, rr.Code, c.want)
		}
	}
}
