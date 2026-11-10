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
	"sort"
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

// testRevision is one of function fn's Knative revisions in namespace team, rendered with these OPENINFRA_*
// values: what a pod of that revision is served.
func testRevision(name, fn string, env map[string]string) *unstructured.Unstructured {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ev := []any{map[string]any{"name": "OPENINFRA_RUNTIME", "value": "nodejs22"}}
	for _, k := range keys {
		ev = append(ev, map[string]any{"name": k, "value": env[k]})
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "serving.knative.dev/v1", "kind": "Revision",
		"metadata": map[string]any{"name": name, "namespace": "team", "labels": map[string]any{knativeServiceLabel: fn}},
		"spec":     map[string]any{"containers": []any{map[string]any{"name": "user-container", "env": ev}}}}}
}

func revisionsClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{knativeRevisionGVR: "RevisionList"}, objs...)
}

func fnCodeFixture(t *testing.T) (*functionCodeHandler, []byte, []byte) {
	t.Helper()
	a := testZip(t, map[string]string{"index.js": "a"})
	b := testZip(t, map[string]string{"index.js": "b"})
	f := newBlobS3()
	f.buckets[lambdaCodeBucket] = true
	f.objects[lambdaCodeBucket+"/team/"+shaOf(a)+".zip"] = a
	f.objects[lambdaCodeBucket+"/team/"+shaOf(b)+".zip"] = b
	dyn := revisionsClient(
		testRevision("fa-00001", "fa", map[string]string{"OPENINFRA_CODE_SHA256": shaOf(a)}),
		testRevision("fb-00001", "fb", map[string]string{"OPENINFRA_CODE_SHA256": shaOf(b)}),
		testRevision("plain-00001", "plain", map[string]string{"OPENINFRA_CODE_CONFIGMAP": "plain-code"}))
	h := &functionCodeHandler{
		identities: fakeFnIdentities{
			"tok-a":       {namespace: "team", name: "fa", revision: "fa-00001"},
			"tok-b":       {namespace: "team", name: "fb", revision: "fb-00001"},
			"tok-plain":   {namespace: "team", name: "plain", revision: "plain-00001"},
			"tok-susp":    {namespace: "team", name: "fa", revision: "fa-00001", suspended: true},
			"tok-norev":   {namespace: "team", name: "fa"},
			"tok-gone":    {namespace: "team", name: "fa", revision: "fa-00009"},
			"tok-another": {namespace: "team", name: "fa", revision: "fb-00001"},
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
		"no token":                    {"", nil, http.StatusUnauthorized},
		"not a function's":            {"tok-other", nil, http.StatusUnauthorized},
		"no stored package":           {"tok-plain", nil, http.StatusNotFound},
		"suspended account":           {"tok-susp", nil, http.StatusForbidden},
		"no revision":                 {"tok-norev", nil, http.StatusUnauthorized},
		"a revision gone":             {"tok-gone", nil, http.StatusNotFound},
		"another function's revision": {"tok-another", nil, http.StatusUnauthorized},
		"through a proxy":             {"tok-a", []string{"X-Forwarded-For", "203.0.113.9"}, http.StatusNotFound},
	} {
		if rr := getFnCode(h, c.token, c.hdr...); rr.Code != c.want || bytes.Equal(rr.Body.Bytes(), a) {
			t.Errorf("%s: got %d, want %d with no package", name, rr.Code, c.want)
		}
	}
}

// fakeLayers refuses the buckets it names, as an account check would.
type fakeLayers map[string]bool

func (f fakeLayers) layerReadDenied(_ context.Context, _, bucket, _ string) (bool, string) {
	if f[bucket] {
		return true, "not this account's"
	}
	return false, ""
}

// A function's pod gets the layers its own revision declares, by index, each only when its account may
// read it; an undeclared index, another function's layers and a refused object are not served (#418).
func TestFunctionCode_OnlyTheFunctionsOwnLayers(t *testing.T) {
	deps := testZip(t, map[string]string{"nodejs/node_modules/dep/index.js": "module.exports = 1;"})
	f := newBlobS3()
	f.buckets["team-layers"], f.buckets["other-account"] = true, true
	f.objects["team-layers/deps.zip"] = deps
	f.objects["other-account/secret.zip"] = []byte("not yours")
	layers := `[{"bucket":"team-layers","key":"deps.zip"},{"bucket":"other-account","key":"secret.zip"}]`
	dyn := revisionsClient(
		testRevision("fl-00001", "fl", map[string]string{"OPENINFRA_CODE_SHA256": strings.Repeat("a", 64), "OPENINFRA_LAYERS": layers}),
		testRevision("plain-00001", "plain", map[string]string{"OPENINFRA_CODE_SHA256": strings.Repeat("a", 64)}),
		testRevision("bad-00001", "bad", map[string]string{"OPENINFRA_LAYERS": "not json"}))
	h := &functionCodeHandler{
		identities: fakeFnIdentities{"tok-l": {namespace: "team", name: "fl", revision: "fl-00001"},
			"tok-plain": {namespace: "team", name: "plain", revision: "plain-00001"},
			"tok-bad":   {namespace: "team", name: "bad", revision: "bad-00001"}},
		dyn: dyn, store: &packageStore{mc: blobMinio(t, f)}, layers: fakeLayers{"other-account": true}, logger: discardLogger(),
	}
	get := func(token, layer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, functionCodePath+"?layer="+layer, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		h.serve(rr, req, "req")
		return rr
	}
	if rr := get("tok-l", "0"); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), deps) {
		t.Fatalf("the function's own layer 0: %d", rr.Code)
	}
	for name, c := range map[string]struct {
		token, layer string
		want         int
	}{
		"an object its account may not read": {"tok-l", "1", http.StatusForbidden},
		"an index it does not declare":       {"tok-l", "2", http.StatusNotFound},
		"not an index":                       {"tok-l", "x", http.StatusNotFound},
		"a function with no layers":          {"tok-plain", "0", http.StatusNotFound},
		"layers that do not parse":           {"tok-bad", "0", http.StatusNotFound},
	} {
		if rr := get(c.token, c.layer); rr.Code != c.want || strings.Contains(rr.Body.String(), "not yours") {
			t.Errorf("%s: %d, want %d with no object", name, rr.Code, c.want)
		}
	}
	h.layers = nil
	if rr := get("tok-l", "0"); rr.Code != http.StatusNotFound {
		t.Errorf("a shim that does not serve layers: %d", rr.Code)
	}
}

// Each revision keeps the code and layers it was rendered with, as each Lambda version keeps its own: once
// the function's latest configuration names other code and another layer, a pod of an earlier revision (a
// published version, or the configuration a failed update left running) still gets its own (#418).
func TestFunctionCode_EachRevisionKeepsItsOwnCodeAndLayers(t *testing.T) {
	v1 := testZip(t, map[string]string{"index.js": "v1"})
	v2 := testZip(t, map[string]string{"index.js": "v2"})
	l1 := testZip(t, map[string]string{"nodejs/node_modules/dep/index.js": "module.exports = 1;"})
	l2 := testZip(t, map[string]string{"nodejs/node_modules/dep/index.js": "module.exports = 2;"})
	f := newBlobS3()
	f.buckets[lambdaCodeBucket], f.buckets["team-layers"] = true, true
	f.objects[lambdaCodeBucket+"/team/"+shaOf(v1)+".zip"] = v1
	f.objects[lambdaCodeBucket+"/team/"+shaOf(v2)+".zip"] = v2
	f.objects["team-layers/l1.zip"], f.objects["team-layers/l2.zip"] = l1, l2
	dyn := revisionsClient(
		testRevision("fn-00001", "fn", map[string]string{"OPENINFRA_CODE_SHA256": shaOf(v1),
			"OPENINFRA_LAYERS": `[{"bucket":"team-layers","key":"l1.zip"}]`}),
		testRevision("fn-00002", "fn", map[string]string{"OPENINFRA_CODE_SHA256": shaOf(v2),
			"OPENINFRA_LAYERS": `[{"bucket":"team-layers","key":"l2.zip"}]`}))
	h := &functionCodeHandler{
		identities: fakeFnIdentities{"tok-1": {namespace: "team", name: "fn", revision: "fn-00001"},
			"tok-2": {namespace: "team", name: "fn", revision: "fn-00002"}},
		dyn: dyn, store: &packageStore{mc: blobMinio(t, f)}, layers: fakeLayers{}, logger: discardLogger(),
	}
	get := func(token, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, functionCodePath+query, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		h.serve(rr, req, "req")
		return rr
	}
	for token, want := range map[string]struct{ code, layer []byte }{"tok-1": {v1, l1}, "tok-2": {v2, l2}} {
		if rr := get(token, ""); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), want.code) {
			t.Errorf("%s: the revision's own package: %d", token, rr.Code)
		}
		if rr := get(token, "?layer=0"); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), want.layer) {
			t.Errorf("%s: the revision's own layer: %d", token, rr.Code)
		}
	}
}

// A layer is read as the function's account would read it: its own account's bucket, not another's that no
// bucket policy opens to it, and never a platform bucket (#418).
func TestLayerReadDenied_IsTheFunctionsAccounts(t *testing.T) {
	s3h, _, _ := s3AccountsFixture(t)
	ctx := context.Background()
	for _, c := range []struct {
		account, bucket string
		denied          bool
	}{
		{testMember, "team-data", false}, {testMember, "mgmt-data", true},
		{"", "mgmt-data", false}, {"", "team-data", true},
		{"", lambdaCodeBucket, true}, {testMember, lambdaCodeBucket, true}, {testMember, "", true},
	} {
		if denied, why := s3h.layerReadDenied(ctx, c.account, c.bucket, "layer.zip"); denied != c.denied {
			t.Errorf("account %q, bucket %q: denied=%v (%s), want %v", c.account, c.bucket, denied, why, c.denied)
		}
	}
}
