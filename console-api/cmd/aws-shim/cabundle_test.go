package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// testCert returns a self-signed certificate PEM (a CA when isCA) and its private key PEM.
func testCert(t *testing.T, cn string, isCA bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

type fakeCASource struct {
	data  []byte
	err   error
	calls int
}

func (f *fakeCASource) get(context.Context) ([]byte, error) {
	f.calls++
	return f.data, f.err
}

func testCABundle(src *fakeCASource, now *time.Time) *caBundleHandler {
	return &caBundleHandler{source: src.get, ttl: 5 * time.Minute, now: func() time.Time { return *now },
		logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func getCABundle(h *caBundleHandler, method string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.serve(w, httptest.NewRequest(method, caBundlePath, nil), "req")
	return w
}

// The endpoint matches ONLY an unsigned GET/HEAD of its exact path, so it can never shadow an AWS call:
// every AWS request is SigV4-signed (header or presigned query), and a signed request — e.g. an S3
// GetObject of key "v1/ca-bundle" in a virtual-hosted bucket — must reach its service.
func TestCABundle_PathMatchNeverShadowsAWS(t *testing.T) {
	h := &caBundleHandler{}
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if !h.isCABundleRequest(httptest.NewRequest(m, caBundlePath, nil)) {
			t.Errorf("unsigned %s %s must match", m, caBundlePath)
		}
	}
	for _, p := range []string{"/", "/mybucket/key", "/v1/vm-credentials", "/v1/ca-bundle/extra", "/v1/ca-bundlex", "/latest/meta-data/"} {
		if h.isCABundleRequest(httptest.NewRequest(http.MethodGet, p, nil)) {
			t.Errorf("%q must not match the CA bundle path", p)
		}
	}
	if h.isCABundleRequest(httptest.NewRequest(http.MethodPut, caBundlePath, nil)) {
		t.Error("a PUT (e.g. an S3 PutObject) must not match")
	}
	signed := httptest.NewRequest(http.MethodGet, caBundlePath, nil)
	signed.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261031/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc")
	if h.isCABundleRequest(signed) {
		t.Error("a SigV4 header-signed request must fall through to its AWS service")
	}
	presigned := httptest.NewRequest(http.MethodGet, caBundlePath+"?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID%2F20261031%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=abc", nil)
	if h.isCABundleRequest(presigned) {
		t.Error("a presigned (query-signed) request must fall through to its AWS service")
	}
}

// At the router: an unsigned GET is answered with the bundle, a signed GET of the same path is not.
func TestCABundle_RouterDispatch(t *testing.T) {
	ca, _ := testCert(t, "root", true)
	now := time.Now()
	rt := &serviceRouter{caBundle: testCABundle(&fakeCASource{data: ca}, &now), services: map[string]awsService{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, httptest.NewRequest(http.MethodGet, caBundlePath, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("unsigned GET must serve the bundle: %d %q", w.Code, w.Body.String())
	}
	signed := httptest.NewRequest(http.MethodGet, caBundlePath, nil)
	signed.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261031/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc")
	w = httptest.NewRecorder()
	rt.ServeHTTP(w, signed)
	if strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("a signed request must not be answered by the CA bundle endpoint (got %d)", w.Code)
	}
}

func TestCABundle_ServesAndCaches(t *testing.T) {
	ca, _ := testCert(t, "root", true)
	src := &fakeCASource{data: ca}
	now := time.Now()
	h := testCABundle(src, &now)
	w := getCABundle(h, http.MethodGet)
	if w.Code != http.StatusOK || w.Body.String() != string(ca) {
		t.Fatalf("want the CA PEM, got %d %q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type = %q", ct)
	}
	getCABundle(h, http.MethodGet)
	if src.calls != 1 {
		t.Fatalf("a second request within the TTL must be served from cache (source calls = %d)", src.calls)
	}
	now = now.Add(6 * time.Minute)
	getCABundle(h, http.MethodGet)
	if src.calls != 2 {
		t.Fatalf("after the TTL the bundle is re-read (source calls = %d)", src.calls)
	}
	if w := getCABundle(h, http.MethodHead); w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "" {
		t.Errorf("HEAD = %d, body %d bytes, Content-Length %q", w.Code, w.Body.Len(), w.Header().Get("Content-Length"))
	}
}

// Honest absence: no published CA = 404; unreadable with nothing cached = 503 (+ Retry-After); a read
// error after a good read keeps serving the last good bundle.
func TestCABundle_AbsentAndUnavailable(t *testing.T) {
	now := time.Now()
	if w := getCABundle(testCABundle(&fakeCASource{err: errCABundleAbsent}, &now), http.MethodGet); w.Code != http.StatusNotFound {
		t.Errorf("unpublished CA must be 404, got %d", w.Code)
	}
	src := &fakeCASource{err: errors.New("apiserver unavailable")}
	h := testCABundle(src, &now)
	w := getCABundle(h, http.MethodGet)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Errorf("unreadable with no cache must be 503 + Retry-After, got %d", w.Code)
	}
	ca, _ := testCert(t, "root", true)
	src.data, src.err = ca, nil
	if w := getCABundle(h, http.MethodGet); w.Code != http.StatusOK {
		t.Fatalf("a failed read is not cached — the next request re-reads (got %d)", w.Code)
	}
	src.err = errors.New("apiserver unavailable")
	now = now.Add(6 * time.Minute)
	if w := getCABundle(h, http.MethodGet); w.Code != http.StatusOK || w.Body.String() != string(ca) {
		t.Errorf("a read error must keep serving the last good bundle, got %d", w.Code)
	}
}

// Only CA certificates ever leave: a key in the source is dropped, a non-CA certificate or garbage
// refuses the bundle, duplicates collapse.
func TestCABundle_SanitizesSource(t *testing.T) {
	ca, key := testCert(t, "root", true)
	leaf, _ := testCert(t, "leaf", false)
	got, err := sanitizeCABundle(append(append(append([]byte{}, key...), ca...), ca...))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(ca) || strings.Contains(string(got), "PRIVATE KEY") {
		t.Fatalf("only the (deduplicated) CA certificate may be served, got:\n%s", got)
	}
	for name, raw := range map[string][]byte{
		"leaf":    leaf,
		"key":     key,
		"garbage": []byte("not a certificate"),
		"bad-der": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")}),
	} {
		if _, err := sanitizeCABundle(raw); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	now := time.Now()
	if w := getCABundle(testCABundle(&fakeCASource{data: leaf}, &now), http.MethodGet); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a non-CA certificate must never be served as the platform CA (got %d)", w.Code)
	}
}

// The Kubernetes source reads ca.crt from the named Secret; a missing Secret or key is "absent".
func TestCABundle_SecretSource(t *testing.T) {
	ca, _ := testCert(t, "root", true)
	cs := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "openinfra-ca-bundle", Namespace: "open-infra-aws-shim"},
		Data:       map[string][]byte{"ca.crt": ca, "tls.key": []byte("leaf key")},
	})
	h := newCABundleHandler(cs, "open-infra-aws-shim", "openinfra-ca-bundle", "ca.crt", nil)
	if b, err := h.source(context.Background()); err != nil || string(b) != string(ca) {
		t.Fatalf("source = %q, %v", b, err)
	}
	if _, err := newCABundleHandler(cs, "open-infra-aws-shim", "missing", "ca.crt", nil).source(context.Background()); !errors.Is(err, errCABundleAbsent) {
		t.Errorf("a missing Secret must be errCABundleAbsent, got %v", err)
	}
	if _, err := newCABundleHandler(cs, "open-infra-aws-shim", "openinfra-ca-bundle", "nokey", nil).source(context.Background()); !errors.Is(err, errCABundleAbsent) {
		t.Errorf("a missing key must be errCABundleAbsent, got %v", err)
	}
}
