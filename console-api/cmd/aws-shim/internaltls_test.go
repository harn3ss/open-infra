package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a fresh self-signed certificate for cn and its key to certFile/keyFile.
func writePair(t *testing.T, certFile, keyFile, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func servedCN(t *testing.T, c *certReloader) string {
	t.Helper()
	got, err := c.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

// A renewed certificate (cert-manager rewrites the Secret volume) is served without a restart; a broken
// pair keeps the previous certificate in service; and before any certificate exists, handshakes fail.
func TestCertReloader_ReloadsRenewalsAndKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	clock := time.Unix(1_000_000, 0)
	c := newCertReloader(certFile, keyFile, nil)
	c.now = func() time.Time { return clock }

	if _, err := c.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("no certificate files yet: GetCertificate must fail")
	}
	writePair(t, certFile, keyFile, "first.svc")
	clock = clock.Add(11 * time.Second)
	if cn := servedCN(t, c); cn != "first.svc" {
		t.Fatalf("served %q, want first.svc", cn)
	}

	writePair(t, certFile, keyFile, "renewed.svc")
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, future, future) // a distinct mtime even on a coarse-grained filesystem
	if cn := servedCN(t, c); cn != "first.svc" {
		t.Fatalf("within the check interval the cached certificate is served, got %q", cn)
	}
	clock = clock.Add(11 * time.Second)
	if cn := servedCN(t, c); cn != "renewed.svc" {
		t.Fatalf("after the interval the renewed certificate is served, got %q", cn)
	}

	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Minute)
	_ = os.Chtimes(certFile, later, later)
	clock = clock.Add(11 * time.Second)
	if cn := servedCN(t, c); cn != "renewed.svc" {
		t.Fatalf("a pair that fails to load keeps the last good certificate, got %q", cn)
	}
}

func TestNewInternalTLSServer_Config(t *testing.T) {
	t.Setenv("INTERNAL_TLS_CERT_FILE", "")
	t.Setenv("INTERNAL_TLS_KEY_FILE", "")
	if s := newInternalTLSServer(http.NotFoundHandler(), nil); s != nil {
		t.Fatal("unset cert/key: no internal TLS listener")
	}
	t.Setenv("INTERNAL_TLS_CERT_FILE", "/tls-internal/tls.crt")
	t.Setenv("INTERNAL_TLS_KEY_FILE", "/tls-internal/tls.key")
	t.Setenv("INTERNAL_TLS_LISTEN_ADDR", "")
	s := newInternalTLSServer(http.NotFoundHandler(), nil)
	if s == nil || s.Addr != ":4567" {
		t.Fatalf("default listener address must be :4567, got %+v", s)
	}
	if s.TLSConfig == nil || s.TLSConfig.GetCertificate == nil || s.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("listener must serve the reloaded certificate with TLS >= 1.2, got %+v", s.TLSConfig)
	}
}

// End to end: the listener serves the mounted certificate, a client that trusts it reaches the
// credentials path through the plaintext guard (the connection is TLS), and a plaintext request is refused.
func TestInternalTLSServer_ServesCredentialsOverTLSOnly(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, "aws-shim.open-infra-aws-shim.svc")
	t.Setenv("INTERNAL_TLS_CERT_FILE", certFile)
	t.Setenv("INTERNAL_TLS_KEY_FILE", keyFile)
	served := 0
	h := plaintextVMCredsGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served++ }), false)
	srv := newInternalTLSServer(h, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "aws-shim.open-infra-aws-shim.svc"}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/v1/vm-credentials")
	if err != nil {
		t.Fatalf("TLS request to the internal listener failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || served != 1 {
		t.Fatalf("over TLS the credentials path must be served, got %d (served=%d)", resp.StatusCode, served)
	}
	// A client that does not trust the certificate never completes the handshake.
	if _, err := (&http.Client{}).Get("https://" + ln.Addr().String() + "/v1/vm-credentials"); err == nil {
		t.Fatal("an untrusted certificate must fail verification")
	}
}

// The VM credentials endpoint is refused on plaintext connections (also via path variants that clean
// to it); TLS connections and every other path pass through; VM_CREDS_ALLOW_PLAINTEXT re-enables it.
func TestPlaintextVMCredsGuard(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	do := func(h http.Handler, target string, overTLS bool) (int, bool) {
		reached = false
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if overTLS {
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, reached
	}
	guarded := plaintextVMCredsGuard(next, false)
	for _, p := range []string{"/v1/vm-credentials", "//v1/vm-credentials", "/v1/./vm-credentials", "/v1/vm-credentials/"} {
		if code, ok := do(guarded, "http://shim"+p, false); ok || code != http.StatusNotFound {
			t.Errorf("plaintext %s must be refused with 404, got %d (reached=%v)", p, code, ok)
		}
	}
	if _, ok := do(guarded, "http://shim/v1/vm-credentials", true); !ok {
		t.Error("over TLS the credentials endpoint must be served")
	}
	for _, p := range []string{"/", "/v1/ca-bundle", "/healthz", "/bucket/v1/vm-credentials"} {
		if _, ok := do(guarded, "http://shim"+p, false); !ok {
			t.Errorf("plaintext %s is not the credentials endpoint and must pass", p)
		}
	}
	if _, ok := do(plaintextVMCredsGuard(next, true), "http://shim/v1/vm-credentials", false); !ok {
		t.Error("VM_CREDS_ALLOW_PLAINTEXT must re-enable the plaintext endpoint")
	}
}
