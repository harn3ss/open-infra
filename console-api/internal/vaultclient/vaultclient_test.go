package vaultclient

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

// tlsServer starts a TLS test server with its own self-signed certificate (httptest's default
// certificate is shared by every test server, so it cannot stand for two different CAs).
func tlsServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(ok))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.StartTLS()
	return s
}

// caFile writes the server's (self-signed) certificate as a PEM file.
func caFile(t *testing.T, path string, s *httptest.Server) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func get(c *http.Client, url string) error {
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func TestTrustsVaultCACert(t *testing.T) {
	s := tlsServer(t)
	defer s.Close()
	path := filepath.Join(t.TempDir(), "ca.crt")
	caFile(t, path, s)

	t.Setenv("VAULT_CACERT", path)
	if err := get(HTTPClient(5*time.Second), s.URL); err != nil {
		t.Fatalf("with VAULT_CACERT naming the server's CA, the request failed: %v", err)
	}
	t.Setenv("VAULT_CACERT", "")
	if err := get(HTTPClient(5*time.Second), s.URL); err == nil {
		t.Fatal("without VAULT_CACERT, a certificate from an unknown CA was trusted")
	}
}

// A rotated CA (a new file at the same path) is trusted without a new client, and the old one is not.
func TestPicksUpARotatedCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.crt")
	a := tlsServer(t)
	defer a.Close()
	b := tlsServer(t)
	defer b.Close()
	caFile(t, path, a)
	t.Setenv("VAULT_CACERT", path)
	c := HTTPClient(5 * time.Second)
	if err := get(c, a.URL); err != nil {
		t.Fatalf("first CA: %v", err)
	}
	if err := get(c, b.URL); err == nil {
		t.Fatal("a server under another CA was trusted")
	}

	caFile(t, path, b)
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if err := get(c, b.URL); err != nil {
		t.Fatalf("after the CA file changed, the new CA was not trusted: %v", err)
	}
	if err := get(c, a.URL); err == nil {
		t.Fatal("after the CA file changed, the old CA was still trusted")
	}
}

// Plain http (today's Vault address) works whatever VAULT_CACERT says, including a missing file.
func TestPlainHTTPUnaffected(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(ok))
	defer s.Close()
	t.Setenv("VAULT_CACERT", filepath.Join(t.TempDir(), "missing.crt"))
	if err := get(HTTPClient(5*time.Second), s.URL); err != nil {
		t.Fatalf("plain http failed: %v", err)
	}
}
