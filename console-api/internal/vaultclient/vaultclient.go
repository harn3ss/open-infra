// Package vaultclient builds the HTTP client the platform's programs use to reach its key service
// (OpenBao, and Vault before it).
//
// When VAULT_CACERT names a PEM file, its certificates are trusted in addition to the system roots, as
// the vault and bao command-line tools read the same variable. The file is read again whenever it
// changes, so a CA delivered through a ConfigMap and later rotated is picked up without a restart.
package vaultclient

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"sync"
	"time"
)

// HTTPClient returns a client with the given timeout that trusts VAULT_CACERT (see the package doc).
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &transport{path: os.Getenv("VAULT_CACERT")}}
}

// transport rebuilds its underlying transport when the CA file changes. With no VAULT_CACERT it is the
// standard transport.
type transport struct {
	path string

	mu   sync.Mutex
	mod  time.Time
	size int64
	rt   *http.Transport
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.current().RoundTrip(r)
}

func (t *transport) current() *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.path == "" {
		if t.rt == nil {
			t.rt = http.DefaultTransport.(*http.Transport).Clone()
		}
		return t.rt
	}
	st, err := os.Stat(t.path)
	if t.rt != nil && (err != nil || (st.ModTime().Equal(t.mod) && st.Size() == t.size)) {
		return t.rt // unchanged, or briefly absent while a ConfigMap update swaps it: keep the last trust
	}
	pool, perr := x509.SystemCertPool()
	if perr != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if err == nil {
		if pem, rerr := os.ReadFile(t.path); rerr == nil {
			pool.AppendCertsFromPEM(pem)
			t.mod, t.size = st.ModTime(), st.Size()
		}
	}
	rt := http.DefaultTransport.(*http.Transport).Clone()
	rt.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if t.rt != nil {
		t.rt.CloseIdleConnections()
	}
	t.rt = rt
	return rt
}
