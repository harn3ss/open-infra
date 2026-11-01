package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"sync"
	"time"
)

// The in-cluster TLS listener. A VM's metadata agent sends its ServiceAccount token to
// /v1/vm-credentials, so it calls this port over TLS and verifies the certificate against the platform
// root CA from the VM's own spec: the token is never in clear text, and never reaches a host that merely
// answers for the shim's name. The certificate (cert-manager, ClusterIssuer openinfra-ca) is mounted from
// a Secret and re-read when cert-manager renews it, so a renewal needs no restart.

const defaultInternalTLSAddr = ":4567"

// certReloader serves the certificate in certFile/keyFile, re-reading them when they change. It checks
// at most once per interval, and keeps serving the last good certificate if a new pair fails to load.
type certReloader struct {
	certFile, keyFile string
	interval          time.Duration
	now               func() time.Time
	logger            *slog.Logger

	mu        sync.Mutex
	cert      *tls.Certificate
	stamp     string // modification times + sizes of the pair last loaded
	checkedAt time.Time
}

func newCertReloader(certFile, keyFile string, logger *slog.Logger) *certReloader {
	return &certReloader{certFile: certFile, keyFile: keyFile, interval: 10 * time.Second, now: time.Now, logger: logger}
}

func fileStamp(p string) (string, error) {
	st, err := os.Stat(p) // follows the Secret volume's ..data symlink, so a renewal changes it
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%d", st.ModTime().UTC().Format(time.RFC3339Nano), st.Size()), nil
}

func (c *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.cert != nil && now.Sub(c.checkedAt) < c.interval {
		return c.cert, nil
	}
	c.checkedAt = now
	cs, cerr := fileStamp(c.certFile)
	ks, kerr := fileStamp(c.keyFile)
	if cerr == nil && kerr == nil {
		if stamp := cs + "|" + ks; stamp != c.stamp || c.cert == nil {
			pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
			if err == nil {
				c.cert, c.stamp = &pair, stamp
				if c.logger != nil {
					c.logger.Info("internal TLS certificate loaded", slog.String("cert", c.certFile))
				}
			} else if c.logger != nil {
				c.logger.Warn("internal TLS certificate did not load; serving the previous one", slog.String("error", err.Error()))
			}
		}
	}
	if c.cert == nil {
		return nil, errors.New("no internal TLS certificate yet")
	}
	return c.cert, nil
}

// newInternalTLSServer is the in-cluster TLS listener, or nil when INTERNAL_TLS_CERT_FILE /
// INTERNAL_TLS_KEY_FILE are unset. Start it with ListenAndServeTLS("", "").
func newInternalTLSServer(handler http.Handler, logger *slog.Logger) *http.Server {
	cert, key := os.Getenv("INTERNAL_TLS_CERT_FILE"), os.Getenv("INTERNAL_TLS_KEY_FILE")
	if cert == "" || key == "" {
		return nil
	}
	addr := os.Getenv("INTERNAL_TLS_LISTEN_ADDR")
	if addr == "" {
		addr = defaultInternalTLSAddr
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: newCertReloader(cert, key, logger).GetCertificate},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// plaintextVMCredsGuard answers 404 for the VM credentials endpoint on a plaintext connection, so a VM's
// token is never accepted in clear text. allow re-enables plaintext (VM_CREDS_ALLOW_PLAINTEXT=true) for a
// guest whose agent predates the TLS port.
func plaintextVMCredsGuard(next http.Handler, allow bool) http.Handler {
	if allow {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil && path.Clean("/"+r.URL.Path) == vmCredsPath {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
