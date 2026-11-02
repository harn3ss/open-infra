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
	label             string // which listener's certificate, for the log
	interval          time.Duration
	now               func() time.Time
	logger            *slog.Logger

	mu        sync.Mutex
	cert      *tls.Certificate
	stamp     string // modification times + sizes of the pair last loaded
	checkedAt time.Time
}

func newCertReloader(certFile, keyFile string, logger *slog.Logger) *certReloader {
	return &certReloader{certFile: certFile, keyFile: keyFile, label: "internal", interval: 10 * time.Second, now: time.Now, logger: logger}
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
					c.logger.Info(c.label+" TLS certificate loaded", slog.String("cert", c.certFile))
				}
			} else if c.logger != nil {
				c.logger.Warn(c.label+" TLS certificate did not load; serving the previous one", slog.String("error", err.Error()))
			}
		}
	}
	if c.cert == nil {
		return nil, errors.New("no " + c.label + " TLS certificate yet")
	}
	return c.cert, nil
}

const defaultAWSNamesTLSAddr = ":8443"

// newAWSNamesTLSServer is the listener for AWS's own hostnames, or nil when TLS_CERT_FILE / TLS_KEY_FILE
// are unset. A VM guest's resolver (platform/aws-shim/guest-aws-endpoints.yaml) answers the amazonaws.com
// names of the services this shim serves with its address; the Service maps 443 here. The certificate is
// the openinfra-aws-endpoints CA's — name-constrained to amazonaws.com and trusted by VM guests only, never
// by the LAN clients that trust the platform root — and is re-read on renewal like the internal one. A
// separate listener rather than a second certificate on the internal port: the metadata agent's port
// keeps exactly the certificate it verifies. The file may not exist yet (the Secret is optional): the
// shim starts, and handshakes fail until cert-manager issues it. Start it with ListenAndServeTLS("", "").
func newAWSNamesTLSServer(handler http.Handler, logger *slog.Logger) *http.Server {
	cert, key := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if cert == "" || key == "" {
		return nil
	}
	addr := os.Getenv("TLS_LISTEN_ADDR")
	if addr == "" {
		addr = defaultAWSNamesTLSAddr
	}
	rl := newCertReloader(cert, key, logger)
	rl.label = "AWS-names"
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: rl.GetCertificate},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
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
