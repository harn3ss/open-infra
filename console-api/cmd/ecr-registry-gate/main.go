// ecr-registry-gate fronts the ECR registry in its pod: it decides each Docker registry request as the ECR
// action AWS authorizes it as (internal/ecrgate) and forwards what passes to the registry on loopback.
//
// Configuration (environment):
//
//	LISTEN_ADDR    where clients connect (default :5000)
//	UPSTREAM       the registry behind the gate (default http://127.0.0.1:5001)
//	TLS_CERT_FILE  with TLS_KEY_FILE, serve TLS with this certificate; it is re-read when the file changes,
//	TLS_KEY_FILE   so a renewed certificate is served without a restart
//
// The gate holds no credential and needs no Kubernetes access: everything it decides on is in the signed
// registry token the client presents, which the registry itself verifies.
package main

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/ecrgate"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	listen := envOr("LISTEN_ADDR", ":5000")
	upstream, err := url.Parse(envOr("UPSTREAM", "http://127.0.0.1:5001"))
	if err != nil || upstream.Host == "" {
		logger.Error("UPSTREAM is not a URL", "upstream", os.Getenv("UPSTREAM"))
		os.Exit(2)
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           ecrgate.New(upstream),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No read or write timeout: a layer upload or download runs as long as it takes.
	}
	certFile, keyFile := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	logger.Info("ecr-registry-gate serving", "addr", listen, "upstream", upstream.String(), "tls", certFile != "")
	if certFile != "" {
		c := &reloadingCert{cert: certFile, key: keyFile}
		if _, err := c.get(nil); err != nil {
			logger.Error("could not load the TLS certificate", "err", err)
			os.Exit(2)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: c.get}
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// reloadingCert serves the certificate in cert/key, loading it again when either file changes.
type reloadingCert struct {
	cert, key string
	mu        sync.Mutex
	stamp     string
	loaded    *tls.Certificate
}

func (c *reloadingCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	stamp := fileStamp(c.cert) + "|" + fileStamp(c.key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded != nil && stamp == c.stamp {
		return c.loaded, nil
	}
	pair, err := tls.LoadX509KeyPair(c.cert, c.key)
	if err != nil {
		if c.loaded != nil {
			return c.loaded, nil // mid-renewal: keep serving the certificate we have
		}
		return nil, err
	}
	c.loaded, c.stamp = &pair, stamp
	return c.loaded, nil
}

func fileStamp(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fi.ModTime().UTC().Format(time.RFC3339Nano) + "/" + strconv.FormatInt(fi.Size(), 10)
}
