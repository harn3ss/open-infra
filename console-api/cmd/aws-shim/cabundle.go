package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The platform root CA bundle — the public certificate of the cluster's root CA (cert-manager
// ClusterIssuer openinfra-ca), served unauthenticated so a VM's metadata agent can add it to the
// guest's trust store at boot: the "platform CA is trusted by the instances it launches" model, as an
// enterprise CA is baked into an AMI. Then an unmodified guest (docker, curl, the SDKs) trusts the
// registry's and S3's TLS addresses, whose certificates openinfra-ca issues.
//
// It is a public certificate (no secret), so there is no authentication. Only CA certificates are ever
// served: the source bytes are parsed and re-encoded, every non-CERTIFICATE PEM block (e.g. a key) is
// dropped, and a certificate that is not a CA is refused.
//
// The shim never reads the root CA's own Secret (cert-manager/openinfra-root-ca), which holds the root's
// PRIVATE key. The certificate is published into the shim's namespace by a cert-manager Certificate
// issued by openinfra-ca (platform/aws-shim/aws-shim.yaml, openinfra-ca-bundle): cert-manager writes the
// issuing CA's certificate into that Secret's ca.crt. The shim already reads Secrets in its own
// namespace (Role aws-shim-keys), so no new grant is needed.
const caBundlePath = "/v1/ca-bundle"

// errCABundleAbsent: the platform publishes no root CA (the Secret or its key does not exist).
var errCABundleAbsent = errors.New("the platform root CA is not published")

type caBundleHandler struct {
	source func(ctx context.Context) ([]byte, error) // raw bundle bytes; errCABundleAbsent when unpublished
	ttl    time.Duration                             // how long a fetched bundle (or its absence) is served before re-reading
	now    func() time.Time
	logger *slog.Logger

	mu      sync.Mutex
	pem     []byte // last good, sanitized bundle
	absent  bool   // the last read found no published CA
	fetched time.Time
}

func newCABundleHandler(cs kubernetes.Interface, namespace, secret, key string, logger *slog.Logger) *caBundleHandler {
	return &caBundleHandler{
		source: func(ctx context.Context) ([]byte, error) {
			s, err := cs.CoreV1().Secrets(namespace).Get(ctx, secret, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return nil, errCABundleAbsent
			}
			if err != nil {
				return nil, err
			}
			if b := s.Data[key]; len(b) > 0 {
				return b, nil
			}
			return nil, errCABundleAbsent
		},
		ttl:    5 * time.Minute,
		now:    time.Now,
		logger: logger,
	}
}

// isCABundleRequest matches ONLY an unsigned GET/HEAD of exactly caBundlePath. Every AWS API call is
// SigV4-signed (an Authorization header or a presigned query), so a signed request — e.g. an S3
// GetObject of key "v1/ca-bundle" in a virtual-hosted bucket — always falls through to its service.
// (Path-style, "/v1/…" can't be an S3 bucket: bucket names are at least 3 characters.)
func (h *caBundleHandler) isCABundleRequest(r *http.Request) bool {
	if r.URL.Path != caBundlePath || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	if r.Header.Get("Authorization") != "" {
		return false
	}
	q := r.URL.Query()
	return q.Get("X-Amz-Credential") == "" && q.Get("X-Amz-Signature") == ""
}

// current returns the bundle to serve and the status: 200 with the bundle, 404 when the platform
// publishes no CA, 503 when it could not be read and no good copy is cached. A read error keeps
// serving the last good bundle.
func (h *caBundleHandler) current(ctx context.Context) ([]byte, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if !h.fetched.IsZero() && now.Sub(h.fetched) < h.ttl {
		return h.cached()
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := h.source(rctx)
	switch {
	case errors.Is(err, errCABundleAbsent):
		h.pem, h.absent, h.fetched = nil, true, now
	case err != nil:
		h.warn("could not read the platform CA bundle", err)
		if h.pem != nil {
			return h.pem, http.StatusOK // keep serving the last good copy; re-read on the next request
		}
		return nil, http.StatusServiceUnavailable
	default:
		clean, serr := sanitizeCABundle(raw)
		if serr != nil {
			h.warn("refusing the published platform CA bundle", serr)
			if h.pem != nil {
				return h.pem, http.StatusOK // the last good copy; re-read on the next request
			}
			return nil, http.StatusServiceUnavailable
		}
		h.pem, h.absent, h.fetched = clean, false, now
	}
	return h.cached()
}

func (h *caBundleHandler) cached() ([]byte, int) {
	switch {
	case h.pem != nil:
		return h.pem, http.StatusOK
	case h.absent:
		return nil, http.StatusNotFound
	}
	return nil, http.StatusServiceUnavailable
}

func (h *caBundleHandler) warn(msg string, err error) {
	if h.logger != nil {
		h.logger.Warn(msg, slog.String("error", err.Error()))
	}
}

func (h *caBundleHandler) serve(w http.ResponseWriter, r *http.Request, requestID string) {
	b, status := h.current(r.Context())
	w.Header().Set("X-Amz-Request-Id", requestID)
	switch status {
	case http.StatusOK:
		sum := sha256.Sum256(b)
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(b)
		}
	case http.StatusNotFound:
		http.Error(w, "this platform publishes no root CA", http.StatusNotFound)
	default:
		w.Header().Set("Retry-After", "30")
		http.Error(w, "the platform root CA bundle is not available yet", http.StatusServiceUnavailable)
	}
}

// sanitizeCABundle keeps only the CA certificates in raw, re-encoded as plain PEM CERTIFICATE blocks
// (headers dropped, duplicates removed). Any other block type — notably a private key — is discarded,
// never served. A certificate that does not parse, or is not a CA (basicConstraints CA:TRUE), refuses
// the whole bundle.
func sanitizeCABundle(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	seen := map[[32]byte]bool{}
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, errors.New("certificate " + c.Subject.String() + " is not a CA certificate")
		}
		sum := sha256.Sum256(blk.Bytes)
		if seen[sum] {
			continue
		}
		seen[sum] = true
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
	}
	if out.Len() == 0 {
		return nil, errors.New("no CA certificate in the published bundle")
	}
	return out.Bytes(), nil
}
