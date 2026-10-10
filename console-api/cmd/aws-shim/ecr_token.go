// ECR per-repo data-plane authorization (the Docker registry v2 bearer-token protocol, with the
// shim as token server) — polyhedron#289.
//
// AWS ECR authorizes push/pull PER REPOSITORY: a token only touches the repos the caller's IAM
// policy allows. The open-infra shim mimics that. The flow:
//
//  1. GetAuthorizationToken returns a short-lived, shim-SIGNED credential that identifies the
//     caller (user "AWS", password = a caller JWT) — mintCaller / verifyCaller.
//  2. `docker login`/push → the registry answers 401 Bearer realm=<the shim's /ecr/token>.
//  3. docker calls /ecr/token with that credential (Basic auth) + a scope
//     (repository:<repo>:pull,push). The endpoint authenticates the caller, authorizes EACH
//     requested repo+action against the caller's ECR permissions, and mints a registry JWT whose
//     `access` claims are ONLY the granted scopes — mintRegistry.
//  4. The registry validates that JWT against its trusted cert (rootcertbundle = this signer's
//     self-signed cert, embedded as x5c) and enforces the per-repo scopes on every layer op.
//
// So a token issued to principal A can push/pull only A's repos, even though all callers share one
// backing registry — the coarse single-htpasswd authority (any token → any repo) is gone.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const ecrTokenSigningSecret = "ecr-token-signing-key"

// ecrTokenSigner signs the caller credential + the registry access tokens. One RSA key; its
// self-signed cert is the registry's rootcertbundle (embedded as x5c in each registry token so the
// registry can build + trust the chain without a separate kid lookup).
type ecrTokenSigner struct {
	priv    *rsa.PrivateKey
	certDER []byte
	certPEM []byte
}

// loadOrCreateECRTokenSigner reads the RSA key + self-signed cert from a Secret (so tokens survive a
// restart), creating them on first use. The Secret's cert.pem is what the registry mounts as its
// token rootcertbundle, so key + trusted cert are minted together and never drift.
func loadOrCreateECRTokenSigner(ctx context.Context, cs kubernetes.Interface, ns string) (*ecrTokenSigner, error) {
	if sec, err := cs.CoreV1().Secrets(ns).Get(ctx, ecrTokenSigningSecret, metav1.GetOptions{}); err == nil {
		if s, ok := ecrSignerFromSecret(sec.Data); ok {
			return s, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}
	s, data, err := newECRTokenSigner()
	if err != nil {
		return nil, err
	}
	_, err = cs.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: ecrTokenSigningSecret, Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "open-infra-aws-shim"}},
		Data: data,
	}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if sec, gerr := cs.CoreV1().Secrets(ns).Get(ctx, ecrTokenSigningSecret, metav1.GetOptions{}); gerr == nil {
			if s2, ok := ecrSignerFromSecret(sec.Data); ok {
				return s2, nil
			}
		}
	} else if err != nil {
		return nil, err
	}
	return s, nil
}

func ecrSignerFromSecret(data map[string][]byte) (*ecrTokenSigner, bool) {
	kb, cb := data["private.pem"], data["cert.pem"]
	if len(kb) == 0 || len(cb) == 0 {
		return nil, false
	}
	kblock, _ := pem.Decode(kb)
	cblock, _ := pem.Decode(cb)
	if kblock == nil || cblock == nil {
		return nil, false
	}
	key, err := x509.ParsePKCS1PrivateKey(kblock.Bytes)
	if err != nil {
		return nil, false
	}
	return &ecrTokenSigner{priv: key, certDER: cblock.Bytes, certPEM: cb}, true
}

func newECRTokenSigner() (*ecrTokenSigner, map[string][]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "open-infra-ecr-token"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return &ecrTokenSigner{priv: key, certDER: certDER, certPEM: certPEM},
		map[string][]byte{"private.pem": keyPEM, "cert.pem": certPEM}, nil
}

// ecrCaller is the identity carried in a caller credential — exactly the fields the token endpoint
// needs to re-run the caller's authorization (the same SubjectAccessReview the control plane does).
type ecrCaller struct {
	Sub    string   `json:"sub"`
	Groups []string `json:"groups,omitempty"`
	Role   string   `json:"role,omitempty"`
}

// mintCaller issues the GetAuthorizationToken credential: a short-lived shim-signed JWT identifying
// the caller (sub + groups/role for authz). It is NOT a registry token — it only proves "I am this
// principal, with this authority" to /ecr/token.
func (s *ecrTokenSigner) mintCaller(c ecrCaller, ttl time.Duration) (string, error) {
	now := time.Now()
	return s.signJWT(
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": "ecr-cred-1"},
		map[string]any{"sub": c.Sub, "groups": c.Groups, "role": c.Role,
			"purpose": "ecr-authz", "iat": now.Unix(), "exp": now.Add(ttl).Unix()},
	)
}

// verifyCaller validates a caller credential and returns its identity. Rejects a bad signature, the
// wrong purpose, or an expired token.
func (s *ecrTokenSigner) verifyCaller(token string) (ecrCaller, error) {
	var claims struct {
		ecrCaller
		Purpose string `json:"purpose"`
		Exp     int64  `json:"exp"`
	}
	if err := s.verifyJWT(token, &claims); err != nil {
		return ecrCaller{}, err
	}
	if claims.Purpose != "ecr-authz" {
		return ecrCaller{}, fmt.Errorf("not an ECR authorization credential")
	}
	if time.Now().Unix() >= claims.Exp {
		return ecrCaller{}, fmt.Errorf("credential expired")
	}
	if claims.Sub == "" {
		return ecrCaller{}, fmt.Errorf("credential has no subject")
	}
	return claims.ecrCaller, nil
}

// ecrAccess is one entry of a registry token's `access` claim — a repository and the granted actions.
type ecrAccess struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// mintRegistry issues the Docker registry access token: an RS256 JWT carrying the GRANTED per-repo
// scopes in its `access` claim, with the signer's cert in x5c so the registry trusts it against its
// rootcertbundle.
func (s *ecrTokenSigner) mintRegistry(subject, issuer, service string, access []ecrAccess, ttl time.Duration) (string, error) {
	now := time.Now()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	return s.signJWT(
		map[string]any{"alg": "RS256", "typ": "JWT", "x5c": []string{base64.StdEncoding.EncodeToString(s.certDER)}},
		map[string]any{
			"iss": issuer, "sub": subject, "aud": service,
			"iat": now.Unix(), "nbf": now.Add(-10 * time.Second).Unix(), "exp": now.Add(ttl).Unix(),
			"jti": base64.RawURLEncoding.EncodeToString(jti), "access": access,
		},
	)
}

// signJWT hand-builds an RS256 JWT with the given header + claims (full header control for x5c).
func (s *ecrTokenSigner) signJWT(header, claims map[string]any) (string, error) {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signing := b64url(hb) + "." + b64url(cb)
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64url(sig), nil
}

// verifyJWT checks an RS256 signature against the signer's own public key and decodes the claims.
func (s *ecrTokenSigner) verifyJWT(token string, claims any) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("malformed JWT")
	}
	h, p, sig := parts[0], parts[1], parts[2]
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("bad signature encoding")
	}
	sum := sha256.Sum256([]byte(h + "." + p))
	if err := rsa.VerifyPKCS1v15(&s.priv.PublicKey, crypto.SHA256, sum[:], sigBytes); err != nil {
		return fmt.Errorf("signature verification failed")
	}
	pb, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return fmt.Errorf("bad claims encoding")
	}
	return json.Unmarshal(pb, claims)
}

// --- the Docker registry token endpoint (/ecr/token) ---
//
// The registry, configured for token auth, redirects docker here (realm) with ?service=&scope=.
// docker presents the GetAuthorizationToken credential (user "AWS", password = the caller JWT) as
// Basic auth. We authenticate the caller, authorize EACH requested repo+action against that caller's
// ECR permissions (the same SubjectAccessReview the control plane runs), and mint a registry token
// whose access claim is only what was granted.

func writeDockerTokenError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]any{"code": code, "message": msg}}})
}

// parseScope parses a Docker auth scope "repository:<name>:<actions>" (name may contain '/').
func parseScope(s string) (ecrAccess, bool) {
	first := strings.Index(s, ":")
	last := strings.LastIndex(s, ":")
	if first < 0 || last <= first {
		return ecrAccess{}, false
	}
	rtype, name, actions := s[:first], s[first+1:last], s[last+1:]
	if rtype != "repository" || name == "" || actions == "" {
		return ecrAccess{}, false
	}
	return ecrAccess{Type: "repository", Name: name, Actions: strings.Split(actions, ",")}, true
}

// ecrActionVerb maps a Docker registry action to the RBAC verb the caller must hold on the repo.
func ecrActionVerb(action string) string {
	switch action {
	case "pull":
		return "get"
	case "push":
		return "create"
	case "delete":
		return "delete"
	}
	return ""
}

// serveToken handles GET /ecr/token — the Docker registry bearer-token issuance.
func (h *ecrHandler) serveToken(w http.ResponseWriter, r *http.Request) {
	if h.signer == nil {
		writeDockerTokenError(w, http.StatusNotImplemented, "UNSUPPORTED", "token auth is not configured on this shim")
		return
	}
	_, pass, ok := r.BasicAuth()
	if !ok || pass == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="ecr"`)
		writeDockerTokenError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	caller, err := h.signer.verifyCaller(pass)
	if err != nil {
		writeDockerTokenError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid ECR credential: "+err.Error())
		return
	}
	claims := iam.Claims{Sub: caller.Sub, Groups: caller.Groups, Role: caller.Role}
	service := r.URL.Query().Get("service")
	ctx := r.Context()

	// Authorize each requested repo+action against this caller; grant only what passes.
	var granted []ecrAccess
	for _, sc := range r.URL.Query()["scope"] {
		for _, one := range strings.Fields(sc) { // some clients join scopes with spaces
			acc, ok := parseScope(one)
			if !ok {
				continue
			}
			var allowed []string
			for _, action := range acc.Actions {
				verb := ecrActionVerb(action)
				if verb == "" {
					continue
				}
				if ok, _ := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, acc.Name); ok {
					allowed = append(allowed, action)
				}
			}
			if len(allowed) > 0 {
				granted = append(granted, ecrAccess{Type: "repository", Name: acc.Name, Actions: allowed})
				h.audit(ctx, "TokenGrant", acc.Name, "allow", strings.Join(allowed, ","))
			} else if len(acc.Actions) > 0 {
				h.audit(ctx, "TokenGrant", acc.Name, "deny", "not authorized")
			}
		}
	}

	// No scope (the `docker login` probe) → an access-less token (login succeeds; the per-repo grant
	// happens on the subsequent scoped pull/push requests).
	tok, err := h.signer.mintRegistry(caller.Sub, h.issuer, service, granted, 5*time.Minute)
	if err != nil {
		writeDockerTokenError(w, http.StatusInternalServerError, "UNKNOWN", "could not mint token")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token": tok, "access_token": tok, "expires_in": 300, "issued_at": time.Now().UTC().Format(time.RFC3339),
	})
}
