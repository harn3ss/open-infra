package main

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// oidcVerifier verifies an sts:AssumeRoleWithWebIdentity token that came from a registered EXTERNAL
// OIDC identity provider (kind: IdentityProvider — polyhedron#136 §2), returning the provider's name
// (used for trust matching as "OIDC::<name>") and the token subject. Fails closed. This is distinct
// from the k8s workload-identity path (tokenReviewer): it trusts external issuers the operator
// explicitly registered, verified with the same coreos/go-oidc path the AppSync JWT auth uses.
type oidcVerifier interface {
	verify(ctx context.Context, token string) (provider, subject string, ok bool)
}

const idpConfigMapLabel = "openinfra.dev/identity-provider"

// idp is one registered provider, parsed from a spec-mirror ConfigMap the IdentityProvider composition
// renders (issuerURL / audiences / subjectClaim).
type idp struct {
	name, issuerURL, subjectClaim string
	audiences                     []string
}

// parseIdPConfigMaps turns the label-selected ConfigMaps into the registry. A ConfigMap missing an
// issuerURL or any audience is skipped — a half-written entry must never become a trusted issuer, and
// an unaudienced provider would accept tokens minted for anyone.
func parseIdPConfigMaps(items []corev1.ConfigMap) []idp {
	var out []idp
	for _, cm := range items {
		iss := strings.TrimSpace(cm.Data["issuerURL"])
		if iss == "" {
			continue
		}
		var auds []string
		for _, a := range strings.Split(cm.Data["audiences"], ",") {
			if a = strings.TrimSpace(a); a != "" {
				auds = append(auds, a)
			}
		}
		if len(auds) == 0 {
			continue
		}
		sc := strings.TrimSpace(cm.Data["subjectClaim"])
		if sc == "" {
			sc = "sub"
		}
		name := strings.TrimSpace(cm.Data["name"])
		if name == "" {
			name = strings.TrimPrefix(cm.Name, "openinfra-idp-")
		}
		out = append(out, idp{name: name, issuerURL: iss, audiences: auds, subjectClaim: sc})
	}
	return out
}

// oidcWebIdentity is the production oidcVerifier. It reads the registry from the ConfigMaps on a short
// TTL and builds one coreos/go-oidc verifier per (issuer, audience) — the SAME JWKS-discovery +
// signature/issuer/audience/expiry verification the AppSync JWT path uses (which rejects alg:none and
// unknown keys — hand-rolled JWT is how bypasses happen). Providers are cached by issuer (discovery is
// network); an unreachable or invalid issuer simply cannot verify (fail closed).
type oidcWebIdentity struct {
	cs  kubernetes.Interface
	ns  string
	ttl time.Duration

	mu        sync.Mutex
	loadedAt  time.Time
	loaded    bool
	entries   []idpVerifier
	providers map[string]*oidc.Provider // cached by issuerURL
}

type idpVerifier struct {
	name, subjectClaim string
	verifiers          []*oidc.IDTokenVerifier // one per audience
}

func newOIDCWebIdentity(cs kubernetes.Interface, ns string, ttl time.Duration) *oidcWebIdentity {
	return &oidcWebIdentity{cs: cs, ns: ns, ttl: ttl, providers: map[string]*oidc.Provider{}}
}

// refresh reloads the registry from the ConfigMaps if the TTL elapsed, (re)building verifiers.
func (o *oidcWebIdentity) refresh(ctx context.Context) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.loaded && time.Since(o.loadedAt) < o.ttl {
		return
	}
	list, err := o.cs.CoreV1().ConfigMaps(o.ns).List(ctx, metav1.ListOptions{LabelSelector: idpConfigMapLabel})
	if err != nil {
		return // keep the last-known registry on a transient list error (never widen on failure)
	}
	var entries []idpVerifier
	for _, p := range parseIdPConfigMaps(list.Items) {
		provider, ok := o.providers[p.issuerURL]
		if !ok {
			np, derr := oidc.NewProvider(ctx, p.issuerURL)
			if derr != nil {
				continue // unreachable/invalid issuer → not trusted until discovery succeeds
			}
			provider = np
			o.providers[p.issuerURL] = provider
		}
		vs := make([]*oidc.IDTokenVerifier, 0, len(p.audiences))
		for _, aud := range p.audiences {
			vs = append(vs, provider.Verifier(&oidc.Config{ClientID: aud}))
		}
		entries = append(entries, idpVerifier{name: p.name, subjectClaim: p.subjectClaim, verifiers: vs})
	}
	o.entries = entries
	o.loaded = true
	o.loadedAt = time.Now()
}

// verify tries the token against every registered (issuer, audience) verifier. go-oidc enforces the
// signature, issuer, audience and expiry, so a token only matches its true issuer with a registered
// audience. First match wins; returns the provider name + subject.
func (o *oidcWebIdentity) verify(ctx context.Context, token string) (string, string, bool) {
	o.refresh(ctx)
	o.mu.Lock()
	entries := o.entries
	o.mu.Unlock()
	for _, e := range entries {
		for _, vf := range e.verifiers {
			idt, err := vf.Verify(ctx, token)
			if err != nil {
				continue
			}
			subject := idt.Subject
			if e.subjectClaim != "sub" {
				var claims map[string]any
				if idt.Claims(&claims) != nil {
					continue
				}
				s, ok := claims[e.subjectClaim].(string)
				if !ok || s == "" {
					continue // configured subject claim absent → cannot form an identity
				}
				subject = s
			}
			if subject == "" {
				continue
			}
			return e.name, subject, true
		}
	}
	return "", "", false
}
