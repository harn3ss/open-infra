package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// withParams attaches chi URL params to a request, the way the router would after matching
// /api/ca/{namespace}/{name}/....
func withParams(r *http.Request, params map[string]string) *http.Request {
	rc := chi.NewRouteContext()
	for k, v := range params {
		rc.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

// allowSAR makes the fake API server say "yes" to every SubjectAccessReview, so a test can drive
// the code path AFTER the gate. Without it the fake returns Allowed=false and every authorize()
// call fails closed.
func allowSAR(cs *fake.Clientset) {
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})
}

// signedIn returns a request carrying a valid session in context, the way requireAuth would have
// left it. mode "local" means authorize() actually consults the (fake) SAR rather than short-circuiting.
func caReq(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	claims := sessionClaims{}
	claims.Sub = "alice"
	claims.Role = "poweruser"
	return r.WithContext(context.WithValue(r.Context(), ctxUser{}, claims))
}

// The SAR gate must deny an unauthorized caller BEFORE anything reaches the ca-issuer. The fake
// clientset denies every SAR by default, so a signed-in poweruser who lacks update on the CA is
// refused with 403 and the issuer is never called.
func TestCAIssueDeniesUnauthorized(t *testing.T) {
	issuerHit := false
	issuer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { issuerHit = true }))
	defer issuer.Close()
	t.Setenv("CA_ISSUER_ENDPOINT", issuer.URL)

	cs := fake.NewSimpleClientset() // default: every SAR denied
	auth := &authStore{cs: cs, ns: "open-infra-console", mode: "local"}

	r := withParams(caReq(http.MethodPost, "/api/ca/default/root-ca/issue", `{"commonName":"web.example.com"}`),
		map[string]string{"namespace": "default", "name": "root-ca"})

	rec := httptest.NewRecorder()
	handleCAIssue(cs, auth, slog.New(slog.DiscardHandler)).ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthorized issue = %d, want 403", rec.Code)
	}
	if issuerHit {
		t.Fatal("the ca-issuer was called despite the SAR gate denying the caller")
	}
}

// Once authorized, the request must be SHAPED correctly on the way to the ca-issuer: forwarded to
// /issue, with "ca" forced to the CA named in the path — even when the caller tried to smuggle a
// different CA in the body — and the rest of the payload preserved. The issuer's response (private
// key included) is relayed back verbatim.
func TestCAIssueForwardsShapedRequest(t *testing.T) {
	var gotPath, gotBody string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"certificate":"CERTPEM","privateKey":"KEYPEM","serialNumber":"aa:bb:cc"}`)
	}))
	defer issuer.Close()
	t.Setenv("CA_ISSUER_ENDPOINT", issuer.URL)

	cs := fake.NewSimpleClientset()
	allowSAR(cs)
	auth := &authStore{cs: cs, ns: "open-infra-console", mode: "local"}

	// The caller tries to target "evil-ca"; the path says "root-ca". The path must win.
	r := withParams(caReq(http.MethodPost, "/api/ca/default/root-ca/issue",
		`{"ca":"evil-ca","commonName":"web.example.com","ttl":"72h","altNames":["a.example.com"]}`),
		map[string]string{"namespace": "default", "name": "root-ca"})

	rec := httptest.NewRecorder()
	handleCAIssue(cs, auth, slog.New(slog.DiscardHandler)).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("issue = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if gotPath != "/issue" {
		t.Errorf("forwarded path = %q, want /issue", gotPath)
	}
	var fwd map[string]any
	if err := json.Unmarshal([]byte(gotBody), &fwd); err != nil {
		t.Fatalf("issuer got non-JSON body %q: %v", gotBody, err)
	}
	if fwd["ca"] != "root-ca" {
		t.Errorf("forwarded ca = %v, want root-ca (path must override the body)", fwd["ca"])
	}
	if fwd["commonName"] != "web.example.com" {
		t.Errorf("commonName not preserved: %v", fwd["commonName"])
	}
	if alt, ok := fwd["altNames"].([]any); !ok || len(alt) != 1 || alt[0] != "a.example.com" {
		t.Errorf("altNames not preserved: %v", fwd["altNames"])
	}
	if !strings.Contains(rec.Body.String(), "CERTPEM") {
		t.Errorf("issuer response not relayed to the browser: %s", rec.Body.String())
	}
}

// Revoke follows the same path→/revoke rule and forces the CA name.
func TestCARevokeForwards(t *testing.T) {
	var gotPath, gotBody string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer issuer.Close()
	t.Setenv("CA_ISSUER_ENDPOINT", issuer.URL)

	cs := fake.NewSimpleClientset()
	allowSAR(cs)
	auth := &authStore{cs: cs, ns: "open-infra-console", mode: "local"}

	r := withParams(caReq(http.MethodPost, "/api/ca/default/root-ca/revoke", `{"serialNumber":"aa:bb:cc"}`),
		map[string]string{"namespace": "default", "name": "root-ca"})

	rec := httptest.NewRecorder()
	handleCARevoke(cs, auth, slog.New(slog.DiscardHandler)).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200", rec.Code)
	}
	if gotPath != "/revoke" {
		t.Errorf("forwarded path = %q, want /revoke", gotPath)
	}
	if !strings.Contains(gotBody, `"ca":"root-ca"`) || !strings.Contains(gotBody, `"serialNumber":"aa:bb:cc"`) {
		t.Errorf("revoke body not shaped correctly: %s", gotBody)
	}
}

// The list endpoint merges the spec-mirror and state ConfigMaps on the openinfra.dev/ca label,
// exactly like handleEncryptionKeys — so a CA shows its declared spec and its live Vault state as
// one object.
func TestCertificateAuthoritiesMerge(t *testing.T) {
	spec := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "openinfra-ca-root",
			Namespace: "open-infra-console",
			Labels:    map[string]string{"openinfra.dev/ca": "root"},
		},
		Data: map[string]string{
			"commonName":     "Example Root CA",
			"hierarchy":      "root",
			"keyType":        "rsa-4096",
			"maxTtl":         "8760h",
			"allowedDomains": "example.com, internal.example.com",
			"pkiMount":       "pki-root",
		},
	}
	state := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "openinfra-ca-state-root",
			Namespace: "open-infra-console",
			Labels:    map[string]string{"openinfra.dev/ca": "root"},
		},
		Data: map[string]string{
			"ready":     "true",
			"pkiMount":  "pki-root",
			"caCertPem": "-----BEGIN CERTIFICATE-----",
			"serial":    "12:34",
			"notAfter":  "2035-01-01T00:00:00Z",
		},
	}
	cs := fake.NewSimpleClientset(spec, state)
	allowSAR(cs)
	auth := &authStore{cs: cs, ns: "open-infra-console", mode: "local"}

	r := caReq(http.MethodGet, "/api/ca", "")
	rec := httptest.NewRecorder()
	handleCertificateAuthorities(cs, auth, slog.New(slog.DiscardHandler)).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rec.Code)
	}
	var out []caView
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d CAs, want 1: %s", len(out), rec.Body.String())
	}
	c := out[0]
	if c.Name != "root" || c.CommonName != "Example Root CA" || c.Hierarchy != "root" {
		t.Errorf("spec not merged: %+v", c)
	}
	if len(c.AllowedDomains) != 2 || c.AllowedDomains[0] != "example.com" || c.AllowedDomains[1] != "internal.example.com" {
		t.Errorf("allowedDomains not split: %v", c.AllowedDomains)
	}
	if !c.Ready || c.Serial != "12:34" || c.NotAfter != "2035-01-01T00:00:00Z" {
		t.Errorf("state not merged: %+v", c)
	}
}
