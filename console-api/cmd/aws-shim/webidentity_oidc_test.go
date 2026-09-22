package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeOIDC verifies pre-canned tokens: token -> {provider, subject}. A missing token is unverifiable.
type fakeOIDC map[string][2]string

func (f fakeOIDC) verify(_ context.Context, tok string) (string, string, bool) {
	v, ok := f[tok]
	if !ok {
		return "", "", false
	}
	return v[0], v[1], true
}

func newOIDCSTS(t *testing.T, roles fakeRoles, o oidcVerifier) *stsHandler {
	h, _ := newSTS(t, roles) // webID stays nil — only the OIDC path is wired
	h.oidcWebID = o
	return h
}

// A token from a registered provider named by the role's trust ("OIDC::<name>") gets role credentials,
// and the assumed subject is the token subject.
func TestWebIdentity_OIDC_TrustedProvider(t *testing.T) {
	h := newOIDCSTS(t,
		fakeRoles{"fed-role": {trust: []string{"OIDC::google"}, groups: []string{"openinfra:users"}}},
		fakeOIDC{"gtok": {"google", "alice@example.com"}})
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("arn:openinfra:iam::open-infra:role/fed-role", "gtok"), iam.Claims{}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("trusted OIDC provider should get creds, got %d: %s", w.Code, w.Body.String())
	}
	var resp assumeRoleWithWebIdentityResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.HasPrefix(resp.Result.Credentials.AccessKeyId, "ASIA") {
		t.Fatalf("credentials incomplete: %+v", resp.Result.Credentials)
	}
	if resp.Result.SubjectFromWebIdentityToken != "alice@example.com" {
		t.Fatalf("subject should be the token subject, got %q", resp.Result.SubjectFromWebIdentityToken)
	}
}

// A role may also trust the exact subject rather than the provider.
func TestWebIdentity_OIDC_TrustedBySubject(t *testing.T) {
	h := newOIDCSTS(t,
		fakeRoles{"fed-role": {trust: []string{"alice@example.com"}}},
		fakeOIDC{"gtok": {"google", "alice@example.com"}})
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("fed-role", "gtok"), iam.Claims{}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("subject-trusted OIDC should get creds, got %d: %s", w.Code, w.Body.String())
	}
}

// A verified token whose provider AND subject the trust does not name is denied.
func TestWebIdentity_OIDC_Untrusted(t *testing.T) {
	h := newOIDCSTS(t,
		fakeRoles{"fed-role": {trust: []string{"OIDC::okta"}}},
		fakeOIDC{"gtok": {"google", "alice@example.com"}})
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("fed-role", "gtok"), iam.Claims{}, "rid")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("untrusted provider must be AccessDenied, got %d: %s", w.Code, w.Body.String())
	}
}

// A token no registered provider verifies is InvalidIdentityToken (fail closed).
func TestWebIdentity_OIDC_InvalidToken(t *testing.T) {
	h := newOIDCSTS(t,
		fakeRoles{"fed-role": {trust: []string{"*"}}},
		fakeOIDC{}) // nothing verifies
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("fed-role", "forged"), iam.Claims{}, "rid")
	if !strings.Contains(w.Body.String(), "InvalidIdentityToken") {
		t.Fatalf("an unverifiable token must be InvalidIdentityToken, got: %s", w.Body.String())
	}
}

// With only the OIDC path wired (webID nil), the action is still enabled (not InvalidAction).
func TestWebIdentity_EnabledWithOnlyOIDC(t *testing.T) {
	h := newOIDCSTS(t,
		fakeRoles{"fed-role": {trust: []string{"*"}}},
		fakeOIDC{"gtok": {"google", "alice@example.com"}})
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("fed-role", "gtok"), iam.Claims{}, "rid")
	if strings.Contains(w.Body.String(), "InvalidAction") {
		t.Fatalf("OIDC-only web identity must be enabled, got: %s", w.Body.String())
	}
}

func TestParseIdPConfigMaps(t *testing.T) {
	cm := func(name string, data map[string]string) corev1.ConfigMap {
		return corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name}, Data: data}
	}
	idps := parseIdPConfigMaps([]corev1.ConfigMap{
		cm("openinfra-idp-google", map[string]string{"name": "google", "issuerURL": "https://accounts.google.com", "audiences": "aud1, aud2", "subjectClaim": "email"}),
		cm("openinfra-idp-noiss", map[string]string{"name": "noiss", "audiences": "a"}),            // no issuer -> skipped
		cm("openinfra-idp-noaud", map[string]string{"name": "noaud", "issuerURL": "https://x"}),    // no audiences -> skipped
		cm("openinfra-idp-defsub", map[string]string{"issuerURL": "https://y", "audiences": "aa"}), // default subjectClaim + name from CM name
	})
	if len(idps) != 2 {
		t.Fatalf("want 2 valid idps (half-written ones skipped), got %d: %+v", len(idps), idps)
	}
	g := idps[0]
	if g.name != "google" || len(g.audiences) != 2 || g.audiences[0] != "aud1" || g.audiences[1] != "aud2" || g.subjectClaim != "email" {
		t.Errorf("google parsed wrong: %+v", g)
	}
	d := idps[1]
	if d.name != "defsub" || d.subjectClaim != "sub" {
		t.Errorf("defsub name/subjectClaim wrong (name from CM, default sub): %+v", d)
	}
}
