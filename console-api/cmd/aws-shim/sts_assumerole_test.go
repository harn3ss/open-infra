package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/awssig"
	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

type fakeRoles map[string]struct{ trust, groups []string }

func (f fakeRoles) Resolve(_ context.Context, name string) ([]string, []string, bool) {
	r, ok := f[name]
	return r.trust, r.groups, ok
}

func testMinter(t *testing.T) *awssts.Minter {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	m, err := awssts.NewMinter(key)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func assumeRequest(roleArn, sessionName string) *http.Request {
	form := url.Values{"Action": {"AssumeRole"}, "RoleArn": {roleArn}, "RoleSessionName": {sessionName}}
	req := httptest.NewRequest("POST", "http://sts.local/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func newSTS(t *testing.T, roles fakeRoles) (*stsHandler, *awssts.Minter) {
	m := testMinter(t)
	return &stsHandler{account: "open-infra", minter: m, roles: roles, logger: discardLogger()}, m
}

// A trusted caller assumes a role and receives temporary credentials.
func TestAssumeRole_TrustedCallerGetsCredentials(t *testing.T) {
	h, _ := newSTS(t, fakeRoles{"deploy-role": {trust: []string{"alice"}, groups: []string{"openinfra:users"}}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("arn:openinfra:iam::open-infra:role/deploy-role", "s1"), iam.Claims{Sub: "alice"}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("trusted assume should be 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp assumeRoleResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c := resp.Result.Credentials
	if !strings.HasPrefix(c.AccessKeyId, "ASIA") || c.SecretAccessKey == "" || c.SessionToken == "" {
		t.Fatalf("credentials incomplete: %+v", c)
	}
	if resp.Result.AssumedRoleUser.Arn != "arn:openinfra:iam::open-infra:assumed-role/deploy-role/s1" {
		t.Fatalf("assumed-role ARN wrong: %q", resp.Result.AssumedRoleUser.Arn)
	}
}

// A caller not named by the trust policy is denied.
func TestAssumeRole_UntrustedCallerDenied(t *testing.T) {
	h, _ := newSTS(t, fakeRoles{"deploy-role": {trust: []string{"alice"}}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("arn:openinfra:iam::open-infra:role/deploy-role", "s1"), iam.Claims{Sub: "mallory"}, "rid")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("untrusted caller must get AccessDenied, got %d: %s", w.Code, w.Body.String())
	}
}

// A role with no trust entries cannot be assumed by anyone (fail closed).
func TestAssumeRole_NoTrustFailsClosed(t *testing.T) {
	h, _ := newSTS(t, fakeRoles{"locked": {trust: nil}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("locked", "s1"), iam.Claims{Sub: "alice"}, "rid")
	if w.Code != http.StatusForbidden {
		t.Fatalf("a role with no trust must deny, got %d", w.Code)
	}
}

// A "*" trust policy admits any authenticated principal.
func TestAssumeRole_WildcardTrust(t *testing.T) {
	h, _ := newSTS(t, fakeRoles{"public": {trust: []string{"*"}, groups: []string{"openinfra:users"}}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("public", "s1"), iam.Claims{Sub: "anyone"}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("wildcard trust should admit any principal, got %d: %s", w.Code, w.Body.String())
	}
}

// An unknown role denies (AccessDenied, not a "not found" that would let callers probe roles).
func TestAssumeRole_UnknownRoleDenied(t *testing.T) {
	h, _ := newSTS(t, fakeRoles{})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("ghost", "s1"), iam.Claims{Sub: "alice"}, "rid")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("unknown role must be AccessDenied, got %d: %s", w.Code, w.Body.String())
	}
}

// Assume disabled (no signing key configured) answers InvalidAction rather than pretending.
func TestAssumeRole_DisabledWhenNoMinter(t *testing.T) {
	h := &stsHandler{account: "open-infra", logger: discardLogger()} // nil minter + roles
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("r", "s"), iam.Claims{Sub: "alice"}, "rid")
	if !strings.Contains(w.Body.String(), "InvalidAction") {
		t.Fatalf("assume with no signing key must be InvalidAction, got: %s", w.Body.String())
	}
}

// End-to-end: assume a role, then use the returned temporary credentials (SigV4 + session token) to
// authenticate — the request acts AS the role (assumed-role claims), not the original user.
func TestAssumeRole_EndToEnd_SessionAuthenticatesAsRole(t *testing.T) {
	h, minter := newSTS(t, fakeRoles{"deploy-role": {trust: []string{"alice"}, groups: []string{"openinfra:users"}}})
	// 1. assume
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("deploy-role", "cli-session"), iam.Claims{Sub: "alice"}, "rid")
	var resp assumeRoleResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c := resp.Result.Credentials

	// 2. sign a later request with the temp creds + carry the session token
	req := signedSessionRequest(t, c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	auth := &authenticator{keys: fakeKeys{}, resolve: func(context.Context, string) ([]string, bool) { return nil, false }, sts: minter}
	claims, err := auth.authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("assumed-role credentials must authenticate: %v", err)
	}
	if claims.AssumedRole != "deploy-role" {
		t.Fatalf("session must act as the role, got AssumedRole=%q", claims.AssumedRole)
	}
	if claims.PrincipalType() != "Role" || claims.PrincipalID() != "deploy-role" {
		t.Fatalf("data-plane principal must be Role/deploy-role, got %s/%s", claims.PrincipalType(), claims.PrincipalID())
	}
	if claims.Sub != "assumed-role/deploy-role/cli-session" {
		t.Fatalf("Sub should carry the assumed-role session id, got %q", claims.Sub)
	}
}

// A session token with a tampered/forged secret cannot authenticate (SigV4 verified against the
// token's sealed secret).
func TestAssumeRole_EndToEnd_WrongSecretRejected(t *testing.T) {
	h, minter := newSTS(t, fakeRoles{"r": {trust: []string{"*"}, groups: []string{"openinfra:users"}}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("r", "s"), iam.Claims{Sub: "alice"}, "rid")
	var resp assumeRoleResponse
	_ = xml.Unmarshal(w.Body.Bytes(), &resp)
	// sign with the WRONG secret but a valid token
	req := signedSessionRequest(t, resp.Result.Credentials.AccessKeyId, "attacker-secret", resp.Result.Credentials.SessionToken)
	auth := &authenticator{keys: fakeKeys{}, resolve: func(context.Context, string) ([]string, bool) { return nil, false }, sts: minter}
	if _, err := auth.authenticate(context.Background(), req); err != errAuth {
		t.Fatalf("a wrong-secret session must be errAuth, got %v", err)
	}
}

// A session token presented to a shim without assume enabled (nil minter) is rejected.
func TestSessionToken_RejectedWhenAssumeDisabled(t *testing.T) {
	auth := &authenticator{keys: fakeKeys{}, resolve: func(context.Context, string) ([]string, bool) { return nil, false }} // sts nil
	req := signedSessionRequest(t, "ASIAEXAMPLE000000", "sk", "sometoken")
	if _, err := auth.authenticate(context.Background(), req); err != errAuth {
		t.Fatalf("a session token with assume disabled must be errAuth, got %v", err)
	}
}

// --- Workload identity (sts:AssumeRoleWithWebIdentity) ---

type fakeReviewer map[string]string // web-identity token -> SA username; missing => not authenticated

func (f fakeReviewer) Review(_ context.Context, tok string) (string, bool) {
	u, ok := f[tok]
	return u, ok
}

func webIdentityRequest(roleArn, token string) *http.Request {
	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn}, "WebIdentityToken": {token}}
	req := httptest.NewRequest("POST", "http://sts.local/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func newWebIDSTS(t *testing.T, roles fakeRoles, rev fakeReviewer) *stsHandler {
	h, _ := newSTS(t, roles)
	h.webID = rev
	return h
}

// A pod whose SA token verifies and whose SA is named by the role's trust gets role credentials.
func TestWebIdentity_TrustedServiceAccount(t *testing.T) {
	const sa = "system:serviceaccount:apps:web-sa"
	h := newWebIDSTS(t,
		fakeRoles{"svc-role": {trust: []string{sa}, groups: []string{"openinfra:users"}}},
		fakeReviewer{"pod-token": sa})
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("arn:openinfra:iam::open-infra:role/svc-role", "pod-token"), iam.Claims{}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("trusted SA should get creds, got %d: %s", w.Code, w.Body.String())
	}
	var resp assumeRoleWithWebIdentityResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.HasPrefix(resp.Result.Credentials.AccessKeyId, "ASIA") || resp.Result.Credentials.SessionToken == "" {
		t.Fatalf("credentials incomplete: %+v", resp.Result.Credentials)
	}
	if resp.Result.SubjectFromWebIdentityToken != sa {
		t.Fatalf("subject should be the SA, got %q", resp.Result.SubjectFromWebIdentityToken)
	}
}

// A verified SA that the role's trust does NOT name is denied.
func TestWebIdentity_UntrustedServiceAccount(t *testing.T) {
	h := newWebIDSTS(t,
		fakeRoles{"svc-role": {trust: []string{"system:serviceaccount:apps:other-sa"}}},
		fakeReviewer{"pod-token": "system:serviceaccount:apps:web-sa"})
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("svc-role", "pod-token"), iam.Claims{}, "rid")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("untrusted SA must be AccessDenied, got %d: %s", w.Code, w.Body.String())
	}
}

// A token the reviewer can't authenticate is rejected with InvalidIdentityToken.
func TestWebIdentity_InvalidTokenRejected(t *testing.T) {
	h := newWebIDSTS(t,
		fakeRoles{"svc-role": {trust: []string{"*"}}},
		fakeReviewer{}) // no token authenticates
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("svc-role", "forged-token"), iam.Claims{}, "rid")
	if !strings.Contains(w.Body.String(), "InvalidIdentityToken") {
		t.Fatalf("an unverifiable token must be InvalidIdentityToken, got: %s", w.Body.String())
	}
}

// Web identity disabled (no reviewer) answers InvalidAction.
func TestWebIdentity_DisabledWhenNoReviewer(t *testing.T) {
	h, _ := newSTS(t, fakeRoles{"svc-role": {trust: []string{"*"}}}) // webID nil
	w := httptest.NewRecorder()
	h.serve(w, webIdentityRequest("svc-role", "pod-token"), iam.Claims{}, "rid")
	if !strings.Contains(w.Body.String(), "InvalidAction") {
		t.Fatalf("web identity with no reviewer must be InvalidAction, got: %s", w.Body.String())
	}
}

// The router dispatches an UNAUTHENTICATED web-identity call (no SigV4) to STS — the SA token is
// the credential.
func TestRouter_DispatchesUnauthenticatedWebIdentity(t *testing.T) {
	const sa = "system:serviceaccount:apps:web-sa"
	h := newWebIDSTS(t,
		fakeRoles{"svc-role": {trust: []string{sa}, groups: []string{"openinfra:users"}}},
		fakeReviewer{"pod-token": sa})
	rt := &serviceRouter{
		auth:     &authenticator{keys: fakeKeys{}, resolve: func(context.Context, string) ([]string, bool) { return nil, false }},
		services: map[string]awsService{"sts": h},
		logger:   discardLogger(),
	}
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, webIdentityRequest("svc-role", "pod-token")) // NO Authorization header
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ASIA") {
		t.Fatalf("router must dispatch unauthenticated web-identity to STS, got %d: %s", w.Code, w.Body.String())
	}
}

// signedSessionRequest signs a request with temporary credentials and attaches the STS session token.
func signedSessionRequest(t *testing.T, accessKeyID, secretKey, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "http://sts.local/", strings.NewReader("Action=GetCallerIdentity"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256) // body hash not verified by our sig path for form; header signed
	req.Header.Set("X-Amz-Security-Token", token)
	cred := awssig.Credential{
		AccessKeyID:   accessKeyID,
		Date:          "20150830",
		Region:        "us-east-1",
		Service:       "sts",
		SignedHeaders: []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token"},
	}
	sig, err := awssig.Sign(req, cred, secretKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKeyID+
		"/20150830/us-east-1/sts/aws4_request, "+
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature="+sig)
	return req
}
