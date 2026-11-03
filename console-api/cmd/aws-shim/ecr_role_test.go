package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// Assumed-role sessions (a VM instance role, a web-identity role) at the ECR front door: the role's
// data-plane policy is its complete ECR authority, default-deny — at GetAuthorizationToken, at every
// control-plane op, and at the registry token realm (/ecr/token) that scopes docker pull/push.

const ecrTestRole = "app-role"

func ecrRoleClaims() iam.Claims {
	return iam.Claims{Sub: "assumed-role/" + ecrTestRole + "/i-0abc", Groups: []string{"openinfra:users"}, AssumedRole: ecrTestRole}
}

// roleChecker is a data-plane engine whose one policy applies to Role::<ecrTestRole>.
func roleChecker(stmts ...policyengine.Statement) *dataplaneauthz.Checker {
	return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{
			Name: ecrTestRole + "-access", AppliesTo: []string{"Role::" + ecrTestRole}, Statements: stmts,
		}}}, nil
	}, time.Minute)
}

func dpAllow(actions []string, resources ...string) policyengine.Statement {
	return policyengine.Statement{Effect: policyengine.Allow, Actions: actions, Resources: resources}
}

func dpDeny(actions []string, resources ...string) policyengine.Statement {
	return policyengine.Statement{Effect: policyengine.Deny, Actions: actions, Resources: resources}
}

// The instance-role policy an EC2 app template carries for pulling its own image (what cfn translates
// `ecr:GetAuthorizationToken` on "*" + the pull actions on repository/<name> into).
func pullPolicy() []policyengine.Statement {
	return []policyengine.Statement{
		dpAllow([]string{"ecr:GetAuthorizationToken"}, "*"),
		dpAllow([]string{"ecr:DescribeRepositories", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
			"ecr:BatchCheckLayerAvailability"}, "Repository::app"),
	}
}

var pushActions = []string{"ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
	"ecr:CompleteLayerUpload", "ecr:PutImage"}

// tokenModeECR is an ECR handler in per-repository token-auth mode (the live configuration).
func tokenModeECR(t *testing.T, sarAllows bool, authz *dataplaneauthz.Checker) *ecrHandler {
	t.Helper()
	h := newECRTestHandler(ecrCS(sarAllows, ecrSecret()), "")
	h.signer = newTestECRSigner(t)
	h.tokenAuth = true
	h.issuer = "openinfra-ecr"
	h.service = "ecr-registry"
	h.authz = authz
	return h
}

// getAuthToken calls GetAuthorizationToken and returns the response + (on success) the caller credential.
func getAuthToken(t *testing.T, h *ecrHandler, claims iam.Claims) (*httptest.ResponseRecorder, string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("GetAuthorizationToken", `{}`), claims, "req-tok")
	if w.Code != http.StatusOK {
		return w, ""
	}
	var resp struct {
		AuthorizationData []struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"authorizationData"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.AuthorizationData) != 1 {
		t.Fatalf("bad GetAuthorizationToken body: %v (%s)", err, w.Body.String())
	}
	raw, err := base64.StdEncoding.DecodeString(resp.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		t.Fatalf("token is not base64: %v", err)
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || user != "AWS" || pass == "" {
		t.Fatalf("token must decode to AWS:<credential>, got %q", string(raw))
	}
	return w, pass
}

func TestECR_GetAuthorizationToken_AssumedRole(t *testing.T) {
	cases := []struct {
		name  string
		authz *dataplaneauthz.Checker
		allow bool
	}{
		{"granted on Resource *", roleChecker(pullPolicy()...), true},
		{"granted by ecr:* on Repository::*", roleChecker(dpAllow([]string{"ecr:*"}, "Repository::*")), true},
		// AWS: GetAuthorizationToken has no resource type — a grant on one repository's ARN does not confer it.
		{"scoped to one repository only", roleChecker(dpAllow([]string{"ecr:GetAuthorizationToken"}, "Repository::app")), false},
		{"no ecr statement", roleChecker(dpAllow([]string{"s3:GetObject"}, "Bucket::assets")), false},
		{"explicit deny wins", roleChecker(dpAllow([]string{"ecr:*"}, "*"), dpDeny([]string{"ecr:GetAuthorizationToken"}, "*")), false},
		{"no policy at all", roleChecker(), false},
		{"data-plane engine not configured", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The SAR reactor allows everything: a role must be decided by its policy alone, never by RBAC.
			h := tokenModeECR(t, true, tc.authz)
			w, cred := getAuthToken(t, h, ecrRoleClaims())
			if !tc.allow {
				assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
			}
			got, err := h.signer.verifyCaller(cred)
			if err != nil {
				t.Fatalf("verify credential: %v", err)
			}
			if got.AssumedRole != ecrTestRole || got.Sub != ecrRoleClaims().Sub {
				t.Fatalf("the credential must carry the assumed role: %+v", got)
			}
		})
	}
}

// Without per-repository token auth the only credential is the shared htpasswd one, which reaches every
// repository — so an assumed role (whose authority may be one repository) is refused one.
func TestECR_GetAuthorizationToken_AssumedRoleNeedsTokenAuth(t *testing.T) {
	h := tokenModeECR(t, true, roleChecker(pullPolicy()...))
	h.tokenAuth = false
	w, _ := getAuthToken(t, h, ecrRoleClaims())
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
	if !strings.Contains(ecrErrorMessage(t, w), "per-repository token auth") {
		t.Fatalf("the refusal must say why, got %q", ecrErrorMessage(t, w))
	}
}

// A User's GetAuthorizationToken is unchanged: the coarse SAR decides, a data-plane policy that names no
// repository-less ecr grant does not block it, and the credential carries no assumed role.
func TestECR_GetAuthorizationToken_UserUnchanged(t *testing.T) {
	user := ecrClaims()
	// A policy that governs ecr for the user but grants nothing repository-less: the user path never runs a
	// data-plane check for an op with no repository, exactly as before.
	userPolicy := dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::" + user.Sub},
			Statements: []policyengine.Statement{dpAllow([]string{"ecr:BatchGetImage"}, "Repository::app")}}}}, nil
	}, time.Minute)
	for _, authz := range []*dataplaneauthz.Checker{nil, userPolicy} {
		h := tokenModeECR(t, true, authz)
		w, cred := getAuthToken(t, h, user)
		if w.Code != http.StatusOK {
			t.Fatalf("a user allowed by RBAC must get a token; status=%d body=%s", w.Code, w.Body.String())
		}
		got, err := h.signer.verifyCaller(cred)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if got.AssumedRole != "" || got.Sub != user.Sub || len(got.Groups) != len(user.Groups) {
			t.Fatalf("a user credential must carry the user and no role: %+v", got)
		}
		if strings.Contains(jwtPayload(t, cred), "assumedRole") {
			t.Fatalf("a user credential must not carry an assumedRole claim: %s", jwtPayload(t, cred))
		}
	}
	// RBAC still gates the user.
	h := tokenModeECR(t, false, nil)
	w, _ := getAuthToken(t, h, user)
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
}

// A role's control-plane ops are default-deny too, and every named repository is checked.
func TestECR_DescribeRepositories_AssumedRole(t *testing.T) {
	h := tokenModeECR(t, true, roleChecker(pullPolicy()...))
	if err := h.putRepo(context.Background(), ecrRepoRecord{RepositoryName: "app", ImageTagMutability: "MUTABLE"}); err != nil {
		t.Fatal(err)
	}
	if err := h.putRepo(context.Background(), ecrRepoRecord{RepositoryName: "other", ImageTagMutability: "MUTABLE"}); err != nil {
		t.Fatal(err)
	}
	call := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, ecrRequest("DescribeRepositories", body), ecrRoleClaims(), "req")
		return w
	}
	if w := call(`{"repositoryNames":["app"]}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"repositoryName":"app"`) {
		t.Fatalf("the role may describe its repository; status=%d body=%s", w.Code, w.Body.String())
	}
	// A second name the role may not describe denies the whole call (not only the first name is checked).
	assertECSErrorType(t, call(`{"repositoryNames":["app","other"]}`), http.StatusBadRequest, "AccessDeniedException")
	// Unfiltered = every repository = Repository::* — a grant on one repository does not reach it.
	assertECSErrorType(t, call(`{}`), http.StatusBadRequest, "AccessDeniedException")
	// Another repository's ops are denied.
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("DeleteRepository", `{"repositoryName":"app"}`), ecrRoleClaims(), "req")
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")

	// No data-plane engine → the role is denied even its own repository (fail closed).
	off := tokenModeECR(t, true, nil)
	w = httptest.NewRecorder()
	off.serve(w, ecrRequest("DescribeRepositories", `{"repositoryNames":["app"]}`), ecrRoleClaims(), "req")
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
}

// A User's data-plane Deny now applies to every repository DescribeRepositories names, not just the first.
func TestECR_DescribeRepositories_UserDenyEachName(t *testing.T) {
	user := ecrClaims()
	authz := dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::" + user.Sub},
			Statements: []policyengine.Statement{
				dpAllow([]string{"ecr:*"}, "*"),
				dpDeny([]string{"ecr:DescribeRepositories"}, "Repository::secret"),
			}}}}, nil
	}, time.Minute)
	h := tokenModeECR(t, true, authz)
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("DescribeRepositories", `{"repositoryNames":["app","secret"]}`), user, "req")
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
}

// --- the registry token realm (/ecr/token) ---

// realmGrant runs the GET token flow with a caller credential and the given scopes and returns the
// registry token's granted access (repo -> sorted actions) plus the HTTP status.
func realmGrant(t *testing.T, h *ecrHandler, cred string, scopes ...string) (map[string][]string, int) {
	t.Helper()
	q := url.Values{"service": {"ecr-registry"}, "scope": scopes}
	req := httptest.NewRequest("GET", "http://ecr/ecr/token?"+q.Encode(), nil)
	req.SetBasicAuth("AWS", cred)
	w := httptest.NewRecorder()
	h.serveToken(w, req)
	if w.Code != http.StatusOK {
		return nil, w.Code
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	tok, _ := m["token"].(string)
	var claims struct {
		Access []ecrAccess `json:"access"`
	}
	if err := json.Unmarshal([]byte(jwtPayload(t, tok)), &claims); err != nil {
		t.Fatalf("decode registry token: %v", err)
	}
	out := map[string][]string{}
	for _, a := range claims.Access {
		out[a.Name] = append(out[a.Name], a.Actions...)
		sort.Strings(out[a.Name])
	}
	return out, w.Code
}

func jwtPayload(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("malformed JWT %q", tok)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("bad JWT payload: %v", err)
	}
	return string(pb)
}

func roleCred(t *testing.T, h *ecrHandler) string {
	t.Helper()
	c := ecrRoleClaims()
	cred, err := h.signer.mintCaller(ecrCaller{Sub: c.Sub, Groups: c.Groups, AssumedRole: c.AssumedRole}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

func TestECRToken_AssumedRoleScopes(t *testing.T) {
	pullPair := []string{"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"}
	cases := []struct {
		name   string
		authz  *dataplaneauthz.Checker
		scopes []string
		want   map[string][]string
	}{
		{
			name:   "pull-only role: its repository's pull, never push, never another repository",
			authz:  roleChecker(pullPolicy()...),
			scopes: []string{"repository:app:pull,push", "repository:other:pull"},
			want:   map[string][]string{"app": {"pull"}},
		},
		{
			name:   "pull needs both image-read actions",
			authz:  roleChecker(dpAllow([]string{"ecr:BatchGetImage"}, "Repository::app")),
			scopes: []string{"repository:app:pull"},
			want:   map[string][]string{},
		},
		{
			name:   "pull needs both image-read actions (the other one)",
			authz:  roleChecker(dpAllow([]string{"ecr:GetDownloadUrlForLayer"}, "Repository::app")),
			scopes: []string{"repository:app:pull"},
			want:   map[string][]string{},
		},
		{
			name:   "push with the full documented set",
			authz:  roleChecker(dpAllow(append(append([]string{}, pullPair...), pushActions...), "Repository::app")),
			scopes: []string{"repository:app:pull,push"},
			want:   map[string][]string{"app": {"pull", "push"}},
		},
		{
			name:   "push missing ecr:PutImage is no push",
			authz:  roleChecker(dpAllow(append(append([]string{}, pullPair...), pushActions[:4]...), "Repository::app")),
			scopes: []string{"repository:app:pull,push"},
			want:   map[string][]string{"app": {"pull"}},
		},
		{
			name:   "ecr:* on a repository prefix",
			authz:  roleChecker(dpAllow([]string{"ecr:*"}, "Repository::team/*")),
			scopes: []string{"repository:team/web:pull,push", "repository:other:pull"},
			want:   map[string][]string{"team/web": {"pull", "push"}},
		},
		{
			name:   "an explicit deny on one repository wins over ecr:* on *",
			authz:  roleChecker(dpAllow([]string{"ecr:*"}, "*"), dpDeny([]string{"ecr:GetDownloadUrlForLayer"}, "Repository::secret")),
			scopes: []string{"repository:secret:pull", "repository:app:pull"},
			want:   map[string][]string{"app": {"pull"}},
		},
		{
			name:   "data-plane engine not configured: nothing",
			authz:  nil,
			scopes: []string{"repository:app:pull"},
			want:   map[string][]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The SAR reactor ALLOWS: were a role evaluated through RBAC, every scope would be granted.
			h := tokenModeECR(t, true, tc.authz)
			got, code := realmGrant(t, h, roleCred(t, h), tc.scopes...)
			if code != http.StatusOK {
				t.Fatalf("token endpoint status=%d", code)
			}
			if !equalGrants(got, tc.want) {
				t.Fatalf("granted %v, want %v", got, tc.want)
			}
		})
	}
}

// The end-to-end shape: a role session's GetAuthorizationToken credential, presented to the realm, gets
// exactly its policy's repositories (the docker login → docker pull flow).
func TestECRToken_AssumedRoleEndToEnd(t *testing.T) {
	h := tokenModeECR(t, true, roleChecker(pullPolicy()...))
	w, cred := getAuthToken(t, h, ecrRoleClaims())
	if w.Code != http.StatusOK {
		t.Fatalf("GetAuthorizationToken status=%d body=%s", w.Code, w.Body.String())
	}
	// docker login probes with no scope: an access-less token.
	if got, code := realmGrant(t, h, cred); code != http.StatusOK || len(got) != 0 {
		t.Fatalf("login probe: status=%d access=%v (want 200, none)", code, got)
	}
	got, _ := realmGrant(t, h, cred, "repository:app:pull", "repository:other:pull,push")
	if !equalGrants(got, map[string][]string{"app": {"pull"}}) {
		t.Fatalf("docker pull grants %v, want only app:pull", got)
	}
}

// A User's realm path is unchanged (the SubjectAccessReview decides), and a credential minted before the
// assumedRole claim existed is read exactly as before — as a User, never as a role.
func TestECRToken_UserAndLegacyCredentialUnchanged(t *testing.T) {
	// A data-plane policy that would grant the role everything: it must never be consulted for these.
	everything := roleChecker(dpAllow([]string{"*"}, "*"))

	allowed := tokenModeECR(t, true, everything)
	user := ecrClaims()
	userCred, err := allowed.signer.mintCaller(ecrCaller{Sub: user.Sub, Groups: user.Groups}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := realmGrant(t, allowed, userCred, "repository:app:pull,push")
	if !equalGrants(got, map[string][]string{"app": {"pull", "push"}}) {
		t.Fatalf("a user allowed by RBAC keeps pull+push, got %v", got)
	}

	// The pre-change credential claim set, verbatim (no assumedRole), for a role-session subject.
	denied := tokenModeECR(t, false, everything)
	now := time.Now()
	legacy, err := denied.signer.signJWT(
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": "ecr-cred-1"},
		map[string]any{"sub": "assumed-role/" + ecrTestRole + "/i-0abc", "groups": []string{"openinfra:users"}, "role": "",
			"purpose": "ecr-authz", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()},
	)
	if err != nil {
		t.Fatal(err)
	}
	c, err := denied.signer.verifyCaller(legacy)
	if err != nil {
		t.Fatalf("a legacy credential must still verify: %v", err)
	}
	if c.AssumedRole != "" || c.Sub != "assumed-role/"+ecrTestRole+"/i-0abc" {
		t.Fatalf("a legacy credential reads as the same User identity as before: %+v", c)
	}
	// Evaluated as a User through RBAC (which denies here) — the role's policy does not apply to it.
	got, _ = realmGrant(t, denied, legacy, "repository:app:pull")
	if len(got) != 0 {
		t.Fatalf("a legacy credential must not be authorized as the role, got %v", got)
	}
}

// "Revoke sessions" on the role refuses its ECR credentials minted before the cutoff.
func TestECRToken_RevokedRoleCredential(t *testing.T) {
	h := tokenModeECR(t, true, roleChecker(pullPolicy()...))
	cred := roleCred(t, h)

	h.revoke = fakeRevoker{cutoff: time.Now().Add(time.Minute), on: true}
	if _, code := realmGrant(t, h, cred, "repository:app:pull"); code != http.StatusUnauthorized {
		t.Fatalf("a credential minted before the role's revoke cutoff must be refused, status=%d", code)
	}
	h.revoke = fakeRevoker{cutoff: time.Now().Add(-time.Hour), on: true}
	if got, _ := realmGrant(t, h, cred, "repository:app:pull"); !equalGrants(got, map[string][]string{"app": {"pull"}}) {
		t.Fatalf("a credential minted after the cutoff keeps its grants, got %v", got)
	}
	// The cutoff is a role lever only — a User credential is not affected by it.
	h.revoke = fakeRevoker{cutoff: time.Now().Add(time.Minute), on: true}
	user := ecrClaims()
	userCred, _ := h.signer.mintCaller(ecrCaller{Sub: user.Sub, Groups: user.Groups}, time.Hour)
	if _, code := realmGrant(t, h, userCred, "repository:app:pull"); code != http.StatusOK {
		t.Fatalf("a user credential is not subject to a role's cutoff, status=%d", code)
	}
}

// A User's ecr: Deny holds at the registry token realm as at the ECR API: RBAC alone no longer grants a
// docker pull or push the User's data-plane policy denies on that repository.
func TestECRToken_UserDataPlaneDenyHolds(t *testing.T) {
	user := ecrClaims()
	userDeny := dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::" + user.Sub}, Statements: []policyengine.Statement{
			dpAllow([]string{"ecr:*"}, "*"),
			dpDeny([]string{"ecr:BatchGetImage"}, "Repository::secret-app"),
			dpDeny([]string{"ecr:PutImage"}, "Repository::app"),
		}}}}, nil
	}, time.Minute)
	h := tokenModeECR(t, true, userDeny)
	cred, err := h.signer.mintCaller(ecrCaller{Sub: user.Sub, Groups: user.Groups}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := realmGrant(t, h, cred, "repository:secret-app:pull", "repository:app:pull,push")
	if !equalGrants(got, map[string][]string{"app": {"pull"}}) {
		t.Fatalf("the User's Denies must remove secret-app pull and app push, got %v", got)
	}
}

func equalGrants(got, want map[string][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for repo, acts := range want {
		g := got[repo]
		if len(g) != len(acts) {
			return false
		}
		for i := range acts {
			if g[i] != acts[i] {
				return false
			}
		}
	}
	return true
}
