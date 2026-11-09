package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The console's IAM pages manage the session's account (iam_scope.go): a session switched into a member
// account's role manages that account's IAM, never the management account's (#417).

const (
	scMember = "900000000002"
	scHome   = "team-b"
)

// scopeAuth is the console's store over a fake API that knows the member account's home namespace, with
// the gate in enforce: the member account's administrator role (and the management account's admin
// user) allowed every IAM action.
func scopeAuth(t *testing.T) (*authStore, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{objects: map[string]map[string]any{}}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	cs := kubernetes.NewForConfigOrDie(&rest.Config{Host: srv.URL, ContentConfig: rest.ContentConfig{ContentType: "application/json"}})
	t.Setenv("KEYS_NAMESPACE", lpStoreNS)
	api.objects["/api/v1/namespaces"] = map[string]any{"kind": "NamespaceList", "apiVersion": "v1", "items": []any{
		map[string]any{"metadata": map[string]any{"name": scHome,
			"labels": map[string]any{accounts.LabelAccountID: scMember, accounts.LabelAccountHome: "true"}}}}}
	w := testWorld(t, map[string]string{"AdministratorAccess": adminDoc}, map[string][]string{
		"Role::member-admin": {"AdministratorAccess"}, "User::admin": {"AdministratorAccess"}})
	newTestAuthz(t, iamauthz.ModeEnforce, w, false)
	return &authStore{cs: cs, ns: lpConsoleNS, mode: "local", sessionKey: []byte("k"), logger: testLogger()}, api
}

func memberSession() sessionClaims {
	c := userClaims("admin")
	c.AssumedRole, c.Account = "member-admin", scMember
	return c
}

// scopeCall serves one IAM page as c, past its route gate (which decided it in enforce).
func scopeCall(h http.HandlerFunc, method, pattern, path, body string, c sessionClaims) *httptest.ResponseRecorder {
	router := chi.NewRouter()
	router.MethodFunc(method, pattern, h)
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := as(httptest.NewRequest(method, path, rd), c)
	r = r.WithContext(withRouteAuthorized(r.Context()))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec
}

func seedObject(api *fakeAPI, path string, obj map[string]any) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.objects[path] = obj
}

func hasObject(api *fakeAPI, path string) bool {
	api.mu.Lock()
	defer api.mu.Unlock()
	_, ok := api.objects[path]
	return ok
}

func seedPolicy(api *fakeAPI, ns, name string, managed bool) {
	labels := map[string]any{}
	if managed {
		labels["openinfra.dev/managed-policy"] = "true"
	}
	seedObject(api, policiesAbsPath(ns)+"/"+name, map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "Policy",
		"metadata": map[string]any{"name": name, "namespace": ns, "labels": labels},
		"spec":     map[string]any{"document": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`}})
}

// A member account's role session creates its own account's users and keys, sees only its own account's
// users, and is never handed the management account's same-named user.
func TestIAMScope_AMemberSessionManagesItsOwnAccountsUsers(t *testing.T) {
	auth, api := scopeAuth(t)
	keysNS := lpStoreNS
	mgmtAlice := usersAbsPath(lpConsoleNS) + "/alice"
	seedObject(api, mgmtAlice, map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
		"metadata": map[string]any{"name": "alice", "namespace": lpConsoleNS}, "spec": map[string]any{"source": "local", "groups": []any{"admins"}}})
	seedObject(api, usersAbsPath(lpConsoleNS)+"/bob", map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
		"metadata": map[string]any{"name": "bob", "namespace": lpConsoleNS}, "spec": map[string]any{"source": "local"}})
	// The management account's alice holds a key.
	store := keyStore(auth.cs, keysNS)
	if err := store.Put(context.Background(), awskeys.Key{AccessKeyID: "OIAKMGMTALICE0000001", SecretKey: "s", Owner: "alice"}); err != nil {
		t.Fatal(err)
	}

	// CreateUser, in the member account: the User lands in its home, the management account's is untouched.
	rec := scopeCall(handleIAMUserCreate(auth.cs, auth, testLogger()), http.MethodPost, "/api/iam/users", "/api/iam/users",
		`{"name":"alice","groups":["devs"],"password":"Member-Pass-1234"}`, memberSession())
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateUser in the member account: %d %s", rec.Code, rec.Body.String())
	}
	if !hasObject(api, usersAbsPath(scHome)+"/alice") {
		t.Fatal("the member account's user was not created in its IAM home")
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created["arn"] != "arn:aws:iam::"+scMember+":user/alice" {
		t.Errorf("the created user's ARN is %v", created["arn"])
	}
	api.mu.Lock()
	groups := api.objects[mgmtAlice]["spec"].(map[string]any)["groups"]
	for p := range api.objects {
		if strings.HasPrefix(p, "/api/v1/namespaces/"+scHome+"/secrets") {
			t.Errorf("a password was written into the member account's own namespace: %s", p)
		}
	}
	api.mu.Unlock()
	if g, _ := groups.([]any); len(g) != 1 || g[0] != "admins" {
		t.Errorf("the management account's alice was changed: groups %v", groups)
	}

	// GetUser: the member account sees its own users only.
	if rec := scopeCall(handleIAMUserGet(auth.cs, auth, testLogger()), http.MethodGet, "/api/iam/users/{name}", "/api/iam/users/bob", "", memberSession()); rec.Code != http.StatusNotFound {
		t.Errorf("the member account read the management account's bob: %d %s", rec.Code, rec.Body.String())
	}

	// CreateAccessKey: the key records the member account, and is listed only there.
	rec = scopeCall(handleIAMAccessKeyCreate(auth.cs, auth, keysNS, testLogger()), http.MethodPost, "/api/iam/users/{name}/access-keys",
		"/api/iam/users/alice/access-keys", "", memberSession())
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateAccessKey in the member account: %d %s", rec.Code, rec.Body.String())
	}
	var key accessKeyCreateView
	_ = json.Unmarshal(rec.Body.Bytes(), &key)
	m, ok := store.Describe(context.Background(), key.AccessKeyID)
	if !ok || m.Account != scMember || m.Owner != "alice" {
		t.Fatalf("the member account's key is %+v (found %v), want owner alice in account %s", m, ok, scMember)
	}
	listed := func(c sessionClaims) []string {
		rec := scopeCall(handleIAMAccessKeysList(auth.cs, auth, keysNS, testLogger()), http.MethodGet, "/api/iam/users/{name}/access-keys",
			"/api/iam/users/alice/access-keys", "", c)
		var out []accessKeyView
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		ids := []string{}
		for _, k := range out {
			ids = append(ids, k.AccessKeyID)
		}
		return ids
	}
	if ids := listed(memberSession()); len(ids) != 1 || ids[0] != key.AccessKeyID {
		t.Errorf("the member account lists %v, want only its alice's key", ids)
	}
	if ids := listed(userClaims("admin")); len(ids) != 1 || ids[0] != "OIAKMGMTALICE0000001" {
		t.Errorf("the management account lists %v, want only its alice's key", ids)
	}
	// The member account cannot deactivate or delete the management account's alice's key.
	if rec := scopeCall(handleIAMAccessKeyDelete(auth.cs, auth, keysNS, testLogger()), http.MethodDelete, "/api/iam/users/{name}/access-keys/{id}",
		"/api/iam/users/alice/access-keys/OIAKMGMTALICE0000001", "", memberSession()); rec.Code != http.StatusNotFound {
		t.Errorf("the member account deleted the management account's key: %d", rec.Code)
	}

	// DeleteUser: the member account's alice goes with its key; the management account's alice and its
	// key stay.
	if rec := scopeCall(handleIAMUserDelete(auth.cs, auth, keysNS, testLogger()), http.MethodDelete, "/api/iam/users/{name}",
		"/api/iam/users/alice", "", memberSession()); rec.Code != http.StatusOK {
		t.Fatalf("DeleteUser in the member account: %d %s", rec.Code, rec.Body.String())
	}
	if hasObject(api, usersAbsPath(scHome)+"/alice") {
		t.Error("the member account's user was not deleted")
	}
	if _, ok := store.Describe(context.Background(), key.AccessKeyID); ok {
		t.Error("the member account's deleted user kept its access key")
	}
	if !hasObject(api, mgmtAlice) {
		t.Error("deleting the member account's alice deleted the management account's")
	}
	if _, ok := store.Describe(context.Background(), "OIAKMGMTALICE0000001"); !ok {
		t.Error("deleting the member account's alice deleted the management account's alice's key")
	}
}

// Deleting a user deletes its access keys, as the AWS console does: none is left to authenticate again as
// a user later created with the same name.
func TestIAMScope_DeleteUserRemovesItsAccessKeys(t *testing.T) {
	auth, api := scopeAuth(t)
	keysNS := lpStoreNS
	seedObject(api, usersAbsPath(lpConsoleNS)+"/carol", map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
		"metadata": map[string]any{"name": "carol", "namespace": lpConsoleNS}, "spec": map[string]any{"source": "local"}})
	store := keyStore(auth.cs, keysNS)
	for _, id := range []string{"OIAKCAROL00000000001", "OIAKCAROL00000000002"} {
		if err := store.Put(context.Background(), awskeys.Key{AccessKeyID: id, SecretKey: "s", Owner: "carol"}); err != nil {
			t.Fatal(err)
		}
	}
	if rec := scopeCall(handleIAMUserDelete(auth.cs, auth, keysNS, testLogger()), http.MethodDelete, "/api/iam/users/{name}",
		"/api/iam/users/carol", "", userClaims("admin")); rec.Code != http.StatusOK {
		t.Fatalf("DeleteUser: %d %s", rec.Code, rec.Body.String())
	}
	if metas, _ := store.List(context.Background(), "carol"); len(metas) != 0 {
		t.Errorf("the deleted user kept %d access key(s)", len(metas))
	}
}

// A member account's policies page lists its own policies and the AWS-managed library, never the
// management account's own policies; the management account's lists its own and the library.
func TestIAMScope_PoliciesAreTheAccountsOwnAndTheManagedLibrary(t *testing.T) {
	auth, api := scopeAuth(t)
	seedPolicy(api, lpConsoleNS, "aws-readonlyaccess", true)
	seedPolicy(api, lpConsoleNS, "mgmt-only", false)
	seedPolicy(api, scHome, "team-policy", false)
	names := func(c sessionClaims) map[string]string {
		rec := scopeCall(handleIAMPoliciesList(auth.cs, auth, testLogger()), http.MethodGet, "/api/iam/policies", "/api/iam/policies", "", c)
		var out []iamPolicyView
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		m := map[string]string{}
		for _, p := range out {
			m[p.Name] = p.ARN
		}
		return m
	}
	member := names(memberSession())
	if _, ok := member["team-policy"]; !ok || member["team-policy"] != "arn:aws:iam::"+scMember+":policy/team-policy" {
		t.Errorf("the member account's own policy: %v", member)
	}
	if _, ok := member["aws-readonlyaccess"]; !ok {
		t.Errorf("the member account does not see the AWS-managed library: %v", member)
	}
	if _, ok := member["mgmt-only"]; ok {
		t.Errorf("the member account sees the management account's own policy: %v", member)
	}
	mgmt := names(userClaims("admin"))
	if _, ok := mgmt["team-policy"]; ok {
		t.Errorf("the management account's page lists a member account's policy: %v", mgmt)
	}
	if _, ok := mgmt["mgmt-only"]; !ok {
		t.Errorf("the management account's own policy is missing: %v", mgmt)
	}
	get := func(name string) int {
		return scopeCall(handleIAMPolicyGet(auth.cs, auth, testLogger()), http.MethodGet, "/api/iam/policies/{name}",
			"/api/iam/policies/"+name, "", memberSession()).Code
	}
	if code := get("mgmt-only"); code != http.StatusNotFound {
		t.Errorf("the member account read the management account's own policy: %d", code)
	}
	if code := get("aws-readonlyaccess"); code != http.StatusOK {
		t.Errorf("the member account could not read an AWS-managed policy: %d", code)
	}
}

// A member account's grant names its own policies or the AWS-managed library, never another account's.
func TestIAMScope_AMemberAccountsGrantNamesOnlyItsOwnPolicies(t *testing.T) {
	auth, api := scopeAuth(t)
	seedPolicy(api, lpConsoleNS, "aws-readonlyaccess", true)
	seedPolicy(api, lpConsoleNS, "mgmt-only", false)
	seedPolicy(api, scHome, "team-policy", false)
	seedPolicy(api, "team-c", "other-account", false)
	r := as(httptest.NewRequest(http.MethodGet, "/", nil), memberSession())
	scoped, ok := iamAuth(httptest.NewRecorder(), r, auth)
	if !ok || !scoped.member() || scoped.ns != scHome {
		t.Fatalf("the member session's scope: %+v %v", scoped, ok)
	}
	for _, c := range []struct {
		ref     string
		missing bool
	}{
		{"team-policy", false}, {scHome + "/team-policy", false}, {"aws-readonlyaccess", false},
		{lpConsoleNS + "/aws-readonlyaccess", false}, {"mgmt-only", true}, {lpConsoleNS + "/mgmt-only", true},
		{"team-c/other-account", true}, {scHome + "/aws-readonlyaccess", true},
	} {
		got, err := scoped.missingPolicy(context.Background(), []string{c.ref})
		if err != nil {
			t.Fatalf("%s: %v", c.ref, err)
		}
		if (got != "") != c.missing {
			t.Errorf("%s: missing=%q, want missing=%v", c.ref, got, c.missing)
		}
	}
}

// The scope of a session in an account the console cannot manage is refused, and nothing is touched.
func TestIAMScope_AnUnknownAccountIsRefused(t *testing.T) {
	auth, api := scopeAuth(t)
	api.mu.Lock()
	delete(api.objects, "/api/v1/namespaces") // no namespace is this account's home
	api.mu.Unlock()
	c := userClaims("admin")
	c.AssumedRole, c.Account = "member-admin", "955555555555"
	rec := httptest.NewRecorder()
	r := as(httptest.NewRequest(http.MethodGet, "/", nil), c)
	if _, ok := iamAuth(rec, r, auth); ok {
		t.Fatalf("an account with no home was given a scope")
	}
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "AccessDenied") {
		t.Errorf("refusal: %d %s", rec.Code, rec.Body.String())
	}
}
