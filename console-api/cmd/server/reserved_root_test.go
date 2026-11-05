package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"golang.org/x/crypto/bcrypt"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// apiServerWithUsers serves the console-auth Secret (root and a second account given role root), and
// kind: Users with password Secrets: alice, and an impostor named root with a valid password of its own.
func apiServerWithUsers(t *testing.T) kubernetes.Interface {
	t.Helper()
	hash := func(pw string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	ns := "open-infra-console"
	local, _ := json.Marshal(map[string]userRec{
		"root": {Hash: hash("break-glass"), Role: "root"},
		"ops":  {Hash: hash("ops-password"), Role: "root"},
	})
	secret := func(name string, data map[string][]byte) any {
		d := map[string]string{}
		for k, v := range data {
			d[k] = base64.StdEncoding.EncodeToString(v)
		}
		return map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": name, "namespace": ns}, "data": d}
	}
	user := func(name, pwSecret string) any {
		return map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "User", "metadata": map[string]any{"name": name},
			"spec": map[string]any{"groups": []string{"admins"}, "source": "local", "passwordSecretRef": map[string]any{"name": pwSecret}}}
	}
	objects := map[string]any{
		"/api/v1/namespaces/" + ns + "/secrets/" + authSecret:               secret(authSecret, map[string][]byte{"users": local}),
		"/api/v1/namespaces/" + ns + "/secrets/alice-pw":                    secret("alice-pw", map[string][]byte{"hash": []byte(hash("alice-password"))}),
		"/api/v1/namespaces/" + ns + "/secrets/impostor-pw":                 secret("impostor-pw", map[string][]byte{"hash": []byte(hash("impostor-password"))}),
		"/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/users/alice":      user("alice", "alice-pw"),
		"/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/users/root":       user("root", "impostor-pw"),
		"/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/users/Root":       user("Root", "impostor-pw"),
		"/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/users/ROOT":       user("ROOT", "impostor-pw"),
		"/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/users/%20root%20": user(" root ", "impostor-pw"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obj, ok := objects[r.URL.EscapedPath()]
		if !ok {
			obj, ok = objects[r.URL.Path]
		}
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(obj)
	}))
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// Only the Secret-backed root signs in as root: a kind: User named root (in any spelling) is never
// accepted, even with its own valid password, and a second Secret account given role root is an
// administrator, not root. The same store signs alice in, so the User path is live in this test.
func TestRootName_OnlyTheSecretRootSignsInAsRoot(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"local", "ldap"} {
		a := &authStore{cs: apiServerWithUsers(t), ns: "open-infra-console", mode: mode}

		if role, _, ok := a.verify(ctx, "alice", "alice-password"); !ok || role != "admin" {
			t.Fatalf("%s: the fixture's kind: User alice did not sign in (role=%q ok=%v)", mode, role, ok)
		}
		if role, groups, ok := a.verify(ctx, "root", "break-glass"); !ok || role != "root" || groups != nil {
			t.Fatalf("%s: break-glass root failed: role=%q groups=%v ok=%v", mode, role, groups, ok)
		}
		for _, name := range []string{"root", "Root", "ROOT", " root "} {
			if role, _, ok := a.verify(ctx, name, "impostor-password"); ok {
				t.Fatalf("%s: a kind: User named %q signed in as role %q: only the Secret-backed root is root", mode, name, role)
			}
		}
		if _, _, ok := a.verify(ctx, "Root", "break-glass"); ok {
			t.Fatalf("%s: root's password signed in under the spelling Root", mode)
		}
		if role, _, ok := a.verify(ctx, "ops", "ops-password"); !ok || role != "admin" {
			t.Fatalf("%s: a Secret account given role root must sign in as an administrator, got role=%q ok=%v", mode, role, ok)
		}
	}
}

// No session names root or carries its role unless it is the Secret root's: issuing one is refused,
// and a cookie issued before the name was reserved no longer parses.
func TestRootName_SessionsNamedRootAreTheSecretRoot(t *testing.T) {
	a := &authStore{sessionKey: []byte("test-session-key-test-session-key")}
	valid := []iam.Claims{
		{Sub: "root", Role: "root"},
		{Sub: "root", Role: "root", AssumedRole: "open-infra-console/admin", Account: "111111111111"}, // root, switched into a role
		{Sub: "alice", Role: "admin", Groups: []string{"openinfra:admins"}},
	}
	for _, c := range valid {
		tok, err := a.issueClaims(c)
		if err != nil {
			t.Fatalf("%+v: refused: %v", c, err)
		}
		if _, ok := a.parse(tok); !ok {
			t.Fatalf("%+v: issued but does not parse", c)
		}
	}
	invalid := []iam.Claims{
		{Sub: "root", Role: "admin", Groups: []string{"openinfra:admins", "openinfra:users"}}, // a kind: User named root
		{Sub: "root", Role: "readonly"}, // a directory account named root
		{Sub: "ROOT", Role: "readonly"}, // a directory account spelled ROOT
		{Sub: " root", Role: "root"},    // not exactly the Secret's root
		{Sub: "alice", Role: "root"},    // only root carries role root
		{Sub: "root", Role: "root", Groups: []string{"openinfra:admins"}},
	}
	for _, c := range invalid {
		if _, err := a.issueClaims(c); err == nil {
			t.Fatalf("%+v: a session was issued", c)
		}
		// The same claims signed as an older console would have: the cookie must not parse.
		body, _ := json.Marshal(sessionClaims{Claims: c, Exp: 1 << 40})
		tok := signedForTest(a, body)
		if _, ok := a.parse(tok); ok {
			t.Fatalf("%+v: an old session cookie still parses", c)
		}
	}
}

// signedForTest signs a raw session body with the store's key, as issueClaims does.
func signedForTest(a *authStore, raw []byte) string {
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Creating a User named root is refused in AWS's shape, from the IAM page in any spelling, before any
// authorization or write.
func TestRootName_ConsoleUserCreateRefusesRoot(t *testing.T) {
	h := handleIAMUserCreate(nil, nil, testLogger())
	for _, name := range []string{"root", "Root", " ROOT "} {
		body, _ := json.Marshal(map[string]any{"name": name, "password": "a-long-password"})
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, "/api/iam/users", bytes.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%q: status %d, want 400", name, w.Code)
		}
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if out["errorCode"] != "InvalidInput" || !strings.Contains(out["error"], "reserved") {
			t.Fatalf("%q: %v, want InvalidInput naming the reservation", name, out)
		}
	}
}

// Through the Kubernetes proxy a User named root cannot be created or changed in any namespace, in
// any mode (JSON or YAML, by name or by apply); it can still be read and deleted, and every other
// User passes with its body intact.
func TestRootName_ProxyRefusesCreatingOrChangingRootUser(t *testing.T) {
	for _, mode := range []iamauthz.Mode{iamauthz.ModeLegacy, iamauthz.ModeEnforce} {
		z := newTestAuthz(t, mode, testWorld(t, map[string]string{"admin": adminDoc}, map[string][]string{"User::root-admin": {"admin"}}), true)
		var forwarded string
		h := z.proxyHandler(k8sPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			forwarded = string(b)
			_, _ = w.Write([]byte("forwarded"))
		}))
		c := userClaims("root-admin", "openinfra:admins")
		send := func(method, path, ctype, body string) *httptest.ResponseRecorder {
			forwarded = ""
			r := httptest.NewRequest(method, k8sPrefix+path, strings.NewReader(body))
			if ctype != "" {
				r.Header.Set("Content-Type", ctype)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, as(r, c))
			return w
		}
		users := "/apis/iam.openinfra.dev/v1/namespaces/team-a/users"
		refused := []struct{ method, path, ctype, body string }{
			{http.MethodPost, users, "application/json", `{"apiVersion":"iam.openinfra.dev/v1","kind":"User","metadata":{"name":"root"}}`},
			{http.MethodPost, users, "application/yaml", "apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata:\n  name: ROOT\n"},
			{http.MethodPost, users, "application/json", `not a body the gate can read`},
			{http.MethodPut, users + "/root", "application/json", `{"metadata":{"name":"root"}}`},
			{http.MethodPatch, users + "/root", "application/apply-patch+yaml", "metadata:\n  name: root\n"},
			{http.MethodPatch, users + "/root", "application/merge-patch+json", `{"spec":{"groups":["admins"]}}`},
		}
		for _, tc := range refused {
			w := send(tc.method, tc.path, tc.ctype, tc.body)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "InvalidInput") || forwarded != "" {
				t.Fatalf("%s: %s %s: status %d body %s forwarded %q, want a 400 InvalidInput", mode, tc.method, tc.path, w.Code, w.Body, forwarded)
			}
		}
		passed := []struct{ method, path, body string }{
			{http.MethodGet, users + "/root", ""},
			{http.MethodDelete, users + "/root", ""},
			{http.MethodPost, users, `{"apiVersion":"iam.openinfra.dev/v1","kind":"User","metadata":{"name":"alice"}}`},
			{http.MethodPost, users, `{"apiVersion":"iam.openinfra.dev/v1","kind":"User","metadata":{"generateName":"root"}}`},
			{http.MethodPost, "/apis/iam.openinfra.dev/v1/namespaces/team-a/groups", `{"metadata":{"name":"root"}}`},
		}
		for _, tc := range passed {
			w := send(tc.method, tc.path, "application/json", tc.body)
			if w.Body.String() != "forwarded" || forwarded != tc.body {
				t.Fatalf("%s: %s %s: status %d body %s, forwarded %q: want it forwarded with its body intact", mode, tc.method, tc.path, w.Code, w.Body, forwarded)
			}
		}
	}
}

// peekBody puts back the whole body, not only the part it read, so a body larger than the peek limit
// reaches its handler whole.
func TestPeekBodyRestoresALargeBody(t *testing.T) {
	big := `{"name":"` + strings.Repeat("x", 2*maxPeek) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(big))
	if got := peekBody(r, "name"); got != "" {
		t.Fatalf("a body over the limit yielded %d bytes", len(got))
	}
	b, _ := io.ReadAll(r.Body)
	if string(b) != big {
		t.Fatalf("the handler read %d bytes of %d", len(b), len(big))
	}
}
