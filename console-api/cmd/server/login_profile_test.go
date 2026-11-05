package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/loginprofile"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

const (
	lpConsoleNS = "open-infra-console"
	lpStoreNS   = "open-infra-aws-shim"
)

func init() { loginBcryptCost = bcrypt.MinCost }

// fakeAPI is the slice of the API server sign-in uses: kind: User (GET, merge PATCH) and Secrets (GET,
// POST, PUT, DELETE), keyed by path.
type fakeAPI struct {
	mu      sync.Mutex
	objects map[string]map[string]any // path -> object
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	typed := func(obj map[string]any) map[string]any {
		if strings.Contains(path, "/secrets") {
			obj["kind"], obj["apiVersion"] = "Secret", "v1"
		}
		return obj
	}
	switch r.Method {
	case http.MethodGet:
		obj, ok := f.objects[path]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`))
			return
		}
		_ = json.NewEncoder(w).Encode(typed(obj))
	case http.MethodPost: // a Secret create: /api/v1/namespaces/<ns>/secrets
		var obj map[string]any
		if json.Unmarshal(body, &obj) != nil || obj["metadata"] == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		name := obj["metadata"].(map[string]any)["name"].(string)
		key := path + "/" + name
		if _, exists := f.objects[key]; exists {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"AlreadyExists","code":409}`))
			return
		}
		f.objects[key] = obj
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(typed(obj))
	case http.MethodPut:
		var obj map[string]any
		_ = json.Unmarshal(body, &obj)
		f.objects[path] = obj
		_ = json.NewEncoder(w).Encode(typed(obj))
	case http.MethodPatch:
		obj, ok := f.objects[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var patch map[string]any
		_ = json.Unmarshal(body, &patch)
		mergePatch(obj, patch)
		_ = json.NewEncoder(w).Encode(obj)
	case http.MethodDelete:
		delete(f.objects, path)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Success"}`))
	}
}

func mergePatch(dst, patch map[string]any) {
	for k, v := range patch {
		if v == nil {
			delete(dst, k)
			continue
		}
		if pm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				mergePatch(dm, pm)
				continue
			}
		}
		dst[k] = v
	}
}

func userPath(name string) string { return usersAbsPath(lpConsoleNS) + "/" + name }

// lpAuth is an authStore over fakeAPI, with user alice (local) whose password is old-pass-1.
func lpAuth(t *testing.T, ann map[string]any) (*authStore, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{objects: map[string]map[string]any{}}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	cs := kubernetes.NewForConfigOrDie(&rest.Config{Host: srv.URL, ContentConfig: rest.ContentConfig{ContentType: "application/json"}})
	a := &authStore{cs: cs, ns: lpConsoleNS, mode: "local", sessionKey: []byte("test-key"), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	t.Setenv("KEYS_NAMESPACE", lpStoreNS)
	ref, _, err := a.storePassword(context.Background(), "alice", "Old-Pass-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{"name": "alice", "namespace": lpConsoleNS}
	if ann != nil {
		meta["annotations"] = ann
	}
	api.objects[userPath("alice")] = map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
		"metadata": meta, "spec": map[string]any{"source": "local", "groups": []any{"readers"}, "passwordSecretRef": ref}}
	return a, api
}

func lpLogin(t *testing.T, a *authStore, user, pw string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"Username": user, "Password": pw})
	w := httptest.NewRecorder()
	handleLogin(a)(w, httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(b)))
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return w, c
		}
	}
	return w, nil
}

func lpGuarded(a *authStore, c *http.Cookie) int {
	r := httptest.NewRequest(http.MethodGet, "/api/buckets", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	a.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, r)
	return w.Code
}

func lpChange(a *authStore, c *http.Cookie, oldPW, newPW string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"oldPassword": oldPW, "newPassword": newPW})
	r := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", bytes.NewReader(b))
	r.AddCookie(c)
	r.Header.Set(csrfHeader, "1")
	w := httptest.NewRecorder()
	handleChangeOwnPassword(a)(w, r)
	return w
}

// A login profile in the credential store signs in, and a PasswordResetRequired one reaches nothing until
// the password is changed with the old one.
func TestConsole_PasswordResetRequired(t *testing.T) {
	a, api := lpAuth(t, map[string]any{loginprofile.AnnResetRequired: "true"})

	w, c := lpLogin(t, a, "alice", "Old-Pass-1")
	if w.Code != 200 || c == nil || !strings.Contains(w.Body.String(), `"passwordResetRequired":true`) {
		t.Fatalf("sign-in with a store profile: %d %s", w.Code, w.Body.String())
	}
	if code := lpGuarded(a, c); code != http.StatusForbidden {
		t.Fatalf("a reset-required session reached the API: %d", code)
	}
	if w := lpChange(a, c, "wrong", "New-Pass-2"); w.Code != 400 || !strings.Contains(w.Body.String(), "oldPassword is invalid") {
		t.Fatalf("a wrong old password: %d %s", w.Code, w.Body.String())
	}
	if w := lpChange(a, c, "Old-Pass-1", "weak"); w.Code != 400 || !strings.Contains(w.Body.String(), "PasswordPolicyViolation") {
		t.Fatalf("a weak new password: %d %s", w.Code, w.Body.String())
	}
	w = lpChange(a, c, "Old-Pass-1", "New-Pass-2")
	if w.Code != 200 {
		t.Fatalf("change password: %d %s", w.Code, w.Body.String())
	}
	var fresh *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie {
			fresh = ck
		}
	}
	if fresh == nil || lpGuarded(a, fresh) != http.StatusOK {
		t.Fatal("after the change the session must be an ordinary one")
	}
	ann := api.objects[userPath("alice")]["metadata"].(map[string]any)["annotations"].(map[string]any)
	if _, still := ann[loginprofile.AnnResetRequired]; still || ann[loginprofile.AnnPasswordLastChanged] == nil {
		t.Fatalf("annotations after the change: %v", ann)
	}
	if w, _ := lpLogin(t, a, "alice", "Old-Pass-1"); w.Code != 401 {
		t.Fatalf("the old password still signs in: %d", w.Code)
	}
	if w, _ := lpLogin(t, a, "alice", "New-Pass-2"); w.Code != 200 || !strings.Contains(w.Body.String(), `"passwordResetRequired":false`) {
		t.Fatalf("the new password: %d %s", w.Code, w.Body.String())
	}
}

// An account password policy past its MaxPasswordAge forces a change; with HardExpiry it refuses.
func TestConsole_PasswordExpiry(t *testing.T) {
	a, _ := lpAuth(t, map[string]any{loginprofile.AnnPasswordLastChanged: "2020-01-01T00:00:00Z"})
	store := a.loginStore()
	if err := store.PutPolicy(context.Background(), "000000000000", loginprofile.Policy{MaxPasswordAge: 30}); err != nil {
		t.Fatal(err)
	}
	if w, c := lpLogin(t, a, "alice", "Old-Pass-1"); w.Code != 200 || !strings.Contains(w.Body.String(), `"passwordResetRequired":true`) || lpGuarded(a, c) != 403 {
		t.Fatalf("an expired password must be changed first: %d %s", w.Code, w.Body.String())
	}
	if err := store.PutPolicy(context.Background(), "000000000000", loginprofile.Policy{MaxPasswordAge: 30, HardExpiry: true}); err != nil {
		t.Fatal(err)
	}
	if w, _ := lpLogin(t, a, "alice", "Old-Pass-1"); w.Code != 403 || !strings.Contains(w.Body.String(), "PasswordExpired") {
		t.Fatalf("HardExpiry refuses an expired password: %d %s", w.Code, w.Body.String())
	}
}

// A User whose passwordSecretRef names someone else's profile, or any other namespace, signs in as no
// one; its own profile signs in.
func TestCRDPasswordHash_StoreRef(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	prof := func(user string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: loginprofile.SecretName(lpConsoleNS, user), Namespace: lpStoreNS,
			Labels: map[string]string{loginprofile.LabelProfile: "true", loginprofile.LabelUser: user, loginprofile.LabelUserNamespace: lpConsoleNS}},
			Data: map[string][]byte{"hash": hash}}
	}
	cs := fake.NewSimpleClientset(prof("bob"), prof("alice"),
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "elsewhere", Namespace: "kube-system"}, Data: map[string][]byte{"hash": hash}})
	t.Setenv("KEYS_NAMESPACE", lpStoreNS)
	a := &authStore{cs: cs, ns: lpConsoleNS}
	user := func(name, ref, ns string) crdUser {
		var u crdUser
		u.Metadata.Name = name
		u.Spec.PasswordSecretRef.Name, u.Spec.PasswordSecretRef.Namespace = ref, ns
		return u
	}
	if _, ok := a.crdPasswordHash(context.Background(), user("alice", loginprofile.SecretName(lpConsoleNS, "alice"), lpStoreNS)); !ok {
		t.Fatal("alice's own store profile must be read")
	}
	if _, ok := a.crdPasswordHash(context.Background(), user("alice", loginprofile.SecretName(lpConsoleNS, "bob"), lpStoreNS)); ok {
		t.Fatal("alice pointing at bob's profile must not sign in")
	}
	if _, ok := a.crdPasswordHash(context.Background(), user("alice", "elsewhere", "kube-system")); ok {
		t.Fatal("a ref into another namespace must never be read")
	}
}
