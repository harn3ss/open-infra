package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
)

type fakeTrust struct {
	vmRoles map[string]bool // "ns/role" -> trusts vm
}

func (f fakeTrust) vmTrusted(_ context.Context, ns, role string) ([]string, bool) {
	if f.vmRoles[ns+"/"+role] {
		return []string{"openinfra:users"}, true
	}
	return nil, false
}

type fakeSAResolver struct {
	byToken map[string]saIdentity
}

func (f fakeSAResolver) resolveSARole(_ context.Context, token string) (saIdentity, bool) {
	id, ok := f.byToken[token]
	return id, ok
}

func testVMCreds(t *testing.T) (*vmCredsHandler, *awssts.Minter) {
	t.Helper()
	m, err := awssts.NewMinter([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	h := &vmCredsHandler{
		resolver: fakeSAResolver{byToken: map[string]saIdentity{
			"good-token":      {role: "vmapp", namespace: "default", caller: "system:serviceaccount:default:vm-web01", vmName: "web01"},
			"untrusted-token": {role: "untrusted", namespace: "default", caller: "system:serviceaccount:default:vm-db01", vmName: "db01"},
			"norole-token":    {role: "", namespace: "default", caller: "system:serviceaccount:default:vm-x", vmName: "x"},
		}},
		trust:  fakeTrust{vmRoles: map[string]bool{"default/vmapp": true}},
		minter: m,
		ttl:    time.Hour,
	}
	return h, m
}

func callVMCreds(h *vmCredsHandler, method, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, vmCredsPath, nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.serve(w, r, "req")
	return w
}

func TestVMCreds_PathMatch(t *testing.T) {
	h, _ := testVMCreds(t)
	if !h.isVMCredsPath(httptest.NewRequest("GET", vmCredsPath, nil)) {
		t.Error("vmCredsPath must match")
	}
	for _, p := range []string{"/", "/mybucket/key", "/latest/meta-data/x"} {
		if h.isVMCredsPath(httptest.NewRequest("GET", p, nil)) {
			t.Errorf("%q must not match the vm-credentials path (no shadowing AWS calls)", p)
		}
	}
}

func TestVMCreds_MintAndVerify(t *testing.T) {
	h, m := testVMCreds(t)
	w := callVMCreds(h, http.MethodGet, "good-token")
	if w.Code != 200 {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	var c containerCreds
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatalf("json: %v", err)
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.Token == "" {
		t.Fatalf("incomplete creds: %+v", c)
	}
	if _, err := time.Parse(time.RFC3339, c.Expiration); err != nil {
		t.Errorf("Expiration not RFC3339: %q", c.Expiration)
	}
	sess, ok := m.Verify(c.AccessKeyID, c.Token)
	if !ok || sess.RoleName != "vmapp" {
		t.Fatalf("minted token must verify to role vmapp, got ok=%v role=%q", ok, sess.RoleName)
	}
}

func TestVMCreds_BearerPrefixTolerated(t *testing.T) {
	h, _ := testVMCreds(t)
	if w := callVMCreds(h, http.MethodGet, "Bearer good-token"); w.Code != 200 {
		t.Fatalf("a Bearer-prefixed token must work, got %d", w.Code)
	}
}

func TestVMCreds_FailClosed(t *testing.T) {
	h, _ := testVMCreds(t)
	cases := []struct {
		name, auth string
		want       int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"bad token", "nonsense", http.StatusUnauthorized},
		{"SA without role annotation", "norole-token", http.StatusUnauthorized},
		{"role not vm-trusted", "untrusted-token", http.StatusForbidden},
	}
	for _, c := range cases {
		if w := callVMCreds(h, http.MethodGet, c.auth); w.Code != c.want {
			t.Errorf("%s: code=%d want %d (%s)", c.name, w.Code, c.want, w.Body.String())
		}
	}
	// A non-GET is rejected.
	if w := callVMCreds(h, http.MethodPost, "good-token"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST must be 405, got %d", w.Code)
	}
}
