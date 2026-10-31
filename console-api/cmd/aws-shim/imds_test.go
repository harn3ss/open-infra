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

type fakePodLookup struct {
	byIP map[string]vmIdentity
}

func (f fakePodLookup) lookup(_ context.Context, ip string) (vmIdentity, bool) {
	id, ok := f.byIP[ip]
	return id, ok && id.role != ""
}

type fakeTrust struct {
	vmRoles map[string]bool // "ns/role" -> trusts vm
}

func (f fakeTrust) vmTrusted(_ context.Context, ns, role string) ([]string, bool) {
	if f.vmRoles[ns+"/"+role] {
		return []string{"openinfra:users"}, true
	}
	return nil, false
}

func testIMDS(t *testing.T) (*imdsHandler, *awssts.Minter) {
	t.Helper()
	m, err := awssts.NewMinter([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	h := &imdsHandler{
		pods: fakePodLookup{byIP: map[string]vmIdentity{
			"10.16.0.5": {role: "app-role", namespace: "team-a", vmName: "web01"},
			"10.16.0.9": {role: "untrusted-role", namespace: "team-a", vmName: "db01"},
		}},
		trust:  fakeTrust{vmRoles: map[string]bool{"team-a/app-role": true}},
		minter: m,
		ttl:    time.Hour,
	}
	return h, m
}

func doGET(h *imdsHandler, path, ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	h.serve(w, r, "req")
	return w
}

func TestIMDS_PathMatch(t *testing.T) {
	h, _ := testIMDS(t)
	yes := []string{"/latest/api/token", "/latest/meta-data/iam/security-credentials/", "/latest/meta-data/iam/security-credentials/app-role"}
	no := []string{"/", "/mybucket/key", "/latest/dynamic/instance-identity/document", "/latest/meta-data"}
	for _, p := range yes {
		if !h.isIMDSPath(httptest.NewRequest(http.MethodGet, p, nil)) {
			t.Errorf("isIMDSPath(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if h.isIMDSPath(httptest.NewRequest(http.MethodGet, p, nil)) {
			t.Errorf("isIMDSPath(%q) = true, want false (must not shadow AWS calls)", p)
		}
	}
}

func TestIMDS_TokenHandshake(t *testing.T) {
	h, _ := testIMDS(t)
	r := httptest.NewRequest(http.MethodPut, "/latest/api/token", nil)
	r.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
	w := httptest.NewRecorder()
	h.serve(w, r, "req")
	if w.Code != 200 || w.Body.Len() == 0 {
		t.Fatalf("token PUT: code=%d bodylen=%d", w.Code, w.Body.Len())
	}
	if w.Header().Get("X-aws-ec2-metadata-token-ttl-seconds") != "300" {
		t.Errorf("TTL header not echoed: %q", w.Header().Get("X-aws-ec2-metadata-token-ttl-seconds"))
	}
}

func TestIMDS_RoleName(t *testing.T) {
	h, _ := testIMDS(t)
	w := doGET(h, "/latest/meta-data/iam/security-credentials/", "10.16.0.5")
	if w.Code != 200 || w.Body.String() != "app-role" {
		t.Fatalf("role-name = %q (code %d), want app-role", w.Body.String(), w.Code)
	}
	// A non-VM source IP resolves to nothing → 404 (nothing leaked).
	if w := doGET(h, "/latest/meta-data/iam/security-credentials/", "10.99.99.99"); w.Code != 404 {
		t.Fatalf("non-VM caller must 404, got %d", w.Code)
	}
}

func TestIMDS_CredentialsMintAndVerify(t *testing.T) {
	h, m := testIMDS(t)
	w := doGET(h, "/latest/meta-data/iam/security-credentials/app-role", "10.16.0.5")
	if w.Code != 200 {
		t.Fatalf("creds code=%d body=%s", w.Code, w.Body.String())
	}
	var c imdsCreds
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatalf("creds json: %v", err)
	}
	if c.Code != "Success" || c.Type != "AWS-HMAC" || c.AccessKeyID == "" || c.SecretAccessKey == "" || c.Token == "" {
		t.Fatalf("incomplete creds: %+v", c)
	}
	if _, err := time.Parse(time.RFC3339, c.Expiration); err != nil {
		t.Errorf("Expiration not RFC3339: %q", c.Expiration)
	}
	// The minted session must verify back to the VM's role (the shim will accept it).
	sess, ok := m.Verify(c.AccessKeyID, c.Token)
	if !ok || sess.RoleName != "app-role" {
		t.Fatalf("minted token must verify to role app-role, got ok=%v role=%q", ok, sess.RoleName)
	}
}

func TestIMDS_WrongRoleNameRefused(t *testing.T) {
	h, _ := testIMDS(t)
	// A VM asking for a role name that isn't its own must not get another role's creds.
	w := doGET(h, "/latest/meta-data/iam/security-credentials/some-other-role", "10.16.0.5")
	if w.Code != 404 {
		t.Fatalf("mismatched role path must 404, got %d", w.Code)
	}
}

func TestIMDS_RoleNotVmTrustedDenied(t *testing.T) {
	h, _ := testIMDS(t)
	// db01's role exists on its pod label but does not trust "vm" → forbidden, nothing minted.
	w := doGET(h, "/latest/meta-data/iam/security-credentials/untrusted-role", "10.16.0.9")
	if w.Code != http.StatusForbidden {
		t.Fatalf("a non-vm-trusted role must be 403, got %d (%s)", w.Code, w.Body.String())
	}
}
