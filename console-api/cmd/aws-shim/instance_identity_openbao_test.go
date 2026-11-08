package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

// Against a real OpenBao: OPENINFRA_TEST_OPENBAO_ADDR and OPENINFRA_TEST_OPENBAO_TOKEN (an administrative
// token), e.g. a throwaway `bao server -dev -dev-root-token-id=<token>`. The policies are the ones the
// openbao-setup Job writes, read from platform/security/openbao.yaml, so this checks what ships.
func TestIdentityTransit_RealOpenBao(t *testing.T) {
	addr, admin := os.Getenv("OPENINFRA_TEST_OPENBAO_ADDR"), os.Getenv("OPENINFRA_TEST_OPENBAO_TOKEN")
	if addr == "" || admin == "" {
		t.Skip("OPENINFRA_TEST_OPENBAO_ADDR and OPENINFRA_TEST_OPENBAO_TOKEN not set")
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	call := func(token, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, addr+"/v1/"+path, r)
		req.Header.Set("X-Vault-Token", token)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	manifest, err := os.ReadFile("../../../platform/security/openbao.yaml")
	if err != nil {
		t.Fatal(err)
	}
	policy := func(name string) string {
		m := regexp.MustCompile(`(?s)vault policy write ` + name + ` - <<'POLICY'\n(.*?)\n\s*POLICY`).FindSubmatch(manifest)
		if m == nil {
			t.Fatalf("no policy %s in openbao.yaml", name)
		}
		var lines []string
		for _, l := range strings.Split(string(m[1]), "\n") {
			lines = append(lines, strings.TrimSpace(l))
		}
		return strings.Join(lines, "\n")
	}
	tokenFor := func(pol string) string {
		t.Helper()
		if c, out := call(admin, "PUT", "sys/policies/acl/"+pol, map[string]any{"policy": policy(pol)}); c/100 != 2 {
			t.Fatalf("policy %s: %d %v", pol, c, out)
		}
		c, out := call(admin, "POST", "auth/token/create", map[string]any{"policies": []string{pol}, "ttl": "10m", "no_default_policy": true})
		if c != 200 {
			t.Fatalf("token for %s: %d %v", pol, c, out)
		}
		return out["auth"].(map[string]any)["client_token"].(string)
	}
	call(admin, "POST", "sys/mounts/openinfra/transit", map[string]any{"type": "transit"}) // already there on a re-run

	// The setup Job's identity creates the key (as the Job does) and cannot sign with it.
	setup := tokenFor("vault-config")
	if c, out := call(setup, "POST", "openinfra/transit/keys/instance-identity", map[string]any{"type": "rsa-2048", "exportable": false, "allow_plaintext_backup": false}); c/100 != 2 {
		t.Fatalf("the setup identity creates the key: %d %v", c, out)
	}
	if c, _ := call(setup, "POST", "openinfra/transit/sign/instance-identity/sha2-256", map[string]any{"input": "AAAA"}); c != http.StatusForbidden {
		t.Fatalf("the setup identity signs: %d, want 403", c)
	}

	shim := tokenFor("aws-shim-identity")
	tr, err := newTransitRSAKey("openinfra/transit/instance-identity", addr, "unused", "/unused")
	if err != nil {
		t.Fatal(err)
	}
	tr.v.token, tr.v.exp = shim, time.Now().Add(time.Hour)
	now := time.Now()
	s := newIdentitySigner(fake.NewSimpleClientset(), shimNS, time.Hour, discardLogger())
	s.now = func() time.Time { return now }
	s.useTransit(&transitSigning{key: tr})
	ctx := context.Background()
	doc := []byte("{\n  \"instanceId\" : \"i-0123456789abcdef0\"\n}")
	sig, p7, err := s.sign(ctx, doc)
	if err != nil || p7 == "" {
		t.Fatalf("sign through OpenBao: %v", err)
	}
	if !s.verify(ctx, doc, sig) {
		t.Fatal("OpenBao's signature does not verify under the served certificate")
	}

	// What the shim's identity may not do.
	for _, c := range []struct{ method, path string }{
		{"GET", "openinfra/transit/export/signing-key/instance-identity"},
		{"POST", "openinfra/transit/keys/instance-identity/rotate"},
		{"POST", "openinfra/transit/keys/instance-identity/config"},
		{"POST", "openinfra/transit/sign/instance-identity/sha2-512"},
		{"POST", "openinfra/transit/encrypt/instance-identity"},
		{"POST", "openinfra/transit/keys/another"},
		{"POST", "transit/encrypt/kms-anything"},
	} {
		if code, _ := call(shim, c.method, c.path, map[string]any{"plaintext": "AAAA", "input": "AAAA"}); code != http.StatusForbidden && code != http.StatusNotFound {
			t.Errorf("the shim's identity: %s %s = %d, want refused", c.method, c.path, code)
		}
	}

	// The Cognito and ECR keys: the setup identity creates them; the shim's identity signs with each and
	// can do nothing else with them.
	for _, k := range []string{"cognito", "ecr-token"} {
		if c, out := call(setup, "POST", "openinfra/transit/keys/"+k, map[string]any{"type": "rsa-2048", "exportable": false, "allow_plaintext_backup": false}); c/100 != 2 {
			t.Fatalf("the setup identity creates %s: %d %v", k, c, out)
		}
		kt, err := newTransitRSAKey("openinfra/transit/"+k, addr, "unused", "/unused")
		if err != nil {
			t.Fatal(err)
		}
		kt.v.token, kt.v.exp = shim, time.Now().Add(time.Hour)
		ts := &transitSigning{key: kt, lifetime: time.Hour, logger: discardLogger()}
		keys, err := ts.keys(ctx)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		d := sha256.Sum256([]byte("token"))
		sig, err := keys.sign(ctx, d[:])
		if err != nil || !keys.verifies(d[:], sig) {
			t.Fatalf("%s: the shim's identity signs: %v", k, err)
		}
		for _, p := range []string{"openinfra/transit/export/signing-key/" + k, "openinfra/transit/keys/" + k + "/rotate"} {
			if code, _ := call(shim, "POST", p, nil); code != http.StatusForbidden && code != http.StatusNotFound {
				t.Errorf("the shim's identity: %s = %d, want refused", p, code)
			}
		}
	}

	// A rotation: the new version signs, the replaced one's document still verifies.
	if c, out := call(admin, "POST", "openinfra/transit/keys/instance-identity/rotate", nil); c/100 != 2 {
		t.Fatalf("rotate: %d %v", c, out)
	}
	now = now.Add(2 * time.Minute)
	sig2, _, err := s.sign(ctx, doc)
	if err != nil || sig2 == sig || !s.verify(ctx, doc, sig2) || !s.verify(ctx, doc, sig) {
		t.Fatalf("after a rotation: %v (new signature differs: %v)", err, sig2 != sig)
	}

	// A key that can be exported is refused.
	call(admin, "POST", "openinfra/transit/keys/exportable-test", map[string]any{"type": "rsa-2048", "exportable": true})
	bad, _ := newTransitRSAKey("openinfra/transit/exportable-test", addr, "unused", "/unused")
	bad.v.token, bad.v.exp = admin, time.Now().Add(time.Hour)
	if _, err := bad.versions(ctx); err == nil || !strings.Contains(err.Error(), "exportable") {
		t.Fatalf("an exportable key: %v", err)
	}
}
