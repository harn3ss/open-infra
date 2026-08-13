package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The secret value the whole test guards: it must reach the caller and must NEVER touch the log.
const testPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END RSA PRIVATE KEY-----"

// fakeVault stands in for a real Vault: it answers Kubernetes-auth login and the PKI issue/revoke
// paths, and records what token/path each call arrived with so the test can assert authz plumbing.
func fakeVault(t *testing.T) (*httptest.Server, *fakeState) {
	t.Helper()
	st := &fakeState{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Role, JWT string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		st.loginRole = body.Role
		st.loginJWT = body.JWT
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "fake-vault-token"},
		})
	})
	mux.HandleFunc("/v1/pki-acme-root/issue/issuer", func(w http.ResponseWriter, r *http.Request) {
		st.issueToken = r.Header.Get("X-Vault-Token")
		st.issuePath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate":   "CERT-PEM",
				"issuing_ca":    "ISSUING-CA-PEM",
				"ca_chain":      []string{"CHAIN-1", "CHAIN-2"},
				"private_key":   testPrivateKey,
				"serial_number": "aa:bb:cc:dd",
			},
		})
	})
	mux.HandleFunc("/v1/pki-acme-root/revoke", func(w http.ResponseWriter, r *http.Request) {
		st.revokeToken = r.Header.Get("X-Vault-Token")
		st.revokePath = r.URL.Path
		var body struct {
			SerialNumber string `json:"serial_number"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		st.revokeSerial = body.SerialNumber
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"revocation_time": 1700000000},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, st
}

type fakeState struct {
	loginRole, loginJWT                   string
	issueToken, issuePath                 string
	revokeToken, revokePath, revokeSerial string
}

func newTestIssuer(t *testing.T, addr string) (*issuer, *bytes.Buffer) {
	t.Helper()
	// A real SA token file, so login() exercises its actual read+POST path.
	tokPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokPath, []byte("SA-JWT-TOKEN"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	return &issuer{
		vaultAddr: addr,
		role:      "ca-issuer",
		tokenPath: tokPath,
		hc:        http.DefaultClient,
		log:       log.New(&logBuf, "ca-issuer ", 0),
	}, &logBuf
}

func TestIssue_ReturnsKeyToCallerButNeverLogsIt(t *testing.T) {
	vault, st := fakeVault(t)
	s, logBuf := newTestIssuer(t, vault.URL)

	reqBody, _ := json.Marshal(issueRequest{
		CA:         "acme-root",
		CommonName: "svc.example.com",
		TTL:        "72h",
		AltNames:   []string{"alt.example.com", "www.example.com"},
	})
	rr := httptest.NewRecorder()
	s.handleIssue(rr, httptest.NewRequest(http.MethodPost, "/issue", bytes.NewReader(reqBody)))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var got issueResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// The private key MUST be returned to the caller, verbatim.
	if got.PrivateKey != testPrivateKey {
		t.Fatalf("private key not returned to caller: got %q", got.PrivateKey)
	}
	if got.Certificate != "CERT-PEM" || got.IssuingCa != "ISSUING-CA-PEM" {
		t.Fatalf("cert/issuingCa not passed through: %+v", got)
	}
	if len(got.CaChain) != 2 || got.CaChain[0] != "CHAIN-1" {
		t.Fatalf("caChain not passed through: %+v", got.CaChain)
	}
	if got.SerialNumber != "aa:bb:cc:dd" {
		t.Fatalf("serialNumber not passed through: %q", got.SerialNumber)
	}

	// The SECURITY INVARIANT: the private key must never appear in the logs.
	if strings.Contains(logBuf.String(), testPrivateKey) {
		t.Fatalf("private key leaked into logs:\n%s", logBuf.String())
	}
	if strings.Contains(logBuf.String(), "SUPERSECRETKEYMATERIAL") {
		t.Fatalf("private key material leaked into logs:\n%s", logBuf.String())
	}
	// The serial number, by contrast, is expected to be logged (audit trail).
	if !strings.Contains(logBuf.String(), "aa:bb:cc:dd") {
		t.Fatalf("expected serial in logs, got:\n%s", logBuf.String())
	}

	// Vault plumbing: logged in as ca-issuer with the SA token, then called with that token.
	if st.loginRole != "ca-issuer" || st.loginJWT != "SA-JWT-TOKEN" {
		t.Fatalf("login not driven by SA token/role: role=%q jwt=%q", st.loginRole, st.loginJWT)
	}
	if st.issueToken != "fake-vault-token" {
		t.Fatalf("issue not authenticated with the vault token: %q", st.issueToken)
	}
	if st.issuePath != "/v1/pki-acme-root/issue/issuer" {
		t.Fatalf("issue hit the wrong vault path: %q", st.issuePath)
	}
}

func TestRevoke(t *testing.T) {
	vault, st := fakeVault(t)
	s, logBuf := newTestIssuer(t, vault.URL)

	reqBody, _ := json.Marshal(revokeRequest{CA: "acme-root", SerialNumber: "aa:bb:cc:dd"})
	rr := httptest.NewRecorder()
	s.handleRevoke(rr, httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(reqBody)))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if st.revokeToken != "fake-vault-token" {
		t.Fatalf("revoke not authenticated with the vault token: %q", st.revokeToken)
	}
	if st.revokePath != "/v1/pki-acme-root/revoke" {
		t.Fatalf("revoke hit the wrong vault path: %q", st.revokePath)
	}
	if st.revokeSerial != "aa:bb:cc:dd" {
		t.Fatalf("revoke serial not forwarded: %q", st.revokeSerial)
	}
	if !strings.Contains(logBuf.String(), "aa:bb:cc:dd") {
		t.Fatalf("expected serial in revoke logs, got:\n%s", logBuf.String())
	}
	// The response must be normalized to the console's camelCase shape (not Vault's snake_case).
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("revoke response is not JSON: %v", err)
	}
	if _, ok := got["revocationTime"]; !ok {
		t.Fatalf("revoke response not normalized to camelCase (want revocationTime): %s", rr.Body.String())
	}
	if _, ok := got["revocation_time"]; ok {
		t.Fatalf("revoke response leaked Vault snake_case revocation_time: %s", rr.Body.String())
	}
}

func TestIssue_RejectsBadCAName(t *testing.T) {
	vault, _ := fakeVault(t)
	s, _ := newTestIssuer(t, vault.URL)

	for _, bad := range []string{"", "../etc", "pki/../secret", "Foo_Bar", "a/b"} {
		reqBody, _ := json.Marshal(issueRequest{CA: bad, CommonName: "x.example.com"})
		rr := httptest.NewRecorder()
		s.handleIssue(rr, httptest.NewRequest(http.MethodPost, "/issue", bytes.NewReader(reqBody)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("ca=%q: expected 400, got %d", bad, rr.Code)
		}
	}
}
