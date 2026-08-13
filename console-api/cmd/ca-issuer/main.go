// Command ca-issuer is the synchronous leaf-certificate issuer for kind: CertificateAuthority.
//
// It authenticates to Vault with its OWN ServiceAccount token via Kubernetes auth (Vault role
// "ca-issuer"), so no Vault credential ever lives in a k8s Secret — nothing with cluster-wide secret
// read (e.g. the console SA) can steal Vault access. Its Vault policy is deliberately narrow: it may
// ONLY issue/revoke leaf certs and rotate CRLs on pki-*/… mounts; it CANNOT generate a root/
// intermediate CA or write PKI roles (that is the provisioner's job, a separate identity/policy).
//
// It serves two endpoints on :8080, both proxied to by the console BFF after a SAR authz check:
//
//	POST /issue  {ca, commonName, ttl, altNames[]} -> Vault pki-<ca>/issue/issuer
//	    -> {certificate, issuingCa, caChain[], privateKey, serialNumber}
//	POST /revoke {ca, serialNumber}                -> Vault pki-<ca>/revoke
//
// SECURITY INVARIANT: the returned private key is handed straight back to the caller and is NEVER
// logged and NEVER persisted. Logs carry only the CA name, common name, and serial number.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// A claim/CA name is a DNS-label-ish token. Validating it before it is interpolated into the Vault
// mount path ("pki-<ca>/…") stops any path-traversal / segment injection through the `ca` field.
var caNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// issuer holds the Vault coordinates and the knobs the test overrides. Everything mutable for testing
// (address, SA-token path, HTTP client, log sink) is a field so main() can wire the real values and
// the test can point them at an httptest fake.
type issuer struct {
	vaultAddr string
	role      string
	tokenPath string
	hc        *http.Client
	log       *log.Logger
}

func main() {
	s := &issuer{
		vaultAddr: envOr("VAULT_ADDR", "http://vault.vault.svc.cluster.local:8200"),
		role:      envOr("VAULT_ROLE", "ca-issuer"),
		tokenPath: envOr("SA_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		hc:        &http.Client{Timeout: 20 * time.Second},
		log:       log.New(os.Stdout, "ca-issuer ", log.LstdFlags|log.LUTC),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/issue", s.handleIssue)
	mux.HandleFunc("/revoke", s.handleRevoke)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	addr := envOr("LISTEN_ADDR", ":8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.log.Printf("listening on %s (vault %s, role %s)", addr, s.vaultAddr, s.role)
	if err := srv.ListenAndServe(); err != nil {
		s.log.Fatalf("server: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---- request/response shapes ----

type issueRequest struct {
	CA         string   `json:"ca"`
	CommonName string   `json:"commonName"`
	TTL        string   `json:"ttl"`
	AltNames   []string `json:"altNames"`
}

type issueResponse struct {
	Certificate  string   `json:"certificate"`
	IssuingCa    string   `json:"issuingCa"`
	CaChain      []string `json:"caChain"`
	PrivateKey   string   `json:"privateKey"`
	SerialNumber string   `json:"serialNumber"`
}

type revokeRequest struct {
	CA           string `json:"ca"`
	SerialNumber string `json:"serialNumber"`
}

// Vault PKI issue data (snake_case wire form from Vault).
type vaultIssueData struct {
	Certificate  string   `json:"certificate"`
	IssuingCa    string   `json:"issuing_ca"`
	CaChain      []string `json:"ca_chain"`
	PrivateKey   string   `json:"private_key"`
	SerialNumber string   `json:"serial_number"`
}

// Vault PKI revoke data (snake_case wire form from Vault).
type vaultRevokeData struct {
	RevocationTime        int64  `json:"revocation_time"`
	RevocationTimeRfc3339 string `json:"revocation_time_rfc3339"`
	State                 string `json:"state"`
}

// revokeResponse is the camelCase revoke result the console consumes (RevokeResult in api.ts). We
// normalize here — as handleIssue does — rather than pass Vault's snake_case through, so the field
// names line up end to end.
type revokeResponse struct {
	RevocationTime        int64  `json:"revocationTime"`
	RevocationTimeRfc3339 string `json:"revocationTimeRfc3339"`
	State                 string `json:"state"`
}

// ---- handlers ----

func (s *issuer) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req issueRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !caNameRe.MatchString(req.CA) {
		httpErr(w, http.StatusBadRequest, "invalid ca name")
		return
	}
	if strings.TrimSpace(req.CommonName) == "" {
		httpErr(w, http.StatusBadRequest, "commonName is required")
		return
	}

	token, err := s.login(r.Context())
	if err != nil {
		s.log.Printf("issue ca=%s cn=%q: vault login failed: %v", req.CA, req.CommonName, err)
		httpErr(w, http.StatusBadGateway, "vault login failed")
		return
	}

	body := map[string]any{"common_name": req.CommonName}
	if req.TTL != "" {
		body["ttl"] = req.TTL
	}
	if len(req.AltNames) > 0 {
		body["alt_names"] = strings.Join(req.AltNames, ",")
	}

	data, err := s.vaultWrite(r.Context(), token, "pki-"+req.CA+"/issue/issuer", body)
	if err != nil {
		// NOTE: never include `data` in the log — the issued key material lives there.
		s.log.Printf("issue ca=%s cn=%q: vault issue failed: %v", req.CA, req.CommonName, err)
		httpErr(w, http.StatusBadGateway, "vault issue failed")
		return
	}

	var d vaultIssueData
	if err := json.Unmarshal(data, &d); err != nil {
		s.log.Printf("issue ca=%s cn=%q: decode vault data failed: %v", req.CA, req.CommonName, err)
		httpErr(w, http.StatusBadGateway, "vault returned an unreadable response")
		return
	}

	// Log the serial only — NEVER the private key.
	s.log.Printf("issued ca=%s cn=%q serial=%s", req.CA, req.CommonName, d.SerialNumber)

	writeJSON(w, http.StatusOK, issueResponse{
		Certificate:  d.Certificate,
		IssuingCa:    d.IssuingCa,
		CaChain:      d.CaChain,
		PrivateKey:   d.PrivateKey,
		SerialNumber: d.SerialNumber,
	})
}

func (s *issuer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req revokeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !caNameRe.MatchString(req.CA) {
		httpErr(w, http.StatusBadRequest, "invalid ca name")
		return
	}
	if strings.TrimSpace(req.SerialNumber) == "" {
		httpErr(w, http.StatusBadRequest, "serialNumber is required")
		return
	}

	token, err := s.login(r.Context())
	if err != nil {
		s.log.Printf("revoke ca=%s serial=%s: vault login failed: %v", req.CA, req.SerialNumber, err)
		httpErr(w, http.StatusBadGateway, "vault login failed")
		return
	}

	data, err := s.vaultWrite(r.Context(), token, "pki-"+req.CA+"/revoke", map[string]any{
		"serial_number": req.SerialNumber,
	})
	if err != nil {
		s.log.Printf("revoke ca=%s serial=%s: vault revoke failed: %v", req.CA, req.SerialNumber, err)
		httpErr(w, http.StatusBadGateway, "vault revoke failed")
		return
	}
	s.log.Printf("revoked ca=%s serial=%s", req.CA, req.SerialNumber)

	// Normalize Vault's snake_case revoke payload into the camelCase the console expects (it carries no
	// key material). Vault returns an empty data object when the serial was already revoked — that is a
	// successful revoke, so emit a zero-valued response rather than an error.
	var vd vaultRevokeData
	if len(data) > 0 {
		_ = json.Unmarshal(data, &vd)
	}
	writeJSON(w, http.StatusOK, revokeResponse{
		RevocationTime:        vd.RevocationTime,
		RevocationTimeRfc3339: vd.RevocationTimeRfc3339,
		State:                 vd.State,
	})
}

// ---- Vault client ----

// login exchanges this pod's ServiceAccount token for a short-lived Vault token via Kubernetes auth.
func (s *issuer) login(ctx context.Context) (string, error) {
	jwt, err := os.ReadFile(s.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read SA token: %w", err)
	}
	reqBody, _ := json.Marshal(map[string]string{
		"role": s.role,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.vaultAddr+"/v1/auth/kubernetes/login", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("vault login %d: %s", resp.StatusCode, vaultErrs(raw))
	}
	var parsed struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode login response: %w", err)
	}
	if parsed.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault login returned no client_token")
	}
	return parsed.Auth.ClientToken, nil
}

// vaultWrite POSTs body to a Vault path (under /v1) with the given token and returns the raw `data`
// object. It never logs the request or response body.
func (s *issuer) vaultWrite(ctx context.Context, token, path string, body map[string]any) (json.RawMessage, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.vaultAddr+"/v1/"+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("vault %s -> %d: %s", path, resp.StatusCode, vaultErrs(raw))
	}
	var parsed struct {
		Data json.RawMessage `json:"data"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("decode vault response: %w", err)
		}
	}
	return parsed.Data, nil
}

func vaultErrs(raw []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &e) == nil && len(e.Errors) > 0 {
		return strings.Join(e.Errors, "; ")
	}
	return "unexpected vault response"
}

// ---- http helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
