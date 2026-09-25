// Vault Transit client for the aws-shim KMS front door (polyhedron#160).
//
// A KMS CMK is a Vault Transit key named "kms-<keyid>"; the shim performs encrypt/decrypt/rotate on
// behalf of callers, gated by Cedar. The shim authenticates to Vault with its OWN ServiceAccount token
// (k8s-auth role aws-shim-kms), whose policy is scoped to the kms- key prefix and nothing else — it
// cannot touch the encryptionkey/volume-crypto keys or any other mount. The Vault token is cached and
// re-fetched on expiry/permission error, so a request is not a login round-trip.
//
// This client is deliberately thin: it does the cryptographic PRIMITIVES (wrap/unwrap a value under a
// managed key, rotate, read version, crypto-erase). AWS's envelope-encryption, EncryptionContext AAD
// binding, key-state machine, and audit all live one layer up in kms.go, so the trust boundary — keys
// never leave Vault — is exactly Vault's.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type vaultTransit struct {
	addr      string
	role      string
	tokenPath string
	hc        *http.Client

	mu    sync.Mutex
	token string
	exp   time.Time
}

// newVaultTransit returns a Transit client when VAULT_ADDR is set, else nil (KMS answers 501).
func newVaultTransit() *vaultTransit {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return nil
	}
	return &vaultTransit{
		addr:      addr,
		role:      getenv("KMS_VAULT_ROLE", "aws-shim-kms"),
		tokenPath: getenv("STS_SA_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		hc:        &http.Client{Timeout: 15 * time.Second},
	}
}

// keyName maps a KMS key id to its Transit key name (the kms- prefix the Vault policy fences on).
func keyName(keyID string) string { return "kms-" + keyID }

func (v *vaultTransit) authToken(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.token != "" && time.Now().Before(v.exp) {
		return v.token, nil
	}
	jwt, err := os.ReadFile(v.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read SA token: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"role": v.role, "jwt": strings.TrimSpace(string(jwt))})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, v.addr+"/v1/auth/kubernetes/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.hc.Do(req)
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
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	if parsed.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault login returned no client_token")
	}
	v.token = parsed.Auth.ClientToken
	ttl := time.Duration(parsed.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = 20 * time.Minute
	}
	v.exp = time.Now().Add(ttl - 2*time.Minute) // refresh a bit early
	return v.token, nil
}

// call performs a Vault API call, re-logging-in once on a 403 (token expired/revoked). method "" = GET.
func (v *vaultTransit) call(ctx context.Context, method, path string, in any) (map[string]any, error) {
	if method == "" {
		method = http.MethodGet
	}
	do := func(token string) (int, []byte, error) {
		var body io.Reader
		if in != nil {
			b, _ := json.Marshal(in)
			body = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, v.addr+"/v1/"+path, body)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("X-Vault-Token", token)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := v.hc.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return resp.StatusCode, raw, nil
	}
	token, err := v.authToken(ctx)
	if err != nil {
		return nil, err
	}
	status, raw, err := do(token)
	if err != nil {
		return nil, err
	}
	if status == http.StatusForbidden {
		// token likely expired/revoked — drop it and retry once with a fresh login
		v.mu.Lock()
		v.token = ""
		v.mu.Unlock()
		if token, err = v.authToken(ctx); err != nil {
			return nil, err
		}
		status, raw, err = do(token)
		if err != nil {
			return nil, err
		}
	}
	if status == http.StatusNoContent || len(raw) == 0 {
		return map[string]any{}, nil
	}
	if status/100 != 2 {
		return nil, &vaultAPIError{status: status, msg: vaultErrs(raw)}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

type vaultAPIError struct {
	status int
	msg    string
}

func (e *vaultAPIError) Error() string { return fmt.Sprintf("vault %d: %s", e.status, e.msg) }

// createKey creates a symmetric AES-256-GCM Transit key (idempotent — Vault registers a repeat write
// as a no-op update).
func (v *vaultTransit) createKey(ctx context.Context, keyID string) error {
	_, err := v.call(ctx, http.MethodPost, "transit/keys/"+keyName(keyID), map[string]any{"type": "aes256-gcm96"})
	return err
}

// encrypt wraps base64 plaintext under the CMK, returning the Vault ciphertext ("vault:vN:...").
// associatedDataB64 is the AEAD additional-authenticated-data (base64) that binds the KMS
// EncryptionContext at the cipher layer — empty when there is no context. aes256-gcm96 authenticates
// it, so a decrypt with different AAD fails cryptographically, exactly like AWS's EncryptionContext.
func (v *vaultTransit) encrypt(ctx context.Context, keyID, plaintextB64, associatedDataB64 string) (string, error) {
	in := map[string]any{"plaintext": plaintextB64}
	if associatedDataB64 != "" {
		in["associated_data"] = associatedDataB64
	}
	out, err := v.call(ctx, http.MethodPost, "transit/encrypt/"+keyName(keyID), in)
	if err != nil {
		return "", err
	}
	return dataString(out, "ciphertext"), nil
}

// decrypt unwraps a Vault ciphertext, returning the base64 plaintext. The SAME associatedDataB64 used
// at encrypt must be supplied or the AEAD tag check fails. A tampered/foreign ciphertext or mismatched
// AAD surfaces as a vaultAPIError (400), which the handler maps to InvalidCiphertextException.
func (v *vaultTransit) decrypt(ctx context.Context, keyID, ciphertext, associatedDataB64 string) (string, error) {
	in := map[string]any{"ciphertext": ciphertext}
	if associatedDataB64 != "" {
		in["associated_data"] = associatedDataB64
	}
	out, err := v.call(ctx, http.MethodPost, "transit/decrypt/"+keyName(keyID), in)
	if err != nil {
		return "", err
	}
	return dataString(out, "plaintext"), nil
}

// rotate advances the CMK to a new backing version; old ciphertext still decrypts (min_decryption_version
// unchanged). The key id/ARN are unchanged — exactly AWS's EnableKeyRotation semantics.
func (v *vaultTransit) rotate(ctx context.Context, keyID string) error {
	_, err := v.call(ctx, http.MethodPost, "transit/keys/"+keyName(keyID)+"/rotate", nil)
	return err
}

// latestVersion reports the key's current backing version (the rotation truth GetKeyRotationStatus reads).
func (v *vaultTransit) latestVersion(ctx context.Context, keyID string) (int, error) {
	out, err := v.call(ctx, http.MethodGet, "transit/keys/"+keyName(keyID), nil)
	if err != nil {
		return 0, err
	}
	data, _ := out["data"].(map[string]any)
	if lv, ok := data["latest_version"].(float64); ok {
		return int(lv), nil
	}
	return 0, nil
}

// destroy crypto-erases the CMK: enable deletion, then delete the Transit key. After this, no ciphertext
// under the key can ever be decrypted again — the KMS key-deletion guarantee.
func (v *vaultTransit) destroy(ctx context.Context, keyID string) error {
	if _, err := v.call(ctx, http.MethodPost, "transit/keys/"+keyName(keyID)+"/config", map[string]any{"deletion_allowed": true}); err != nil {
		return err
	}
	_, err := v.call(ctx, http.MethodDelete, "transit/keys/"+keyName(keyID), nil)
	return err
}

func dataString(out map[string]any, field string) string {
	data, _ := out["data"].(map[string]any)
	s, _ := data[field].(string)
	return s
}
