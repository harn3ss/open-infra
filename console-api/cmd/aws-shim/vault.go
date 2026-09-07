package main

// Vault custody of the sts:AssumeRole session-token sealing key (#111 §1).
//
// The shim authenticates to Vault with its OWN ServiceAccount token via Kubernetes auth (Vault role
// aws-shim-sts), so no long-lived Vault credential — and no raw AES key — ever lives in a k8s Secret
// that anything with cluster-wide `get secrets` could read. This is the exact custody pattern the
// encryptionkey / volume-crypto / parameter / ca-issuer reconcilers use (SA-token login, narrow
// read-only policy). The Vault policy for this role grants read on ONE path — sts/data/signing-key —
// and nothing else.
//
// The 32-byte key is read from a KV-v2 mount, so the read path carries the KV-v2 `data/` infix
// (sts/data/signing-key) and the value is nested under `.data.data.<field>`. The key is stored
// base64-encoded. Fetch failures are non-fatal to the process: the caller treats an unavailable key
// as "STS disabled" (fail-closed), never a crash.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
)

// vaultKeyFetcher logs into Vault with the pod's SA token and reads the STS sealing key. Every field
// is overridable via env so the deployment can point it at the cluster Vault and a test at a fake.
type vaultKeyFetcher struct {
	addr      string // VAULT_ADDR
	role      string // STS_VAULT_ROLE (Vault k8s-auth role, default aws-shim-sts)
	kvPath    string // STS_VAULT_KV_PATH (KV-v2 read path, default sts/data/signing-key)
	field     string // STS_VAULT_KEY_FIELD (field in the KV secret, default key)
	tokenPath string // STS_SA_TOKEN_PATH (projected SA token, default the standard mount)
	hc        *http.Client
}

// newVaultKeyFetcher returns a fetcher when VAULT_ADDR is set, else nil (Vault custody not configured).
// It reads only env — it is stateless — so the periodic re-fetch loop can rebuild it cheaply.
func newVaultKeyFetcher() *vaultKeyFetcher {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return nil
	}
	return &vaultKeyFetcher{
		addr:      addr,
		role:      getenv("STS_VAULT_ROLE", "aws-shim-sts"),
		kvPath:    getenv("STS_VAULT_KV_PATH", "sts/data/signing-key"),
		field:     getenv("STS_VAULT_KEY_FIELD", "key"),
		tokenPath: getenv("STS_SA_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		hc:        &http.Client{Timeout: 15 * time.Second},
	}
}

// fetch logs into Vault and reads the sealing key, returning the raw (base64-decoded) key bytes. It
// does NOT validate length — NewMinter/Rotate reject a non-32-byte key — but it does reject an empty
// or non-base64 value, which are unambiguous misconfigurations of the stored secret.
func (f *vaultKeyFetcher) fetch(ctx context.Context) ([]byte, error) {
	token, err := f.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault login: %w", err)
	}
	b64, err := f.readKey(ctx, token)
	if err != nil {
		return nil, err
	}
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, fmt.Errorf("vault %s: field %q is empty", f.kvPath, f.field)
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("vault %s: field %q is not valid base64: %w", f.kvPath, f.field, err)
	}
	return key, nil
}

// login exchanges the pod's ServiceAccount token for a short-lived Vault token via Kubernetes auth.
func (f *vaultKeyFetcher) login(ctx context.Context) (string, error) {
	jwt, err := os.ReadFile(f.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read SA token: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"role": f.role, "jwt": strings.TrimSpace(string(jwt))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.addr+"/v1/auth/kubernetes/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("login %d: %s", resp.StatusCode, vaultErrs(raw))
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
		return "", fmt.Errorf("login returned no client_token")
	}
	return parsed.Auth.ClientToken, nil
}

// readKey GETs the KV-v2 secret and returns the configured field's string value. Never logs the value.
func (f *vaultKeyFetcher) readKey(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.addr+"/v1/"+f.kvPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := f.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("read %s -> %d: %s", f.kvPath, resp.StatusCode, vaultErrs(raw))
	}
	// KV-v2 nests the payload under data.data; the field holds the base64 key.
	var parsed struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode %s response: %w", f.kvPath, err)
	}
	v, ok := parsed.Data.Data[f.field]
	if !ok {
		return "", fmt.Errorf("vault %s: no field %q in secret", f.kvPath, f.field)
	}
	return v, nil
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

// loadSTSSigningKey resolves the STS sealing key at startup. Vault custody takes precedence when
// VAULT_ADDR is set and yields a usable 32-byte key; STS_SIGNING_KEY (base64 AES-256) is an explicit
// dev/override fallback. It returns (nil, "", nil) when neither is available, which the caller treats
// as "STS disabled" (fail closed, identity surface unchanged). A Vault error (unreachable, key absent,
// wrong length) is NON-fatal — logged, then it falls through to the env fallback — so a Vault outage
// never crashes the shim. A malformed STS_SIGNING_KEY stays fatal, preserving the pre-Vault behavior of
// failing loud on an explicit operator setting.
func loadSTSSigningKey(ctx context.Context, logger *slog.Logger) (key []byte, source string, err error) {
	if f := newVaultKeyFetcher(); f != nil {
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		k, ferr := f.fetch(fctx)
		cancel()
		switch {
		case ferr != nil:
			logger.Warn("sts: Vault sealing-key fetch failed; trying STS_SIGNING_KEY fallback",
				slog.String("err", ferr.Error()))
		case len(k) == 32:
			return k, "vault", nil
		default:
			logger.Warn("sts: Vault sealing key is not 32 bytes (AES-256); ignoring", slog.Int("len", len(k)))
		}
	}
	if b64 := getenv("STS_SIGNING_KEY", ""); b64 != "" {
		k, derr := base64.StdEncoding.DecodeString(b64)
		if derr != nil {
			return nil, "", fmt.Errorf("STS_SIGNING_KEY is not valid base64: %w", derr)
		}
		return k, "env", nil
	}
	return nil, "", nil
}

// rotateSTSSigningKey periodically re-fetches the Vault-custodied sealing key and rotates the Minter.
// A changed key becomes the new primary while the previous key is retained for one overlap window, so a
// rotation does not invalidate sessions minted moments before it. A fetch/rotate failure keeps the
// current key(s) (logged, retried next tick) — never a crash. Exits when ctx is done.
func rotateSTSSigningKey(ctx context.Context, m *awssts.Minter, every time.Duration, logger *slog.Logger) {
	f := newVaultKeyFetcher()
	if f == nil || m == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			k, err := f.fetch(fctx)
			cancel()
			if err != nil {
				logger.Warn("sts: periodic Vault key re-fetch failed; keeping current key(s)",
					slog.String("err", err.Error()))
				continue
			}
			rotated, rerr := m.Rotate(k)
			switch {
			case rerr != nil:
				logger.Warn("sts: rotated key rejected; keeping current key(s)", slog.String("err", rerr.Error()))
			case rotated:
				logger.Info("sts: sealing key rotated from Vault; previous key retained for one overlap window")
			}
		}
	}
}

// stsKeyRefreshInterval is the period between Vault sealing-key re-fetches (STS_KEY_REFRESH, default 10m).
func stsKeyRefreshInterval() time.Duration {
	if v := os.Getenv("STS_KEY_REFRESH"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 10 * time.Minute
}
