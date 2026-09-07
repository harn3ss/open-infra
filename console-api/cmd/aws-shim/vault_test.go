package main

import (
	"context"
	"encoding/base64"
	"testing"
)

// key32 is a deterministic 32-byte AES-256 key for the env-fallback tests.
func key32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// When neither Vault nor STS_SIGNING_KEY is configured, the loader returns no key — the caller leaves
// the Minter nil and STS stays disabled (fail closed, identity surface unchanged).
func TestLoadSTSSigningKey_DisabledWhenUnset(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("STS_SIGNING_KEY", "")
	key, src, err := loadSTSSigningKey(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if key != nil || src != "" {
		t.Fatalf("expected disabled (nil key, empty source), got key=%v src=%q", key, src)
	}
}

// With no Vault but a valid STS_SIGNING_KEY, the env fallback supplies the key (source "env").
func TestLoadSTSSigningKey_EnvFallback(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("STS_SIGNING_KEY", base64.StdEncoding.EncodeToString(key32()))
	key, src, err := loadSTSSigningKey(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if src != "env" {
		t.Fatalf("source: got %q want env", src)
	}
	if len(key) != 32 {
		t.Fatalf("key length: got %d want 32", len(key))
	}
}

// A malformed STS_SIGNING_KEY is a fatal misconfiguration (an explicit operator setting), preserving
// the pre-Vault fail-loud behavior rather than silently disabling STS.
func TestLoadSTSSigningKey_BadEnvIsFatal(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("STS_SIGNING_KEY", "not!base64!!")
	if _, _, err := loadSTSSigningKey(context.Background(), discardLogger()); err == nil {
		t.Fatal("a non-base64 STS_SIGNING_KEY must be a fatal error")
	}
}

// VAULT_ADDR is set but the SA token file is absent (as in a unit-test env), so the Vault fetch fails
// fast. That failure is NON-fatal: the loader falls through to the env fallback — here unset, so STS
// stays disabled. Proves a Vault outage never crashes the shim.
func TestLoadSTSSigningKey_VaultUnavailableFallsThrough(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	t.Setenv("STS_SA_TOKEN_PATH", "/nonexistent/openinfra-test/sa-token")
	t.Setenv("STS_SIGNING_KEY", "")
	key, src, err := loadSTSSigningKey(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("a Vault failure must be non-fatal, got err: %v", err)
	}
	if key != nil || src != "" {
		t.Fatalf("expected disabled after Vault failure with no env fallback, got key=%v src=%q", key, src)
	}
}

// With Vault unreachable but a valid STS_SIGNING_KEY present, the loader falls through to the env key.
func TestLoadSTSSigningKey_VaultDownEnvWins(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	t.Setenv("STS_SA_TOKEN_PATH", "/nonexistent/openinfra-test/sa-token")
	t.Setenv("STS_SIGNING_KEY", base64.StdEncoding.EncodeToString(key32()))
	key, src, err := loadSTSSigningKey(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if src != "env" || len(key) != 32 {
		t.Fatalf("expected env fallback key, got src=%q len=%d", src, len(key))
	}
}

// newVaultKeyFetcher is nil exactly when VAULT_ADDR is unset (Vault custody not configured).
func TestNewVaultKeyFetcher_NilWithoutAddr(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	if f := newVaultKeyFetcher(); f != nil {
		t.Fatal("no VAULT_ADDR must yield a nil fetcher")
	}
	t.Setenv("VAULT_ADDR", "http://vault.example:8200")
	f := newVaultKeyFetcher()
	if f == nil {
		t.Fatal("VAULT_ADDR set must yield a fetcher")
	}
	if f.role != "aws-shim-sts" || f.kvPath != "sts/data/signing-key" || f.field != "key" {
		t.Fatalf("fetcher defaults wrong: role=%q kvPath=%q field=%q", f.role, f.kvPath, f.field)
	}
}
