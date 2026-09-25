package main

import "testing"

func TestBlobRoundTrip(t *testing.T) {
	blob := encodeBlob("key-123", "vault:v1:abcdef==")
	kid, ct, err := decodeBlob(blob)
	if err != nil {
		t.Fatalf("decodeBlob error: %v", err)
	}
	if kid != "key-123" || ct != "vault:v1:abcdef==" {
		t.Errorf("round-trip mismatch: kid=%q ct=%q", kid, ct)
	}
}

func TestDecodeBlobRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not-base64!!!", "aGVsbG8="} { // last is valid base64 but not our JSON envelope
		if _, _, err := decodeBlob(bad); err == nil {
			t.Errorf("decodeBlob(%q) should have errored", bad)
		}
	}
}

// The AAD that binds EncryptionContext must be identical regardless of the map's key order — otherwise a
// decrypt with a logically-equal context would fail. encoding/json sorts keys, which we rely on.
func TestEncryptionContextAADOrderIndependent(t *testing.T) {
	a, err := encryptionContextAAD(map[string]any{"a": "1", "b": "2", "c": "3"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := encryptionContextAAD(map[string]any{"c": "3", "a": "1", "b": "2"})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("AAD not order-independent: %q vs %q", a, b)
	}
	if a == "" {
		t.Error("non-empty context produced empty AAD")
	}
}

func TestEncryptionContextAADEmpty(t *testing.T) {
	for _, v := range []any{nil, map[string]any{}} {
		aad, err := encryptionContextAAD(v)
		if err != nil {
			t.Fatal(err)
		}
		if aad != "" {
			t.Errorf("empty context should yield empty AAD, got %q", aad)
		}
	}
}

func TestEncryptionContextAADRejectsNonString(t *testing.T) {
	if _, err := encryptionContextAAD(map[string]any{"n": 5}); err == nil {
		t.Error("non-string EncryptionContext value should error")
	}
}

// A distinct context must produce a distinct AAD (so it actually binds).
func TestEncryptionContextAADDistinguishes(t *testing.T) {
	a, _ := encryptionContextAAD(map[string]any{"tenant": "acme"})
	b, _ := encryptionContextAAD(map[string]any{"tenant": "globex"})
	if a == b {
		t.Error("different contexts produced the same AAD")
	}
}

func TestVerbForKMSOp(t *testing.T) {
	cases := map[string]string{
		"Decrypt":             "get",
		"DescribeKey":         "get",
		"Encrypt":             "create",
		"GenerateDataKey":     "create",
		"CreateKey":           "create",
		"ScheduleKeyDeletion": "delete",
		"DeleteAlias":         "delete",
	}
	for op, want := range cases {
		got, ok := verbForKMSOp(op)
		if !ok || got != want {
			t.Errorf("verbForKMSOp(%q)=%q,%v want %q", op, got, ok, want)
		}
	}
	if _, ok := verbForKMSOp("Sign"); ok {
		t.Error("Sign should be unknown (asymmetric not supported)")
	}
}

func TestContextKeys(t *testing.T) {
	if got := contextKeys(map[string]any{"b": "2", "a": "1"}); got != "a,b" {
		t.Errorf("contextKeys not sorted/joined: %q", got)
	}
	for _, v := range []any{nil, map[string]any{}} {
		if got := contextKeys(v); got != "" {
			t.Errorf("empty context should give empty string, got %q", got)
		}
	}
}

func TestKeyName(t *testing.T) {
	if keyName("abc") != "kms-abc" {
		t.Errorf("keyName wrong: %q", keyName("abc"))
	}
}

func TestFirstString(t *testing.T) {
	body := map[string]any{"KeyId": "", "TargetKeyId": "tgt", "n": 5}
	if got := firstString(body, "KeyId", "TargetKeyId"); got != "tgt" {
		t.Errorf("firstString skipped empty wrong: %q", got)
	}
	if got := firstString(body, "missing"); got != "" {
		t.Errorf("firstString missing should be empty: %q", got)
	}
}
