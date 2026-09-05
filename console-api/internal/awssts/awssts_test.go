package awssts

import (
	"strings"
	"testing"
	"time"
)

func newTestMinter(t *testing.T) *Minter {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	m, err := NewMinter(key)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m
}

func TestMintVerify_Roundtrip(t *testing.T) {
	m := newTestMinter(t)
	akid, sk, tok, exp, err := m.Mint("deploy-role", []string{"openinfra:users"}, "sess1", "alice", time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(akid, "ASIA") {
		t.Errorf("temp access key should start ASIA, got %q", akid)
	}
	if sk == "" || tok == "" {
		t.Fatal("empty secret/token")
	}
	if time.Until(exp) < 50*time.Minute {
		t.Errorf("expiry too soon: %v", exp)
	}
	sess, ok := m.Verify(akid, tok)
	if !ok {
		t.Fatal("Verify should succeed for a fresh token")
	}
	if sess.RoleName != "deploy-role" || sess.SessionName != "sess1" || sess.Caller != "alice" {
		t.Errorf("session identity wrong: %+v", sess)
	}
	if sess.SecretKey != sk {
		t.Error("token must carry the same secret the caller received (stateless verify)")
	}
}

func TestVerify_FailsClosed(t *testing.T) {
	m := newTestMinter(t)
	akid, _, tok, _, _ := m.Mint("r", []string{"openinfra:users"}, "s", "bob", time.Hour)

	t.Run("wrong access key id", func(t *testing.T) {
		if _, ok := m.Verify("ASIADIFFERENT0000", tok); ok {
			t.Fatal("a token must not verify against a different access key id")
		}
	})
	t.Run("tampered token", func(t *testing.T) {
		bad := tok[:len(tok)-2] + "xy"
		if _, ok := m.Verify(akid, bad); ok {
			t.Fatal("a tampered token must fail the GCM tag")
		}
	})
	t.Run("token from a different key", func(t *testing.T) {
		other := make([]byte, 32)
		for i := range other {
			other[i] = 0xAA
		}
		om, _ := NewMinter(other)
		if _, ok := om.Verify(akid, tok); ok {
			t.Fatal("a token minted by another key must not open")
		}
	})
	t.Run("expired token", func(t *testing.T) {
		// Mint clamps below MinDuration up to 15m; forge an already-expired session directly.
		expTok, _ := m.seal(Session{RoleName: "r", AccessKeyID: akid, SecretKey: "x", Expiry: time.Now().Add(-time.Minute)})
		if _, ok := m.Verify(akid, expTok); ok {
			t.Fatal("an expired token must fail closed")
		}
	})
}

func TestMint_ClampsDuration(t *testing.T) {
	m := newTestMinter(t)
	_, _, _, exp, _ := m.Mint("r", nil, "s", "c", 100*time.Hour) // over max
	if d := time.Until(exp); d > MaxDuration+time.Minute {
		t.Errorf("duration should clamp to MaxDuration, got %v", d)
	}
	_, _, _, exp2, _ := m.Mint("r", nil, "s", "c", time.Second) // under min
	if d := time.Until(exp2); d < MinDuration-time.Minute {
		t.Errorf("duration should clamp up to MinDuration, got %v", d)
	}
}

func TestNewMinter_RejectsBadKey(t *testing.T) {
	if _, err := NewMinter([]byte("short")); err == nil {
		t.Fatal("a non-32-byte key must be rejected")
	}
}
