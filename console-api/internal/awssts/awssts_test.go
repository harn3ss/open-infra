package awssts

import (
	"strings"
	"sync"
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

// keyOf returns a deterministic 32-byte key filled with b (for readable rotation tests).
func keyOf(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// TestRotate_DualKeyOverlap: after a rotation, a token sealed by the PREVIOUS key still verifies
// (the overlap window), a fresh token mints+verifies under the NEW primary, and a token sealed by an
// UNRELATED key is rejected.
func TestRotate_DualKeyOverlap(t *testing.T) {
	m := newTestMinter(t) // primary = key {0,1,2,...}

	// Mint a token under the ORIGINAL key, then rotate.
	akid, sk, tok, _, err := m.Mint("r", []string{"openinfra:users"}, "s", "alice", time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	rotated, err := m.Rotate(keyOf(0x11))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !rotated {
		t.Fatal("Rotate should report a change for a new key")
	}

	// A token sealed by the PREVIOUS key still verifies during the overlap window.
	sess, ok := m.Verify(akid, tok)
	if !ok {
		t.Fatal("a token sealed by the previous key must still verify during the overlap window")
	}
	if sess.SecretKey != sk {
		t.Error("previous-key token opened to the wrong secret")
	}

	// A fresh token mints under the NEW primary and verifies.
	akid2, _, tok2, _, err := m.Mint("r", nil, "s2", "bob", time.Hour)
	if err != nil {
		t.Fatalf("Mint after rotate: %v", err)
	}
	if _, ok := m.Verify(akid2, tok2); !ok {
		t.Fatal("a token minted under the new primary must verify")
	}

	// A token sealed by a key held by NEITHER the primary nor the previous slot is rejected.
	other, _ := NewMinter(keyOf(0x99))
	oAkid, _, oTok, _, _ := other.Mint("r", nil, "s3", "eve", time.Hour)
	if _, ok := m.Verify(oAkid, oTok); ok {
		t.Fatal("a token sealed by neither held key must fall closed")
	}
}

// TestRotate_AgesOutOldKeyPastOverlap: with a single overlap slot, two rotations push the oldest key
// out — a token sealed by it then falls closed (the revoke-all lever documented in docs/aws-shim.md).
func TestRotate_AgesOutOldKeyPastOverlap(t *testing.T) {
	m := newTestMinter(t)
	akid, _, tok, _, _ := m.Mint("r", nil, "s", "alice", time.Hour) // sealed by key0

	if _, err := m.Rotate(keyOf(0x11)); err != nil { // key0 -> previous
		t.Fatalf("Rotate 1: %v", err)
	}
	if _, err := m.Rotate(keyOf(0x22)); err != nil { // key0 aged out of the single slot
		t.Fatalf("Rotate 2: %v", err)
	}
	if _, ok := m.Verify(akid, tok); ok {
		t.Fatal("a token sealed by a key aged out past the overlap must fall closed")
	}
}

// TestRotate_NoopOnUnchangedKey: re-fetching the SAME key is a no-op — it must not push the primary
// into and out of the single overlap slot (which would silently shorten the real overlap window).
func TestRotate_NoopOnUnchangedKey(t *testing.T) {
	m := newTestMinter(t)
	if rotated, err := m.Rotate(keyOf(0x00)); err != nil {
		// newTestMinter fills the key with 0,1,2,... not all-0x00, so this IS a change; adjust below.
		t.Fatalf("Rotate: %v", err)
	} else if !rotated {
		t.Fatal("0x00 differs from the 0,1,2,... test key, so this should have rotated")
	}
	// Now re-apply the exact current primary (0x00) — must be a no-op.
	rotated, err := m.Rotate(keyOf(0x00))
	if err != nil {
		t.Fatalf("Rotate (same): %v", err)
	}
	if rotated {
		t.Fatal("re-fetching the current primary must be a no-op (no previous-key churn)")
	}

	// Prove the overlap slot was not consumed by the no-op: mint under the current key, do ONE real
	// rotation, and confirm the token still verifies (it occupies the single previous slot).
	akid, _, tok, _, _ := m.Mint("r", nil, "s", "c", time.Hour)
	if _, err := m.Rotate(keyOf(0x11)); err != nil {
		t.Fatalf("Rotate (real): %v", err)
	}
	if _, ok := m.Verify(akid, tok); !ok {
		t.Fatal("after a no-op rotate then one real rotate, the prior-key token should still verify")
	}
}

// TestRotate_RejectsBadKeyKeepsExisting: a wrong-length key is rejected and leaves the working keys
// untouched (fail-safe — a bad re-fetch never disables a live minter).
func TestRotate_RejectsBadKeyKeepsExisting(t *testing.T) {
	m := newTestMinter(t)
	akid, _, tok, _, _ := m.Mint("r", nil, "s", "c", time.Hour)
	if _, err := m.Rotate([]byte("too-short")); err == nil {
		t.Fatal("Rotate must reject a non-32-byte key")
	}
	if _, ok := m.Verify(akid, tok); !ok {
		t.Fatal("a rejected rotation must leave the existing key(s) working")
	}
}

// TestRotate_Concurrent stresses the mutex: background Rotate calls run while goroutines Mint and
// Verify. Purpose is the data-race detector (run with -race) plus the guarantee that Mint never errors
// under concurrent rotation. It does NOT assert that every freshly minted token verifies — that would
// be racy by design, since two rotations can age a key out of the single overlap slot between a mint
// and its verify; the overlap SEMANTICS are covered deterministically by TestRotate_DualKeyOverlap and
// TestRotate_AgesOutOldKeyPastOverlap.
func TestRotate_Concurrent(t *testing.T) {
	m := newTestMinter(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Rotators churn the key set continuously.
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					if _, err := m.Rotate(keyOf(seed + byte(i))); err != nil {
						t.Errorf("Rotate: %v", err)
						return
					}
				}
			}
		}(byte(r * 40))
	}

	// Minters/verifiers exercise the hot path concurrently with rotation.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				akid, _, tok, _, err := m.Mint("r", nil, "s", "c", time.Hour)
				if err != nil {
					t.Errorf("Mint under concurrent rotation must not error: %v", err)
					return
				}
				_, _ = m.Verify(akid, tok) // result is intentionally not asserted (see doc above)
			}
		}()
	}

	// Let the mint/verify goroutines run, then stop the rotators.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(stop)
	}()
	wg.Wait()
}
