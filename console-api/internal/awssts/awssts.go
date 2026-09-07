// Package awssts mints and verifies the temporary session credentials that back a faithful
// sts:AssumeRole on the aws-shim. It follows AWS's model: AssumeRole returns an AccessKeyId +
// SecretAccessKey + an opaque SessionToken, and every later call signs with those and carries the
// SessionToken in X-Amz-Security-Token.
//
// The token is STATELESS by construction: it is an AES-256-GCM sealed blob carrying the session
// (the assumed role, its groups, the session name, the caller, the temp secret, and the expiry).
// The shim recovers the temp secret from the token itself to verify the SigV4 signature, so there
// is no server-side session store to replicate across shim replicas or to lose on restart — the
// same property that lets AWS STS scale. Tampering fails the GCM tag; a token minted by an unrelated
// key simply fails to open and the request falls closed. The sealing key is Vault-custodied and may be
// rotated: a Minter holds the current key plus one previous key for an overlap window, so a rotation
// does not cut sessions minted moments before it — but a session sealed by NO held key (the previous
// key aged out, or a deliberate revoke-all rotation) falls closed, the only revocation lever a
// stateless token has short of expiry (see docs/aws-shim.md).
package awssts

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Session is the identity an assumed-role credential acts as. It is sealed inside the SessionToken.
type Session struct {
	RoleName    string    `json:"role"`   // the assumed kind: Role name (the data-plane principal id)
	Groups      []string  `json:"groups"` // impersonation groups the session acts as
	SessionName string    `json:"sess"`   // RoleSessionName (audit/ARN)
	Caller      string    `json:"caller"` // the principal that assumed the role (audit)
	AccessKeyID string    `json:"akid"`   // binds the token to its access key id
	SecretKey   string    `json:"sk"`     // temp secret the shim uses to verify SigV4
	Expiry      time.Time `json:"exp"`    // hard expiry; a stale token falls closed
}

// Minter seals and opens session tokens. It holds one PRIMARY AES-256 key, used to seal (Mint) and to
// open (Verify), plus — to survive a key rotation without cutting live sessions — up to a bounded
// number of PREVIOUS keys used ONLY to open (Verify) tokens minted before the rotation. Rotating the
// Vault-custodied key therefore does not immediately invalidate outstanding sessions: they stay
// verifiable for one overlap window, while a token that opens under NONE of the held keys falls
// closed. The set is guarded by a mutex so Rotate may run on a background goroutine (the periodic
// Vault re-fetch) concurrently with request-path Mint/Verify.
type Minter struct {
	mu      sync.RWMutex
	entries []keyEntry // entries[0] is the primary (Mint + Verify); entries[1:] are previous (Verify only)
	maxPrev int        // how many previous keys to retain for the overlap window
}

// keyEntry pairs a raw key (kept only to detect an unchanged key on re-fetch) with its AEAD.
type keyEntry struct {
	raw  []byte
	aead cipher.AEAD
}

func newKeyEntry(key []byte) (keyEntry, error) {
	if len(key) != 32 {
		return keyEntry{}, fmt.Errorf("awssts: signing key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return keyEntry{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return keyEntry{}, err
	}
	raw := make([]byte, len(key))
	copy(raw, key)
	return keyEntry{raw: raw, aead: aead}, nil
}

// MinDuration / MaxDuration / DefaultDuration bound an assume-role session, mirroring STS's 15m..12h
// window with a 1h default.
const (
	MinDuration     = 15 * time.Minute
	MaxDuration     = 12 * time.Hour
	DefaultDuration = 1 * time.Hour
)

// NewMinter builds a Minter from a 32-byte AES-256 key. A key of the wrong length is rejected so a
// misconfigured deployment fails loudly at startup rather than minting weak tokens. The Minter retains
// one previous key across a Rotate, giving a single overlap window for in-flight sessions.
func NewMinter(key []byte) (*Minter, error) {
	e, err := newKeyEntry(key)
	if err != nil {
		return nil, err
	}
	return &Minter{entries: []keyEntry{e}, maxPrev: 1}, nil
}

// Rotate installs newKey as the primary sealing key, keeping the outgoing primary as a previous key
// (bounded by maxPrev) so tokens minted just before the rotation still Verify during the overlap
// window. It is a no-op (rotated=false) when newKey already IS the current primary, so a periodic
// re-fetch of an unchanged Vault key does not churn the previous-key set. A wrong-length key is
// rejected, leaving the existing keys untouched.
func (m *Minter) Rotate(newKey []byte) (rotated bool, err error) {
	e, err := newKeyEntry(newKey)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.entries) > 0 && bytes.Equal(m.entries[0].raw, e.raw) {
		return false, nil
	}
	// Prepend the new primary; retain at most maxPrev previous keys. append to a fresh slice so any
	// reader holding the old slice header (in open) keeps seeing an immutable snapshot — no data race.
	next := append([]keyEntry{e}, m.entries...)
	if len(next) > m.maxPrev+1 {
		next = next[:m.maxPrev+1]
	}
	m.entries = next
	return true, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Mint issues a temporary credential for an assumed role: a fresh ASIA-prefixed access key id, a
// random secret, and a sealed SessionToken carrying both plus the identity and expiry.
func (m *Minter) Mint(role string, groups []string, sessionName, caller string, ttl time.Duration) (accessKeyID, secretKey, sessionToken string, expiry time.Time, err error) {
	if ttl <= 0 {
		ttl = DefaultDuration
	}
	if ttl < MinDuration {
		ttl = MinDuration
	}
	if ttl > MaxDuration {
		ttl = MaxDuration
	}
	akid, err := randToken(15)
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	// AWS temporary access key ids start ASIA; keep that convention so tooling recognizes it.
	accessKeyID = "ASIA" + b32.EncodeToString(akid)[:16]
	sk, err := randToken(30)
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	secretKey = base64.RawStdEncoding.EncodeToString(sk)
	expiry = time.Now().UTC().Add(ttl)
	sess := Session{
		RoleName: role, Groups: groups, SessionName: sessionName, Caller: caller,
		AccessKeyID: accessKeyID, SecretKey: secretKey, Expiry: expiry,
	}
	sessionToken, err = m.seal(sess)
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	return accessKeyID, secretKey, sessionToken, expiry, nil
}

var errBadToken = errors.New("awssts: invalid or expired session token")

// Verify opens a session token and confirms it belongs to accessKeyID and has not expired. Any
// failure — a token minted by another key, tampering, a mismatched access key, or expiry — returns
// ok=false, so the caller falls closed.
func (m *Minter) Verify(accessKeyID, sessionToken string) (Session, bool) {
	sess, err := m.open(sessionToken)
	if err != nil {
		return Session{}, false
	}
	if sess.AccessKeyID != accessKeyID {
		return Session{}, false
	}
	if time.Now().UTC().After(sess.Expiry) {
		return Session{}, false
	}
	return sess, true
}

func (m *Minter) seal(s Session) (string, error) {
	plain, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	m.mu.RLock()
	aead := m.entries[0].aead // seal always uses the primary (newest) key
	m.mu.RUnlock()
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nonce, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func (m *Minter) open(token string) (Session, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Session{}, err
	}
	m.mu.RLock()
	entries := m.entries // slice-header snapshot; entries are immutable once created (Rotate swaps the slice)
	m.mu.RUnlock()
	// Try the primary, then each retained previous key — so a token sealed by the key in force before a
	// rotation still opens during the overlap window, while a token sealed by no held key falls closed.
	for _, e := range entries {
		ns := e.aead.NonceSize()
		if len(raw) < ns {
			continue
		}
		nonce, ct := raw[:ns], raw[ns:]
		plain, oerr := e.aead.Open(nil, nonce, ct, nil)
		if oerr != nil {
			continue
		}
		var s Session
		if err := json.Unmarshal(plain, &s); err != nil {
			return Session{}, err
		}
		return s, nil
	}
	return Session{}, errBadToken
}

func randToken(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
