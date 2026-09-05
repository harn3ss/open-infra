// Package awssts mints and verifies the temporary session credentials that back a faithful
// sts:AssumeRole on the aws-shim. It follows AWS's model: AssumeRole returns an AccessKeyId +
// SecretAccessKey + an opaque SessionToken, and every later call signs with those and carries the
// SessionToken in X-Amz-Security-Token.
//
// The token is STATELESS by construction: it is an AES-256-GCM sealed blob carrying the session
// (the assumed role, its groups, the session name, the caller, the temp secret, and the expiry).
// The shim recovers the temp secret from the token itself to verify the SigV4 signature, so there
// is no server-side session store to replicate across shim replicas or to lose on restart — the
// same property that lets AWS STS scale. Tampering fails the GCM tag; a token minted by a different
// key (or after a key rotation) simply fails to open and the request falls closed.
package awssts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Minter seals and opens session tokens with a single AES-256 key.
type Minter struct {
	aead cipher.AEAD
}

// MinDuration / MaxDuration / DefaultDuration bound an assume-role session, mirroring STS's 15m..12h
// window with a 1h default.
const (
	MinDuration     = 15 * time.Minute
	MaxDuration     = 12 * time.Hour
	DefaultDuration = 1 * time.Hour
)

// NewMinter builds a Minter from a 32-byte AES-256 key. A key of the wrong length is rejected so a
// misconfigured deployment fails loudly at startup rather than minting weak tokens.
func NewMinter(key []byte) (*Minter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("awssts: signing key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Minter{aead: aead}, nil
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
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := m.aead.Seal(nonce, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func (m *Minter) open(token string) (Session, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Session{}, err
	}
	ns := m.aead.NonceSize()
	if len(raw) < ns {
		return Session{}, errBadToken
	}
	nonce, ct := raw[:ns], raw[ns:]
	plain, err := m.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return Session{}, errBadToken
	}
	var s Session
	if err := json.Unmarshal(plain, &s); err != nil {
		return Session{}, err
	}
	return s, nil
}

func randToken(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
