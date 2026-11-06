package awssts

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// An IAM user's own session (GetSessionToken) and its MFA context survive the seal, and its length is
// bounded by the cap it was minted under (36 hours for a user session, 12 for a role's).
func TestMintSession_UserSessionWithMFA(t *testing.T) {
	m := newTestMinter(t)
	at := time.Now().Add(-time.Minute).Unix()
	akid, _, tok, exp, err := m.MintSession(Session{User: "alice", Account: "912345678901", MFA: true, MFAAuthTime: at,
		AccessKeyID: "ignored", SecretKey: "ignored"}, 40*time.Hour, MaxUserSessionDuration)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d > MaxUserSessionDuration || d < MaxUserSessionDuration-time.Minute {
		t.Errorf("a 40-hour ask is capped at 36 hours, got %v", d)
	}
	s, ok := m.Verify(akid, tok)
	if !ok || s.User != "alice" || s.Account != "912345678901" || !s.MFA || s.MFAAuthTime != at || s.RoleName != "" {
		t.Fatalf("session %+v %v", s, ok)
	}
	if s.AccessKeyID != akid || s.SecretKey == "ignored" {
		t.Error("the minter's own key id and secret replace whatever the template carried")
	}
	// A role's session keeps its 12-hour cap; one minted the old way carries no MFA.
	_, _, _, exp, _ = m.MintSession(Session{RoleName: "r"}, 40*time.Hour, MaxDuration)
	if time.Until(exp) > MaxDuration {
		t.Errorf("a role session over 12 hours: %v", time.Until(exp))
	}
	akid, _, tok, _, _ = m.Mint("r", nil, "s", "alice", time.Hour)
	if s, _ := m.Verify(akid, tok); s.MFA || s.Federated || s.User != "" {
		t.Errorf("a plain role session: %+v", s)
	}
}

// A user session is sealed apart from role sessions: an opener that knows only role sessions (a replica
// that predates user sessions opens with no additional data) cannot open it at all, so it is never read
// as a role session of no role.
func TestUserSessionIsSealedApart(t *testing.T) {
	m := newTestMinter(t)
	_, _, tok, _, err := m.MintSession(Session{User: "alice"}, time.Hour, MaxUserSessionDuration)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	aead := m.entries[0].aead
	ns := aead.NonceSize()
	if _, err := aead.Open(nil, raw[:ns], raw[ns:], nil); err == nil {
		t.Fatal("a user session opened without its additional data: an older replica would read it as a role session")
	}
	// And the reverse: a role session's payload claiming a user does not open as a user session.
	nonce := make([]byte, ns)
	plain, _ := json.Marshal(Session{User: "alice", AccessKeyID: "ASIAX", Expiry: time.Now().Add(time.Hour)})
	forged := base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, nil))
	if _, ok := m.Verify("ASIAX", forged); ok {
		t.Fatal("a token sealed as a role session opened as a user session")
	}
}
