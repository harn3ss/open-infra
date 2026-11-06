package awssts

import (
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
