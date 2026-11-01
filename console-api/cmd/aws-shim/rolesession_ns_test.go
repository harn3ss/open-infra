package main

import (
	"context"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
)

// recordingRevoker remembers the principal it was asked about.
type recordingRevoker struct{ asked []string }

func (r *recordingRevoker) RevokedBefore(_ context.Context, role string) (time.Time, bool) {
	r.asked = append(r.asked, role)
	return time.Time{}, false
}

// A session for a Role outside the IAM home namespace acts as "<namespace>/<name>": it is a different
// data-plane principal from a same-named home Role, and its revocation is read off its own Role. A
// session for a home Role — and every token minted before sessions carried a namespace — keeps the
// bare role name, so existing policies and sessions behave exactly as before.
func TestSessionClaims_PrincipalIsNamespaceQualified(t *testing.T) {
	for _, tc := range []struct {
		name, ns, want string
	}{
		{"legacy token (no namespace)", "", "app"},
		{"home namespace", "open-infra-console", "app"},
		{"VM instance role in its namespace", "tenant-b", "tenant-b/app"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rev := &recordingRevoker{}
			a := &authenticator{home: "open-infra-console", revoke: rev}
			c, ok := a.sessionClaims(context.Background(), awssts.Session{RoleName: "app", Namespace: tc.ns, SessionName: "s1"})
			if !ok {
				t.Fatal("unrevoked session refused")
			}
			if c.AssumedRole != tc.want || c.PrincipalID() != tc.want || c.PrincipalType() != "Role" {
				t.Errorf("principal = %s/%s, want Role/%s", c.PrincipalType(), c.PrincipalID(), tc.want)
			}
			if c.Sub != "assumed-role/app/s1" {
				t.Errorf("Sub = %q (the AWS-style session name keeps the bare role name)", c.Sub)
			}
			if len(rev.asked) != 1 || rev.asked[0] != tc.want {
				t.Errorf("revocation asked about %v, want [%s]", rev.asked, tc.want)
			}
		})
	}
}

// MintIn seals the Role's namespace into the token; Mint leaves it empty (home).
func TestMintIn_CarriesNamespace(t *testing.T) {
	m := testMinter(t)
	akid, _, tok, _, err := m.MintIn("tenant-b", "app", nil, "vm1", "system:serviceaccount:tenant-b:vm-vm1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := m.Verify(akid, tok)
	if !ok || s.Namespace != "tenant-b" || s.RoleName != "app" {
		t.Fatalf("Verify = %+v ok=%v", s, ok)
	}
	akid, _, tok, _, _ = m.Mint("app", nil, "s", "alice", time.Hour)
	if s, _ := m.Verify(akid, tok); s.Namespace != "" {
		t.Fatalf("Mint must leave the namespace empty, got %q", s.Namespace)
	}
}

// The revoke cutoff of a namespaced principal is read off the Role in its own namespace, never off a
// same-named home Role.
func TestRoleCutoffCache_QualifiedPrincipalReadsItsOwnNamespace(t *testing.T) {
	cut := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	tenantRole := roleObj("app", cut.Format(time.RFC3339))
	tenantRole.SetNamespace("tenant-b")
	homeRole := roleObj("app", "")
	homeRole.SetNamespace("open-infra-console")
	c := newRoleCutoffCache(newFakeDyn(tenantRole, homeRole), "open-infra-console", time.Minute)

	if got, on := c.RevokedBefore(context.Background(), "tenant-b/app"); !on || !got.Equal(cut) {
		t.Errorf("tenant-b/app cutoff = %v on=%v, want %v", got, on, cut)
	}
	if _, on := c.RevokedBefore(context.Background(), "app"); on {
		t.Errorf("the home Role app sets no cutoff; tenant-b's must not apply to it")
	}
}
