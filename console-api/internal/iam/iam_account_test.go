package iam

import (
	"slices"
	"testing"
)

// The legacy group mapping keeps the implicit users group; the enforce-mode mapping does not, so a
// principal with no groups is in none.
func TestMemberGroups_NoImplicitUsersGroup(t *testing.T) {
	if got := GroupsFromSpec([]string{"dev"}); !slices.Equal(got, []string{"openinfra:dev", "openinfra:users"}) {
		t.Errorf("legacy GroupsFromSpec changed: %v", got)
	}
	if got := MemberGroups([]string{"dev", "", "x,system:masters"}); !slices.Equal(got, []string{"openinfra:dev"}) {
		t.Errorf("MemberGroups: %v", got)
	}
	if got := MemberGroups(nil); len(got) != 0 {
		t.Errorf("no groups must be none: %v", got)
	}
	if got := RoleGroups("poweruser"); !slices.Equal(got, []string{"openinfra:powerusers", "openinfra:users"}) {
		t.Errorf("legacy RoleGroups changed: %v", got)
	}
	if got := RoleMemberGroups("readonly"); !slices.Equal(got, []string{"openinfra:readers"}) {
		t.Errorf("RoleMemberGroups: %v", got)
	}
}

func TestAccountIdentity(t *testing.T) {
	if u, ok := AccountIdentity(Claims{Sub: "alice"}); !ok || u != "openinfra:000000000000:alice" {
		t.Errorf("management account user: %q", u)
	}
	if u, _ := AccountIdentity(Claims{Sub: "deployer/s", AssumedRole: "deployer", Account: "123456789012"}); u != "openinfra:123456789012:role/deployer" {
		t.Errorf("assumed role: %q", u)
	}
	if _, ok := AccountIdentity(Claims{}); ok {
		t.Error("no subject must be no identity")
	}
	u, groups, _ := IdentityFor(Claims{Sub: "alice", Groups: []string{"openinfra:admins"}}, true)
	if u != "openinfra:000000000000:alice" || groups != nil {
		t.Errorf("enforce identity: %q %v", u, groups)
	}
	u, groups, _ = IdentityFor(Claims{Sub: "alice", Groups: []string{"openinfra:admins"}}, false)
	if u != "openinfra:alice" || !slices.Equal(groups, []string{"openinfra:admins"}) {
		t.Errorf("legacy identity changed: %q %v", u, groups)
	}
}
