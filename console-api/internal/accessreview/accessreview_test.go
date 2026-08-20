package accessreview

import (
	"testing"
	"time"
)

// fixed clock so dormancy math is deterministic.
var now = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func principalByName(r Report, name string) (Principal, bool) {
	for _, p := range r.Principals {
		if p.Name == name {
			return p, true
		}
	}
	return Principal{}, false
}

func TestBuild_Flags(t *testing.T) {
	in := Inputs{
		ConsoleNS:    "open-infra-console",
		LookbackDays: 90,
		Users: []UserInput{
			// admin, active recently → only "privileged".
			{Name: "alice", Source: "local", HasPassword: true, Groups: []string{"admins"}, LastSeen: now.Add(-1 * time.Hour)},
			// reader, dormant (last seen 200d ago).
			{Name: "bob", Source: "local", HasPassword: true, Groups: []string{"readers"}, LastSeen: now.Add(-200 * 24 * time.Hour)},
			// local, no password → cannot sign in.
			{Name: "carol", Source: "local", HasPassword: false, Groups: []string{"readers"}},
			// enabled, has password, never seen → no recent activity.
			{Name: "dave", Source: "local", HasPassword: true, Groups: []string{"powerusers"}},
			// disabled but still in an effective group → retains access.
			{Name: "erin", Source: "local", HasPassword: true, Disabled: true, Groups: []string{"admins"}},
			// member of a group that does not exist / not ready → inert membership; also never seen.
			{Name: "frank", Source: "local", HasPassword: true, Groups: []string{"ghosts"}},
			// directory user, active, plain reader via a READY custom group → clean, no flags.
			{Name: "grace", Source: "directory", HasPassword: false, Groups: []string{"data-team"}, LastSeen: now.Add(-2 * time.Hour)},
		},
		Groups: []GroupInput{
			{Name: "data-team", ClusterRole: "openinfra-role-analyst", Ready: true},
			{Name: "ghosts", Ready: false}, // exists but not ready → inert
		},
		Roles: []RoleInput{
			{Name: "analyst", ClusterRole: "openinfra-role-analyst", Policies: []string{"read-data"}, Ready: true},
		},
		Policies: []PolicyInput{{Name: "read-data", ActionCount: 3}},
	}

	r := Build(in, now)

	check := func(name string, want ...string) {
		p, ok := principalByName(r, name)
		if !ok {
			t.Fatalf("principal %q missing", name)
		}
		if len(p.Flags) != len(want) {
			t.Fatalf("%s flags = %v, want %v", name, p.Flags, want)
		}
		for _, w := range want {
			if !hasFlag(p.Flags, w) {
				t.Fatalf("%s flags = %v, missing %q", name, p.Flags, w)
			}
		}
	}

	check("alice", FlagPrivileged)
	if p, _ := principalByName(r, "alice"); !p.Admin {
		t.Error("alice should be admin (admins → open-infra-console)")
	}
	check("bob", FlagDormant)
	check("carol", FlagNoCredential)
	check("dave", FlagNoRecentActivity)
	check("erin", FlagDisabledRetaining)
	check("frank", FlagInertGroups, FlagNoRecentActivity)
	check("grace") // no flags

	if p, _ := principalByName(r, "frank"); len(p.InertGroups) != 1 || p.InertGroups[0] != "ghosts" {
		t.Errorf("frank inert groups = %v, want [ghosts]", p.InertGroups)
	}
	if p, _ := principalByName(r, "grace"); len(p.StandingRoles) != 1 || p.StandingRoles[0] != "openinfra-role-analyst" {
		t.Errorf("grace standing roles = %v, want [openinfra-role-analyst]", p.StandingRoles)
	}
	// disabled account must NOT accrue dormancy/activity flags on top of retains-access.
	if p, _ := principalByName(r, "erin"); len(p.Flags) != 1 {
		t.Errorf("erin should carry exactly one flag, got %v", p.Flags)
	}
}

func TestBuild_Summary(t *testing.T) {
	in := Inputs{
		Users: []UserInput{
			{Name: "a", Source: "local", HasPassword: true, Groups: []string{"admins"}, LastSeen: now},
			{Name: "b", Source: "local", HasPassword: true, Disabled: true, Groups: []string{"readers"}},
			{Name: "c", Source: "local", HasPassword: true, Groups: []string{"readers"}}, // no recent activity
		},
		Policies: []PolicyInput{{Name: "p"}},
		Roles:    []RoleInput{{Name: "r"}},
	}
	r := Build(in, now)
	s := r.Summary
	if s.Principals != 3 || s.Enabled != 2 || s.Disabled != 1 {
		t.Fatalf("counts: principals=%d enabled=%d disabled=%d", s.Principals, s.Enabled, s.Disabled)
	}
	if s.Privileged != 1 {
		t.Errorf("privileged = %d, want 1", s.Privileged)
	}
	if s.DisabledRetaining != 1 {
		t.Errorf("disabledRetaining = %d, want 1", s.DisabledRetaining)
	}
	if s.NoRecentActivity != 1 {
		t.Errorf("noRecentActivity = %d, want 1", s.NoRecentActivity)
	}
	if s.WithStandingAccess != 3 {
		t.Errorf("withStandingAccess = %d, want 3", s.WithStandingAccess)
	}
	if s.Policies != 1 || s.Roles != 1 {
		t.Errorf("reference counts: policies=%d roles=%d", s.Policies, s.Roles)
	}
	// b (disabled) should still be counted as needing review.
	if s.NeedsReview < 2 {
		t.Errorf("needsReview = %d, want ≥2", s.NeedsReview)
	}
}

func TestBuild_Grants(t *testing.T) {
	created := now.Add(-1 * time.Hour)
	in := Inputs{
		Users: []UserInput{
			{Name: "alice", Source: "local", HasPassword: true, Groups: []string{"oncall"}, LastSeen: now},
		},
		Groups: []GroupInput{{Name: "oncall", ClusterRole: "openinfra-role-oncall", Ready: true}},
		Grants: []GrantInput{
			// direct grant to alice
			{Name: "g-direct", SubjectKind: "User", SubjectName: "alice", ClusterRole: "open-infra-poweruser",
				Reason: "incident", Duration: "4h", CreatedAt: created, Bound: true},
			// grant to the oncall group alice is in
			{Name: "g-group", SubjectKind: "Group", SubjectName: "oncall", ClusterRole: "openinfra-role-oncall",
				Duration: "8h", CreatedAt: created, Bound: true},
			// grant to a different user — must NOT attach
			{Name: "g-other", SubjectKind: "User", SubjectName: "zzz", ClusterRole: "open-infra-poweruser",
				Duration: "1h", CreatedAt: created, Bound: true},
		},
	}
	r := Build(in, now)
	p, _ := principalByName(r, "alice")
	if len(p.Grants) != 2 {
		t.Fatalf("alice grants = %d, want 2 (%v)", len(p.Grants), p.Grants)
	}
	var direct, viaGroup *GrantRef
	for i := range p.Grants {
		switch p.Grants[i].Name {
		case "g-direct":
			direct = &p.Grants[i]
		case "g-group":
			viaGroup = &p.Grants[i]
		}
	}
	if direct == nil || direct.ViaGroup != "" {
		t.Errorf("g-direct should attach directly, got %+v", direct)
	}
	if viaGroup == nil || viaGroup.ViaGroup != "oncall" {
		t.Errorf("g-group should attach via oncall, got %+v", viaGroup)
	}
	// expiry = created + 4h.
	wantExp := created.Add(4 * time.Hour).UTC().Format(time.RFC3339)
	if direct.ExpiresAt != wantExp {
		t.Errorf("g-direct expiresAt = %q, want %q", direct.ExpiresAt, wantExp)
	}
	if !hasFlag(p.Flags, FlagActiveGrant) {
		t.Errorf("alice should carry %q, flags = %v", FlagActiveGrant, p.Flags)
	}
	if r.Summary.WithActiveGrants != 1 {
		t.Errorf("withActiveGrants = %d, want 1", r.Summary.WithActiveGrants)
	}
}
