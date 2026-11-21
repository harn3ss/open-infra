package main

// IAM instance profiles made with the IAM API, against a real Postgres store (OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go).

import (
	"context"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

var instanceProfileIDRe = regexp.MustCompile(`<InstanceProfileId>(AIPA[A-Z2-7]{17})</InstanceProfileId>`)

// profileStoreFixture is profileFixture (the apps stack's two profiles) with a profile store.
func profileStoreFixture(t *testing.T) (*iamHandler, map[string]string) {
	t.Helper()
	st := &iamProfileStore{db: freshPGDB(t)}
	for i := 0; i < 2; i++ { // idempotent
		if err := st.ensureSchema(context.Background()); err != nil {
			t.Fatalf("ensureSchema (run %d): %v", i+1, err)
		}
	}
	h, refs := profileFixture(t)
	h.profiles = st
	return h, refs
}

// ipMust serves one IAM request in ctx and fails the test unless it answers want; it returns the body,
// unescaped.
func ipMust(t *testing.T, h *iamHandler, ctx context.Context, c iam.Claims, want int, kv ...string) string {
	t.Helper()
	w := ipCall(h, ctx, c, kv...)
	if w.Code != want {
		t.Fatalf("%v as %s: %d (want %d) %s", kv, c.Sub, w.Code, want, w.Body.String())
	}
	return html.UnescapeString(w.Body.String())
}

// A profile's whole life through the IAM API, as AWS answers each step: made with its path and tags, given
// one role (a second is LimitExceeded, an unknown one NoSuchEntity), read and listed with the stack's
// profiles, kept from deletion while it has its role (and the role kept from deletion while the profile
// has it), then emptied and deleted.
func TestIAMPG_InstanceProfileLifecycle(t *testing.T) {
	h, _ := profileStoreFixture(t)
	putProfileRole(t, h, "default", "web-role")
	putProfileRole(t, h, "default", "batch-role")
	ctx := context.Background()
	call := func(want int, kv ...string) string {
		t.Helper()
		return ipMust(t, h, ctx, profileReader, want, kv...)
	}

	b := call(200, "Action", "CreateInstanceProfile", "InstanceProfileName", "WebProfile", "Path", "/app/",
		"Tags.member.1.Key", "team", "Tags.member.1.Value", "web")
	m := instanceProfileIDRe.FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("CreateInstanceProfile: no AIPA id of 21 characters: %s", b)
	}
	id := m[1]
	mustContain(t, "CreateInstanceProfile", b, "<CreateInstanceProfileResult><InstanceProfile><Path>/app/</Path><InstanceProfileName>WebProfile</InstanceProfileName>",
		"<Arn>arn:aws:iam::000000000000:instance-profile/app/WebProfile</Arn>", "<CreateDate>", "<Roles></Roles>",
		"<Tags><member><Key>team</Key><Value>web</Value></member></Tags>")
	// A name is the account's once, in any case — the stack's profiles' names included.
	for _, n := range []string{"webprofile", "BatchProfile"} {
		if b := call(409, "Action", "CreateInstanceProfile", "InstanceProfileName", n); !strings.Contains(b, "<Code>EntityAlreadyExists</Code>") ||
			!strings.Contains(b, "Instance Profile "+n+" already exists.") {
			t.Errorf("CreateInstanceProfile %s: %s", n, b)
		}
	}

	call(200, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "webprofile", "RoleName", "web-role")
	if b := call(409, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "WebProfile", "RoleName", "batch-role"); !strings.Contains(b,
		"<Code>LimitExceeded</Code><Message>Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1</Message>") {
		t.Errorf("a second role: %s", b)
	}
	if b := call(404, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "NoSuchProfile", "RoleName", "web-role"); !strings.Contains(b,
		"<Message>Instance Profile NoSuchProfile cannot be found.</Message>") {
		t.Errorf("an unknown profile: %s", b)
	}
	call(200, "Action", "CreateInstanceProfile", "InstanceProfileName", "Empty")
	if b := call(404, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "Empty", "RoleName", "ghost"); !strings.Contains(b,
		"<Message>The role with name ghost cannot be found.</Message>") {
		t.Errorf("an unknown role: %s", b)
	}

	b = call(200, "Action", "GetInstanceProfile", "InstanceProfileName", "WEBPROFILE")
	mustContain(t, "GetInstanceProfile", b, "<InstanceProfileName>WebProfile</InstanceProfileName><InstanceProfileId>"+id+"</InstanceProfileId>",
		"<Roles><member><Path>/</Path><RoleName>web-role</RoleName><RoleId>"+roleID("web-role")+"</RoleId><Arn>arn:aws:iam::000000000000:role/web-role</Arn>",
		"<AssumeRolePolicyDocument>", "ec2.amazonaws.com", "<Key>team</Key>")
	b = call(200, "Action", "ListInstanceProfiles")
	mustContain(t, "ListInstanceProfiles", b, "<InstanceProfileName>WebProfile</InstanceProfileName>", "<InstanceProfileName>Empty</InstanceProfileName>",
		"<InstanceProfileName>BatchProfile</InstanceProfileName>")
	if strings.Contains(b, "<Tags>") {
		t.Errorf("a list leaves out the tags, as IAM's does: %s", b)
	}
	if b := call(200, "Action", "ListInstanceProfiles", "PathPrefix", "/app/"); !strings.Contains(b, "WebProfile") || strings.Contains(b, "Empty") || strings.Contains(b, "BatchProfile") {
		t.Errorf("PathPrefix /app/: %s", b)
	}
	if b := call(200, "Action", "ListInstanceProfilesForRole", "RoleName", "web-role"); !strings.Contains(b, "WebProfile") || strings.Contains(b, "Empty") {
		t.Errorf("ListInstanceProfilesForRole web-role: %s", b)
	}

	// The CloudFormation front door reads the account's profiles with their roles.
	if ip, err := h.profiles.forStacks(ctx); err != nil || ip["webprofile"].Role != "web-role" || ip["webprofile"].Path != "/app/" ||
		ip["empty"].Name != "Empty" || ip["empty"].Role != "" || len(ip) != 2 {
		t.Errorf("forStacks: %v %v", ip, err)
	}
	if ip := (&cfnDoorway{instanceProfiles: h.profiles.forStacks}).caps(ctx).InstanceProfiles; ip["webprofile"].Role != "web-role" {
		t.Errorf("the deploy Capabilities' instance profiles: %v", ip)
	}

	// While the profile has its role, neither the profile nor the role is deleted.
	if b := call(409, "Action", "DeleteInstanceProfile", "InstanceProfileName", "WebProfile"); !strings.Contains(b,
		"<Code>DeleteConflict</Code><Message>Cannot delete entity, must remove roles from instance profile first.</Message>") {
		t.Errorf("deleting a profile with a role: %s", b)
	}
	if b := call(409, "Action", "DeleteRole", "RoleName", "web-role"); !strings.Contains(b, "<Code>DeleteConflict</Code>") {
		t.Errorf("deleting a role a profile has: %s", b)
	}
	if b := call(404, "Action", "RemoveRoleFromInstanceProfile", "InstanceProfileName", "WebProfile", "RoleName", "batch-role"); !strings.Contains(b,
		"<Message>The role with name batch-role cannot be found.</Message>") {
		t.Errorf("removing a role the profile does not have: %s", b)
	}
	call(200, "Action", "RemoveRoleFromInstanceProfile", "InstanceProfileName", "WebProfile", "RoleName", "WEB-ROLE")
	if b := call(200, "Action", "GetInstanceProfile", "InstanceProfileName", "WebProfile"); !strings.Contains(b, "<Roles></Roles>") {
		t.Errorf("the role was removed: %s", b)
	}
	call(200, "Action", "DeleteInstanceProfile", "InstanceProfileName", "webProfile")
	call(404, "Action", "GetInstanceProfile", "InstanceProfileName", "WebProfile")
	if b := call(404, "Action", "DeleteInstanceProfile", "InstanceProfileName", "WebProfile"); !strings.Contains(b,
		"<Code>NoSuchEntity</Code><Message>Instance Profile WebProfile cannot be found.</Message>") {
		t.Errorf("deleting a profile there is not: %s", b)
	}
	call(200, "Action", "DeleteRole", "RoleName", "web-role")
}

// Each account has profiles of its own: a member account's profile of the same name as the management
// account's is its own, with its own account in its ARN, holding a role of its own account, never seen,
// changed or deleted by the other; the CloudFormation front door reads each stack's account's.
func TestIAMPG_InstanceProfilesAccounts(t *testing.T) {
	h, _ := profileStoreFixture(t)
	h.authz = doorAccountsAuthz(t)
	putProfileRole(t, h, "default", "web-role")
	putProfileRole(t, h, memberHome, "member-role")
	mgmt, member := context.Background(), memberCtx()
	alice, bob := iam.Claims{Sub: "alice"}, iam.Claims{Sub: "bob", Account: testMember}
	call := func(ctx context.Context, c iam.Claims, want int, kv ...string) string {
		t.Helper()
		return ipMust(t, h, ctx, c, want, kv...)
	}
	call(mgmt, alice, 200, "Action", "CreateInstanceProfile", "InstanceProfileName", "Web")
	call(mgmt, alice, 200, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "Web", "RoleName", "web-role")
	b := call(member, bob, 200, "Action", "CreateInstanceProfile", "InstanceProfileName", "Web")
	mustContain(t, "the member account's CreateInstanceProfile", b, "<Arn>arn:aws:iam::"+testMember+":instance-profile/Web</Arn>")
	// The member account's role is its own; the management account's web-role is not one of its roles.
	call(member, bob, 404, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "Web", "RoleName", "web-role")
	call(member, bob, 200, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "Web", "RoleName", "member-role")

	b = call(member, bob, 200, "Action", "GetInstanceProfile", "InstanceProfileName", "Web")
	mustHave(t, "the member account's profile", b, []string{"<RoleName>member-role</RoleName>", "arn:aws:iam::" + testMember + ":role/member-role"},
		[]string{"web-role", "arn:aws:iam::000000000000:"})
	b = call(mgmt, alice, 200, "Action", "GetInstanceProfile", "InstanceProfileName", "Web")
	mustHave(t, "the management account's profile", b, []string{"<RoleName>web-role</RoleName>"}, []string{"member-role", testMember})
	if b := call(mgmt, alice, 200, "Action", "ListInstanceProfiles"); strings.Contains(b, testMember) || strings.Count(b, "<InstanceProfileName>Web</InstanceProfileName>") != 1 {
		t.Errorf("the management account listed another account's profile: %s", b)
	}

	if ip, err := h.profiles.forStacks(member); err != nil || ip["web"].Role != "member-role" || len(ip) != 1 {
		t.Errorf("the member account's profiles for its stacks: %v %v", ip, err)
	}
	if ip, err := h.profiles.forStacks(mgmt); err != nil || ip["web"].Role != "web-role" || len(ip) != 1 {
		t.Errorf("the management account's profiles for its stacks: %v %v", ip, err)
	}

	// Removing and deleting in the member account leaves the management account's profile as it was.
	call(member, bob, 200, "Action", "RemoveRoleFromInstanceProfile", "InstanceProfileName", "Web", "RoleName", "member-role")
	call(member, bob, 200, "Action", "DeleteInstanceProfile", "InstanceProfileName", "Web")
	call(member, bob, 404, "Action", "GetInstanceProfile", "InstanceProfileName", "Web")
	if b := call(mgmt, alice, 200, "Action", "GetInstanceProfile", "InstanceProfileName", "Web"); !strings.Contains(b, "<RoleName>web-role</RoleName>") {
		t.Errorf("the management account's profile must be untouched: %s", b)
	}
}

// A principal whose policy does not allow an operation is refused it on the profile's ARN, and nothing
// changes: a User denied iam:DeleteInstanceProfile on one profile keeps it; one allowed everything but
// iam:PassRole cannot give the profile a role.
func TestIAMPG_InstanceProfileDenied(t *testing.T) {
	h, _ := profileStoreFixture(t)
	putProfileRole(t, h, "default", "web-role")
	ctx := context.Background()
	ipMust(t, h, ctx, profileReader, 200, "Action", "CreateInstanceProfile", "InstanceProfileName", "Web", "Path", "/app/")
	user := iam.Claims{Sub: "tester"}
	h.cs, h.cfn.cs = csWithSAR(false), csWithSAR(false)
	h.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"iam:*"}, "*"),
		dpDeny([]string{"iam:DeleteInstanceProfile"}, "ARN::arn:aws:iam::000000000000:instance-profile/app/Web"),
		dpDeny([]string{"iam:PassRole"}, "*")))
	if b := ipMust(t, h, ctx, user, 403, "Action", "DeleteInstanceProfile", "InstanceProfileName", "Web"); !strings.Contains(b,
		"is not authorized to perform: iam:DeleteInstanceProfile on resource: arn:aws:iam::000000000000:instance-profile/app/Web") {
		t.Errorf("a Deny on the profile's ARN: %s", b)
	}
	if b := ipMust(t, h, ctx, user, 403, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "Web", "RoleName", "web-role"); !strings.Contains(b, "iam:PassRole") {
		t.Errorf("a Deny of iam:PassRole: %s", b)
	}
	if b := ipMust(t, h, ctx, user, 200, "Action", "GetInstanceProfile", "InstanceProfileName", "Web"); !strings.Contains(b, "<Roles></Roles>") {
		t.Errorf("the refused calls changed the profile: %s", b)
	}
	// An assumed role with no policy is refused even the profile's read.
	h.authz = checkerInMode(t, "enforce")
	ipMust(t, h, ctx, iam.Claims{Sub: "assumed-role/r/s", AssumedRole: "r"}, 403, "Action", "GetInstanceProfile", "InstanceProfileName", "Web")
}
