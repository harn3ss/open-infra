package main

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// profileStackTemplate is an app stack's instance role and the two instance profiles that carry it: one
// under a path, one named.
const profileStackTemplate = `
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      Path: /svc/
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [{ Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }]
  AppProfile:
    Type: AWS::IAM::InstanceProfile
    Properties: { Path: /app/, Roles: [!Ref AppRole] }
  BatchProfile:
    Type: AWS::IAM::InstanceProfile
    Properties: { InstanceProfileName: BatchProfile, Roles: [!Ref AppRole] }
`

func profileStackRecord(name, ns string) cfn.StackRecord {
	return cfn.StackRecord{Name: name, Namespace: ns, Status: "CREATE_COMPLETE", Template: profileStackTemplate,
		CreatedAt: "2026-11-01T10:00:00Z", UpdatedAt: "2026-11-01T10:00:00Z",
		Resources: []cfn.StackResource{{LogicalID: "AppRole", APIVersion: "iam.openinfra.dev/v1", Kind: "Role", Name: name + "-approle",
			Type: "AWS::IAM::Role", Status: "CREATE_COMPLETE"}}}
}

// profileFixture is the IAM front door with the CloudFormation front door's records holding the apps stack,
// and the stack's profiles' physical ids (what DescribeStackResources lists), by logical id.
func profileFixture(t *testing.T, recs ...cfn.StackRecord) (*iamHandler, map[string]string) {
	t.Helper()
	rec := profileStackRecord("apps", ec2TestNS)
	objs := []runtime.Object{stackRecordConfigMap(t, rec)}
	for _, r := range recs {
		objs = append(objs, stackRecordConfigMap(t, r))
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), structuralLists, objs...)
	door := &cfnDoorway{shimDyn: dyn, ns: ec2TestNS, account: "000000000000", region: "us-east-1", cs: csWithSAR(true), authzNS: "authz",
		callerDyn: func(string, []string) (dynamic.Interface, error) { return dyn, nil }, logger: discardLogger()}
	h := newIAMHandler(csWithSAR(true), fakeDynWith(gvrRoles), nil, nil, "default", "000000000000", "us-east-1", discardLogger())
	h.cfn = door
	refs := map[string]string{}
	for _, f := range door.foldedResources(context.Background(), &rec, nil) {
		refs[f.LogicalID] = f.PhysicalID
	}
	if refs["AppProfile"] == "" || refs["BatchProfile"] != "BatchProfile" {
		t.Fatalf("DescribeStackResources' physical ids: %v", refs)
	}
	return h, refs
}

func iamCall(h *iamHandler, claims iam.Claims, form url.Values) *httptest.ResponseRecorder {
	return serveWith(h, formOp(form), claims)
}

var profileReader = iam.Claims{Sub: "tester", Groups: []string{"openinfra:readers"}}

// GetInstanceProfile reads a stack's profile by the name its Ref gave the stack: its path, the ARN the
// stack's Fn::GetAtt Arn gives, an AIPA id, the stack's create date, and its role as the stack made it.
func TestIAM_GetInstanceProfile(t *testing.T) {
	h, refs := profileFixture(t)
	name := refs["AppProfile"]
	rec := profileStackRecord("apps", ec2TestNS)
	trs, err := cfn.TemplateResourcesOf(&rec, nil, "AWS::IAM::InstanceProfile", "AWS::IAM::Role")
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]map[string]string{}
	for _, tr := range trs {
		attrs[tr.LogicalID] = tr.Attrs
	}
	w := iamCall(h, profileReader, url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {name}})
	if w.Code != 200 {
		t.Fatalf("GetInstanceProfile: %d %s", w.Code, w.Body.String())
	}
	mustContain(t, "GetInstanceProfile", w.Body.String(), "<GetInstanceProfileResult><InstanceProfile><Path>/app/</Path>",
		"<InstanceProfileName>"+name+"</InstanceProfileName>", "<InstanceProfileId>AIPA",
		"<Arn>"+attrs["AppProfile"]["Arn"]+"</Arn>", "<Arn>arn:aws:iam::000000000000:instance-profile/app/"+name+"</Arn>",
		"<CreateDate>2026-11-01T10:00:00Z</CreateDate>",
		"<Roles><member><Path>/svc/</Path><RoleName>apps-approle</RoleName><RoleId>"+attrs["AppRole"]["RoleId"]+"</RoleId>",
		"<Arn>"+attrs["AppRole"]["Arn"]+"</Arn>", "<AssumeRolePolicyDocument>", "ec2.amazonaws.com")
	// IAM names are unique without regard to case.
	if w := iamCall(h, profileReader, url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {"batchprofile"}}); w.Code != 200 ||
		!strings.Contains(w.Body.String(), "<InstanceProfileName>BatchProfile</InstanceProfileName><InstanceProfileId>"+instanceProfileID("apps", "BatchProfile")) {
		t.Errorf("GetInstanceProfile in another case: %d %s", w.Code, w.Body.String())
	}
	w = iamCall(h, profileReader, url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {"nope"}})
	if w.Code != 404 || !strings.Contains(w.Body.String(), "<Code>NoSuchEntity</Code>") {
		t.Errorf("an unknown profile: %d %s", w.Code, w.Body.String())
	}
	if w := iamCall(h, profileReader, url.Values{"Action": {"GetInstanceProfile"}}); w.Code != 400 || !strings.Contains(w.Body.String(), "ValidationError") {
		t.Errorf("no name: %d %s", w.Code, w.Body.String())
	}
}

// ListInstanceProfiles lists the account's stacks' profiles by name, under a path prefix, paged by Marker;
// ListInstanceProfilesForRole those carrying the role, and NoSuchEntity for a role there is not.
func TestIAM_ListInstanceProfiles(t *testing.T) {
	h, refs := profileFixture(t)
	app := refs["AppProfile"]
	list := func(f url.Values) string {
		w := iamCall(h, profileReader, f)
		if w.Code != 200 {
			t.Fatalf("%v: %d %s", f, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	b := list(url.Values{"Action": {"ListInstanceProfiles"}})
	mustContain(t, "ListInstanceProfiles", b, "<InstanceProfileName>BatchProfile</InstanceProfileName>", "<InstanceProfileName>"+app+"</InstanceProfileName>",
		"<IsTruncated>false</IsTruncated>")
	if b := list(url.Values{"Action": {"ListInstanceProfiles"}, "PathPrefix": {"/app/"}}); !strings.Contains(b, app) || strings.Contains(b, "BatchProfile") {
		t.Errorf("PathPrefix /app/: %s", b)
	}
	b = list(url.Values{"Action": {"ListInstanceProfiles"}, "MaxItems": {"1"}})
	if !strings.Contains(b, "<IsTruncated>true</IsTruncated><Marker>BatchProfile</Marker>") || strings.Contains(b, app) {
		t.Fatalf("the first page of one: %s", b)
	}
	if b := list(url.Values{"Action": {"ListInstanceProfiles"}, "MaxItems": {"1"}, "Marker": {"BatchProfile"}}); !strings.Contains(b, app) || strings.Contains(b, "BatchProfile") {
		t.Errorf("the second page: %s", b)
	}
	b = list(url.Values{"Action": {"ListInstanceProfilesForRole"}, "RoleName": {"apps-approle"}})
	mustContain(t, "ListInstanceProfilesForRole", b, "<ListInstanceProfilesForRoleResult><InstanceProfiles>", app, "BatchProfile")
	w := iamCall(h, profileReader, url.Values{"Action": {"ListInstanceProfilesForRole"}, "RoleName": {"nope"}})
	if w.Code != 404 || !strings.Contains(w.Body.String(), "<Code>NoSuchEntity</Code>") {
		t.Errorf("an unknown role: %d %s", w.Code, w.Body.String())
	}
}

// Authorized on the profile's ARN (with its path) before anything about it is answered: an assumed role with
// no policy is refused whether the profile exists or not; a User's Deny on one profile's ARN refuses that
// one; in legacy a caller that may not read the stack is refused its profile and not listed it.
func TestIAM_InstanceProfiles_Denied(t *testing.T) {
	h, refs := profileFixture(t)
	role := iam.Claims{Sub: "assumed-role/r/s", AssumedRole: "r"}
	h.authz = checkerFor()
	for _, f := range []url.Values{
		{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {refs["AppProfile"]}},
		{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {"nope"}},
		{"Action": {"ListInstanceProfiles"}},
		{"Action": {"ListInstanceProfilesForRole"}, "RoleName": {"apps-approle"}},
	} {
		if w := iamCall(h, role, f); w.Code != 403 || !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("%v by an assumed role with no policy: %d %s", f, w.Code, w.Body.String())
		}
	}
	arn := "arn:aws:iam::000000000000:instance-profile/app/" + refs["AppProfile"]
	h.authz = checkerFor(dpAllow([]string{"iam:*"}, "*"), dpDeny([]string{"iam:GetInstanceProfile"}, "ARN::"+arn))
	user := iam.Claims{Sub: "tester"}
	if w := iamCall(h, user, url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {refs["AppProfile"]}}); w.Code != 403 {
		t.Errorf("a Deny on the profile's ARN (with its path): %d %s", w.Code, w.Body.String())
	}
	if w := iamCall(h, user, url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {"BatchProfile"}}); w.Code != 200 {
		t.Errorf("the Deny names one profile: %d %s", w.Code, w.Body.String())
	}
	h.authz = nil
	h.cfn.cs = csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return !(a.Resource == "applications" && a.Name == "apps") })
	if w := iamCall(h, profileReader, url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {"BatchProfile"}}); w.Code != 403 {
		t.Errorf("a caller that may not read the stack read its profile: %d %s", w.Code, w.Body.String())
	}
	if b := iamCall(h, profileReader, url.Values{"Action": {"ListInstanceProfiles"}}).Body.String(); strings.Contains(b, "BatchProfile") {
		t.Errorf("a caller that may not read the stack was listed its profile: %s", b)
	}
	h.cs = csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return a.Resource != "roles" })
	if w := iamCall(h, profileReader, url.Values{"Action": {"ListInstanceProfiles"}}); w.Code != 403 {
		t.Errorf("a caller RBAC refuses IAM's roles: %d %s", w.Code, w.Body.String())
	}
}

// In enforce IAM policy alone decides, on the profile's ARN: a grant under its path reaches that profile
// and no other, and no SubjectAccessReview counts.
func TestIAM_InstanceProfiles_Enforce(t *testing.T) {
	h, refs := profileFixture(t)
	h.cs, h.cfn.cs = csWithSAR(false), csWithSAR(false)
	user := iam.Claims{Sub: "tester"}
	h.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"iam:GetInstanceProfile"}, "ARN::arn:aws:iam::000000000000:instance-profile/app/*"),
		dpAllow([]string{"iam:ListInstanceProfiles"}, "*")))
	if w := iamCall(h, user, url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {refs["AppProfile"]}}); w.Code != 200 {
		t.Errorf("enforce: a grant under the profile's path: %d %s", w.Code, w.Body.String())
	}
	if w := iamCall(h, user, url.Values{"Action": {"GetInstanceProfile"}, "InstanceProfileName": {"BatchProfile"}}); w.Code != 403 ||
		!strings.Contains(w.Body.String(), "not authorized to perform: iam:GetInstanceProfile") {
		t.Errorf("enforce: a profile outside the granted path: %d %s", w.Code, w.Body.String())
	}
	if w := iamCall(h, user, url.Values{"Action": {"ListInstanceProfiles"}}); w.Code != 200 || !strings.Contains(w.Body.String(), "BatchProfile") {
		t.Errorf("enforce: ListInstanceProfiles lists the account's: %d %s", w.Code, w.Body.String())
	}
	if w := iamCall(h, user, url.Values{"Action": {"ListInstanceProfilesForRole"}, "RoleName": {"apps-approle"}}); w.Code != 403 {
		t.Errorf("enforce: ListInstanceProfilesForRole is not granted: %d %s", w.Code, w.Body.String())
	}
}

// A member account's request reads its own stacks' profiles, with its own account in their ARNs; the
// management account's never sees them.
func TestIAM_InstanceProfiles_AccountScoped(t *testing.T) {
	h, _ := profileFixture(t, profileStackRecord("team-apps", memberHome))
	member, err := h.instanceProfiles(memberCtx())
	if err != nil {
		t.Fatal(err)
	}
	if len(member) != 2 {
		t.Fatalf("a member account's profiles: %d", len(member))
	}
	for _, p := range member {
		if p.rec.Name != "team-apps" || !strings.HasPrefix(p.arn, "arn:aws:iam::"+testMember+":instance-profile/") ||
			!strings.HasPrefix(p.roles[0].arn, "arn:aws:iam::"+testMember+":role/") {
			t.Errorf("a member account's profile %s of stack %s (%s)", p.name, p.rec.Name, p.arn)
		}
	}
	mgmt, err := h.instanceProfiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range mgmt {
		if p.rec.Name != "apps" {
			t.Errorf("the management account listed stack %s's profile", p.rec.Name)
		}
	}
}
