package main

import (
	"context"
	"html"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ec2TrustDoc is an instance role's trust policy: EC2 may assume it.
const ec2TrustDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

// putProfileRole makes a kind: Role in ns that trusts EC2's instances, as CreateRole makes one.
func putProfileRole(t *testing.T, h *iamHandler, ns, name string) {
	t.Helper()
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1", "kind": "Role",
		"metadata": map[string]any{"name": name, "namespace": ns, "annotations": map[string]any{assumeRolePolicyAnnotation: ec2TrustDoc}},
		"spec":     map[string]any{"trust": []any{"vm"}, "policies": []any{}},
	}}
	if _, err := h.dyn.Resource(gvrRoles).Namespace(ns).Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// ipCall serves one IAM request, its form given as name/value pairs, in ctx.
func ipCall(h *iamHandler, ctx context.Context, claims iam.Claims, kv ...string) *httptest.ResponseRecorder {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return serveWith(h, formOp(v).WithContext(ctx), claims)
}

// The instance-profile writes are each authorized on the profile's ARN before anything is answered: an
// assumed role with no policy, and a User whose RBAC refuses IAM's roles, are refused every one, whether the
// profile exists or not.
func TestIAM_InstanceProfileWrites_DeniedWithoutPolicy(t *testing.T) {
	h, _ := profileFixture(t)
	putProfileRole(t, h, "default", "web-role")
	ctx := context.Background()
	writes := [][]string{
		{"Action", "CreateInstanceProfile", "InstanceProfileName", "Web"},
		{"Action", "CreateInstanceProfile", "InstanceProfileName", "Web", "Path", "/app/", "Tags.member.1.Key", "team", "Tags.member.1.Value", "a"},
		{"Action", "DeleteInstanceProfile", "InstanceProfileName", "BatchProfile"},
		{"Action", "DeleteInstanceProfile", "InstanceProfileName", "nope"},
		{"Action", "AddRoleToInstanceProfile", "InstanceProfileName", "BatchProfile", "RoleName", "web-role"},
		{"Action", "AddRoleToInstanceProfile", "InstanceProfileName", "nope", "RoleName", "web-role"},
		{"Action", "RemoveRoleFromInstanceProfile", "InstanceProfileName", "BatchProfile", "RoleName", "apps-approle"},
	}
	h.authz = checkerFor()
	role := iam.Claims{Sub: "assumed-role/r/s", AssumedRole: "r"}
	for _, f := range writes {
		if w := ipCall(h, ctx, role, f...); w.Code != 403 || !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") {
			t.Errorf("%v by an assumed role with no policy: %d %s", f, w.Code, w.Body.String())
		}
	}
	h.authz = nil
	h.cs = csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return a.Resource != "roles" })
	for _, f := range writes {
		if w := ipCall(h, ctx, profileReader, f...); w.Code != 403 || !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") {
			t.Errorf("%v by a caller RBAC refuses IAM's roles: %d %s", f, w.Code, w.Body.String())
		}
	}
}

// In enforce IAM policy alone decides, as AWS does: CreateInstanceProfile on the profile's ARN (its path
// included), tags on create need iam:TagInstanceProfile too, and AddRoleToInstanceProfile needs iam:PassRole
// on the role besides.
func TestIAM_InstanceProfileWrites_Enforce(t *testing.T) {
	h, _ := profileFixture(t)
	putProfileRole(t, h, "default", "web-role")
	h.cs, h.cfn.cs = csWithSAR(false), csWithSAR(false)
	ctx := context.Background()
	user := iam.Claims{Sub: "tester"}
	h.authz = checkerInMode(t, "enforce", userDoc(
		dpAllow([]string{"iam:CreateInstanceProfile"}, "ARN::arn:aws:iam::000000000000:instance-profile/app/*"),
		dpAllow([]string{"iam:AddRoleToInstanceProfile"}, "ARN::arn:aws:iam::000000000000:instance-profile/*")))
	w := ipCall(h, ctx, user, "Action", "CreateInstanceProfile", "InstanceProfileName", "Other", "Path", "/ops/")
	if w.Code != 403 || !strings.Contains(w.Body.String(),
		"is not authorized to perform: iam:CreateInstanceProfile on resource: arn:aws:iam::000000000000:instance-profile/ops/Other") {
		t.Errorf("a profile outside the granted path: %d %s", w.Code, w.Body.String())
	}
	w = ipCall(h, ctx, user, "Action", "CreateInstanceProfile", "InstanceProfileName", "Web", "Path", "/app/", "Tags.member.1.Key", "team", "Tags.member.1.Value", "a")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "not authorized to perform: iam:TagInstanceProfile") {
		t.Errorf("tags on create without iam:TagInstanceProfile: %d %s", w.Code, w.Body.String())
	}
	// Granted: past the gate, this shim keeps no profiles (no store), which it says.
	if w := ipCall(h, ctx, user, "Action", "CreateInstanceProfile", "InstanceProfileName", "Web", "Path", "/app/"); w.Code != 500 ||
		!strings.Contains(w.Body.String(), "instance-profile store is not configured") {
		t.Errorf("an allowed CreateInstanceProfile with no store: %d %s", w.Code, w.Body.String())
	}
	// iam:AddRoleToInstanceProfile alone does not pass the role.
	w = ipCall(h, ctx, user, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "Web", "RoleName", "web-role")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "not authorized to perform: iam:PassRole on resource: Role::web-role") {
		t.Errorf("AddRoleToInstanceProfile without iam:PassRole: %d %s", w.Code, w.Body.String())
	}
	// With it, the request is past both gates (and the profile is not one this shim has).
	h.authz = checkerInMode(t, "enforce", userDoc(
		dpAllow([]string{"iam:AddRoleToInstanceProfile"}, "ARN::arn:aws:iam::000000000000:instance-profile/*"),
		dpAllow([]string{"iam:PassRole"}, "Role::web-role")))
	if w := ipCall(h, ctx, user, "Action", "AddRoleToInstanceProfile", "InstanceProfileName", "Web", "RoleName", "web-role"); w.Code != 404 ||
		!strings.Contains(w.Body.String(), "Instance Profile Web cannot be found.") {
		t.Errorf("AddRoleToInstanceProfile with iam:PassRole: %d %s", w.Code, w.Body.String())
	}
	if w := ipCall(h, ctx, user, "Action", "DeleteInstanceProfile", "InstanceProfileName", "Web"); w.Code != 403 ||
		!strings.Contains(w.Body.String(), "not authorized to perform: iam:DeleteInstanceProfile") {
		t.Errorf("DeleteInstanceProfile is not granted: %d %s", w.Code, w.Body.String())
	}
}

// A profile a stack holds is the stack's: the IAM API reads it and changes it only through its stack.
func TestIAM_InstanceProfileWrites_StackProfileIsUnmodifiable(t *testing.T) {
	h, refs := profileFixture(t)
	putProfileRole(t, h, "default", "web-role")
	ctx := context.Background()
	for _, f := range [][]string{
		{"Action", "DeleteInstanceProfile", "InstanceProfileName", "BatchProfile"},
		{"Action", "AddRoleToInstanceProfile", "InstanceProfileName", "batchprofile", "RoleName", "web-role"},
		{"Action", "RemoveRoleFromInstanceProfile", "InstanceProfileName", refs["AppProfile"], "RoleName", "apps-approle"},
	} {
		if w := ipCall(h, ctx, profileReader, f...); w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>UnmodifiableEntity</Code>") ||
			!strings.Contains(w.Body.String(), "CloudFormation stack apps") {
			t.Errorf("%v on a stack's profile: %d %s", f, w.Code, w.Body.String())
		}
	}
	// Its name is taken: CreateInstanceProfile of it is EntityAlreadyExists (once there is a store), and
	// without a store the shim says it keeps none.
	if w := ipCall(h, ctx, profileReader, "Action", "CreateInstanceProfile", "InstanceProfileName", "BatchProfile"); w.Code != 500 {
		t.Errorf("CreateInstanceProfile with no store: %d %s", w.Code, w.Body.String())
	}
}

// CreateInstanceProfile validates as IAM does: a name and path IAM accepts, at most 50 tags, no key twice.
func TestIAM_CreateInstanceProfile_Validation(t *testing.T) {
	h, _ := profileFixture(t)
	ctx := context.Background()
	for _, c := range []struct {
		kv   []string
		code string
	}{
		{[]string{"Action", "CreateInstanceProfile"}, "Value null at 'instanceProfileName'"},
		{[]string{"Action", "CreateInstanceProfile", "InstanceProfileName", "web profile"}, "at 'instanceProfileName' failed to satisfy constraint: Member must satisfy regular expression pattern"},
		{[]string{"Action", "CreateInstanceProfile", "InstanceProfileName", strings.Repeat("a", 129)}, "Member must have length less than or equal to 128"},
		{[]string{"Action", "CreateInstanceProfile", "InstanceProfileName", "Web", "Path", "app"}, "Value 'app' at 'path' failed to satisfy constraint"},
		{[]string{"Action", "CreateInstanceProfile", "InstanceProfileName", "Web", "Tags.member.1.Key", "a", "Tags.member.1.Value", "1",
			"Tags.member.2.Key", "a", "Tags.member.2.Value", "2"}, "Duplicate tag keys"},
		{[]string{"Action", "DeleteInstanceProfile"}, "Value null at 'instanceProfileName'"},
		{[]string{"Action", "AddRoleToInstanceProfile", "InstanceProfileName", "Web"}, "Value null at 'roleName'"},
	} {
		if w := ipCall(h, ctx, profileReader, c.kv...); w.Code != 400 || !strings.Contains(html.UnescapeString(w.Body.String()), c.code) {
			t.Errorf("%v: %d %s", c.kv, w.Code, w.Body.String())
		}
	}
}
