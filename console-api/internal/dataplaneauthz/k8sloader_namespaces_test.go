package dataplaneauthz

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
)

const home = DefaultHomeNamespace

func iamObj(kind, ns, name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec":       spec,
	}}
}

func dataPlane(appliesTo []any, actions ...any) map[string]any {
	return map[string]any{"dataPlane": map[string]any{
		"appliesTo":  appliesTo,
		"statements": []any{map[string]any{"effect": "Allow", "actions": actions, "resources": []any{"*"}}},
	}}
}

func loaderOver(t *testing.T, objs ...*unstructured.Unstructured) *Checker {
	t.Helper()
	rt := make([]runtime.Object, len(objs))
	for i, o := range objs {
		rt[i] = o
	}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		policyGVR: "PolicyList", roleGVR: "RoleList", userGVR: "UserList", groupGVR: "GroupList", iamauthz.GrantGVR: "GrantList",
	}, rt...)
	return New(K8sLoaderIn(dc, home), time.Minute)
}

// A Role is a principal of its own namespace: a same-named Role elsewhere neither inherits its
// policies nor lends it its own (item 8b — the keys were bare names merged across namespaces).
func TestK8sLoader_SameNamedRolesInTwoNamespacesAreTwoPrincipals(t *testing.T) {
	c := loaderOver(t,
		iamObj("Policy", home, "s3-all", dataPlane(nil, "s3:*")),
		iamObj("Policy", "tenant-b", "sqs-all", dataPlane(nil, "sqs:*")),
		iamObj("Role", home, "app", map[string]any{"policies": []any{"s3-all"}}),
		iamObj("Role", "tenant-b", "app", map[string]any{"policies": []any{"sqs-all"}}),
	)
	ctx := context.Background()
	cases := []struct {
		pid, action string
		want        bool
	}{
		{"app", "s3:GetObject", true},             // the home Role's own policy
		{"app", "sqs:SendMessage", false},         // not tenant-b's
		{"tenant-b/app", "sqs:SendMessage", true}, // tenant-b's own
		{"tenant-b/app", "s3:GetObject", false},   // not the home Role's
	}
	for _, tc := range cases {
		if ok, _, why := c.Authorize(ctx, "Role", tc.pid, nil, tc.action, "Bucket", "b", nil); ok != tc.want {
			t.Errorf("Role %s %s: allowed=%v (%s), want %v", tc.pid, tc.action, ok, why, tc.want)
		}
	}
}

// A bare spec.policies reference resolves to the principal's own namespace's Policy first, then the
// home namespace's (the managed library). A namespaced principal cannot reach a third namespace.
func TestK8sLoader_PolicyReferencesResolveOwnNamespaceThenHome(t *testing.T) {
	c := loaderOver(t,
		iamObj("Policy", home, "managed-s3", dataPlane(nil, "s3:*")),
		iamObj("Policy", home, "shadowed", dataPlane(nil, "dynamodb:*")),
		iamObj("Policy", "tenant-b", "shadowed", dataPlane(nil, "sns:*")),
		iamObj("Policy", "tenant-c", "foreign", dataPlane(nil, "kms:*")),
		iamObj("Role", "tenant-b", "vm", map[string]any{"policies": []any{"managed-s3", "shadowed", "tenant-c/foreign"}}),
	)
	ctx := context.Background()
	for _, tc := range []struct {
		action string
		want   bool
	}{
		{"s3:GetObject", true},      // home managed policy (no tenant-b policy of that name)
		{"sns:Publish", true},       // tenant-b's own "shadowed" wins over home's
		{"dynamodb:GetItem", false}, // home's "shadowed" is not attached
		{"kms:Decrypt", false},      // a third namespace's Policy cannot be attached
	} {
		if ok, _, why := c.Authorize(ctx, "Role", "tenant-b/vm", nil, tc.action, "Bucket", "b", nil); ok != tc.want {
			t.Errorf("tenant-b/vm %s: allowed=%v (%s), want %v", tc.action, ok, why, tc.want)
		}
	}
}

// A Policy outside home governs only its own namespace's principals through appliesTo; a home Policy
// may name a principal in any namespace explicitly.
func TestK8sLoader_AppliesToIsScopedToThePolicysNamespace(t *testing.T) {
	c := loaderOver(t,
		// tenant-b Policies: bare names, an explicit own-namespace name, "*", and entries that try to
		// reach home principals or groups (dropped).
		iamObj("Policy", "tenant-b", "b-bare", dataPlane([]any{"Role::app"}, "s3:*")),
		iamObj("Policy", "tenant-b", "b-star", dataPlane([]any{"*"}, "sqs:*")),
		iamObj("Policy", "tenant-b", "b-reach", dataPlane([]any{"User::open-infra-console/alice", "Group::admins", "Role::tenant-c/app"}, "kms:*")),
		// home Policy naming a tenant-b principal explicitly.
		iamObj("Policy", home, "h-explicit", dataPlane([]any{"Role::tenant-b/app"}, "dynamodb:*")),
	)
	ctx := context.Background()
	check := func(ptype, pid string, groups []string, action string, want bool) {
		t.Helper()
		ok, _, why := c.Authorize(ctx, ptype, pid, groups, action, "Bucket", "b", nil)
		if ok != want {
			t.Errorf("%s %s %s: allowed=%v (%s), want %v", ptype, pid, action, ok, why, want)
		}
	}
	check("Role", "tenant-b/app", nil, "s3:GetObject", true)                  // b-bare = tenant-b/app
	check("Role", "app", nil, "s3:GetObject", false)                          // ... not the home Role app
	check("Role", "tenant-b/app", nil, "sqs:SendMessage", true)               // b-star covers tenant-b
	check("Role", "tenant-c/app", nil, "sqs:SendMessage", false)              // ... not tenant-c
	check("Role", "app", nil, "sqs:SendMessage", false)                       // ... nor home
	check("User", "alice", []string{"openinfra:admins"}, "kms:Decrypt", true) // b-reach dropped: alice ungoverned (coarse RBAC stands)
	check("Role", "tenant-c/app", nil, "kms:Decrypt", false)                  // ... and cannot reach tenant-c
	check("Role", "tenant-b/app", nil, "dynamodb:GetItem", true)              // h-explicit
	if _, governed, _ := c.Authorize(ctx, "User", "alice", []string{"openinfra:admins"}, "kms:Decrypt", "Key", "k", nil); governed {
		t.Errorf("a tenant-b Policy must not govern the home User alice")
	}
}

// A permission boundary that names a Policy the principal may not use compiles to deny-all, as an
// unresolvable boundary always has (it never silently lifts the cap).
func TestK8sLoader_ForeignBoundaryFailsClosed(t *testing.T) {
	c := loaderOver(t,
		iamObj("Policy", "tenant-b", "allow-s3", dataPlane(nil, "s3:*")),
		iamObj("Policy", "tenant-c", "wide-boundary", dataPlane(nil, "*")),
		iamObj("Role", "tenant-b", "vm", map[string]any{"policies": []any{"allow-s3"}, "permissionBoundary": "tenant-c/wide-boundary"}),
		iamObj("Role", "tenant-b", "vm2", map[string]any{"policies": []any{"allow-s3"}}),
	)
	ctx := context.Background()
	if ok, _, _ := c.Authorize(ctx, "Role", "tenant-b/vm", nil, "s3:GetObject", "Bucket", "b", nil); ok {
		t.Errorf("a boundary from another namespace must cap to nothing")
	}
	if ok, _, why := c.Authorize(ctx, "Role", "tenant-b/vm2", nil, "s3:GetObject", "Bucket", "b", nil); !ok {
		t.Errorf("control: tenant-b/vm2 should be allowed: %s", why)
	}
}

func TestQualifiedName(t *testing.T) {
	for _, tc := range []struct{ ns, name, want string }{
		{home, "app", "app"},
		{"", "app", "app"},
		{"tenant-b", "app", "tenant-b/app"},
	} {
		got := QualifiedName(home, tc.ns, tc.name)
		if got != tc.want {
			t.Errorf("QualifiedName(%q,%q) = %q, want %q", tc.ns, tc.name, got, tc.want)
		}
		ns, name := SplitQualified(home, got)
		wantNS := tc.ns
		if wantNS == "" {
			wantNS = home
		}
		if ns != wantNS || name != tc.name {
			t.Errorf("SplitQualified(%q) = %q,%q", got, ns, name)
		}
	}
}
