package dataplaneauthz

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// #7 read-half parity: kind: Policy dataPlane statements that use notActions/notResources must load
// through K8sLoader into the engine's complement axes and ENFORCE "any except these", including the
// per-service governance gate — a Deny NotAction with empty Actions must still be seen as GOVERNING the
// service, or the forbid is silently bypassed (coarse RBAC stands) which is a fail-open.
func TestK8sLoader_Complement(t *testing.T) {
	policy := func(name, principal string, stmts ...map[string]any) *unstructured.Unstructured {
		anyStmts := make([]any, len(stmts))
		for i, s := range stmts {
			anyStmts[i] = s
		}
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Policy",
			"metadata":   map[string]any{"name": name, "namespace": "iam"},
			"spec": map[string]any{
				"dataPlane": map[string]any{
					"appliesTo":  []any{principal},
					"statements": anyStmts,
				},
			},
		}}
	}

	// alice: Allow everything EXCEPT s3:DeleteObject (a NotAction grant over all resources).
	alice := policy("alice-notaction", "User::alice",
		map[string]any{"effect": "Allow", "notActions": []any{"s3:DeleteObject"}, "resources": []any{"*"}})
	// bob: Allow dynamodb:GetItem on every table EXCEPT Table::secret (a NotResource scope).
	bob := policy("bob-notresource", "User::bob",
		map[string]any{"effect": "Allow", "actions": []any{"dynamodb:GetItem"}, "notResources": []any{"Table::secret"}})
	// carol: Deny everything EXCEPT s3:GetObject (a Deny NotAction — the fail-open regression guard).
	carol := policy("carol-deny-notaction", "User::carol",
		map[string]any{"effect": "Allow", "actions": []any{"s3:*"}, "resources": []any{"*"}},
		map[string]any{"effect": "Deny", "notActions": []any{"s3:GetObject"}, "resources": []any{"*"}})

	scheme := runtime.NewScheme()
	lists := map[schema.GroupVersionResource]string{
		policyGVR: "PolicyList",
		roleGVR:   "RoleList",
		userGVR:   "UserList",
		groupGVR:  "GroupList",
	}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, lists, alice, bob, carol)
	c := New(K8sLoader(dc), time.Minute)
	ctx := context.Background()

	check := func(name, pid, action, rt, rid string, wantAllow, wantGov bool) {
		t.Helper()
		a, g, r := c.Authorize(ctx, "User", pid, nil, action, rt, rid, nil)
		if a != wantAllow || g != wantGov {
			t.Errorf("%s: allowed=%v governed=%v (%s), want %v/%v", name, a, g, r, wantAllow, wantGov)
		}
	}

	// NotAction grant: delete excluded, everything else on s3 allowed — and alice IS governed for s3.
	check("alice get (NotAction allows)", "alice", "s3:GetObject", "Bucket", "x", true, true)
	check("alice delete (NotAction excludes)", "alice", "s3:DeleteObject", "Bucket", "x", false, true)

	// NotResource scope: GetItem allowed everywhere but Table::secret.
	check("bob getitem public (NotResource allows)", "bob", "dynamodb:GetItem", "Table", "public", true, true)
	check("bob getitem secret (NotResource excludes)", "bob", "dynamodb:GetItem", "Table", "secret", false, true)

	// Deny NotAction regression: the forbid must FIRE (govern + deny) for a non-excluded action, not be
	// bypassed as "ungoverned". GetObject is the one carve-out and survives the broad allow.
	check("carol put (Deny NotAction fires)", "carol", "s3:PutObject", "Bucket", "x", false, true)
	check("carol get (Deny NotAction carve-out)", "carol", "s3:GetObject", "Bucket", "x", true, true)
}
