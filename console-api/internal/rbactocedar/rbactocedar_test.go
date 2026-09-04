package rbactocedar

import (
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// req builds a keyed policyengine.Request (keeps the assertions terse + vet-clean).
func req(ptype, pid, action, rtype, rid string) policyengine.Request {
	return policyengine.Request{
		Principal: policyengine.Principal{Type: ptype, ID: pid},
		Action:    action,
		Resource:  policyengine.Resource{Type: rtype, ID: rid},
	}
}

func TestGenerate_ClusterAndNamespacedGrants(t *testing.T) {
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"reader": {
				ObjectMeta: metav1.ObjectMeta{Name: "reader"},
				Rules: []rbacv1.PolicyRule{
					{Verbs: []string{"get", "list", "watch"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
					{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}},
				},
			},
			"admin": {
				ObjectMeta: metav1.ObjectMeta{Name: "admin"},
				Rules:      []rbacv1.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
			},
		},
		Roles: map[string]rbacv1.Role{
			"team-a/ns-reader": {
				ObjectMeta: metav1.ObjectMeta{Name: "ns-reader", Namespace: "team-a"},
				Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}}},
			},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "reader"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "viewers"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "admin"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "kube-system", Name: "op"}}},
		},
		RoleBindings: []rbacv1.RoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"}, RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "ns-reader"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}}},
		},
	}
	grants := Generate(in)

	byP := map[string]Grant{}
	for _, g := range grants {
		byP[g.Principal] = g
	}

	// The cluster-wide reader grant compiles + enforces as intended.
	viewers, ok := byP["Group::viewers"]
	if !ok {
		t.Fatalf("missing Group::viewers grant; got %v", keys(byP))
	}
	eng, err := policyengine.NewEngine(viewers.Statements)
	if err != nil {
		t.Fatalf("viewers compile: %v", err)
	}
	if d := eng.Authorize(req("Group", "viewers", "get", "deployments.apps", "team-a/web")); !d.Allowed {
		t.Errorf("viewers should get deployments.apps cluster-wide: %s", d.Reason)
	}
	if d := eng.Authorize(req("Group", "viewers", "get", "NonResourceURL", "/healthz")); !d.Allowed {
		t.Errorf("viewers should get /healthz")
	}
	if d := eng.Authorize(req("Group", "viewers", "delete", "deployments.apps", "x/y")); d.Allowed {
		t.Errorf("viewers should NOT delete (verb not granted)")
	}

	// The namespaced role grant is scoped to its namespace.
	alice := byP["User::alice"]
	ea, _ := policyengine.NewEngine(alice.Statements)
	if d := ea.Authorize(req("User", "alice", "get", "secrets", "team-a/s1")); !d.Allowed {
		t.Errorf("alice should get secrets in team-a: %s", d.Reason)
	}
	if d := ea.Authorize(req("User", "alice", "get", "secrets", "kube-system/s1")); d.Allowed {
		t.Errorf("alice must NOT get secrets outside team-a (namespaced grant)")
	}

	// cluster-admin (*/*/*) grants everything.
	op := byP["ServiceAccount::kube-system/op"]
	eo, _ := policyengine.NewEngine(op.Statements)
	if d := eo.Authorize(req("ServiceAccount", "kube-system/op", "delete", "nodes", "n1")); !d.Allowed {
		t.Errorf("cluster-admin SA should do anything: %s", d.Reason)
	}
}

// resource "*" in a specific apiGroup is widened + must record a caveat (honest about the loss).
func TestGenerate_WildcardResourceCaveat(t *testing.T) {
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"appsall": {ObjectMeta: metav1.ObjectMeta{Name: "appsall"}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{"apps"}, Resources: []string{"*"}}}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "appsall"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "g"}}},
		},
	}
	g := Generate(in)
	if len(g) != 1 || !strings.Contains(strings.Join(g[0].Caveats, " "), "widened to all groups") {
		t.Fatalf("expected a widening caveat, got %#v", g)
	}
}

func keys(m map[string]Grant) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}
