package rbactocedar

import (
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PassRole is the custom RBAC verb `passrole` on roles.iam.openinfra.dev: the admission policy
// openinfra-pass-role asks the authorizer for it (platform/security/pass-role.yaml), and in enforce mode
// the Cedar corpus decides, so the verb must survive the RBAC -> Cedar translation exactly.
func passRoleEngine(t *testing.T, rule rbacv1.PolicyRule) *policyengine.Engine {
	t.Helper()
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"pass": {ObjectMeta: metav1.ObjectMeta{Name: "pass"}, Rules: []rbacv1.PolicyRule{rule}},
		},
		Roles: map[string]rbacv1.Role{},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "pass"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "pass"},
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "openinfra:admins"}},
		}},
	}
	grants := Generate(in)
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	eng, err := policyengine.NewEngine(grants[0].Statements)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestGenerate_PassRoleCustomVerbSurvives(t *testing.T) {
	eng := passRoleEngine(t, rbacv1.PolicyRule{APIGroups: []string{"iam.openinfra.dev"}, Resources: []string{"roles"}, Verbs: []string{"passrole"}})
	if d := eng.Authorize(req("Group", "openinfra:admins", "passrole", "roles.iam.openinfra.dev", "tenant-b/app")); !d.Allowed {
		t.Errorf("passrole on a role should be allowed: %s", d.Reason)
	}
	for _, verb := range []string{"get", "create", "update", "delete"} {
		if d := eng.Authorize(req("Group", "openinfra:admins", verb, "roles.iam.openinfra.dev", "tenant-b/app")); d.Allowed {
			t.Errorf("a passrole-only grant must not allow %s", verb)
		}
	}
	if d := eng.Authorize(req("Group", "openinfra:admins", "passrole", "users.iam.openinfra.dev", "tenant-b/app")); d.Allowed {
		t.Errorf("passrole on roles must not cover users")
	}
}

func TestGenerate_WildcardVerbCoversPassRole(t *testing.T) {
	eng := passRoleEngine(t, rbacv1.PolicyRule{APIGroups: []string{"iam.openinfra.dev"}, Resources: []string{"roles"}, Verbs: []string{"*"}})
	if d := eng.Authorize(req("Group", "openinfra:admins", "passrole", "roles.iam.openinfra.dev", "tenant-b/app")); !d.Allowed {
		t.Errorf("a * verb grant should cover passrole: %s", d.Reason)
	}
}

// A passrole grant scoped with resourceNames must authorize only those Roles.
//
// DEPENDS ON the generator honouring resourceNames (a separate fix to ruleToStatements/resourceString).
// Until that lands, Generate widens a resourceNames rule to the whole resource type and this test
// FAILS — that failure is the bug it guards.
func TestGenerate_PassRoleResourceNamesScoped(t *testing.T) {
	eng := passRoleEngine(t, rbacv1.PolicyRule{APIGroups: []string{"iam.openinfra.dev"}, Resources: []string{"roles"},
		ResourceNames: []string{"app"}, Verbs: []string{"passrole"}})
	if d := eng.Authorize(req("Group", "openinfra:admins", "passrole", "roles.iam.openinfra.dev", "tenant-b/app")); !d.Allowed {
		t.Errorf("passrole on the named role should be allowed: %s", d.Reason)
	}
	if d := eng.Authorize(req("Group", "openinfra:admins", "passrole", "roles.iam.openinfra.dev", "tenant-b/other")); d.Allowed {
		t.Errorf("a resourceNames-scoped passrole grant must not authorize a different Role")
	}
}
