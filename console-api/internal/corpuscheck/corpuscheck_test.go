package corpuscheck

import (
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/rbactocedar"
	"github.com/harn3ss/open-infra/policyengine"
)

func grant(p string, caveats []string, stmts ...policyengine.Statement) rbactocedar.Grant {
	return rbactocedar.Grant{Principal: p, Statements: stmts, Caveats: caveats}
}
func allow(actions, resources []string) policyengine.Statement {
	return policyengine.Statement{Effect: policyengine.Allow, Actions: actions, Resources: resources}
}

func findingsFor(t *testing.T, g rbactocedar.Grant) map[string]Severity {
	t.Helper()
	m := map[string]Severity{}
	for _, f := range Check([]rbactocedar.Grant{g}) {
		m[f.Rule] = f.Severity
	}
	return m
}

func TestCheck_ClusterAdminIsHigh(t *testing.T) {
	f := findingsFor(t, grant("ServiceAccount::kube-system/op", nil, allow([]string{"*"}, []string{"*"})))
	if f["cluster-admin-equivalent"] != High {
		t.Fatalf("full-* grant must be High cluster-admin-equivalent, got %v", f)
	}
	// The subsuming rule means we don't ALSO emit the narrower wildcard-resource warning for it.
	if _, ok := f["wildcard-resource"]; ok {
		t.Errorf("cluster-admin should subsume wildcard-resource, got %v", f)
	}
}

func TestCheck_WildcardResourceAndSecrets(t *testing.T) {
	f := findingsFor(t, grant("Group::viewers", nil, allow([]string{"get", "list"}, []string{"*"})))
	if f["wildcard-resource"] != Warn {
		t.Errorf("resource \"*\" must warn, got %v", f)
	}
	if f["secrets-cluster-wide"] != Warn {
		t.Errorf("get/list on \"*\" reads secrets cluster-wide -> warn, got %v", f)
	}
	// A narrow, safe grant produces nothing.
	if g := findingsFor(t, grant("Group::app", nil, allow([]string{"get"}, []string{"configmaps::team-a/*"}))); len(g) != 0 {
		t.Errorf("a narrow grant should produce no findings, got %v", g)
	}
}

func TestCheck_EscalationAndCaveats(t *testing.T) {
	f := findingsFor(t, grant("ServiceAccount::x/y", []string{"resourceNames [...] not scoped"},
		allow([]string{"bind", "escalate"}, []string{"clusterroles.rbac.authorization.k8s.io::*"})))
	if f["privilege-escalation-verb"] != Warn {
		t.Errorf("bind/escalate must warn, got %v", f)
	}
	if f["faithfulness-caveat"] != Info {
		t.Errorf("a grant with caveats must record an info finding, got %v", f)
	}
}
