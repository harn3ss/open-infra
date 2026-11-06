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

// A RoleBinding ServiceAccount subject that omits its namespace defaults to the binding's namespace
// (as Kubernetes does), so the grant lands on the real "ServiceAccount::<ns>/name" principal the API
// server sends — not a malformed "ServiceAccount::/name" that never matches. This is exactly the shape
// of argocd's / snapshot-controller's bindings, whose namespaced grants were being dropped.
func TestGenerate_RoleBindingSAWithoutNamespace(t *testing.T) {
	in := Inputs{
		Roles: map[string]rbacv1.Role{
			"argocd/argocd-server": {
				ObjectMeta: metav1.ObjectMeta{Name: "argocd-server", Namespace: "argocd"},
				Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get", "list", "watch"}, APIGroups: []string{""}, Resources: []string{"secrets"}}},
			},
		},
		RoleBindings: []rbacv1.RoleBinding{
			// Subject omits Namespace — the real argocd RoleBinding shape.
			{ObjectMeta: metav1.ObjectMeta{Namespace: "argocd"}, RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "argocd-server"},
				Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "argocd-server"}}},
		},
	}
	byP := map[string]Grant{}
	for _, g := range Generate(in) {
		byP[g.Principal] = g
	}
	if _, bad := byP["ServiceAccount::/argocd-server"]; bad {
		t.Fatalf("grant landed on a malformed namespace-less principal; got %v", keys(byP))
	}
	g, ok := byP["ServiceAccount::argocd/argocd-server"]
	if !ok {
		t.Fatalf("missing ServiceAccount::argocd/argocd-server grant; got %v", keys(byP))
	}
	eng, err := policyengine.NewEngine(g.Statements)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if d := eng.Authorize(req("User", "system:serviceaccount:argocd:argocd-server", "list", "secrets", "argocd/s1")); !d.Allowed {
		t.Errorf("argocd-server should list secrets in argocd: %s", d.Reason)
	}
}

// resource "*" in a SPECIFIC apiGroup is scoped to that group ("*.<group>"), NOT widened to every
// group — Cedar is never broader than the RBAC rule. (This is the AC-6 de-widening fix.)
func TestGenerate_WildcardResourceScopedToGroup(t *testing.T) {
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"appsall": {ObjectMeta: metav1.ObjectMeta{Name: "appsall"}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{"apps"}, Resources: []string{"*"}}}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "appsall"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "g"}}},
		},
	}
	g := Generate(in)
	if len(g) != 1 {
		t.Fatalf("expected 1 grant, got %d: %#v", len(g), g)
	}
	if strings.Contains(strings.Join(g[0].Caveats, " "), "widened to all groups") {
		t.Errorf("must NOT widen a specific-group * to all groups: %#v", g[0].Caveats)
	}
	eng, err := policyengine.NewEngine(g[0].Statements)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Matches any resource IN the apps group (the group wildcard)...
	if d := eng.Authorize(req("Group", "g", "get", "deployments.apps", "ns/x")); !d.Allowed {
		t.Errorf("should allow get on deployments.apps: %s", d.Reason)
	}
	if d := eng.Authorize(req("Group", "g", "get", "statefulsets.apps", "ns/y")); !d.Allowed {
		t.Errorf("should allow get on statefulsets.apps: %s", d.Reason)
	}
	// ...but NOT a resource in ANOTHER group (no widening — this is the whole point).
	if d := eng.Authorize(req("Group", "g", "get", "secrets", "ns/s")); d.Allowed {
		t.Errorf("must NOT allow core secrets from an apps-group grant (no widening)")
	}
	if d := eng.Authorize(req("Group", "g", "get", "databases.openinfra.dev", "ns/db")); d.Allowed {
		t.Errorf("must NOT allow databases.openinfra.dev from an apps-group grant (no widening)")
	}
}

// apiGroups:["*"] with a concrete (sub)resource must match that resource in ANY group — the core form
// AND the grouped form. This is the HPA "*/scale" grant: it has to authorize get on
// "deployments/scale.apps" (grouped), not just core-group scale.
func TestGenerate_AllGroupsConcreteResource(t *testing.T) {
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"hpa": {ObjectMeta: metav1.ObjectMeta{Name: "hpa"}, Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"get", "update"}, APIGroups: []string{"*"}, Resources: []string{"*/scale"}},
			}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "hpa"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "kube-system", Name: "hpa"}}},
		},
	}
	g := Generate(in)
	if len(g) != 1 {
		t.Fatalf("expected 1 grant, got %d: %#v", len(g), g)
	}
	eng, err := policyengine.NewEngine(g[0].Statements)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Grouped scale subresource (apps) — the case that regressed.
	if d := eng.Authorize(req("ServiceAccount", "kube-system/hpa", "get", "deployments/scale.apps", "default/web")); !d.Allowed {
		t.Errorf("should allow get on deployments/scale.apps (scale in any group): %s", d.Reason)
	}
	// Core-group scale subresource.
	if d := eng.Authorize(req("ServiceAccount", "kube-system/hpa", "update", "replicationcontrollers/scale", "default/rc")); !d.Allowed {
		t.Errorf("should allow update on core replicationcontrollers/scale: %s", d.Reason)
	}
	// But NOT the base object (scale grant is subresource-only).
	if d := eng.Authorize(req("ServiceAccount", "kube-system/hpa", "get", "deployments.apps", "default/web")); d.Allowed {
		t.Errorf("must NOT allow get on the deployments.apps object from a */scale grant")
	}
}

// A principal that can create (cluster)rolebindings must get the escalation-prevention caveat —
// the CNPG/CDI implicit-bind class the shadow run surfaced (no static bind rule to mirror).
func TestGenerate_RoleBindingCreatorCaveat(t *testing.T) {
	build := func(verbs ...string) []Grant {
		return Generate(Inputs{
			ClusterRoles: map[string]rbacv1.ClusterRole{
				"binder": {ObjectMeta: metav1.ObjectMeta{Name: "binder"}, Rules: []rbacv1.PolicyRule{
					{Verbs: verbs, APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"rolebindings"}},
				}},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "binder"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "cnpg-system", Name: "cloudnative-pg"}}},
			},
		})
	}
	if g := build("create", "get"); len(g) != 1 || !strings.Contains(strings.Join(g[0].Caveats, " "), "bind a role it lacks an explicit") {
		t.Fatalf("a rolebinding creator should get the escalation-prevention caveat, got %#v", g)
	}
	if g := build("get", "list", "watch"); len(g) == 1 && strings.Contains(strings.Join(g[0].Caveats, " "), "bind a role it lacks") {
		t.Errorf("a mere reader of rolebindings must NOT get the escalation caveat: %#v", g[0].Caveats)
	}
}

func keys(m map[string]Grant) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

// resourceNames narrow a grant to those names, as RBAC does. Before this, a resourceNames rule compiled to
// the whole resource type: a ServiceAccount allowed to impersonate four named groups could impersonate
// system:masters.
func TestGenerate_ResourceNamesAreScoped(t *testing.T) {
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"impersonator": {
				ObjectMeta: metav1.ObjectMeta{Name: "impersonator"},
				Rules: []rbacv1.PolicyRule{{Verbs: []string{"impersonate"}, APIGroups: []string{""}, Resources: []string{"groups"},
					ResourceNames: []string{"openinfra:admins", "openinfra:readers"}}},
			},
			"cm-reader": {
				ObjectMeta: metav1.ObjectMeta{Name: "cm-reader"},
				Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"},
					ResourceNames: []string{"shared-config"}}},
			},
			"weird": {
				ObjectMeta: metav1.ObjectMeta{Name: "weird"},
				Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"},
					ResourceNames: []string{"a*"}}},
			},
		},
		Roles: map[string]rbacv1.Role{
			"team-a/one-secret": {
				ObjectMeta: metav1.ObjectMeta{Name: "one-secret", Namespace: "team-a"},
				Rules: []rbacv1.PolicyRule{{Verbs: []string{"get", "update", "create", "list"}, APIGroups: []string{""}, Resources: []string{"secrets"},
					ResourceNames: []string{"app-creds"}}},
			},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "impersonator"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "shim", Name: "front"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cm-reader"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "shim", Name: "front"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "weird"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "odd"}}},
		},
		RoleBindings: []rbacv1.RoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"}, RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "one-secret"},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "bob"}}},
		},
	}
	byP := map[string]Grant{}
	for _, g := range Generate(in) {
		byP[g.Principal] = g
	}
	engine := func(p string) *policyengine.Engine {
		t.Helper()
		g, ok := byP[p]
		if !ok {
			t.Fatalf("missing %s grant; got %v", p, keys(byP))
		}
		e, err := policyengine.NewEngine(g.Statements)
		if err != nil {
			t.Fatalf("%s compile: %v", p, err)
		}
		return e
	}
	sa := "system:serviceaccount:shim:front"
	front := engine("ServiceAccount::shim/front")
	for _, c := range []struct {
		verb, rtype, id string
		want            bool
	}{
		{"impersonate", "groups", "openinfra:admins", true},
		{"impersonate", "groups", "openinfra:readers", true},
		{"impersonate", "groups", "system:masters", false},
		{"impersonate", "groups", "", false},
		{"get", "configmaps", "kube-system/shared-config", true},
		{"get", "configmaps", "other-ns/shared-config", true}, // cluster-wide binding: the name in any namespace
		{"get", "configmaps", "kube-system/other", false},
	} {
		if d := front.Authorize(req("User", sa, c.verb, c.rtype, c.id)); d.Allowed != c.want {
			t.Errorf("front %s %s %q: allowed=%v, want %v (%s)", c.verb, c.rtype, c.id, d.Allowed, c.want, d.Reason)
		}
	}

	bob := engine("User::bob")
	for _, c := range []struct {
		verb, id string
		want     bool
	}{
		{"get", "team-a/app-creds", true},
		{"update", "team-a/app-creds", true},
		{"get", "team-a/other", false},
		{"get", "team-b/app-creds", false}, // a RoleBinding grant stays in its namespace
		{"create", "team-a/", false},       // no name at create time: RBAC does not grant it either
		{"list", "team-a/", false},
	} {
		if d := bob.Authorize(req("User", "bob", c.verb, "secrets", c.id)); d.Allowed != c.want {
			t.Errorf("bob %s secrets %q: allowed=%v, want %v (%s)", c.verb, c.id, d.Allowed, c.want, d.Reason)
		}
	}

	// RBAC matches a "*" name literally; Cedar would read it as a prefix wildcard. Outside signers the
	// name is dropped (never broader than RBAC), with a caveat.
	odd := byP["User::odd"]
	if len(odd.Statements) != 0 {
		t.Errorf("a* on configmaps must grant nothing; got %+v", odd.Statements)
	}
	if !strings.Contains(strings.Join(odd.Caveats, " "), "dropped") {
		t.Errorf("expected a caveat for the dropped name; got %v", odd.Caveats)
	}
}

// Signers are the one type whose names use the "<domain>/*" form: the API server checks it literally
// when approving or signing, so it stays a wildcard within the name (cert-manager's approver relies on
// it), and only on signers.
func TestGenerate_SignerNameWildcard(t *testing.T) {
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{"approver": {
			ObjectMeta: metav1.ObjectMeta{Name: "approver"},
			Rules: []rbacv1.PolicyRule{{Verbs: []string{"approve"}, APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"signers"}, ResourceNames: []string{"issuers.cert-manager.io/*"}}},
		}},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "approver"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "cert-manager", Name: "cm"}}}},
	}
	gs := Generate(in)
	if len(gs) != 1 {
		t.Fatalf("grants = %+v", gs)
	}
	e, err := policyengine.NewEngine(gs[0].Statements)
	if err != nil {
		t.Fatal(err)
	}
	sa := "system:serviceaccount:cert-manager:cm"
	for id, want := range map[string]bool{
		"issuers.cert-manager.io/*":           true, // the form the API server checks
		"issuers.cert-manager.io/ns.issuer":   true,
		"clusterissuers.cert-manager.io/one":  false,
		"kubernetes.io/kube-apiserver-client": false,
	} {
		if d := e.Authorize(req("User", sa, "approve", "signers.certificates.k8s.io", id)); d.Allowed != want {
			t.Errorf("approve signer %q: allowed=%v want %v", id, d.Allowed, want)
		}
	}
	if d := e.Authorize(req("User", sa, "approve", "configmaps", "issuers.cert-manager.io/x")); d.Allowed {
		t.Errorf("the signer wildcard must not reach another type")
	}
}

// cert-manager's approver is checked on its OWN signers resource (cert-manager.io), the shape the live
// cert-manager ClusterRole has: dropping it would stop every certificate approval.
func TestGenerate_CertManagerSignerWildcard(t *testing.T) {
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{"cm-approve": {
			ObjectMeta: metav1.ObjectMeta{Name: "cm-approve"},
			Rules: []rbacv1.PolicyRule{{Verbs: []string{"approve"}, APIGroups: []string{"cert-manager.io"},
				Resources: []string{"signers"}, ResourceNames: []string{"issuers.cert-manager.io/*", "clusterissuers.cert-manager.io/*"}}},
		}},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cm-approve"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "cert-manager", Name: "cert-manager"}}}},
	}
	e, err := policyengine.NewEngine(Generate(in)[0].Statements)
	if err != nil {
		t.Fatal(err)
	}
	sa := "system:serviceaccount:cert-manager:cert-manager"
	for id, want := range map[string]bool{
		"issuers.cert-manager.io/*":                   true,
		"clusterissuers.cert-manager.io/*":            true,
		"clusterissuers.cert-manager.io/openinfra-ca": true,
		"other.example.com/*":                         false,
	} {
		if d := e.Authorize(req("User", sa, "approve", "signers.cert-manager.io", id)); d.Allowed != want {
			t.Errorf("approve %q: allowed=%v want %v", id, d.Allowed, want)
		}
	}
}

// The RBAC the IAM compiler generates (its principals' bindings, the service-linked roles' bindings) is
// carried by the iam-corpus it writes each pass, never by this snapshot.
func TestGenerate_SkipsTheIAMCompilersBindings(t *testing.T) {
	cr := rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "openinfra:service-linked:aws-shim"},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}}}
	sa := rbacv1.Subject{Kind: "ServiceAccount", Namespace: "open-infra-aws-shim", Name: "aws-shim"}
	ref := rbacv1.RoleRef{Kind: "ClusterRole", Name: cr.Name}
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{cr.Name: cr},
		RoleBindings: []rbacv1.RoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Name: cr.Name, Namespace: "shop", Labels: map[string]string{"openinfra.dev/generated-by": "iam-compiler"}},
				RoleRef: ref, Subjects: []rbacv1.Subject{sa}},
			{ObjectMeta: metav1.ObjectMeta{Name: "hand-written", Namespace: "ops"}, RoleRef: ref, Subjects: []rbacv1.Subject{sa}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Name: "gen", Labels: map[string]string{"openinfra.dev/generated-by": "iam-compiler"}},
				RoleRef: ref, Subjects: []rbacv1.Subject{{Kind: "User", Name: "someone"}}},
		},
	}
	grants := Generate(in)
	if len(grants) != 1 || grants[0].Principal != "ServiceAccount::open-infra-aws-shim/aws-shim" {
		t.Fatalf("grants = %+v, want the hand-written binding's alone", grants)
	}
	for _, st := range grants[0].Statements {
		for _, r := range st.Resources {
			if r != "configmaps::ops/*" {
				t.Fatalf("a compiled binding reached the corpus: %v", r)
			}
		}
	}
}
