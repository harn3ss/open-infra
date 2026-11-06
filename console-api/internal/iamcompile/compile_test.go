package iamcompile

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/controlplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// doc compiles an AWS JSON policy document exactly as the evaluator does.
func doc(t *testing.T, name, document string) iamauthz.Policy {
	t.Helper()
	stmts, _, err := iamauthz.CompileDocument(document)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return iamauthz.Policy{Name: name, Statements: stmts}
}

const (
	adminDoc     = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	powerUserDoc = `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},
		{"Effect":"Allow","Action":["iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization","account:ListRegions"],"Resource":"*"}]}`
)

// world builds a World where each user named in attach has those policies attached.
func world(policies []iamauthz.Policy, attach map[string][]string) iamauthz.World {
	w := iamauthz.World{Docs: policies, Attach: map[string][]string{}}
	for k, v := range attach {
		w.Attach[k] = v
	}
	return w
}

// corpusChecker compiles, serialises and re-parses the corpus, then evaluates it with the webhook's own
// control-plane checker — exactly the path a request takes.
func corpusChecker(t *testing.T, out Output) *controlplaneauthz.Checker {
	t.Helper()
	raw, err := MarshalCorpus(out.Corpus)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ParseCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	return controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return docs, nil }, time.Hour)
}

func can(c *controlplaneauthz.Checker, user, verb, group, resource, ns, name string) bool {
	spec := authzv1.SubjectAccessReviewSpec{User: user,
		ResourceAttributes: &authzv1.ResourceAttributes{Verb: verb, Group: group, Resource: resource, Namespace: ns, Name: name}}
	if r, sub, ok := strings.Cut(resource, "/"); ok {
		spec.ResourceAttributes.Resource, spec.ResourceAttributes.Subresource = r, sub
	}
	return c.Evaluate(context.Background(), spec).Allowed
}

// rbacAllows is RBAC's rule matching over the generated objects for one user (enough for these tests:
// no aggregation, no non-resource URLs).
func rbacAllows(out Output, user, verb, group, resource, ns, name string) bool {
	roles := map[string]rbacv1.ClusterRole{}
	for _, cr := range out.ClusterRoles {
		roles[cr.Name] = cr
	}
	match := func(rules []rbacv1.PolicyRule) bool {
		for _, r := range rules {
			if !(has(r.Verbs, verb) || has(r.Verbs, "*")) || !(has(r.APIGroups, group) || has(r.APIGroups, "*")) ||
				!(has(r.Resources, resource) || has(r.Resources, "*")) {
				continue
			}
			if len(r.ResourceNames) > 0 && !has(r.ResourceNames, name) {
				continue
			}
			return true
		}
		return false
	}
	bound := func(subjects []rbacv1.Subject) bool {
		for _, s := range subjects {
			if s.Kind == "User" && s.Name == user {
				return true
			}
		}
		return false
	}
	for _, b := range out.ClusterRoleBindings {
		if bound(b.Subjects) && match(roles[b.RoleRef.Name].Rules) {
			return true
		}
	}
	for _, b := range out.RoleBindings {
		if b.Namespace == ns && bound(b.Subjects) && match(roles[b.RoleRef.Name].Rules) {
			return true
		}
	}
	return false
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func reportFor(out Output, name string) PrincipalReport {
	for _, r := range out.Principals {
		if r.Name == name {
			return r
		}
	}
	return PrincipalReport{}
}

const (
	alice = "openinfra:000000000000:alice"
	bob   = "openinfra:000000000000:bob"
)

// AdministratorAccess is everything, as on AWS: every verb on every kind and the operator surface,
// one wildcard in the one-account world, in the corpus and in RBAC.
func TestCompile_AdministratorAccessIsEverything(t *testing.T) {
	out := Compile(Input{
		World:      world([]iamauthz.Policy{doc(t, "AdministratorAccess", adminDoc)}, map[string][]string{"Group::admins": {"AdministratorAccess"}}),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice", Groups: []string{"admins"}}},
	})
	c := corpusChecker(t, out)
	for _, q := range [][]string{
		{"create", "openinfra.dev", "buckets", "team-a", ""},
		{"delete", "iam.openinfra.dev", "users", "open-infra-console", "carol"},
		{"get", "", "secrets", "kube-system", "x"},
		{"list", "kubevirt.io", "virtualmachineinstances", "", ""},
		{"delete", "", "nodes", "", "n1"},
	} {
		if !can(c, alice, q[0], q[1], q[2], q[3], q[4]) {
			t.Errorf("corpus: AdministratorAccess must allow %v", q)
		}
		if !rbacAllows(out, alice, q[0], q[1], q[2], q[3], q[4]) {
			t.Errorf("rbac: AdministratorAccess must allow %v", q)
		}
	}
	// Verbs no IAM policy can grant stay out, even for "*".
	if can(c, alice, "impersonate", "", "users", "", "system:admin") || rbacAllows(out, alice, "impersonate", "", "users", "", "system:admin") {
		t.Error("impersonate is not an IAM action: AdministratorAccess must not grant it")
	}
	if can(c, alice, "escalate", "rbac.authorization.k8s.io", "clusterroles", "", "x") {
		t.Error("escalate is not an IAM action")
	}
}

// PowerUserAccess is AWS's document: everything but IAM (and Organizations/Account) — so no writes to
// IAM kinds, iam:ListRoles still allowed — and, because a NotAction never reaches the operator surface,
// no raw Secrets, Pods or RBAC objects.
func TestCompile_PowerUserAccessDeniedIAMWritesAndTheOperatorSurface(t *testing.T) {
	out := Compile(Input{
		World:      world([]iamauthz.Policy{doc(t, "PowerUserAccess", powerUserDoc)}, map[string][]string{"User::alice": {"PowerUserAccess"}}),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice"}},
	})
	c := corpusChecker(t, out)
	allow := [][]string{
		{"create", "openinfra.dev", "buckets", "team-a", ""},
		{"delete", "openinfra.dev", "functions", "team-a", "f1"},
		{"list", "iam.openinfra.dev", "roles", "open-infra-console", ""},
	}
	deny := [][]string{
		{"create", "iam.openinfra.dev", "users", "open-infra-console", ""},
		{"update", "iam.openinfra.dev", "policies", "open-infra-console", "p"},
		{"delete", "iam.openinfra.dev", "roles", "open-infra-console", "r"},
		{"get", "", "secrets", "kube-system", "x"},
		{"create", "rbac.authorization.k8s.io", "rolebindings", "team-a", ""},
		{"list", "", "pods", "team-a", ""},
	}
	for _, q := range allow {
		if !can(c, alice, q[0], q[1], q[2], q[3], q[4]) || !rbacAllows(out, alice, q[0], q[1], q[2], q[3], q[4]) {
			t.Errorf("PowerUserAccess must allow %v (corpus and rbac)", q)
		}
	}
	for _, q := range deny {
		if can(c, alice, q[0], q[1], q[2], q[3], q[4]) || rbacAllows(out, alice, q[0], q[1], q[2], q[3], q[4]) {
			t.Errorf("PowerUserAccess must not allow %v", q)
		}
	}
}

// A principal with no policy compiles to nothing at all: no corpus entry, no RBAC, so every request is
// default-denied (as on AWS) — the legacy implicit users group confers nothing.
func TestCompile_NoPolicyIsNothing(t *testing.T) {
	out := Compile(Input{World: world(nil, nil),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "bob", Groups: []string{"users"}}}})
	if len(out.Corpus) != 0 || len(out.ClusterRoles)+len(out.ClusterRoleBindings)+len(out.RoleBindings) != 0 {
		t.Fatalf("a principal with no policy must compile to nothing, got %d grants, %d roles", len(out.Corpus), len(out.ClusterRoles))
	}
	if can(corpusChecker(t, out), bob, "get", "", "namespaces", "", "default") {
		t.Fatal("a principal with no policy must be denied everything, discovery included")
	}
}

// Never widen: a Deny is kept in the corpus (exactly, by name pattern) and keeps the whole verb out of
// RBAC, which cannot express it.
func TestCompile_DenyIsExactInTheCorpusAndKeepsRBACOut(t *testing.T) {
	d := doc(t, "fns", `{"Statement":[
		{"Effect":"Allow","Action":"lambda:*","Resource":"*"},
		{"Effect":"Deny","Action":"lambda:DeleteFunction","Resource":"arn:aws:lambda:us-east-1:000000000000:function:prod-*"}]}`)
	out := Compile(Input{World: world([]iamauthz.Policy{d}, map[string][]string{"User::alice": {"fns"}}),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice"}}})
	c := corpusChecker(t, out)
	if !can(c, alice, "delete", "openinfra.dev", "functions", "team-a", "dev-1") {
		t.Error("corpus: deleting a function outside the Deny is allowed")
	}
	if can(c, alice, "delete", "openinfra.dev", "functions", "team-a", "prod-1") {
		t.Error("corpus: the Deny on prod-* must hold")
	}
	if rbacAllows(out, alice, "delete", "openinfra.dev", "functions", "team-a", "dev-1") {
		t.Error("rbac: a verb a Deny touches must not be in the generated RBAC (it cannot express the Deny)")
	}
	if !rbacAllows(out, alice, "get", "openinfra.dev", "functions", "team-a", "prod-1") {
		t.Error("rbac: the verbs no Deny touches are generated")
	}
	if !strings.Contains(strings.Join(reportFor(out, "alice").Dropped, " "), "RBAC cannot express") {
		t.Errorf("the RBAC narrowing must be reported, got %v", reportFor(out, "alice").Dropped)
	}
}

// A literal resource name compiles to exactly that name: the corpus id and an RBAC resourceNames rule.
// A name pattern is corpus-only. A name on a create — whose authorization request carries no name — is
// dropped (narrower) and reported.
func TestCompile_NamesAreExact(t *testing.T) {
	d := doc(t, "one", `{"Statement":[
		{"Effect":"Allow","Action":["lambda:GetFunction","lambda:DeleteFunction","lambda:CreateFunction"],"Resource":"arn:aws:lambda:us-east-1:000000000000:function:orders"},
		{"Effect":"Allow","Action":"lambda:UpdateFunctionConfiguration","Resource":"arn:aws:lambda:us-east-1:000000000000:function:etl-*"}]}`)
	out := Compile(Input{World: world([]iamauthz.Policy{d}, map[string][]string{"User::alice": {"one"}}),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice"}}})
	c := corpusChecker(t, out)
	for _, q := range []struct {
		verb, name string
		corpus, rb bool
	}{
		{"get", "orders", true, true},
		{"delete", "orders", true, true},
		{"get", "billing", false, false},
		{"create", "", false, false},
		{"update", "etl-nightly", true, false},
		{"update", "orders", false, false},
	} {
		if got := can(c, alice, q.verb, "openinfra.dev", "functions", "team-a", q.name); got != q.corpus {
			t.Errorf("corpus %s %q = %v, want %v", q.verb, q.name, got, q.corpus)
		}
		if got := rbacAllows(out, alice, q.verb, "openinfra.dev", "functions", "team-a", q.name); got != q.rb {
			t.Errorf("rbac %s %q = %v, want %v", q.verb, q.name, got, q.rb)
		}
	}
	dropped := strings.Join(reportFor(out, "alice").Dropped, " ")
	for _, want := range []string{"limited to names is dropped for a verb whose request carries no name", "name pattern is in the corpus only"} {
		if !strings.Contains(dropped, want) {
			t.Errorf("report must say %q, got %v", want, reportFor(out, "alice").Dropped)
		}
	}
}

// A condition the control plane cannot evaluate drops an Allow and makes a Deny unconditional — both
// narrower — and the resource-account condition an ARN's account sets is honoured exactly.
func TestCompile_ConditionsNeverWiden(t *testing.T) {
	d := doc(t, "cond", `{"Statement":[
		{"Effect":"Allow","Action":"lambda:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}},
		{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"},
		{"Effect":"Deny","Action":"dynamodb:DeleteTable","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}},
		{"Effect":"Allow","Action":"openinfra:*","Resource":"arn:aws:openinfra:us-east-1:111111111111:dataflow/*"}]}`)
	out := Compile(Input{World: world([]iamauthz.Policy{d}, map[string][]string{"User::alice": {"cond"}}),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice"}}})
	c := corpusChecker(t, out)
	if can(c, alice, "get", "openinfra.dev", "functions", "team-a", "f") || rbacAllows(out, alice, "get", "openinfra.dev", "functions", "team-a", "f") {
		t.Error("a conditional Allow must be dropped")
	}
	if !can(c, alice, "get", "openinfra.dev", "tables", "team-a", "t") {
		t.Error("the unconditional Allow stands")
	}
	if can(c, alice, "delete", "openinfra.dev", "tables", "team-a", "t") {
		t.Error("a conditional Deny must apply unconditionally")
	}
	if can(c, alice, "get", "openinfra.dev", "dataflows", "team-a", "x") {
		t.Error("an Allow on another account's resources grants nothing on this account's control plane")
	}
}

// A permission boundary intersects: the identity's s3:* within a boundary of s3:Get*/List* is reads.
func TestCompile_BoundaryIntersects(t *testing.T) {
	w := world([]iamauthz.Policy{
		doc(t, "s3all", `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`),
		doc(t, "reads", `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}]}`),
	}, map[string][]string{"User::alice": {"s3all"}})
	w.Boundary = map[string]string{"User::alice": "reads"}
	out := Compile(Input{World: w, Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice"}}})
	c := corpusChecker(t, out)
	if !can(c, alice, "list", "openinfra.dev", "buckets", "team-a", "") || !rbacAllows(out, alice, "list", "openinfra.dev", "buckets", "team-a", "") {
		t.Error("inside the boundary: list buckets")
	}
	if can(c, alice, "create", "openinfra.dev", "buckets", "team-a", "") || rbacAllows(out, alice, "create", "openinfra.dev", "buckets", "team-a", "") {
		t.Error("outside the boundary: create buckets must be denied")
	}
}

// In an account world, a member account's principal is confined to its account's namespaces: even
// AdministratorAccess is no wildcard there, binds per namespace, and never reaches cluster-scoped
// platform objects or another account's namespace.
func TestCompile_MemberAccountIsConfined(t *testing.T) {
	const member = "912345678901"
	out := Compile(Input{
		World:             world([]iamauthz.Policy{doc(t, "AdministratorAccess", adminDoc)}, map[string][]string{"User::team-a/dana": {"AdministratorAccess"}}),
		Principals:        []Principal{{Kind: "User", Namespace: "team-a", Name: "dana"}},
		NamespaceAccounts: map[string]string{"team-a": member, "team-a-data": member, "open-infra-console": "000000000000", "team-b": "923456789012"},
	})
	dana := "openinfra:" + member + ":dana"
	c := corpusChecker(t, out)
	for _, ns := range []string{"team-a", "team-a-data"} {
		if !can(c, dana, "create", "openinfra.dev", "buckets", ns, "") || !rbacAllows(out, dana, "create", "openinfra.dev", "buckets", ns, "") {
			t.Errorf("an account's admin may create in its own namespace %s", ns)
		}
		if !can(c, dana, "get", "", "secrets", ns, "x") {
			t.Errorf("an account's admin reaches its own namespaced operator objects in %s", ns)
		}
	}
	for _, q := range [][]string{
		{"create", "openinfra.dev", "buckets", "team-b", ""},
		{"list", "openinfra.dev", "buckets", "", ""},
		{"get", "", "nodes", "", "n1"},
		{"get", "", "secrets", "kube-system", "x"},
	} {
		if can(c, dana, q[0], q[1], q[2], q[3], q[4]) || rbacAllows(out, dana, q[0], q[1], q[2], q[3], q[4]) {
			t.Errorf("a member account's admin must not reach %v", q)
		}
	}
	if len(out.ClusterRoleBindings) != 0 || len(out.RoleBindings) != 2 {
		t.Errorf("member accounts bind per namespace only: %d cluster bindings, %d role bindings", len(out.ClusterRoleBindings), len(out.RoleBindings))
	}
	if r := reportFor(out, "dana"); r.Identity != dana || r.Account != member {
		t.Errorf("report identity/account = %q/%q", r.Identity, r.Account)
	}
}

// The name "root" is reserved for the management account's break-glass root: a User named root
// compiles to nothing, whatever it is attached, so it can never be generated root's identity.
func TestCompile_ReservedRoot(t *testing.T) {
	out := Compile(Input{
		World:      world([]iamauthz.Policy{doc(t, "AdministratorAccess", adminDoc)}, map[string][]string{"User::root": {"AdministratorAccess"}}),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "root"}},
	})
	if len(out.Corpus) != 0 || len(out.ClusterRoles) != 0 {
		t.Fatal("a User named root must compile to nothing")
	}
	if !strings.Contains(strings.Join(reportFor(out, "root").Dropped, " "), "reserved") {
		t.Error("the reservation must be reported")
	}
}

// Roles compile too, as the identity an assumed-role session acts as.
func TestCompile_RoleIdentity(t *testing.T) {
	d := doc(t, "q", `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}`)
	out := Compile(Input{World: world([]iamauthz.Policy{d}, map[string][]string{"Role::main-dev/worker": {"q"}}),
		Principals: []Principal{{Kind: "Role", Namespace: "main-dev", Name: "worker"}}})
	r := reportFor(out, "worker")
	if r.Identity != "openinfra:000000000000:role/main-dev/worker" {
		t.Fatalf("role identity = %q", r.Identity)
	}
	if !can(corpusChecker(t, out), r.Identity, "create", "openinfra.dev", "queues", "main-dev", "") {
		t.Error("a role's sqs:* creates queues")
	}
	if len(out.ClusterRoles) == 0 || !strings.HasPrefix(out.ClusterRoles[0].Name, "openinfra-iam:000000000000:role:main-dev.worker") {
		t.Errorf("generated name = %v", out.ClusterRoles)
	}
	for _, o := range out.ClusterRoles {
		if o.Labels[GeneratedByLabel] != GeneratedBy {
			t.Errorf("%s must carry the generated-by label", o.Name)
		}
	}
}

// The corpus round-trips through its document form.
func TestCorpusRoundTrip(t *testing.T) {
	g := []Grant{{AppliesTo: []string{"User::" + alice}, Caveats: []string{"x"},
		Statements: []Statement{{Effect: "Allow", Actions: []string{"get"}, Resources: []string{"buckets.openinfra.dev::*"}}}}}
	raw, err := MarshalCorpus(g)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ParseCorpus(raw)
	if err != nil || len(docs) != 1 || docs[0].Statements[0].Effect != policyengine.Allow || docs[0].AppliesTo[0] != "User::"+alice {
		t.Fatalf("round trip: %v %+v", err, docs)
	}
	if !IsAccountIdentity(alice) || IsAccountIdentity("openinfra:alice") || IsAccountIdentity("system:serviceaccount:a:b") {
		t.Error("IsAccountIdentity")
	}
}

// The platform's own namespaces carry the management account's label: that is still a one-account world,
// so an administrator's grant is the cluster-wide wildcard — every API group and resource, the operator
// surface included — not one enumerated over the labelled namespaces alone (which left the API server
// refusing an administrator kube-system's Secrets and the cluster-scoped kind: Account).
func TestCompile_ManagementLabelsAloneKeepAdministratorsClusterWide(t *testing.T) {
	out := Compile(Input{
		World:             world([]iamauthz.Policy{doc(t, "AdministratorAccess", adminDoc)}, map[string][]string{"User::admin": {"AdministratorAccess"}}),
		Principals:        []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "admin"}},
		NamespaceAccounts: map[string]string{"open-infra-console": "000000000000", "open-infra-s3": "000000000000"},
	})
	wild := false
	for _, cr := range out.ClusterRoles {
		for _, r := range cr.Rules {
			if len(r.APIGroups) == 1 && r.APIGroups[0] == "*" && len(r.Resources) == 1 && r.Resources[0] == "*" {
				wild = true
			}
		}
	}
	if !wild {
		t.Fatal("an administrator in a world of management-account namespaces did not get the cluster-wide wildcard")
	}
	// With a member account present, the management account's grants are enumerated (a wildcard would
	// reach the member account's namespaces).
	out = Compile(Input{
		World:             world([]iamauthz.Policy{doc(t, "AdministratorAccess", adminDoc)}, map[string][]string{"User::admin": {"AdministratorAccess"}}),
		Principals:        []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "admin"}},
		NamespaceAccounts: map[string]string{"open-infra-console": "000000000000", "team-a": "912345678901"},
	})
	for _, cr := range out.ClusterRoles {
		for _, r := range cr.Rules {
			if len(r.APIGroups) == 1 && r.APIGroups[0] == "*" && len(r.Resources) == 1 && r.Resources[0] == "*" {
				t.Fatal("with a member account present, the management account's administrator got a cluster-wide wildcard")
			}
		}
	}
}
