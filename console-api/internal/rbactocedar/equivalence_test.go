package rbactocedar

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/controlplaneauthz"
	authzv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// rbacAllows is a reference RBAC authorizer: Kubernetes' rule matching (the semantics of
// plugin/pkg/auth/authorizer/rbac and its evaluation helpers), written out so the corpus can be checked
// against it without importing k8s.io/kubernetes. Names match exactly; "*/sub" matches a subresource of
// any resource; a RoleBinding grants only namespaced requests in its own namespace; non-resource URLs
// come only from ClusterRoleBindings and match exactly or by a trailing "*" prefix.
func rbacAllows(in Inputs, spec authzv1.SubjectAccessReviewSpec) bool {
	subjectMatches := func(s rbacv1.Subject, bindingNS string) bool {
		switch s.Kind {
		case "User":
			return s.Name == spec.User
		case "Group":
			for _, g := range spec.Groups {
				if g == s.Name {
					return true
				}
			}
		case "ServiceAccount":
			ns := s.Namespace
			if ns == "" {
				ns = bindingNS
			}
			return spec.User == "system:serviceaccount:"+ns+":"+s.Name
		}
		return false
	}
	has := func(xs []string, v string) bool {
		for _, x := range xs {
			if x == "*" || x == v {
				return true
			}
		}
		return false
	}
	ruleAllows := func(r rbacv1.PolicyRule) bool {
		if ra := spec.ResourceAttributes; ra != nil {
			if !has(r.Verbs, ra.Verb) || !has(r.APIGroups, ra.Group) {
				return false
			}
			combined := ra.Resource
			if ra.Subresource != "" {
				combined += "/" + ra.Subresource
			}
			resOK := false
			for _, rr := range r.Resources {
				if rr == "*" || rr == combined || (ra.Subresource != "" && rr == "*/"+ra.Subresource) {
					resOK = true
				}
			}
			if !resOK {
				return false
			}
			if len(r.ResourceNames) == 0 {
				return true
			}
			for _, n := range r.ResourceNames {
				if n == ra.Name {
					return true
				}
			}
			return false
		}
		nra := spec.NonResourceAttributes
		if nra == nil || !has(r.Verbs, nra.Verb) {
			return false
		}
		for _, u := range r.NonResourceURLs {
			if u == "*" || u == nra.Path || (strings.HasSuffix(u, "*") && strings.HasPrefix(nra.Path, strings.TrimSuffix(u, "*"))) {
				return true
			}
		}
		return false
	}
	for _, crb := range in.ClusterRoleBindings {
		cr, ok := in.ClusterRoles[crb.RoleRef.Name]
		if !ok {
			continue
		}
		for _, s := range crb.Subjects {
			if subjectMatches(s, "") {
				for _, r := range cr.Rules {
					if ruleAllows(r) {
						return true
					}
				}
			}
		}
	}
	ra := spec.ResourceAttributes
	if ra == nil || ra.Namespace == "" {
		return false
	}
	for _, rb := range in.RoleBindings {
		if rb.Namespace != ra.Namespace {
			continue
		}
		var rules []rbacv1.PolicyRule
		if rb.RoleRef.Kind == "ClusterRole" {
			rules = in.ClusterRoles[rb.RoleRef.Name].Rules
		} else {
			rules = in.Roles[rb.Namespace+"/"+rb.RoleRef.Name].Rules
		}
		for _, s := range rb.Subjects {
			if subjectMatches(s, rb.Namespace) {
				for _, r := range rules {
					if ruleAllows(r) {
						return true
					}
				}
			}
		}
	}
	return false
}

func cr(name string, rules ...rbacv1.PolicyRule) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}
}

func rule(verbs, groups, resources, names []string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{Verbs: verbs, APIGroups: groups, Resources: resources, ResourceNames: names}
}

func l(xs ...string) []string { return xs }

// equivalenceInputs is a representative RBAC set: plain grants, resourceNames (cluster-wide and in a
// Role), subresources (named and "*/status"), a specific group's "*", every group's concrete resource,
// non-resource URLs, signers, a ServiceAccount subject with no namespace, and a namespaced binding of a
// ClusterRole. It deliberately leaves out the one documented residual (core "*" resources, which Cedar
// cannot keep to the core group).
func equivalenceInputs() Inputs {
	return Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"pods-read":      cr("pods-read", rule(l("get", "list", "watch"), l(""), l("pods"), nil)),
			"scale":          cr("scale", rule(l("update", "patch"), l("apps"), l("deployments/scale"), nil), rule(l("get"), l("*"), l("*/status"), nil)),
			"named-cm":       cr("named-cm", rule(l("get", "update"), l(""), l("configmaps"), l("app-config", "other"))),
			"group-wild":     cr("group-wild", rule(l("*"), l("openinfra.dev"), l("*"), nil)),
			"all-groups":     cr("all-groups", rule(l("get"), l("*"), l("secrets"), nil)),
			"nonresource":    cr("nonresource", rbacv1.PolicyRule{Verbs: l("get"), NonResourceURLs: l("/healthz", "/metrics/*")}),
			"signers":        cr("signers", rule(l("approve"), l("certificates.k8s.io"), l("signers"), l("issuers.cert-manager.io/*"))),
			"crd-status":     cr("crd-status", rule(l("patch"), l("openinfra.dev"), l("applications/status"), nil)),
			"impersonate":    cr("impersonate", rule(l("impersonate"), l(""), l("groups"), l("openinfra:admins")), rule(l("impersonate"), l(""), l("users"), nil)),
			"multi-verb-job": cr("multi-verb-job", rule(l("create", "delete"), l("batch"), l("jobs"), nil)),
			"star-name":      cr("star-name", rule(l("get"), l(""), l("configmaps"), l("cfg-*"))),
		},
		Roles: map[string]rbacv1.Role{
			"ns1/one-secret": {ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "one-secret"},
				Rules: []rbacv1.PolicyRule{rule(l("get"), l(""), l("secrets"), l("db-pass"))}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "pods-read"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "g-readers"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "scale"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "kube-system", Name: "hpa"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "group-wild"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "g-ops"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "all-groups"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "bob"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "nonresource"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "g-mon"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "signers"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "cert-manager", Name: "cm"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "named-cm"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "carol"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "impersonate"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "front", Name: "door"}}},
			{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "star-name"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "frank"}}},
		},
		RoleBindings: []rbacv1.RoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "named-cm"},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1"}, RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "one-secret"},
				Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "app"}}}, // namespace defaults to ns1
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns2"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "crd-status"},
				Subjects: []rbacv1.Subject{{Kind: "Group", Name: "g-ops"}}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns2"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "multi-verb-job"},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}}},
		},
	}
}

type principalFixture struct {
	user   string
	groups []string
}

// TestCorpusMatchesRBAC evaluates every request in a grid through the control-plane webhook's own
// evaluator (controlplaneauthz.Checker over the generated corpus) and through the reference RBAC
// authorizer, and requires the same answer. Two differences are allowed, both documented in scopeToNames:
// the signer wildcard may allow a specific signer name under an approved "<domain>/*" (the API server
// checks that "<domain>/*" form itself, so it grants nothing more), and a "*" name on any other type is
// dropped, so the corpus denies the object literally named so (narrower, never broader).
func TestCorpusMatchesRBAC(t *testing.T) {
	in := equivalenceInputs()
	var docs []controlplaneauthz.PolicyDoc
	for _, g := range Generate(in) {
		docs = append(docs, controlplaneauthz.PolicyDoc{Statements: g.Statements, AppliesTo: []string{g.Principal}})
	}
	checker := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return docs, nil }, time.Hour)

	principals := []principalFixture{
		{"alice", nil}, {"bob", nil}, {"carol", nil}, {"frank", nil}, {"nobody", nil},
		{"dave", l("g-readers")}, {"erin", l("g-ops")}, {"mon", l("g-mon")},
		{"system:serviceaccount:ns1:app", l("system:serviceaccounts", "system:serviceaccounts:ns1")},
		{"system:serviceaccount:ns2:app", l("system:serviceaccounts", "system:serviceaccounts:ns2")},
		{"system:serviceaccount:kube-system:hpa", l("system:serviceaccounts")},
		{"system:serviceaccount:cert-manager:cm", l("system:serviceaccounts")},
		{"system:serviceaccount:front:door", l("system:serviceaccounts")},
	}
	type res struct{ group, resource, sub string }
	resources := []res{
		{"", "pods", ""}, {"", "pods", "log"}, {"", "configmaps", ""}, {"", "secrets", ""}, {"apps", "secrets", ""},
		{"apps", "deployments", ""}, {"apps", "deployments", "scale"}, {"apps", "deployments", "status"},
		{"batch", "jobs", "status"}, {"batch", "jobs", ""},
		{"openinfra.dev", "applications", ""}, {"openinfra.dev", "applications", "status"}, {"openinfra.dev", "buckets", ""},
		{"certificates.k8s.io", "signers", ""}, {"", "groups", ""}, {"", "users", ""},
	}
	verbs := l("get", "list", "watch", "create", "update", "patch", "delete", "approve", "impersonate")
	namespaces := l("", "ns1", "ns2")
	names := l("", "app-config", "db-pass", "other", "issuers.cert-manager.io/*", "issuers.cert-manager.io/ns1.iss",
		"openinfra:admins", "system:masters", "cfg-*", "cfg-x")

	var mismatches []string
	checked := 0
	for _, p := range principals {
		for _, r := range resources {
			for _, v := range verbs {
				for _, ns := range namespaces {
					for _, n := range names {
						spec := authzv1.SubjectAccessReviewSpec{User: p.user, Groups: p.groups,
							ResourceAttributes: &authzv1.ResourceAttributes{Verb: v, Group: r.group, Resource: r.resource, Subresource: r.sub, Namespace: ns, Name: n}}
						want := rbacAllows(in, spec)
						got := checker.Evaluate(context.Background(), spec).Allowed
						checked++
						if got == want {
							continue
						}
						if got && !want && r.resource == "signers" && strings.HasPrefix(n, "issuers.cert-manager.io/") {
							continue // the signer wildcard: see above
						}
						if !got && want && strings.Contains(n, "*") && r.resource != "signers" {
							continue // a "*" name off signers is dropped: narrower than RBAC, never broader
						}
						mismatches = append(mismatches, fmt.Sprintf("%s %v: %s %s/%s/%s ns=%q name=%q: corpus=%v rbac=%v",
							p.user, p.groups, v, r.group, r.resource, r.sub, ns, n, got, want))
					}
				}
			}
		}
		for _, path := range l("/healthz", "/healthz/x", "/metrics", "/metrics/a", "/api") {
			for _, v := range l("get", "post") {
				spec := authzv1.SubjectAccessReviewSpec{User: p.user, Groups: p.groups,
					NonResourceAttributes: &authzv1.NonResourceAttributes{Verb: v, Path: path}}
				want, got := rbacAllows(in, spec), checker.Evaluate(context.Background(), spec).Allowed
				checked++
				if got != want {
					mismatches = append(mismatches, fmt.Sprintf("%s: %s %s: corpus=%v rbac=%v", p.user, v, path, got, want))
				}
			}
		}
	}
	if len(mismatches) > 0 {
		max := len(mismatches)
		if max > 40 {
			max = 40
		}
		t.Fatalf("%d of %d decisions differ from RBAC (first %d):\n%s", len(mismatches), checked, max, strings.Join(mismatches[:max], "\n"))
	}
	t.Logf("%d decisions match RBAC", checked)
}

// A ClusterRole annotated openinfra.dev/impersonate-users narrows its impersonate-users grant in the
// corpus to matching names: the aws-shim and the console only ever impersonate openinfra:<user>, so a
// stolen token for either cannot impersonate a control-plane user (system:kube-controller-manager mints
// any ServiceAccount's token). Everything else about the role — the pinned groups — is unchanged, and
// the corpus is only ever narrower than RBAC.
func TestCorpusImpersonationNarrowing(t *testing.T) {
	in := equivalenceInputs()
	imp := in.ClusterRoles["impersonate"]
	imp.Annotations = map[string]string{ImpersonateUsersAnnotation: "openinfra:*"}
	in.ClusterRoles["impersonate"] = imp

	var docs []controlplaneauthz.PolicyDoc
	for _, g := range Generate(in) {
		docs = append(docs, controlplaneauthz.PolicyDoc{Statements: g.Statements, AppliesTo: []string{g.Principal}})
	}
	checker := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return docs, nil }, time.Hour)
	door := "system:serviceaccount:front:door"
	for _, c := range []struct {
		resource, name string
		corpus, rbac   bool
	}{
		{"users", "openinfra:alice", true, true},
		{"users", "openinfra:role:deployer", true, true},
		{"users", "system:kube-controller-manager", false, true},
		{"users", "kube-apiserver", false, true},
		{"users", "system:admin", false, true},
		{"users", "openinfra", false, true}, // the prefix includes the colon
		{"groups", "openinfra:admins", true, true},
		{"groups", "system:masters", false, false},
	} {
		spec := authzv1.SubjectAccessReviewSpec{User: door, Groups: l("system:serviceaccounts"),
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "impersonate", Resource: c.resource, Name: c.name}}
		if got := checker.Evaluate(context.Background(), spec).Allowed; got != c.corpus {
			t.Errorf("corpus impersonate %s %q = %v, want %v", c.resource, c.name, got, c.corpus)
		}
		if got := rbacAllows(in, spec); got != c.rbac {
			t.Errorf("rbac impersonate %s %q = %v, want %v", c.resource, c.name, got, c.rbac)
		}
	}
	var caveats []string
	for _, g := range Generate(in) {
		if g.Principal == "ServiceAccount::front/door" {
			caveats = g.Caveats
		}
	}
	if !strings.Contains(strings.Join(caveats, " "), "impersonate users narrowed") {
		t.Errorf("the narrowing must be recorded as a caveat; got %v", caveats)
	}
}

// openinfra.dev/impersonate-users-deny names exact users the holder may never impersonate, whatever its
// allow pattern says: the aws-shim's ceiling uses it for the break-glass root identities, which only the
// console's root sign-in may act as. Other openinfra:* users stay impersonable; a wildcard deny entry is
// ignored with a caveat (a Deny never covers more than its literal name).
func TestCorpusImpersonationDeny(t *testing.T) {
	in := equivalenceInputs()
	imp := in.ClusterRoles["impersonate"]
	imp.Annotations = map[string]string{
		ImpersonateUsersAnnotation:     "openinfra:*",
		ImpersonateUsersDenyAnnotation: "openinfra:root, openinfra:000000000000:root, openinfra:*",
	}
	in.ClusterRoles["impersonate"] = imp

	var docs []controlplaneauthz.PolicyDoc
	var caveats []string
	for _, g := range Generate(in) {
		docs = append(docs, controlplaneauthz.PolicyDoc{Statements: g.Statements, AppliesTo: []string{g.Principal}})
		if g.Principal == "ServiceAccount::front/door" {
			caveats = g.Caveats
		}
	}
	checker := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return docs, nil }, time.Hour)
	door := "system:serviceaccount:front:door"
	for _, c := range []struct {
		name string
		want bool
	}{
		{"openinfra:alice", true},
		{"openinfra:000000000000:alice", true},
		{"openinfra:root", false},
		{"openinfra:000000000000:root", false},
		{"openinfra:912345678901:root", true}, // a member account's root is an ordinary principal
	} {
		spec := authzv1.SubjectAccessReviewSpec{User: door, Groups: l("system:serviceaccounts"),
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "impersonate", Resource: "users", Name: c.name}}
		if got := checker.Evaluate(context.Background(), spec).Allowed; got != c.want {
			t.Errorf("corpus impersonate users %q = %v, want %v", c.name, got, c.want)
		}
	}
	joined := strings.Join(caveats, " ")
	if !strings.Contains(joined, "is denied by "+ImpersonateUsersDenyAnnotation) || !strings.Contains(joined, `"openinfra:*" on ClusterRole`) {
		t.Errorf("the deny and the ignored wildcard entry must be recorded as caveats; got %v", caveats)
	}
}

// With SkipIAMPrincipals the corpus leaves out every openinfra:* user and group subject — their grants
// come from the iam-corpus once IAM is the authority — and keeps every platform identity exactly as
// before. Off (the default), nothing changes.
func TestGenerate_SkipIAMPrincipals(t *testing.T) {
	in := Inputs{
		ClusterRoles: map[string]rbacv1.ClusterRole{"r": cr("r", rule(l("get"), l(""), l("pods"), nil))},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "r"}, Subjects: []rbacv1.Subject{
			{Kind: "Group", Name: "openinfra:admins"},
			{Kind: "User", Name: "openinfra:000000000000:root"},
			{Kind: "ServiceAccount", Namespace: "kube-system", Name: "op"},
			{Kind: "Group", Name: "system:masters"},
		}}},
		RoleBindings: []rbacv1.RoleBinding{{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "r"},
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "openinfra:alice"}, {Kind: "ServiceAccount", Name: "app"}}}},
	}
	principals := func(gs []Grant) []string {
		var out []string
		for _, g := range gs {
			out = append(out, g.Principal)
		}
		return out
	}
	all := principals(Generate(in))
	if len(all) != 6 {
		t.Fatalf("default: every subject keeps its grant, got %v", all)
	}
	in.SkipIAMPrincipals = true
	got := strings.Join(principals(Generate(in)), ",")
	if got != "Group::system:masters,ServiceAccount::kube-system/op,ServiceAccount::team-a/app" {
		t.Fatalf("SkipIAMPrincipals must keep exactly the platform identities, got %s", got)
	}
}

// An unusable pattern (empty, "*" alone, a "*" mid-name, odd characters) is ignored with a caveat — it
// never widens and never silently drops the grant.
func TestImpersonationNarrowing_UnusablePatternsAreIgnored(t *testing.T) {
	for _, p := range l("", "*", "open*infra:*", "openinfra:**", "openinfra\"x*") {
		c := cr("imp", rule(l("impersonate"), l(""), l("users"), nil))
		c.Annotations = map[string]string{ImpersonateUsersAnnotation: p}
		rest, narrowed, cav := narrowImpersonation(c)
		if len(narrowed) != 0 || len(rest) != 1 || len(cav) != 1 {
			t.Errorf("pattern %q: rest=%v narrowed=%v caveats=%v", p, rest, narrowed, cav)
		}
	}
}
