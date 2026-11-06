package iamcompile

import (
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/rbactocedar"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Service-linked roles are what a platform service may do inside a member account, as AWS's
// service-linked roles are (AWSServiceRoleForECS, AWSServiceRoleForRDS): the service defines the
// permissions, every account has the role, and the account's own principals do not edit it. Here a
// service-linked role is a ClusterRole in the platform's manifests, labelled ServiceLinkedRoleLabel and
// named ServiceLinkedRolePrefix+<service>, whose ServicePrincipalsAnno names the service's
// ServiceAccounts. Each pass binds it in every member account's home namespace and compiles the same
// grant into the iam-corpus. A new account's services can then act in it within one pass, and no
// regenerated RBAC corpus is needed. The management account's services keep the platform's own
// bindings, unchanged.
const (
	ServiceLinkedRoleLabel  = "openinfra.dev/service-linked-role"
	ServicePrincipalsAnno   = "openinfra.dev/service-principals"
	ServiceLinkedRolePrefix = "openinfra:service-linked:"
	// AccountHomeLabel marks an account's home namespace (the account composition sets it on the first
	// of the account's namespaces): where the front doors keep a member account's resources.
	AccountHomeLabel = "openinfra.dev/account-home"
)

// ServiceLinkedRole is one service's role: the ClusterRole's name and rules, and the ServiceAccounts it
// is for.
type ServiceLinkedRole struct {
	Name       string
	Principals []rbacv1.Subject
	Rules      []rbacv1.PolicyRule
}

// IsServiceLinkedRoleName reports whether a ClusterRole name is a service-linked role's.
func IsServiceLinkedRoleName(name string) bool {
	return strings.HasPrefix(name, ServiceLinkedRolePrefix) && len(name) > len(ServiceLinkedRolePrefix)
}

// ParseServicePrincipals reads a ServicePrincipalsAnno value ("<namespace>/<serviceaccount>", comma
// separated) into ServiceAccount subjects. Anything else is dropped, never widened to more principals.
func ParseServicePrincipals(v string) []rbacv1.Subject {
	var out []rbacv1.Subject
	seen := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		ns, name, ok := strings.Cut(p, "/")
		if !ok || !dnsLabel(ns) || !dnsSubdomain(name) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Namespace: ns, Name: name})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Namespace+"/"+out[i].Name < out[j].Namespace+"/"+out[j].Name
	})
	return out
}

func dnsLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func dnsSubdomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if !dnsLabel(part) {
			return false
		}
	}
	return true
}

// memberHomes is every member account's home namespace, sorted.
func (in Input) memberHomes() []string {
	var out []string
	for ns, a := range in.NamespaceAccounts {
		if a != "" && a != iamauthz.ManagementAccount && in.Homes[ns] {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

// serviceLinked compiles every service-linked role into each member account's home: a RoleBinding of
// the role to its ServiceAccounts, and the corpus grant RBAC-to-Cedar makes of that binding (the same
// translation as the platform's RBAC corpus, so the two authorizers agree).
func serviceLinked(in Input) ([]rbacv1.RoleBinding, []Grant) {
	homes := in.memberHomes()
	if len(homes) == 0 || len(in.ServiceLinkedRoles) == 0 {
		return nil, nil
	}
	roles := map[string]rbacv1.ClusterRole{}
	var rbs []rbacv1.RoleBinding
	for _, slr := range in.ServiceLinkedRoles {
		if !IsServiceLinkedRoleName(slr.Name) || len(slr.Principals) == 0 || len(slr.Rules) == 0 {
			continue
		}
		roles[slr.Name] = rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: slr.Name}, Rules: slr.Rules}
		for _, ns := range homes {
			rbs = append(rbs, rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      slr.Name,
					Namespace: ns,
					Labels: map[string]string{
						GeneratedByLabel:       GeneratedBy,
						ServiceLinkedRoleLabel: "true",
						AccountIDLabel:         in.NamespaceAccounts[ns],
					},
				},
				RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: slr.Name},
				Subjects: append([]rbacv1.Subject(nil), slr.Principals...),
			})
		}
	}
	if len(rbs) == 0 {
		return nil, nil
	}
	// The translation reads the bindings as RBAC (without the compiler's own label, which marks the RBAC
	// the platform's hand-run corpus leaves to this one).
	plain := make([]rbacv1.RoleBinding, len(rbs))
	for i, rb := range rbs {
		plain[i] = rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: rb.Name, Namespace: rb.Namespace},
			RoleRef: rb.RoleRef, Subjects: rb.Subjects}
	}
	var grants []Grant
	for _, g := range rbactocedar.Generate(rbactocedar.Inputs{ClusterRoles: roles, RoleBindings: plain}) {
		out := Grant{AppliesTo: []string{g.Principal}, Caveats: g.Caveats}
		for _, st := range g.Statements {
			out.Statements = append(out.Statements, Statement{
				Effect: string(st.Effect), Actions: st.Actions, Resources: st.Resources,
			})
		}
		if len(out.Statements) > 0 {
			grants = append(grants, out)
		}
	}
	return rbs, grants
}
