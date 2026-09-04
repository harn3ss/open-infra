// Package rbactocedar translates the cluster's Kubernetes RBAC (ClusterRoles/Roles and their
// bindings) into open-infra control-plane Cedar statements (kind: Policy spec.controlPlane), one
// grant per principal. It is how #109 Phase 2 step 3 — "give each implicit principal an explicit
// Cedar grant" — is done at scale and reproducibly, rather than hand-authoring ~200 policies.
//
// Faithfulness is the whole point, so it is honest about where the translation is lossy (it records
// caveats rather than silently over- or under-granting). The output is a starting corpus for the
// SHADOW run: the divergence the webhook then observes is exactly the signal to refine it. It never
// invents a Deny — RBAC is allow-only, so this emits only Allow statements.
package rbactocedar

import (
	"fmt"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/policyengine"
	rbacv1 "k8s.io/api/rbac/v1"
)

// Grant is one principal's aggregated control-plane statements, plus faithfulness caveats.
type Grant struct {
	Principal  string // "Group::x", "ServiceAccount::ns/name", "User::x"
	Statements []policyengine.Statement
	Caveats    []string
}

// Inputs is the cluster RBAC to translate.
type Inputs struct {
	ClusterRoles        map[string]rbacv1.ClusterRole // keyed by name
	Roles               map[string]rbacv1.Role        // keyed by "namespace/name"
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	RoleBindings        []rbacv1.RoleBinding
}

// Generate aggregates RBAC into per-principal control-plane grants mirroring what RBAC allows.
func Generate(in Inputs) []Grant {
	byPrincipal := map[string]*Grant{}
	add := func(subj rbacv1.Subject, rules []rbacv1.PolicyRule, scopeNS string) {
		p := principal(subj)
		if p == "" {
			return
		}
		g := byPrincipal[p]
		if g == nil {
			g = &Grant{Principal: p}
			byPrincipal[p] = g
		}
		for _, r := range rules {
			stmts, caveats := ruleToStatements(r, scopeNS)
			g.Statements = append(g.Statements, stmts...)
			g.Caveats = append(g.Caveats, caveats...)
		}
	}

	for _, crb := range in.ClusterRoleBindings {
		if cr, ok := in.ClusterRoles[crb.RoleRef.Name]; ok {
			for _, s := range crb.Subjects {
				add(s, cr.Rules, "") // "" scope = cluster-wide
			}
		}
	}
	for _, rb := range in.RoleBindings {
		var rules []rbacv1.PolicyRule
		switch rb.RoleRef.Kind {
		case "ClusterRole":
			if cr, ok := in.ClusterRoles[rb.RoleRef.Name]; ok {
				rules = cr.Rules
			}
		case "Role":
			if r, ok := in.Roles[rb.Namespace+"/"+rb.RoleRef.Name]; ok {
				rules = r.Rules
			}
		}
		for _, s := range rb.Subjects {
			add(s, rules, rb.Namespace) // namespaced scope
		}
	}

	out := make([]Grant, 0, len(byPrincipal))
	for _, g := range byPrincipal {
		g.Statements = dedupeStatements(g.Statements)
		g.Caveats = dedupeStrings(g.Caveats)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Principal < out[j].Principal })
	return out
}

func principal(s rbacv1.Subject) string {
	switch s.Kind {
	case "User":
		return "User::" + s.Name
	case "Group":
		return "Group::" + s.Name
	case "ServiceAccount":
		return "ServiceAccount::" + s.Namespace + "/" + s.Name
	}
	return ""
}

// ruleToStatements turns one RBAC rule into Cedar Allow statements, scoped by the binding
// (scopeNS "" = cluster-wide; otherwise a RoleBinding's namespace).
func ruleToStatements(r rbacv1.PolicyRule, scopeNS string) ([]policyengine.Statement, []string) {
	if len(r.Verbs) == 0 {
		return nil, nil
	}
	var stmts []policyengine.Statement
	var caveats []string

	if len(r.NonResourceURLs) > 0 {
		res := make([]string, 0, len(r.NonResourceURLs))
		for _, u := range r.NonResourceURLs {
			res = append(res, "NonResourceURL::"+u)
		}
		stmts = append(stmts, policyengine.Statement{Effect: policyengine.Allow, Actions: r.Verbs, Resources: res})
	}

	if len(r.Resources) > 0 {
		var res []string
		for _, grp := range orDefault(r.APIGroups, []string{""}) {
			for _, rsc := range r.Resources {
				rs, cav := resourceString(grp, rsc, scopeNS)
				res = append(res, rs)
				caveats = append(caveats, cav...)
			}
		}
		if len(r.ResourceNames) > 0 {
			caveats = append(caveats, fmt.Sprintf("resourceNames %v are not scoped — this grants the whole resource type (broader than the RBAC rule); tighten before enforce", r.ResourceNames))
		}
		stmts = append(stmts, policyengine.Statement{Effect: policyengine.Allow, Actions: r.Verbs, Resources: res})
	}
	return stmts, caveats
}

// resourceString maps (apiGroup, resource) + scope to a Cedar resource string "<resource>.<group>::<scope>".
func resourceString(group, resource, scopeNS string) (string, []string) {
	var caveats []string
	// A full wildcard matches anything, so scope is moot.
	if resource == "*" {
		if group != "" && group != "*" {
			caveats = append(caveats, fmt.Sprintf("resource \"*\" in apiGroup %q is widened to all groups (the corpus has no group-only wildcard) — tighten before enforce", group))
		}
		return "*", caveats
	}
	t := resource
	if group != "" && group != "*" {
		t = resource + "." + group
	}
	scope := "*"
	if scopeNS != "" {
		scope = scopeNS + "/*"
	}
	return t + "::" + scope, caveats
}

func orDefault(xs, def []string) []string {
	if len(xs) == 0 {
		return def
	}
	return xs
}

func dedupeStatements(in []policyengine.Statement) []policyengine.Statement {
	seen := map[string]bool{}
	var out []policyengine.Statement
	for _, s := range in {
		key := string(s.Effect) + "|" + strings.Join(s.Actions, ",") + "|" + strings.Join(s.Resources, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
