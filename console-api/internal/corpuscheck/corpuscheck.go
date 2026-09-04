// Package corpuscheck audits a control-plane Cedar corpus (the per-principal grants produced by
// rbactocedar, or authored by hand) for dangerous patterns — the machine-checkable assurance that,
// under RBAC, the CIS Kubernetes Benchmark supplied for free (no cluster-admin sprawl, no wildcard
// grants, minimal service-account privilege). Under Cedar-as-authority that assurance becomes the
// project's own to generate (#109 Phase 3 / #110 CM-6, CA-2/CA-7). It reports; it does not mutate.
package corpuscheck

import (
	"fmt"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/rbactocedar"
)

type Severity string

const (
	Info Severity = "info"
	Warn Severity = "warn"
	High Severity = "high"
)

// Finding is one audit result against one principal.
type Finding struct {
	Principal string
	Rule      string
	Severity  Severity
	Detail    string
}

// Check audits every grant and returns findings, most-severe first then by principal.
func Check(grants []rbactocedar.Grant) []Finding {
	var out []Finding
	for _, g := range grants {
		out = append(out, checkGrant(g)...)
	}
	rank := map[Severity]int{High: 0, Warn: 1, Info: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		return out[i].Principal < out[j].Principal
	})
	return out
}

func checkGrant(g rbactocedar.Grant) []Finding {
	var f []Finding
	for _, s := range g.Statements {
		acts := set(s.Actions)
		anyAction := acts["*"]
		// cluster-admin-equivalent: any action on any resource.
		if anyAction && hasResource(s.Resources, "*") {
			f = append(f, Finding{g.Principal, "cluster-admin-equivalent", High,
				"grants action \"*\" on resource \"*\" — full control-plane authority"})
			continue // this subsumes the narrower findings for this statement
		}
		// any-resource-type wildcard (broad blast radius even if the verbs are limited).
		if hasResource(s.Resources, "*") {
			f = append(f, Finding{g.Principal, "wildcard-resource", Warn,
				fmt.Sprintf("grants %v on ANY resource type (resource \"*\")", s.Actions)})
		}
		// cluster-wide secrets read (a common exfil path).
		if readsSecretsClusterWide(s.Actions, s.Resources) {
			f = append(f, Finding{g.Principal, "secrets-cluster-wide", Warn,
				"can read Secrets cluster-wide"})
		}
		// privilege-escalation verbs.
		if esc := escalationVerbs(s.Actions); len(esc) > 0 {
			f = append(f, Finding{g.Principal, "privilege-escalation-verb", Warn,
				fmt.Sprintf("grants %v (RBAC escalation verbs) — confirm this is intended", esc)})
		}
	}
	if len(g.Caveats) > 0 {
		f = append(f, Finding{g.Principal, "faithfulness-caveat", Info, strings.Join(g.Caveats, "; ")})
	}
	return f
}

func hasResource(res []string, want string) bool {
	for _, r := range res {
		if r == want {
			return true
		}
	}
	return false
}

// readsSecretsClusterWide reports a get/list/watch (or "*") over "secrets::*" or a bare "*".
func readsSecretsClusterWide(actions, resources []string) bool {
	reads := false
	for _, a := range actions {
		if a == "*" || a == "get" || a == "list" || a == "watch" {
			reads = true
		}
	}
	if !reads {
		return false
	}
	for _, r := range resources {
		if r == "secrets::*" || r == "*" {
			return true
		}
	}
	return false
}

func escalationVerbs(actions []string) []string {
	danger := map[string]bool{"escalate": true, "bind": true, "impersonate": true}
	var out []string
	for _, a := range actions {
		if danger[a] {
			out = append(out, a)
		}
	}
	return out
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Summary counts findings by severity.
func Summary(findings []Finding) map[Severity]int {
	m := map[Severity]int{}
	for _, f := range findings {
		m[f.Severity]++
	}
	return m
}
