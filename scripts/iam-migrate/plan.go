package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/policyengine"
)

// Obj is one Kubernetes object as the migration reads it: identity, labels and annotations, and spec.
type Obj struct {
	Kind        string
	Namespace   string
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	Spec        map[string]any
}

// Binding is a ClusterRoleBinding that grants a ClusterRole to the console's group openinfra:<Group>
// directly (the built-in groups ship as such bindings, not as kind: Group).
type Binding struct {
	Name, ClusterRole, Group string
}

// World is everything the migration reads.
type World struct {
	Home     string // the IAM home namespace (open-infra-console)
	Policies []Obj
	Groups   []Obj
	Users    []Obj
	Roles    []Obj
	Bindings []Binding
}

// Change is one write the migration makes: a merge patch of an object's spec (Create=true makes it).
type Change struct {
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace"`
	Name      string         `json:"name"`
	Create    bool           `json:"create,omitempty"`
	Patch     map[string]any `json:"patch"` // the spec merge patch (for a create: the whole spec)
	Why       string         `json:"why"`
}

// Plan is what the migration would do, and what it leaves as is with why.
type Plan struct {
	Changes []Change `json:"changes"`
	Kept    []string `json:"kept"`
	Notes   []string `json:"notes"`
}

// tierPolicy is the AWS managed policy equivalent of a ClusterRole a group grants as a permission tier.
var tierPolicy = map[string]string{
	"open-infra-console":   "AdministratorAccess",
	"open-infra-poweruser": "PowerUserAccess",
	"open-infra-readonly":  "ReadOnlyAccess",
	"ecr-pusher":           "AmazonEC2ContainerRegistryPowerUser",
	"ecr-runtime-puller":   "AmazonEC2ContainerRegistryPullOnly",
}

// supersededBindings are static bindings whose authority an attached managed policy already carries, so
// they need no group of their own (AdministratorAccess includes iam:PassRole).
var supersededBindings = map[string]string{
	"openinfra-pass-role": "AdministratorAccess (iam:PassRole) on the admins group",
}

func toStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	if l, ok := v.([]string); ok {
		out = append(out, l...)
	}
	return out
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func appendUnique(list []string, add ...string) ([]string, bool) {
	changed := false
	for _, a := range add {
		found := false
		for _, x := range list {
			if x == a {
				found = true
				break
			}
		}
		if !found {
			list = append(list, a)
			changed = true
		}
	}
	return list, changed
}

// statementsFromSpec reads native data-plane statements (kind: Policy spec.dataPlane.statements).
func statementsFromSpec(v any) []policyengine.Statement {
	var out []policyengine.Statement
	l, _ := v.([]any)
	for _, s := range l {
		m, _ := s.(map[string]any)
		if m == nil {
			continue
		}
		st := policyengine.Statement{
			Effect:       policyengine.Effect(fmt.Sprint(m["effect"])),
			Actions:      toStrings(m["actions"]),
			NotActions:   toStrings(m["notActions"]),
			Resources:    toStrings(m["resources"]),
			NotResources: toStrings(m["notResources"]),
		}
		if c, ok := m["condition"].(map[string]any); ok && len(c) > 0 {
			st.Condition = map[string]string{}
			for k, v := range c {
				st.Condition[k] = fmt.Sprint(v)
			}
		}
		for _, x := range toSliceMaps(m["ipConditions"]) {
			st.IPConditions = append(st.IPConditions, policyengine.IPCondition{Key: fmt.Sprint(x["key"]), CIDR: fmt.Sprint(x["cidr"]), Negate: x["negate"] == true})
		}
		for _, x := range toSliceMaps(m["likeConditions"]) {
			st.LikeConditions = append(st.LikeConditions, policyengine.LikeCondition{Key: fmt.Sprint(x["key"]), Pattern: fmt.Sprint(x["pattern"]), Negate: x["negate"] == true})
		}
		for _, x := range toSliceMaps(m["timeConditions"]) {
			st.TimeConditions = append(st.TimeConditions, policyengine.TimeCondition{Key: fmt.Sprint(x["key"]), Op: fmt.Sprint(x["op"]), Target: fmt.Sprint(x["target"])})
		}
		for _, x := range toSliceMaps(m["keyConditions"]) {
			st.KeyConditions = append(st.KeyConditions, policyengine.KeyCondition{Key: fmt.Sprint(x["key"]), Op: fmt.Sprint(x["op"]), Value: fmt.Sprint(x["value"]), IfExists: x["ifExists"] == true})
		}
		out = append(out, st)
	}
	return out
}

func toSliceMaps(v any) []map[string]any {
	var out []map[string]any
	l, _ := v.([]any)
	for _, x := range l {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// rolePolicyName mirrors kind: Role's spec.policies item limits (an RFC 1123 name of at most 56
// characters, no namespace prefix): a policy name outside them cannot be attached to a Role by name.
func rolePolicyName(name string) bool {
	if len(name) == 0 || len(name) > 56 || strings.Contains(name, "/") {
		return false
	}
	for i, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || ((r == '-' || r == '.') && i > 0 && i < len(name)-1)
		if !ok {
			return false
		}
	}
	return true
}

type principalKey struct{ kind, ns, name string }

// Build plans the migration of w to the AWS policy model, additively: every write adds the new form
// beside the old (a document beside dataPlane, policies beside a clusterRole, an AWS managed policy beside
// its deprecated alias), so nothing anyone holds today changes until the cutover drops the old forms
// (dropLegacy). Nothing is guessed: what has no faithful new form is kept and reported.
func Build(w World, dropLegacy bool) Plan {
	var p Plan
	home := w.Home
	if home == "" {
		home = "open-infra-console"
	}
	policyByKey := map[string]Obj{}
	for _, o := range w.Policies {
		policyByKey[o.Namespace+"/"+o.Name] = o
	}
	// principal attachments to add, by principal
	attach := map[principalKey][]string{}
	exists := map[principalKey]Obj{}
	for _, o := range w.Groups {
		exists[principalKey{"Group", o.Namespace, o.Name}] = o
	}
	for _, o := range w.Users {
		exists[principalKey{"User", o.Namespace, o.Name}] = o
	}
	for _, o := range w.Roles {
		exists[principalKey{"Role", o.Namespace, o.Name}] = o
	}
	ref := func(principalNS, policyNS, policyName string) string {
		if policyNS == principalNS || policyNS == home {
			return policyName
		}
		return policyNS + "/" + policyName
	}

	// 1. Policies: a document from the native statements, and the inline axis (appliesTo) as attachments.
	sort.Slice(w.Policies, func(i, j int) bool {
		return w.Policies[i].Namespace+"/"+w.Policies[i].Name < w.Policies[j].Namespace+"/"+w.Policies[j].Name
	})
	for _, o := range w.Policies {
		id := o.Namespace + "/" + o.Name
		if o.Labels["openinfra.dev/managed-policy"] == "true" {
			continue // the shipped library: AWS-named ones carry their documents, kebab ones are aliases
		}
		if _, has := o.Spec["document"]; has {
			continue
		}
		if cp, ok := o.Spec["controlPlane"].(map[string]any); ok && cp != nil {
			p.Kept = append(p.Kept, fmt.Sprintf("Policy %s: its controlPlane block (Kubernetes verbs on cluster resources) is platform-operator authority with no AWS policy form; kept as is", id))
			continue
		}
		if o.Spec["statements"] != nil {
			p.Kept = append(p.Kept, fmt.Sprintf("Policy %s: its statements (RBAC verbs on openinfra.dev kinds) need the action table to become a document; kept until the cutover migrates them", id))
		}
		dp, _ := o.Spec["dataPlane"].(map[string]any)
		if dp == nil {
			continue
		}
		stmts := statementsFromSpec(dp["statements"])
		if len(stmts) == 0 {
			continue
		}
		doc, skipped, err := policyengine.ExportAWS(stmts)
		if err != nil || len(skipped) > 0 {
			p.Kept = append(p.Kept, fmt.Sprintf("Policy %s: not migrated, a statement has no faithful AWS form (%s)", id, strings.Join(append(skipped, errString(err)), "; ")))
			continue
		}
		var docObj map[string]any
		_ = json.Unmarshal([]byte(doc), &docObj)
		patch := map[string]any{"document": docObj}
		why := fmt.Sprintf("its %d data-plane statement(s) as an AWS document", len(stmts))
		// The inline axis: a Policy naming its principals becomes those principals' attached policy.
		appliesKept := false
		for _, a := range toStrings(dp["appliesTo"]) {
			typ, name, ok := strings.Cut(a, "::")
			if !ok || (typ != "User" && typ != "Group" && typ != "Role") {
				appliesKept = true
				p.Notes = append(p.Notes, fmt.Sprintf("Policy %s applies to %q, which no AWS attachment expresses (an identity policy is attached to principals, not to everyone); its appliesTo is kept", id, a))
				continue
			}
			pns := o.Namespace
			if i := strings.IndexByte(name, '/'); i > 0 {
				pns, name = name[:i], name[i+1:]
			}
			k := principalKey{typ, pns, name}
			r := ref(pns, o.Namespace, o.Name)
			if typ == "Role" && !rolePolicyName(r) {
				appliesKept = true
				p.Notes = append(p.Notes, fmt.Sprintf("Policy %s: its name does not fit a Role's spec.policies (an RFC 1123 name of at most 56 characters); its appliesTo %s is kept", id, a))
				continue
			}
			attach[k], _ = appendUnique(attach[k], r)
		}
		if dropLegacy && !appliesKept {
			patch["dataPlane"] = nil
		}
		p.Changes = append(p.Changes, Change{Kind: "Policy", Namespace: o.Namespace, Name: o.Name, Patch: patch, Why: why})
	}

	// 2. Groups: a permission tier becomes its managed policy.
	groupPolicies := map[principalKey][]string{}
	for _, o := range w.Groups {
		k := principalKey{"Group", o.Namespace, o.Name}
		if cr, _ := o.Spec["clusterRole"].(string); cr != "" {
			if mp, ok := tierPolicy[cr]; ok {
				groupPolicies[k], _ = appendUnique(groupPolicies[k], cfn.ManagedPolicyObjectName(mp))
			} else {
				p.Kept = append(p.Kept, fmt.Sprintf("Group %s/%s: its clusterRole %s has no managed-policy equivalent; kept", o.Namespace, o.Name, cr))
			}
		}
	}
	for _, b := range w.Bindings {
		k := principalKey{"Group", home, b.Group}
		if why, ok := supersededBindings[b.ClusterRole]; ok {
			p.Notes = append(p.Notes, fmt.Sprintf("binding %s (%s → openinfra:%s) is carried by %s", b.Name, b.ClusterRole, b.Group, why))
			continue
		}
		if mp, ok := tierPolicy[b.ClusterRole]; ok {
			groupPolicies[k], _ = appendUnique(groupPolicies[k], cfn.ManagedPolicyObjectName(mp))
			continue
		}
		if len(attach[k]) == 0 {
			p.Kept = append(p.Kept, fmt.Sprintf("binding %s (%s → openinfra:%s) has no managed-policy equivalent and the group has no data-plane policy; kept", b.Name, b.ClusterRole, b.Group))
		}
	}
	for k, pols := range groupPolicies {
		attach[k], _ = appendUnique(attach[k], pols...)
	}

	// 3. Users and Roles: a deprecated alias in spec.policies gains its AWS managed equivalent.
	alias := map[string]string{}
	for _, o := range w.Policies {
		if eq := o.Annotations["openinfra.dev/aws-equivalent"]; eq != "" && eq != "none" && o.Namespace == home {
			alias[o.Name] = cfn.ManagedPolicyObjectName(eq)
		}
	}
	for _, list := range [][]Obj{w.Users, w.Roles, w.Groups} {
		for _, o := range list {
			k := principalKey{o.Kind, o.Namespace, o.Name}
			for _, pol := range toStrings(o.Spec["policies"]) {
				if eq, ok := alias[pol]; ok {
					attach[k], _ = appendUnique(attach[k], eq)
				}
			}
		}
	}

	// Emit the principal writes, in a stable order.
	keys := make([]principalKey, 0, len(attach))
	for k := range attach {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return a.kind+a.ns+"/"+a.name < b.kind+b.ns+"/"+b.name
	})
	for _, k := range keys {
		add := attach[k]
		if o, ok := exists[k]; ok {
			cur := toStrings(o.Spec["policies"])
			next, changed := appendUnique(append([]string(nil), cur...), add...)
			patch := map[string]any{}
			if changed {
				patch["policies"] = toAny(next)
			}
			if dropLegacy && k.kind == "Group" {
				if cr, _ := o.Spec["clusterRole"].(string); cr != "" {
					if _, ok := tierPolicy[cr]; ok {
						patch["clusterRole"] = nil
					}
				}
			}
			if len(patch) == 0 {
				continue
			}
			p.Changes = append(p.Changes, Change{Kind: k.kind, Namespace: k.ns, Name: k.name, Patch: patch,
				Why: "attach " + strings.Join(add, ", ")})
			continue
		}
		if k.kind != "Group" {
			p.Notes = append(p.Notes, fmt.Sprintf("%s %s/%s is named by a policy but does not exist; nothing attached", k.kind, k.ns, k.name))
			continue
		}
		p.Changes = append(p.Changes, Change{Kind: "Group", Namespace: k.ns, Name: k.name, Create: true,
			Patch: map[string]any{"description": "Created by scripts/iam-migrate: the policies the openinfra:" + k.name + " group grants, as a container of policies", "policies": toAny(add)},
			Why:   "create the group as a container of " + strings.Join(add, ", ")})
	}
	return p
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Summary counts the plan's writes by kind.
func (p Plan) Summary() string {
	byKind := map[string]int{}
	creates := 0
	for _, c := range p.Changes {
		byKind[c.Kind]++
		if c.Create {
			creates++
		}
	}
	return fmt.Sprintf("%d writes (%d Policy, %d Group of which %d new, %d User, %d Role); %d kept as is; %d notes",
		len(p.Changes), byKind["Policy"], byKind["Group"], creates, byKind["User"], byKind["Role"], len(p.Kept), len(p.Notes))
}
