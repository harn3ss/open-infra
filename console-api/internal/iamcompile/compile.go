package iamcompile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/awsaction"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Labels and annotations on everything the compiler generates.
const (
	GeneratedByLabel = "openinfra.dev/generated-by"
	GeneratedBy      = "iam-compiler"
	PrincipalLabel   = "openinfra.dev/iam-principal" // a short hash: label values cannot carry the identity
	AccountLabel     = "openinfra.dev/iam-account"
	IdentityAnno     = "openinfra.dev/iam-identity" // the Kubernetes user the generated objects bind
	// ReservedRoot is the user name reserved for the management account's break-glass root. A kind: User
	// with it compiles to nothing (it would be impersonated as root).
	ReservedRoot = "root"
)

// Principal is one IAM principal to compile: a kind: User (with its spec.groups, plain names) or a
// kind: Role.
type Principal struct {
	Kind      string // "User" or "Role"
	Namespace string
	Name      string
	Groups    []string
}

// Input is everything one compile reads.
type Input struct {
	World iamauthz.World
	// Home is the management account's IAM home namespace (iamauthz.DefaultHomeNamespace).
	Home       string
	Principals []Principal
	// NamespaceAccounts maps each namespace that belongs to an account (label openinfra.dev/account-id)
	// to its account id. Empty — no namespace labelled yet — is today's one-account world: the
	// management account's grants are cluster-wide.
	NamespaceAccounts map[string]string
}

// Output is one compile's result.
type Output struct {
	Corpus              []Grant
	ClusterRoles        []rbacv1.ClusterRole
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	RoleBindings        []rbacv1.RoleBinding
	Principals          []PrincipalReport
}

// PrincipalReport is what compiling one principal produced and what it could not express.
type PrincipalReport struct {
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Account   string   `json:"account"`
	Identity  string   `json:"identity,omitempty"`
	Policies  []string `json:"policies,omitempty"`
	Allows    int      `json:"allows"` // (kind or resource, verb) pairs the corpus allows
	Denies    int      `json:"denies"`
	RBACRules int      `json:"rbacRules"`
	// Dropped lists what was left out or narrowed, with the reason: never widened.
	Dropped []string `json:"dropped,omitempty"`
}

// Status is the one-line compile result for a principal's status.compiled.
func (r PrincipalReport) Status() string {
	if len(r.Dropped) == 0 {
		return "ok"
	}
	return fmt.Sprintf("ok, %d narrowed (see the iam-compiler report)", len(r.Dropped))
}

// Compile compiles every principal's IAM policies into the iam-corpus and generated RBAC.
func Compile(in Input) Output {
	if in.Home == "" {
		in.Home = iamauthz.DefaultHomeNamespace
	}
	accts := accountNamespaces(in.NamespaceAccounts)
	var out Output
	for _, p := range sortedPrincipals(in.Principals) {
		pc := compilePrincipal(in, accts, p)
		out.Principals = append(out.Principals, pc.report)
		if pc.grant != nil {
			out.Corpus = append(out.Corpus, *pc.grant)
		}
		out.ClusterRoles = append(out.ClusterRoles, pc.clusterRoles...)
		out.ClusterRoleBindings = append(out.ClusterRoleBindings, pc.clusterRoleBindings...)
		out.RoleBindings = append(out.RoleBindings, pc.roleBindings...)
	}
	return out
}

func sortedPrincipals(ps []Principal) []Principal {
	out := append([]Principal(nil), ps...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return out
}

// accountNamespaces inverts NamespaceAccounts: account id -> its namespaces, sorted.
func accountNamespaces(m map[string]string) map[string][]string {
	out := map[string][]string{}
	for ns, acct := range m {
		out[acct] = append(out[acct], ns)
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

// rset is a set of claim names of one kind: every name, or literal names and name globs.
type rset struct {
	all   bool
	names map[string]bool
	globs map[string]bool
}

func (s *rset) addName(n string) {
	if s.names == nil {
		s.names = map[string]bool{}
	}
	s.names[n] = true
}

func (s *rset) addGlob(g string) {
	if s.globs == nil {
		s.globs = map[string]bool{}
	}
	s.globs[g] = true
}

func (s rset) empty() bool { return !s.all && len(s.names) == 0 && len(s.globs) == 0 }

func (s *rset) union(o rset) {
	if o.all {
		s.all = true
	}
	for n := range o.names {
		s.addName(n)
	}
	for g := range o.globs {
		s.addGlob(g)
	}
}

// intersect is s ∩ o (identity ∩ permission boundary). A glob meets a glob only when they are equal
// (narrower otherwise).
func intersect(s, o rset) rset {
	switch {
	case s.all && o.all:
		return rset{all: true}
	case s.all:
		return rset{names: copySet(o.names), globs: copySet(o.globs)}
	case o.all:
		return rset{names: copySet(s.names), globs: copySet(s.globs)}
	}
	var r rset
	for n := range s.names {
		if o.names[n] || matchesAny(o.globs, n) {
			r.addName(n)
		}
	}
	for n := range o.names {
		if matchesAny(s.globs, n) {
			r.addName(n)
		}
	}
	for g := range s.globs {
		if o.globs[g] {
			r.addGlob(g)
		}
	}
	return r
}

func copySet(m map[string]bool) map[string]bool {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func matchesAny(globs map[string]bool, n string) bool {
	for g := range globs {
		if glob(g, n) {
			return true
		}
	}
	return false
}

// kindCtx is one table kind in one account, ready for resource matching.
type kindCtx struct {
	entry    awsaction.Entry
	typedAll string // the typed resource of "every name" (the ARN with a literal "*" name)
	hint     string // typedAll up to its first "*": a pattern that could target this kind starts so
	pre, suf string // around the name in the typed resource; namesOK=false when names cannot be read
	namesOK  bool
}

const namePlaceholder = "oiname0placeholder"

func newKindCtx(e awsaction.Entry, scope awsaction.Scope) kindCtx {
	k := kindCtx{entry: e, typedAll: typedOf(e.ARNFor(scope, "*", nil))}
	k.hint = k.typedAll
	if i := strings.IndexByte(k.hint, '*'); i >= 0 {
		k.hint = k.hint[:i]
	}
	// A kind whose ARN carries a physical name from its spec (NameField) names resources by that name,
	// not the claim's, so a name in a policy cannot be mapped to a claim (narrower: names unsupported).
	if e.NameField == "" {
		t := typedOf(e.ARNFor(scope, namePlaceholder, nil))
		if i := strings.Index(t, namePlaceholder); i >= 0 && !strings.Contains(t, "*") {
			k.pre, k.suf, k.namesOK = t[:i], t[i+len(namePlaceholder):], true
		}
	}
	return k
}

// mightTarget reports whether a resource pattern could name a resource of this kind (conservative: a
// pattern whose literal prefix is compatible with the kind's).
func (k kindCtx) mightTarget(p string) bool {
	lp := p
	if i := strings.IndexByte(lp, '*'); i >= 0 {
		lp = lp[:i]
	}
	return strings.HasPrefix(k.hint, lp) || strings.HasPrefix(lp, k.hint)
}

// verbMode is how a verb's request names its resource: "*" (a List, or a Get the service authorizes on
// "*"), one named resource the control plane sees (get, update, delete), or a create, whose name the
// control plane's authorization request does not carry.
type verbMode int

const (
	modeStar verbMode = iota
	modeNamed
	modeCreate
)

func modeFor(e awsaction.Entry, v awsaction.Verb) verbMode {
	switch {
	case v == awsaction.List || (v == awsaction.Get && e.GlobalDescribe):
		return modeStar
	case v == awsaction.Create:
		return modeCreate
	}
	return modeNamed
}

// cover is what one statement's resources cover of one kind.
type cover struct {
	set        rset
	except     rset // NotResource: every name except these (set.all is then true)
	unmappable bool // a pattern that could name this kind but cannot be read as claim names
	nameScoped bool // limited to names, for a verb whose request carries none (create)
}

func (k kindCtx) coverFor(st policyengine.Statement, mode verbMode) cover {
	var c cover
	if len(st.NotResources) > 0 {
		for _, p := range st.NotResources {
			if mode == modeStar {
				if glob(p, "*") {
					return cover{} // excludes the request itself
				}
				continue
			}
			if p == "*" || glob(p, k.typedAll) {
				return cover{} // excludes every name
			}
			if n, isGlob, ok := k.nameOf(p); ok {
				if isGlob {
					c.except.addGlob(n)
				} else {
					c.except.addName(n)
				}
			} else if k.mightTarget(p) {
				c.unmappable = true
			}
		}
		c.set.all = true
		return c
	}
	for _, p := range st.Resources {
		if mode == modeStar {
			if glob(p, "*") {
				c.set.all = true
			}
			continue
		}
		if p == "*" || glob(p, k.typedAll) {
			c.set.all = true
			continue
		}
		if n, isGlob, ok := k.nameOf(p); ok {
			if mode == modeCreate {
				c.nameScoped = true
				continue
			}
			if isGlob {
				c.set.addGlob(n)
			} else {
				c.set.addName(n)
			}
		} else if k.mightTarget(p) {
			c.unmappable = true
		}
	}
	return c
}

// nameOf reads a claim name (or name glob) from a typed resource pattern of this kind.
func (k kindCtx) nameOf(p string) (string, bool, bool) {
	if !k.namesOK || !strings.HasPrefix(p, k.pre) || !strings.HasSuffix(p, k.suf) || len(p) <= len(k.pre)+len(k.suf) {
		return "", false, false
	}
	n := p[len(k.pre) : len(p)-len(k.suf)]
	if strings.Contains(n, "/") && !strings.Contains(k.pre+k.suf, "/") {
		return "", false, false
	}
	return n, strings.Contains(n, "*"), true
}

// principalCompile is one principal's result.
type principalCompile struct {
	report              PrincipalReport
	grant               *Grant
	clusterRoles        []rbacv1.ClusterRole
	clusterRoleBindings []rbacv1.ClusterRoleBinding
	roleBindings        []rbacv1.RoleBinding
}

// target is one thing a verb is granted on: a claim kind, or an operator resource.
type target struct {
	group, resource string
	namespaced      bool
	claim           bool
	label           string // for reports: the kind or resource
}

func compilePrincipal(in Input, accts map[string][]string, p Principal) principalCompile {
	id := iamauthz.QualifiedName(in.Home, p.Namespace, p.Name)
	account := iamauthz.ManagementAccount
	if a, ok := in.NamespaceAccounts[p.Namespace]; ok && a != "" {
		account = a
	}
	rep := PrincipalReport{Kind: p.Kind, Namespace: p.Namespace, Name: p.Name, Account: account}
	if p.Kind == "User" && p.Name == ReservedRoot {
		rep.Dropped = append(rep.Dropped, `the user name "root" is reserved for the management account's break-glass root; this User compiles to nothing`)
		return principalCompile{report: rep}
	}
	identity := "openinfra:" + account + ":" + p.Name
	if p.Kind == "Role" {
		identity = "openinfra:" + account + ":role/" + id
	}
	rep.Identity = identity

	groups := p.Groups
	if p.Kind != "User" {
		groups = nil
	}
	pols := in.World.PoliciesFor(p.Kind, id, groups)
	var stmts []policyengine.Statement
	for _, pol := range pols {
		rep.Policies = append(rep.Policies, pol.Name)
		stmts = append(stmts, pol.Statements...)
	}
	hasBoundary, bstmts := in.World.BoundaryFor(p.Kind, id)

	scope := awsaction.Scope{Account: account}
	// Where this principal's grants land: its account's namespaces, or — for the management account in
	// a cluster where no namespace is labelled yet — everywhere (today's one-account world).
	nsList := accts[account]
	clusterWide := account == iamauthz.ManagementAccount && len(in.NamespaceAccounts) == 0
	if !clusterWide && len(nsList) == 0 {
		rep.Dropped = append(rep.Dropped, "account "+account+" has no namespaces: nothing to grant on")
		return principalCompile{report: rep}
	}

	var dropped []string
	drop := func(s string) { dropped = append(dropped, s) }

	// The verb-level decisions, per target.
	type decision struct {
		allow, deny rset
		rbacOK      bool // RBAC may carry the allow (no Deny, NotResource exception or name glob in the way)
	}
	decide := func(kc kindCtx, action string, mode verbMode, label string) decision {
		var allow, except, deny rset
		for _, st := range stmts {
			if !statementActs(st, action) {
				continue
			}
			ok, conditional := conditionScope(st, account)
			if !ok {
				continue
			}
			c := kc.coverFor(st, mode)
			if st.Effect == policyengine.Deny {
				if conditional {
					drop(label + " " + action + ": a conditional Deny applies unconditionally (the control plane carries no condition keys)")
				}
				if c.unmappable || c.nameScoped || !c.except.empty() {
					deny.all = true
					drop(label + " " + action + ": a Deny the control plane cannot limit to names applies to every name")
				} else {
					deny.union(c.set)
				}
				continue
			}
			if conditional {
				if !c.set.empty() || c.unmappable || c.nameScoped {
					drop(label + " " + action + ": a conditional Allow is dropped (the control plane carries no condition keys)")
				}
				continue
			}
			if c.unmappable {
				drop(label + " " + action + ": an Allow on resources that cannot be read as claim names is dropped")
			}
			if c.nameScoped {
				drop(label + " " + action + ": an Allow limited to names is dropped for a verb whose request carries no name")
			}
			allow.union(c.set)
			except.union(c.except)
		}
		if hasBoundary {
			var ballow, bdeny rset
			for _, st := range bstmts {
				if !statementActs(st, action) {
					continue
				}
				ok, conditional := conditionScope(st, account)
				if !ok {
					continue
				}
				c := kc.coverFor(st, mode)
				if st.Effect == policyengine.Deny {
					if c.unmappable || c.nameScoped || !c.except.empty() {
						bdeny.all = true
					} else {
						bdeny.union(c.set)
					}
					continue
				}
				if conditional || c.unmappable || c.nameScoped || !c.except.empty() {
					continue // narrower: the boundary allows less
				}
				ballow.union(c.set)
			}
			narrowed := intersect(allow, ballow)
			if !allow.empty() && narrowed.empty() {
				drop(label + " " + action + ": outside the permission boundary")
			}
			allow = narrowed
			deny.union(bdeny)
		}
		d := decision{allow: allow, deny: deny}
		// A NotResource exception becomes a Deny on the excepted names (narrower: it also wins over
		// another statement that allows them). A create's request carries no name, so the exception
		// cannot be enforced at create time: the create is dropped instead.
		if allow.all && !except.empty() {
			if mode == modeCreate {
				d.allow = rset{}
				drop(label + " " + action + ": a NotResource Allow is dropped for a create, whose request carries no name to except")
			} else {
				d.deny.union(except)
				drop(label + " " + action + ": a NotResource Allow becomes an Allow on every name plus a Deny on the excepted ones")
			}
		}
		d.rbacOK = d.deny.empty()
		if !d.allow.empty() && !d.deny.empty() {
			drop(label + " " + action + ": not in the generated RBAC (a Deny applies, which RBAC cannot express)")
		} else if len(d.allow.globs) > 0 {
			drop(label + " " + action + ": a name pattern is in the corpus only (RBAC names resources exactly)")
		}
		return d
	}

	cedar := map[policyengine.Effect]map[string][]string{policyengine.Allow: {}, policyengine.Deny: {}}
	addCedar := func(effect policyengine.Effect, verbs []string, resources ...string) {
		k := strings.Join(verbs, ",")
		cedar[effect][k] = append(cedar[effect][k], resources...)
	}
	var nsRules, clusterRules []rbacv1.PolicyRule

	// ids builds the control-plane resource ids for a target and a name pattern ("*" = every name).
	ids := func(t target, name string) []string {
		rtypes := []string{t.resource}
		if t.claim {
			rtypes = append(rtypes, t.resource+"/status")
		}
		var out []string
		for _, rt := range rtypes {
			full := rt
			if t.group != "" {
				full = rt + "." + t.group
			}
			switch {
			case !t.namespaced:
				out = append(out, full+"::"+name)
			case clusterWide:
				if name == "*" {
					out = append(out, full+"::*")
				} else {
					out = append(out, full+"::*/"+name)
				}
			default:
				for _, ns := range nsList {
					out = append(out, full+"::"+ns+"/"+name)
				}
			}
		}
		return out
	}
	// denyIDs is ids for a Deny, which also covers a request that names the object with no namespace
	// in the one-account world (a Deny is never narrower than it can be made).
	denyIDs := func(t target, name string) []string {
		out := ids(t, name)
		if clusterWide && t.namespaced && name != "*" {
			full := t.resource
			if t.group != "" {
				full += "." + t.group
			}
			out = append(out, full+"::"+name)
		}
		return out
	}
	rbacResources := func(t target) []string {
		if t.claim {
			return []string{t.resource, t.resource + "/status"}
		}
		return []string{t.resource}
	}

	apply := func(t target, v awsaction.Verb, d decision) {
		verbs := k8sVerbs(v, d.allow.all)
		if d.allow.all {
			rep.Allows++
			addCedar(policyengine.Allow, verbs, ids(t, "*")...)
		} else if !d.allow.empty() {
			rep.Allows++
			nv := k8sVerbs(v, false)
			for _, n := range sortedKeys(d.allow.names) {
				addCedar(policyengine.Allow, nv, ids(t, n)...)
			}
			for _, g := range sortedKeys(d.allow.globs) {
				addCedar(policyengine.Allow, nv, ids(t, g)...)
			}
		}
		if !d.deny.empty() {
			rep.Denies++
			all := k8sVerbs(v, true)
			if d.deny.all {
				addCedar(policyengine.Deny, all, ids(t, "*")...)
			} else {
				for _, n := range append(sortedKeys(d.deny.names), sortedKeys(d.deny.globs)...) {
					addCedar(policyengine.Deny, all, denyIDs(t, n)...)
				}
			}
		}
		if d.allow.empty() || !d.rbacOK {
			return
		}
		rule := rbacv1.PolicyRule{APIGroups: []string{t.group}, Resources: rbacResources(t), Verbs: verbs}
		if !d.allow.all {
			// RBAC names resources exactly: the literal names, never a pattern (the corpus has those).
			if (v == awsaction.Get || v == awsaction.Update || v == awsaction.Delete) && len(d.allow.names) > 0 {
				rule.ResourceNames = sortedKeys(d.allow.names)
				rule.Verbs = k8sVerbs(v, false)
			} else {
				return
			}
		}
		if t.namespaced {
			nsRules = append(nsRules, rule)
		} else {
			clusterRules = append(clusterRules, rule)
		}
	}

	// A verb granted on everything — every table kind, every operator resource and the rest of the
	// operator surface, with no Deny or boundary in the way — is one wildcard, which also covers other
	// groups' CRDs. Only in a cluster-wide (one-account) world: account-scoped grants are enumerated, so
	// a wildcard can never reach another account's namespaces.
	wildcard := map[awsaction.Verb]bool{}
	if clusterWide {
		for _, v := range awsaction.Verbs {
			wildcard[v] = everything(stmts, hasBoundary, bstmts, account, scope, v)
		}
	}

	for _, kind := range awsaction.Kinds() {
		e, _ := awsaction.Lookup(kind)
		kc := newKindCtx(e, scope)
		t := target{group: e.Group, resource: e.Resource, namespaced: true, claim: true, label: kind}
		for _, v := range awsaction.Verbs {
			action, ok := e.Action(v)
			if !ok || wildcard[v] {
				continue
			}
			apply(t, v, decide(kc, action, modeFor(e, v), kind))
		}
	}
	for _, or := range operatorResources {
		if !or.Namespaced && account != iamauthz.ManagementAccount {
			continue // a member account never reaches cluster-scoped platform objects
		}
		t := target{group: or.Group, resource: or.Resource, namespaced: or.Namespaced, label: or.Resource}
		for _, v := range awsaction.Verbs {
			if wildcard[v] {
				continue
			}
			action, _, ok := scope.ForKubernetes(string(v), or.Group, or.Resource, "", "")
			if !ok {
				continue
			}
			// The operator surface is granted on every name or not at all (its ARNs name
			// <resource>/<namespace>/<name>, which a claim-name mapping does not cover).
			d := decide(operatorKind(or, scope), action, modeStar, or.Resource)
			apply(t, v, d)
		}
	}
	for _, v := range awsaction.Verbs {
		if !wildcard[v] {
			continue
		}
		verbs := k8sVerbs(v, true)
		rep.Allows++
		addCedar(policyengine.Allow, verbs, "*")
		clusterRules = append(clusterRules, rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: verbs})
	}
	if rep.Allows > 0 {
		addCedar(policyengine.Allow, []string{"get"}, prefixed("NonResourceURL::", discoveryPaths)...)
	}

	rep.Dropped = dedupe(dropped)
	pc := principalCompile{report: rep}
	if g := buildGrant(identity, cedar); g != nil {
		g.Caveats = rep.Dropped
		pc.grant = g
	}
	pc.clusterRoles, pc.clusterRoleBindings, pc.roleBindings = buildRBAC(p, id, account, identity, clusterWide, nsList,
		mergeRules(nsRules), mergeRules(clusterRules))
	pc.report.RBACRules = len(mergeRules(nsRules)) + len(mergeRules(clusterRules))
	return pc
}

// everything reports whether a principal's policies grant verb v on every table kind and the whole
// operator surface, with no Deny, condition or boundary narrowing it — Action "*" on Resource "*".
func everything(stmts []policyengine.Statement, hasBoundary bool, bstmts []policyengine.Statement, account string,
	scope awsaction.Scope, v awsaction.Verb) bool {
	if hasBoundary {
		return false
	}
	for _, st := range stmts {
		if st.Effect == policyengine.Deny {
			return false // any Deny: enumerate, so it can be honoured
		}
	}
	grants := func(action string) bool {
		for _, st := range stmts {
			if ok, conditional := conditionScope(st, account); !ok || conditional {
				continue
			}
			if len(st.NotResources) > 0 || !statementActs(st, action) {
				continue
			}
			for _, r := range st.Resources {
				if r == "*" {
					return true
				}
			}
		}
		return false
	}
	for _, kind := range awsaction.Kinds() {
		e, _ := awsaction.Lookup(kind)
		if a, ok := e.Action(v); ok && !grants(a) {
			return false
		}
	}
	for _, or := range append(append([]operatorResource(nil), operatorResources...), sentinelOperator) {
		a, _, ok := scope.ForKubernetes(string(v), or.Group, or.Resource, "", "")
		if ok && !grants(a) {
			return false
		}
	}
	return true
}

// operatorKind is the matching context for an operator resource: its requests are on "*" (modeStar).
func operatorKind(or operatorResource, scope awsaction.Scope) kindCtx {
	arn := fmt.Sprintf("arn:aws:%s:%s:%s:%s/*", operatorPrefix, awsaction.DefaultRegion, scope.Account, or.Resource)
	k := kindCtx{typedAll: typedOf(arn)}
	k.hint = strings.TrimSuffix(k.typedAll, "*")
	return k
}

// k8sVerbs is the Kubernetes verbs an awsaction verb is. deletecollection rides with delete only on
// every name.
func k8sVerbs(v awsaction.Verb, all bool) []string {
	switch v {
	case awsaction.Get:
		return []string{"get"}
	case awsaction.List:
		return []string{"list", "watch"}
	case awsaction.Create:
		return []string{"create"}
	case awsaction.Update:
		return []string{"update", "patch"}
	case awsaction.Delete:
		if all {
			return []string{"delete", "deletecollection"}
		}
		return []string{"delete"}
	}
	return nil
}

func buildGrant(identity string, cedar map[policyengine.Effect]map[string][]string) *Grant {
	g := &Grant{AppliesTo: []string{"User::" + identity}}
	for _, effect := range []policyengine.Effect{policyengine.Deny, policyengine.Allow} {
		for _, verbs := range sortedKeysOf(cedar[effect]) {
			res := dedupe(cedar[effect][verbs])
			if len(res) == 0 {
				continue
			}
			g.Statements = append(g.Statements, Statement{Effect: string(effect), Actions: strings.Split(verbs, ","), Resources: res})
		}
	}
	if len(g.Statements) == 0 {
		return nil
	}
	return g
}

// mergeRules folds rules with the same groups, verbs and resourceNames into one, deterministically.
func mergeRules(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	type key struct{ groups, verbs, names string }
	byKey := map[key]*rbacv1.PolicyRule{}
	var order []key
	for _, r := range rules {
		k := key{strings.Join(r.APIGroups, ","), strings.Join(r.Verbs, ","), strings.Join(r.ResourceNames, ",")}
		if byKey[k] == nil {
			rr := rbacv1.PolicyRule{APIGroups: r.APIGroups, Verbs: r.Verbs, ResourceNames: r.ResourceNames}
			byKey[k] = &rr
			order = append(order, k)
		}
		byKey[k].Resources = append(byKey[k].Resources, r.Resources...)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.groups != b.groups {
			return a.groups < b.groups
		}
		if a.verbs != b.verbs {
			return a.verbs < b.verbs
		}
		return a.names < b.names
	})
	out := make([]rbacv1.PolicyRule, 0, len(order))
	for _, k := range order {
		r := *byKey[k]
		r.Resources = dedupe(r.Resources)
		out = append(out, r)
	}
	return out
}

// buildRBAC renders a principal's generated RBAC: one ClusterRole of its namespaced rules, bound in each
// of its account's namespaces (or cluster-wide in the one-account world), and one of its cluster-scoped
// rules (the management account's operator surface) bound cluster-wide.
func buildRBAC(p Principal, id, account, identity string, clusterWide bool, nsList []string,
	nsRules, clusterRules []rbacv1.PolicyRule) ([]rbacv1.ClusterRole, []rbacv1.ClusterRoleBinding, []rbacv1.RoleBinding) {
	base := GeneratedName(p.Kind, id, account)
	meta := func(name, ns string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: ns,
			Labels: map[string]string{GeneratedByLabel: GeneratedBy, AccountLabel: account,
				PrincipalLabel: principalHash(p.Kind, id, account)},
			Annotations: map[string]string{IdentityAnno: identity}}
	}
	subject := []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: identity}}
	var crs []rbacv1.ClusterRole
	var crbs []rbacv1.ClusterRoleBinding
	var rbs []rbacv1.RoleBinding
	if len(nsRules) > 0 {
		crs = append(crs, rbacv1.ClusterRole{TypeMeta: crType, ObjectMeta: meta(base, ""), Rules: nsRules})
		ref := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: base}
		if clusterWide {
			crbs = append(crbs, rbacv1.ClusterRoleBinding{TypeMeta: crbType, ObjectMeta: meta(base, ""), RoleRef: ref, Subjects: subject})
		} else {
			for _, ns := range nsList {
				rbs = append(rbs, rbacv1.RoleBinding{TypeMeta: rbType, ObjectMeta: meta(base, ns), RoleRef: ref, Subjects: subject})
			}
		}
	}
	if len(clusterRules) > 0 {
		name := base + ":cluster"
		crs = append(crs, rbacv1.ClusterRole{TypeMeta: crType, ObjectMeta: meta(name, ""), Rules: clusterRules})
		crbs = append(crbs, rbacv1.ClusterRoleBinding{TypeMeta: crbType, ObjectMeta: meta(name, ""),
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}, Subjects: subject})
	}
	return crs, crbs, rbs
}

var (
	crType  = metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}
	crbType = metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}
	rbType  = metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"}
)

// GeneratedName is the name of a principal's generated RBAC: "openinfra-iam:<account>:<kind>:<id>",
// with a namespaced id's "/" as ".". RBAC names may not contain "/".
func GeneratedName(kind, id, account string) string {
	return "openinfra-iam:" + account + ":" + strings.ToLower(kind) + ":" + strings.ReplaceAll(id, "/", ".")
}

func principalHash(kind, id, account string) string {
	h := sha256.Sum256([]byte(account + "/" + kind + "/" + id))
	return hex.EncodeToString(h[:])[:20]
}

func prefixed(prefix string, xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = prefix + x
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupe(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
