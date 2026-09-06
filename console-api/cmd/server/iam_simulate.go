package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	"k8s.io/client-go/kubernetes"
)

// The IAM policy simulator — the open-infra analog of AWS's policy simulator. Pick a principal
// (User/Group/Role), one or more actions, and an optional resource, and it answers "would this be
// Allowed or Denied under the CURRENT policies?" without performing the action.
//
// It reuses the platform's REAL enforcement paths so the answer matches what would actually happen:
//   - control plane: an impersonated SubjectAccessReview via the shared authorization core
//     (internal/iam.CanDo) — the exact check the console and the aws-shim gate every request with;
//   - data plane: the same Cedar-backed engine (internal/dataplaneauthz + policyengine) the aws-shim
//     enforces spec.dataPlane with — so an explicit Deny or a request condition is evaluated for real.
//
// It does NOT reimplement Cedar or RBAC. Honest limitations (surfaced in the response `limitations`):
//   - For a DATA-plane action the effective allow is coarse RBAC AND the data-plane verdict, exactly
//     as the shim does; the coarse gate's k8s verb is derived from the action by an approximate
//     operation→verb mapping (the aws-shim's own mapping is the source of truth).
//   - spec.controlPlane Cedar is Phase-2 shadow and NOT enforced, so it is not evaluated here; the
//     control plane is RBAC only.
//   - A Role's control-plane permissions take effect only through a Group bound to its aggregated
//     ClusterRole; an unbound Role grants nothing (reported as "indeterminate").
//
// Gated by the same SAR as the other IAM endpoints (list policies) — admins-only, fail closed.

// dataServices are the aws-shim front doors whose actions the data-plane engine governs.
var dataServices = []string{"s3", "dynamodb", "lambda"}

func isDataService(s string) bool {
	for _, x := range dataServices {
		if x == s {
			return true
		}
	}
	return false
}

type simulateReq struct {
	Principal string         `json:"principal"` // "User::alice", "Group::eng", "Role::deployer" ("alice" ⇒ User)
	Actions   []string       `json:"actions"`   // "virtualmachines:Get" (control), "s3:GetObject" (data)
	Resource  string         `json:"resource"`  // optional; typed for data plane, e.g. "Bucket::assets"
	Namespace string         `json:"namespace"` // optional; control-plane SAR namespace (defaults to console ns)
	Context   map[string]any `json:"context"`   // optional data-plane condition context (sourceIp, ...)
}

// planeResult is one plane's verdict. Decision is allow|deny|not-governed|indeterminate.
type planeResult struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Governed *bool  `json:"governed,omitempty"` // data plane only: whether any policy governs the service
}

type simResult struct {
	Action       string       `json:"action"`
	Plane        string       `json:"plane"`    // control | data | unknown
	Decision     string       `json:"decision"` // net effective decision
	Reason       string       `json:"reason"`
	Enforced     bool         `json:"enforced"`               // true when evaluated via a real enforcement path
	ControlPlane *planeResult `json:"controlPlane,omitempty"` // set for control actions, and the coarse gate of a data action
	DataPlane    *planeResult `json:"dataPlane,omitempty"`    // set for data actions
}

type simulateResp struct {
	Principal   string      `json:"principal"`
	Resource    string      `json:"resource,omitempty"`
	Results     []simResult `json:"results"`
	Warnings    []string    `json:"warnings"`
	Limitations []string    `json:"limitations"`
}

// simPrincipal is a resolved principal ready for both planes.
type simPrincipal struct {
	pType, name string
	// control plane
	controlClaims    iam.Claims
	controlEvaluable bool
	controlNote      string // why control is indeterminate (unbound role)
	// data plane
	dataType, dataID string
	dataGroups       []string
	warnings         []string
}

func handleIAMSimulate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A simulation reads the whole policy/identity set to answer a what-if, so gate it exactly
		// like listing policies — admins-only, the same SAR the other IAM endpoints use.
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "policies", auth.ns, "") {
			return
		}
		var in simulateReq
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if strings.TrimSpace(in.Principal) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "principal is required (e.g. User::alice, Group::eng, Role::deployer)"})
			return
		}
		acts := nonEmpty(in.Actions)
		if len(acts) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one action is required"})
			return
		}

		sp, code, errMsg := resolveSimPrincipal(r.Context(), auth, in.Principal)
		if errMsg != "" {
			writeJSON(w, code, map[string]string{"error": errMsg})
			return
		}

		ns := strings.TrimSpace(in.Namespace)
		if ns == "" {
			ns = auth.ns
		}
		reqCtx := simContext(in.Context)
		resType, resID := splitTyped(in.Resource)
		checker := dataPlaneCheckerFor(auth.listCRDPolicies(r.Context()))

		out := simulateResp{
			Principal: sp.pType + "::" + sp.name,
			Resource:  strings.TrimSpace(in.Resource),
			Results:   make([]simResult, 0, len(acts)),
			Warnings:  sp.warnings,
			Limitations: []string{
				"Control-plane decisions use an impersonated SubjectAccessReview — the exact check the console and aws-shim enforce with.",
				"Data-plane decisions use the same Cedar engine the aws-shim enforces spec.dataPlane with.",
				"For a data-plane action the coarse control-plane gate's k8s verb is derived by an approximate operation→verb mapping; the aws-shim's mapping is authoritative.",
				"spec.controlPlane Cedar is Phase-2 shadow and is not enforced, so it is not evaluated here — the control plane is RBAC only.",
			},
		}
		if out.Warnings == nil {
			out.Warnings = []string{}
		}

		for _, action := range acts {
			out.Results = append(out.Results, simulateAction(r.Context(), cs, checker, sp, action, ns, resType, resID, reqCtx))
		}
		logger.Info("iam: policy simulation", "principal", out.Principal, "actions", len(acts), "by", subjectOf(r))
		writeJSON(w, http.StatusOK, out)
	}
}

// simulateAction evaluates one action on the plane that owns it.
func simulateAction(ctx context.Context, cs kubernetes.Interface, checker *dataplaneauthz.Checker,
	sp simPrincipal, action, ns, resType, resID string, reqCtx map[string]any) simResult {
	plane, left, right, ok := classifyAction(action)
	if !ok {
		return simResult{
			Action: action, Plane: "unknown", Decision: "unknown",
			Reason: "action must be <resource>:<verb> over openinfra.dev (control plane) or <service>:<op> for s3/dynamodb/lambda (data plane)",
		}
	}
	if plane == "control" {
		cp := evalControl(ctx, cs, sp, left, right, ns, "")
		return simResult{Action: action, Plane: "control", Decision: cp.Decision, Reason: cp.Reason, Enforced: sp.controlEvaluable, ControlPlane: &cp}
	}
	// data-plane action: net = coarse RBAC AND the data-plane verdict (mirrors the shim).
	cp := evalDataCoarse(ctx, cs, sp, left, right, ns)
	dp := evalData(ctx, checker, sp, action, resType, resID, reqCtx)
	decision, reason := combineDecision(cp, dp)
	return simResult{Action: action, Plane: "data", Decision: decision, Reason: reason, Enforced: true, ControlPlane: &cp, DataPlane: &dp}
}

// resolveSimPrincipal turns "Type::name" into an evaluable principal, or returns an HTTP code +
// message. Type defaults to User when "::" is absent.
func resolveSimPrincipal(ctx context.Context, auth *authStore, raw string) (simPrincipal, int, string) {
	pType, name := parsePrincipal(raw)
	sp := simPrincipal{pType: pType, name: name, warnings: []string{}}
	switch pType {
	case "User":
		u, ok := auth.rawUser(ctx, name)
		if !ok {
			return sp, http.StatusNotFound, "no such user: " + name
		}
		groups := iam.GroupsFromSpec(u.Spec.Groups)
		sp.controlClaims = iam.Claims{Sub: name, Groups: groups}
		sp.controlEvaluable = true
		sp.dataType, sp.dataID, sp.dataGroups = "User", name, groups
		if u.Spec.Disabled {
			sp.warnings = append(sp.warnings, "user is disabled — sign-in is refused, but its attached permissions are shown")
		}
	case "Group":
		if _, ok := auth.crdGroupByName(ctx, name); !ok {
			return sp, http.StatusNotFound, "no such group: " + name
		}
		groups := []string{"openinfra:" + name, "openinfra:users"}
		sp.controlClaims = iam.Claims{Sub: "group:" + name, Groups: groups}
		sp.controlEvaluable = true
		sp.dataType, sp.dataID, sp.dataGroups = "Group", name, []string{"openinfra:" + name}
		if !isBuiltinGroup(name) {
			sp.warnings = append(sp.warnings, "group is outside the impersonation ceiling — inert until an operator widens it; the RBAC shown reflects its ClusterRole if one is bound")
		}
	case "Role":
		if _, ok := auth.crdRoleByName(ctx, name); !ok {
			return sp, http.StatusNotFound, "no such role: " + name
		}
		sp.dataType, sp.dataID, sp.dataGroups = "Role", name, nil
		// A role grants on the control plane only through a Group bound to its aggregated
		// ClusterRole; evaluate via such a group if one exists and is impersonable, else say so.
		crName := "openinfra-role-" + name
		var boundGroup string
		for _, g := range groupsUsingClusterRole(auth.listCRDGroups(ctx), crName) {
			if isBuiltinGroup(g) {
				boundGroup = g
				break
			}
		}
		if boundGroup != "" {
			sp.controlClaims = iam.Claims{Sub: "role:" + name, Groups: []string{"openinfra:" + boundGroup, "openinfra:users"}}
			sp.controlEvaluable = true
			sp.warnings = append(sp.warnings, "control plane evaluated via group "+boundGroup+", which binds this role")
		} else {
			sp.controlNote = "role is not bound to any impersonable group, so it grants nothing on the control plane until a Group points at " + crName
		}
	default:
		return sp, http.StatusBadRequest, "principal must be User::<name>, Group::<name>, or Role::<name>"
	}
	return sp, http.StatusOK, ""
}

// evalControl runs a control-plane SAR (verb on <resource>.openinfra.dev) as the principal.
func evalControl(ctx context.Context, cs kubernetes.Interface, sp simPrincipal, resource, verb, ns, name string) planeResult {
	if !sp.controlEvaluable {
		return planeResult{Decision: "indeterminate", Reason: sp.controlNote}
	}
	allowed, reason := iam.CanDo(ctx, cs, sp.controlClaims, verb, "openinfra.dev", resource, ns, name)
	if allowed {
		return planeResult{Decision: "allow", Reason: "allowed by RBAC (SubjectAccessReview)"}
	}
	return planeResult{Decision: "deny", Reason: orDefault(reason, "denied by RBAC")}
}

// evalDataCoarse runs the coarse control-plane gate a data-plane action also passes through: a SAR
// on the underlying openinfra.dev kind (s3→buckets, dynamodb→tables, lambda→functions) with an
// approximate verb derived from the operation.
func evalDataCoarse(ctx context.Context, cs kubernetes.Interface, sp simPrincipal, service, op, ns string) planeResult {
	kind := dataServiceKind(service)
	if kind == "" {
		return planeResult{Decision: "indeterminate", Reason: "unknown data service: " + service}
	}
	if !sp.controlEvaluable {
		return planeResult{Decision: "indeterminate", Reason: sp.controlNote}
	}
	allowed, reason := iam.CanDo(ctx, cs, sp.controlClaims, coarseVerb(op), "openinfra.dev", kind, ns, "")
	if allowed {
		return planeResult{Decision: "allow", Reason: "allowed by RBAC on " + kind + " (approx verb " + coarseVerb(op) + ")"}
	}
	return planeResult{Decision: "deny", Reason: orDefault(reason, "denied by RBAC on "+kind)}
}

// evalData runs the fine-grained data-plane Cedar check (the same engine the shim enforces with).
func evalData(ctx context.Context, checker *dataplaneauthz.Checker, sp simPrincipal,
	action, resType, resID string, reqCtx map[string]any) planeResult {
	allowed, governed, reason := checker.Authorize(ctx, sp.dataType, sp.dataID, sp.dataGroups, action, resType, resID, reqCtx)
	g := governed
	if !governed {
		return planeResult{Decision: "not-governed", Governed: &g,
			Reason: "no data-plane policy governs this service for this principal — the control-plane decision stands"}
	}
	if allowed {
		return planeResult{Decision: "allow", Reason: reason, Governed: &g}
	}
	return planeResult{Decision: "deny", Reason: reason, Governed: &g}
}

// combineDecision merges the coarse control-plane gate and the data-plane verdict for a data-plane
// action, exactly as the shim would: a control-plane deny blocks; a governed data-plane deny then
// overrides an allow (this is the "looks allowed but a Deny blocks it" case AWS's simulator surfaces).
func combineDecision(cp, dp planeResult) (string, string) {
	if cp.Decision == "deny" {
		return "deny", "denied by control-plane RBAC: " + cp.Reason
	}
	if dp.Decision == "deny" {
		if cp.Decision == "allow" {
			return "deny", "allowed by control-plane RBAC but denied by a data-plane policy: " + dp.Reason
		}
		return "deny", "denied by a data-plane policy: " + dp.Reason
	}
	if cp.Decision == "allow" {
		if dp.Decision == "not-governed" {
			return "allow", "allowed by control-plane RBAC; no data-plane policy narrows it"
		}
		return "allow", "allowed by control-plane RBAC and data-plane policy"
	}
	// cp indeterminate, dp not a deny
	return "indeterminate", orDefault(cp.Reason, "control-plane decision is indeterminate")
}

// dataPlaneCheckerFor builds a one-shot Cedar checker over every policy's spec.dataPlane block —
// the same PolicyDoc shape the shim's live K8sLoader produces, but from the already-parsed list so
// the simulator needs no dynamic client. Policies without a data-plane block are ignored.
func dataPlaneCheckerFor(ps []crdPolicy) *dataplaneauthz.Checker {
	var docs []dataplaneauthz.PolicyDoc
	for _, p := range ps {
		b := p.Spec.DataPlane
		if b == nil || len(b.Statements) == 0 {
			continue
		}
		doc := dataplaneauthz.PolicyDoc{AppliesTo: b.AppliesTo}
		for _, s := range b.Statements {
			doc.Statements = append(doc.Statements, policyengine.Statement{
				Effect:    policyengine.Effect(canonEffect(s.Effect)),
				Actions:   s.Actions,
				Resources: s.Resources,
				Condition: s.Condition,
			})
		}
		docs = append(docs, doc)
	}
	return dataplaneauthz.New(func(context.Context) ([]dataplaneauthz.PolicyDoc, error) { return docs, nil }, time.Minute)
}

// classifyAction decides which plane owns an action and splits it. A control-plane action is
// <openinfra-resource>:<verb> (both known); a data-plane action is <service>:<op> for a known
// data service. ok=false for anything else.
func classifyAction(action string) (plane, left, right string, ok bool) {
	a := strings.TrimSpace(action)
	i := strings.IndexByte(a, ':')
	if i <= 0 || i == len(a)-1 {
		return "", "", "", false
	}
	left, right = a[:i], a[i+1:]
	if isPolicyResource(left) && policyVerbs[strings.ToLower(right)] {
		return "control", left, strings.ToLower(right), true
	}
	if isDataService(left) {
		return "data", left, right, true
	}
	return "", left, right, false
}

// dataServiceKind maps a data service to the openinfra.dev kind its coarse RBAC gate is checked on.
func dataServiceKind(service string) string {
	switch service {
	case "s3":
		return "buckets"
	case "dynamodb":
		return "tables"
	case "lambda":
		return "functions"
	}
	return ""
}

// coarseVerb approximates the k8s verb the coarse RBAC gate needs for a data-plane operation. This
// is a documented approximation — the aws-shim's own mapping is authoritative (see limitations).
func coarseVerb(op string) string {
	o := strings.ToLower(op)
	switch {
	case strings.HasPrefix(o, "put"), strings.HasPrefix(o, "create"), strings.HasPrefix(o, "update"),
		strings.HasPrefix(o, "write"), strings.HasPrefix(o, "batchwrite"), strings.HasPrefix(o, "upload"):
		return "create"
	case strings.HasPrefix(o, "delete"):
		return "delete"
	default:
		// get/list/describe/query/scan/head/batchget/invoke and anything unknown → the read gate.
		return "get"
	}
}

// parsePrincipal splits "Type::name"; a bare string is treated as a User.
func parsePrincipal(s string) (pType, name string) {
	s = strings.TrimSpace(s)
	if t, n, ok := strings.Cut(s, "::"); ok {
		return strings.TrimSpace(t), strings.TrimSpace(n)
	}
	return "User", s
}

// splitTyped splits a typed resource "Type::id" into its parts; "", "*" and an untyped value all
// yield an empty type so only wildcard-resource statements match.
func splitTyped(s string) (typ, id string) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return "", ""
	}
	if t, n, ok := strings.Cut(s, "::"); ok {
		return t, n
	}
	return "", s
}

// simContext builds the Cedar condition context, defaulting authenticated=true (the request is past
// SigV4 in the real shim) and coercing "true"/"false" strings to booleans so bool conditions match.
func simContext(in map[string]any) map[string]any {
	out := map[string]any{"authenticated": true}
	for k, v := range in {
		if s, ok := v.(string); ok {
			switch s {
			case "true":
				out[k] = true
				continue
			case "false":
				out[k] = false
				continue
			}
		}
		out[k] = v
	}
	return out
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
