package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
)

// Managing kind: Policy and kind: Role from the console (IAM stage 2).
//
// Like the Users/Groups endpoints, every handler here authorizes the SIGNED-IN user with a
// SubjectAccessReview against iam.openinfra.dev before acting (see authorize), so it is
// admins-only, exactly as restricted as kubectl. The console's ServiceAccount does the work;
// the human's own RBAC decides whether it happens.
//
// A Policy is an attachable document of Allow statements over the openinfra.dev product
// surface. The composition enforces a permission boundary (it hardcodes apiGroups:
// [openinfra.dev] and drops any resource outside policyResources), so a policy can NEVER
// grant secrets/RBAC. We validate here too — not for safety, the boundary already has that —
// but so a typo'd action fails with a clear message instead of being silently dropped.

// policyResources is the openinfra.dev surface a Policy may name. MUST match the whitelist
// in platform/abstraction/policy-composition.yaml and the grants in provider-setup.yaml —
// if they drift, a valid-looking action here would be silently dropped by the composition.
var policyResources = []string{
	"applications", "functions", "models", "virtualmachines", "vmimages", "volumes",
	"fileshares", "directories", "migrations", "replications", "dataflows", "streams",
	"securitygroups", "faultinjections", "queries", "httpapis", "graphqlapis",
	"databaseproxies", "statemachines", "trainingjobs", "modelpackages", "batchtransforms", "processingjobs", "modelmonitors", "featuregroups",
	"scheduledjobs", "autoscalinggroups",
	"staticsites", "parameters", "emailsenders",
	"tables", "buckets", "queues",
}

// policyVerbs are the verbs an action may use (case-insensitive), plus "*".
var policyVerbs = map[string]bool{
	"get": true, "list": true, "watch": true, "create": true,
	"update": true, "patch": true, "delete": true, "*": true,
}

func isPolicyResource(r string) bool {
	if r == "*" {
		return true
	}
	for _, x := range policyResources {
		if x == r {
			return true
		}
	}
	return false
}

const (
	// managedPolicyLabel marks a Policy CR as an out-of-the-box MANAGED policy — the AWS
	// "AWS managed" analog. The managed-policy LIBRARY ships these as kind: Policy CRs carrying
	// this label (set to exactly "true"); GitOps owns them, so the console treats them as
	// read-only: no edit, no delete. This label is the contract with the library and must match
	// what those CRs set.
	managedPolicyLabel = "openinfra.dev/managed-policy"
	// policyCategoryLabel groups managed policies (e.g. "job-function", "administrator") the way
	// AWS's "AWS managed - job function" set does. Advisory only; surfaced in the view when present.
	policyCategoryLabel = "openinfra.dev/policy-category"
	// managedReadOnlyMsg is the 403 body when a client tries to update or delete a managed policy.
	managedReadOnlyMsg = "managed policies are read-only — they are provisioned out of the box by GitOps and cannot be changed from the console"
)

// isManagedPolicy reports whether a Policy's labels mark it as an out-of-the-box managed policy.
// A managed policy is read-only from the console — mutation is refused server-side.
func isManagedPolicy(labels map[string]string) bool {
	return labels[managedPolicyLabel] == "true"
}

// ── CR types (read side) ─────────────────────────────────────────────────────────

type policyStatement struct {
	Effect    string   `json:"effect,omitempty"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources,omitempty"`
}

// cedarStatement is one Cedar-backed statement carried on spec.dataPlane / spec.controlPlane —
// the model Kubernetes RBAC cannot express (explicit Deny + request conditions). It mirrors the
// XRD shape exactly and maps 1:1 to policyengine.Statement at enforcement time.
type cedarStatement struct {
	Effect    string            `json:"effect"`
	Actions   []string          `json:"actions"`
	Resources []string          `json:"resources,omitempty"`
	Condition map[string]string `json:"condition,omitempty"`
}

// cedarBlock is a spec.dataPlane or spec.controlPlane block: the principals it governs plus its
// Cedar statements. A nil block means the policy carries no such plane (the common case), which is
// why the views and requests use a pointer — absent stays absent through the round-trip.
type cedarBlock struct {
	AppliesTo  []string         `json:"appliesTo"`
	Statements []cedarStatement `json:"statements"`
}

type crdPolicy struct {
	Metadata struct {
		Name string `json:"name"`
		// Annotations carry free-form tags (openinfra.dev/tag-*); see iam_tags.go.
		Annotations map[string]string `json:"annotations,omitempty"`
		// Labels carry the managed-policy contract (openinfra.dev/managed-policy,
		// openinfra.dev/policy-category) set by the GitOps-shipped managed-policy library.
		Labels map[string]string `json:"labels,omitempty"`
	} `json:"metadata"`
	Spec struct {
		Description  string            `json:"description"`
		Statements   []policyStatement `json:"statements"`
		DataPlane    *cedarBlock       `json:"dataPlane,omitempty"`
		ControlPlane *cedarBlock       `json:"controlPlane,omitempty"`
	} `json:"spec"`
	Status struct {
		Ready       bool   `json:"ready"`
		ClusterRole string `json:"clusterRole"`
		RuleCount   int    `json:"ruleCount"`
	} `json:"status"`
}

type crdRole struct {
	Metadata struct {
		Name string `json:"name"`
		// Annotations carry free-form tags (openinfra.dev/tag-*); see iam_tags.go.
		Annotations map[string]string `json:"annotations,omitempty"`
	} `json:"metadata"`
	Spec struct {
		Description string   `json:"description"`
		Policies    []string `json:"policies"`
		Trust       []string `json:"trust"`
	} `json:"spec"`
	Status struct {
		Ready       bool   `json:"ready"`
		ClusterRole string `json:"clusterRole"`
	} `json:"status"`
}

func policiesAbsPath(ns string) string {
	return "/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/policies"
}
func rolesAbsPath(ns string) string {
	return "/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/roles"
}

func (a *authStore) listCRDPolicies(ctx context.Context) []crdPolicy {
	rc := a.rawREST()
	if rc == nil {
		return nil
	}
	raw, err := rc.Get().AbsPath(policiesAbsPath(a.ns)).DoRaw(ctx)
	if err != nil {
		return nil
	}
	var list struct {
		Items []crdPolicy `json:"items"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	return list.Items
}

func (a *authStore) crdPolicyByName(ctx context.Context, name string) (crdPolicy, bool) {
	var p crdPolicy
	rc := a.rawREST()
	if rc == nil {
		return p, false
	}
	raw, err := rc.Get().AbsPath(policiesAbsPath(a.ns) + "/" + name).DoRaw(ctx)
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return p, false
	}
	return p, p.Metadata.Name != ""
}

func (a *authStore) listCRDRoles(ctx context.Context) []crdRole {
	rc := a.rawREST()
	if rc == nil {
		return nil
	}
	raw, err := rc.Get().AbsPath(rolesAbsPath(a.ns)).DoRaw(ctx)
	if err != nil {
		return nil
	}
	var list struct {
		Items []crdRole `json:"items"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	return list.Items
}

func (a *authStore) crdRoleByName(ctx context.Context, name string) (crdRole, bool) {
	var r crdRole
	rc := a.rawREST()
	if rc == nil {
		return r, false
	}
	raw, err := rc.Get().AbsPath(rolesAbsPath(a.ns) + "/" + name).DoRaw(ctx)
	if err != nil || json.Unmarshal(raw, &r) != nil {
		return r, false
	}
	return r, r.Metadata.Name != ""
}

// ── Views ──────────────────────────────────────────────────────────────────────

type iamPolicyView struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Statements  []policyStatement `json:"statements"`
	// DataPlane/ControlPlane carry the Cedar blocks (Allow/Deny + conditions) so the visual/JSON
	// editor can read and write them. Omitted (pointer nil) for a policy that has neither, so the
	// existing control-plane-only shape is unchanged for old consumers.
	DataPlane    *cedarBlock `json:"dataPlane,omitempty"`
	ControlPlane *cedarBlock `json:"controlPlane,omitempty"`
	ClusterRole  string      `json:"clusterRole"`
	RuleCount    int         `json:"ruleCount"`
	Ready        bool        `json:"ready"`
	// Managed is true for an out-of-the-box managed policy (openinfra.dev/managed-policy: "true").
	// The console renders these read-only and the update/delete handlers refuse to mutate them —
	// they are provisioned by GitOps, never the console (the AWS "AWS managed" policy analog).
	Managed bool `json:"managed"`
	// Category is the managed-policy grouping (openinfra.dev/policy-category), e.g. "job-function".
	// Empty for a customer-managed policy or a managed one that sets no category.
	Category string `json:"category,omitempty"`
	// Tags are free-form key/value pairs (the AWS Tags tab), read from openinfra.dev/tag-*
	// annotations. Always a map (never null) so the SPA can iterate it. See iam_tags.go.
	Tags map[string]string `json:"tags"`
}

type iamRoleView struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Policies    []string `json:"policies"`
	// Trust is the AssumeRole trust policy (principal names, or "*"). Always an array (never null)
	// so the UI can render/edit it safely; empty means the role is assumable by no one (fail closed).
	Trust       []string `json:"trust"`
	ClusterRole string   `json:"clusterRole"`
	Ready       bool     `json:"ready"`
	// Tags are free-form key/value pairs (the AWS Tags tab), read from openinfra.dev/tag-*
	// annotations. Always a map (never null) so the SPA can iterate it. See iam_tags.go.
	Tags map[string]string `json:"tags"`
}

func policyView(p crdPolicy) iamPolicyView {
	return iamPolicyView{
		Name: p.Metadata.Name, Description: p.Spec.Description, Statements: p.Spec.Statements,
		DataPlane: p.Spec.DataPlane, ControlPlane: p.Spec.ControlPlane,
		ClusterRole: p.Status.ClusterRole, RuleCount: p.Status.RuleCount, Ready: p.Status.Ready,
		Managed:  isManagedPolicy(p.Metadata.Labels),
		Category: p.Metadata.Labels[policyCategoryLabel],
		Tags:     tagsFromAnnotations(p.Metadata.Annotations),
	}
}

func roleView(r crdRole) iamRoleView {
	return iamRoleView{
		Name: r.Metadata.Name, Description: r.Spec.Description, Policies: r.Spec.Policies,
		Trust:       groupList(r.Spec.Trust),
		ClusterRole: r.Status.ClusterRole, Ready: r.Status.Ready,
		Tags: tagsFromAnnotations(r.Metadata.Annotations),
	}
}

// ── Validation ───────────────────────────────────────────────────────────────────

// validateStatements returns a human error if any action is malformed or names a resource
// outside the boundary. Only effect Allow is accepted (Deny is a later, admission-time
// concern). Returns "" when valid.
func validateStatements(sts []policyStatement) string {
	if len(sts) == 0 {
		return "a policy needs at least one statement"
	}
	for _, s := range sts {
		if e := strings.TrimSpace(s.Effect); e != "" && !strings.EqualFold(e, "Allow") {
			return fmt.Sprintf("effect %q is not supported — only Allow (Deny is a future admission-time feature)", s.Effect)
		}
		if len(s.Actions) == 0 {
			return "every statement needs at least one action"
		}
		for _, act := range s.Actions {
			parts := strings.SplitN(strings.TrimSpace(act), ":", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return fmt.Sprintf("action %q must be <resource>:<verb>, e.g. virtualmachines:Get", act)
			}
			res, verb := parts[0], strings.ToLower(parts[1])
			if !isPolicyResource(res) {
				return fmt.Sprintf("%q names an unknown resource — a policy can only grant on openinfra.dev kinds (%s) or *",
					act, strings.Join(policyResources, ", "))
			}
			if !policyVerbs[verb] {
				return fmt.Sprintf("%q has an unknown verb — use Get/List/Watch/Create/Update/Patch/Delete or *", act)
			}
		}
	}
	return ""
}

// validateCedar checks a data-plane / control-plane Cedar block's shape without the RBAC boundary
// that applies to control-plane statements: it permits Deny and conditions (the whole point of
// Cedar), but still rejects a malformed effect, an empty action list, or a resource that is neither
// "*", a wildcard, nor "Type::id" (so a typo fails here with a clear message instead of at compile
// time in the engine). A nil block, or a block with no statements, is valid — a data-plane-only
// intent may be absent. plane is only used to prefix the message ("dataPlane"/"controlPlane").
func validateCedar(plane string, b *cedarBlock) string {
	if b == nil {
		return ""
	}
	for _, s := range b.Statements {
		eff := strings.TrimSpace(s.Effect)
		if eff == "" {
			return fmt.Sprintf("%s: every statement needs an effect (Allow or Deny)", plane)
		}
		if !strings.EqualFold(eff, "Allow") && !strings.EqualFold(eff, "Deny") {
			return fmt.Sprintf("%s: effect %q is not supported — use Allow or Deny", plane, s.Effect)
		}
		if len(nonEmpty(s.Actions)) == 0 {
			return fmt.Sprintf("%s: every statement needs at least one action", plane)
		}
		for _, res := range s.Resources {
			res = strings.TrimSpace(res)
			if res == "" || res == "*" || strings.Contains(res, "*") {
				continue
			}
			if !strings.Contains(res, "::") {
				return fmt.Sprintf("%s: resource %q must be Type::id (e.g. Bucket::assets), a wildcard, or *", plane, res)
			}
		}
	}
	return ""
}

// cedarHasStatements reports whether a block carries at least one statement — used to decide
// whether a policy has any rule at all (a data-plane-only policy has no control-plane statements).
func cedarHasStatements(b *cedarBlock) bool { return b != nil && len(b.Statements) > 0 }

// canonEffect canonicalises an effect string to exactly "Allow" or "Deny" (the engine's compile
// switch is case-sensitive, and the XRD enum is exactly those two). Anything not "Deny" is Allow.
func canonEffect(e string) string {
	if strings.EqualFold(strings.TrimSpace(e), "Deny") {
		return "Deny"
	}
	return "Allow"
}

// nonEmpty returns the input with blank entries trimmed out.
func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// normCedar canonicalises a Cedar block for the API server: effect to Allow/Deny, trimmed
// actions/resources, appliesTo cleaned. Always emits appliesTo + statements arrays so the stored
// shape is predictable and round-trips cleanly.
func normCedar(b *cedarBlock) map[string]any {
	stmts := make([]any, 0, len(b.Statements))
	for _, s := range b.Statements {
		sm := map[string]any{
			"effect":  canonEffect(s.Effect),
			"actions": nonEmpty(s.Actions),
		}
		if res := nonEmpty(s.Resources); len(res) > 0 {
			sm["resources"] = res
		}
		if len(s.Condition) > 0 {
			sm["condition"] = s.Condition
		}
		stmts = append(stmts, sm)
	}
	return map[string]any{
		"appliesTo":  nonEmpty(b.AppliesTo),
		"statements": stmts,
	}
}

// ── Policy handlers ────────────────────────────────────────────────────────────

func handleIAMPoliciesList(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "policies", auth.ns, "") {
			return
		}
		ps := auth.listCRDPolicies(r.Context())
		out := make([]iamPolicyView, 0, len(ps))
		for _, p := range ps {
			out = append(out, policyView(p))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func handleIAMPolicyGet(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "get", "iam.openinfra.dev", "policies", auth.ns, name) {
			return
		}
		p, ok := auth.crdPolicyByName(r.Context(), name)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such policy"})
			return
		}
		writeJSON(w, http.StatusOK, policyView(p))
	}
}

type policyReq struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Statements  []policyStatement `json:"statements"`
	// DataPlane/ControlPlane are optional Cedar blocks. A nil pointer means "not provided" — on
	// update the stored block is then left untouched (backward-compatible with the old client that
	// only knew about statements); send an empty block ({appliesTo:[],statements:[]}) to clear one.
	DataPlane    *cedarBlock `json:"dataPlane,omitempty"`
	ControlPlane *cedarBlock `json:"controlPlane,omitempty"`
}

// validatePolicyReq runs the shared validation for a create/update body: control-plane statements
// against the permission boundary (when present), Cedar blocks for shape, and the requirement that
// a policy carry at least one rule somewhere. Returns "" when valid.
func validatePolicyReq(in policyReq) string {
	if len(in.Statements) > 0 {
		if msg := validateStatements(in.Statements); msg != "" {
			return msg
		}
	}
	if msg := validateCedar("dataPlane", in.DataPlane); msg != "" {
		return msg
	}
	if msg := validateCedar("controlPlane", in.ControlPlane); msg != "" {
		return msg
	}
	if len(in.Statements) == 0 && !cedarHasStatements(in.DataPlane) && !cedarHasStatements(in.ControlPlane) {
		return "a policy needs at least one statement (or a data-plane/control-plane rule)"
	}
	return ""
}

func handleIAMPolicyCreate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in policyReq
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if !validName(in.Name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be a lowercase DNS label (a-z, 0-9, -)"})
			return
		}
		if msg := validatePolicyReq(in); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if !authorize(w, r, cs, auth, logger, "create", "iam.openinfra.dev", "policies", auth.ns, in.Name) {
			return
		}
		spec := map[string]any{"description": in.Description, "statements": normStatements(in.Statements)}
		if in.DataPlane != nil {
			spec["dataPlane"] = normCedar(in.DataPlane)
		}
		if in.ControlPlane != nil {
			spec["controlPlane"] = normCedar(in.ControlPlane)
		}
		body := map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Policy",
			"metadata":   map[string]any{"name": in.Name, "namespace": auth.ns},
			"spec":       spec,
		}
		if err := auth.postCR(r.Context(), policiesAbsPath(auth.ns), body); err != nil {
			logger.Error("iam: create policy", "policy", in.Name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: policy created", "policy", in.Name, "by", subjectOf(r))
		writeJSON(w, http.StatusCreated, map[string]string{"name": in.Name})
	}
}

func handleIAMPolicyUpdate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var in policyReq
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if msg := validatePolicyReq(in); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if !authorize(w, r, cs, auth, logger, "update", "iam.openinfra.dev", "policies", auth.ns, name) {
			return
		}
		// Managed policies are provisioned out of the box by GitOps — read-only from the console.
		// Refuse the mutation even for an admin, so the library stays the single source of truth.
		if p, ok := auth.crdPolicyByName(r.Context(), name); ok && isManagedPolicy(p.Metadata.Labels) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": managedReadOnlyMsg})
			return
		}
		spec := map[string]any{"description": in.Description, "statements": normStatements(in.Statements)}
		// Only touch a Cedar plane when the request carries it (pointer non-nil): a client that
		// doesn't know about dataPlane leaves an existing block intact; sending an empty block
		// clears one.
		if in.DataPlane != nil {
			spec["dataPlane"] = normCedar(in.DataPlane)
		}
		if in.ControlPlane != nil {
			spec["controlPlane"] = normCedar(in.ControlPlane)
		}
		patch := map[string]any{"spec": spec}
		if err := auth.patchCR(r.Context(), policiesAbsPath(auth.ns)+"/"+name, patch); err != nil {
			logger.Error("iam: update policy", "policy", name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: policy updated", "policy", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

func handleIAMPolicyDelete(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "delete", "iam.openinfra.dev", "policies", auth.ns, name) {
			return
		}
		// Managed policies are owned by GitOps — the console never deletes them.
		if p, ok := auth.crdPolicyByName(r.Context(), name); ok && isManagedPolicy(p.Metadata.Labels) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": managedReadOnlyMsg})
			return
		}
		// A policy still attached to a role would leave that role silently thinner. Warn.
		if in := rolesUsingPolicy(auth.listCRDRoles(r.Context()), name); len(in) > 0 && r.URL.Query().Get("force") != "true" {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": fmt.Sprintf("%d role(s) still attach this policy", len(in)), "roles": in,
			})
			return
		}
		if err := auth.deleteCR(r.Context(), policiesAbsPath(auth.ns)+"/"+name); err != nil {
			logger.Error("iam: delete policy", "policy", name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: policy deleted", "policy", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

// ── Role handlers ──────────────────────────────────────────────────────────────

func handleIAMRolesList(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "roles", auth.ns, "") {
			return
		}
		rs := auth.listCRDRoles(r.Context())
		out := make([]iamRoleView, 0, len(rs))
		for _, x := range rs {
			out = append(out, roleView(x))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func handleIAMRoleGet(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "get", "iam.openinfra.dev", "roles", auth.ns, name) {
			return
		}
		x, ok := auth.crdRoleByName(r.Context(), name)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such role"})
			return
		}
		writeJSON(w, http.StatusOK, roleView(x))
	}
}

type roleReq struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Policies    []string `json:"policies"`
	// Trust is the AssumeRole trust policy (kind: User names, or "*"). On update it is applied only
	// when present in the request body (a non-nil slice — an explicit [] clears it, an absent key
	// leaves the stored trust untouched, so an old client that doesn't send trust cannot wipe it).
	Trust []string `json:"trust"`
}

func handleIAMRoleCreate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in roleReq
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if !validName(in.Name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be a lowercase DNS label (a-z, 0-9, -)"})
			return
		}
		if !authorize(w, r, cs, auth, logger, "create", "iam.openinfra.dev", "roles", auth.ns, in.Name) {
			return
		}
		body := map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Role",
			"metadata":   map[string]any{"name": in.Name, "namespace": auth.ns},
			"spec": map[string]any{
				"description": in.Description,
				"policies":    cleanGroups(in.Policies),
				// nil trust normalises to [] — a role starts assumable by no one (fail closed),
				// exactly as an AWS role needs an explicit trust policy.
				"trust": cleanGroups(in.Trust),
			},
		}
		if err := auth.postCR(r.Context(), rolesAbsPath(auth.ns), body); err != nil {
			logger.Error("iam: create role", "role", in.Name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: role created", "role", in.Name, "by", subjectOf(r))
		writeJSON(w, http.StatusCreated, map[string]string{"name": in.Name})
	}
}

func handleIAMRoleUpdate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var in roleReq
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if !authorize(w, r, cs, auth, logger, "update", "iam.openinfra.dev", "roles", auth.ns, name) {
			return
		}
		spec := map[string]any{"description": in.Description, "policies": cleanGroups(in.Policies)}
		// Apply trust only when the request carries it, so an old client (which never sends trust)
		// leaves the stored trust policy intact rather than silently clearing it.
		if in.Trust != nil {
			spec["trust"] = cleanGroups(in.Trust)
		}
		patch := map[string]any{"spec": spec}
		if err := auth.patchCR(r.Context(), rolesAbsPath(auth.ns)+"/"+name, patch); err != nil {
			logger.Error("iam: update role", "role", name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: role updated", "role", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

func handleIAMRoleDelete(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "delete", "iam.openinfra.dev", "roles", auth.ns, name) {
			return
		}
		// A group bound to this role's ClusterRole would be left granting nothing. Warn.
		crName := "openinfra-role-" + name
		if in := groupsUsingClusterRole(auth.listCRDGroups(r.Context()), crName); len(in) > 0 && r.URL.Query().Get("force") != "true" {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": fmt.Sprintf("%d group(s) use this role", len(in)), "groups": in,
			})
			return
		}
		if err := auth.deleteCR(r.Context(), rolesAbsPath(auth.ns)+"/"+name); err != nil {
			logger.Error("iam: delete role", "role", name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: role deleted", "role", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────────

// normStatements canonicalises what we send to the API server: default effect to Allow,
// trim, and default resources to ["*"] (RBAC can't scope list/watch by name today).
func normStatements(sts []policyStatement) []any {
	out := make([]any, 0, len(sts))
	for _, s := range sts {
		eff := strings.TrimSpace(s.Effect)
		if eff == "" {
			eff = "Allow"
		}
		acts := make([]string, 0, len(s.Actions))
		for _, a := range s.Actions {
			if a = strings.TrimSpace(a); a != "" {
				acts = append(acts, a)
			}
		}
		res := s.Resources
		if len(res) == 0 {
			res = []string{"*"}
		}
		out = append(out, map[string]any{"effect": eff, "actions": acts, "resources": res})
	}
	return out
}

func rolesUsingPolicy(roles []crdRole, policy string) []string {
	var out []string
	for _, r := range roles {
		for _, p := range r.Spec.Policies {
			if strings.TrimSpace(p) == policy {
				out = append(out, r.Metadata.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func groupsUsingClusterRole(groups []crdGroup, clusterRole string) []string {
	var out []string
	for _, g := range groups {
		if g.Spec.ClusterRole == clusterRole {
			out = append(out, g.Metadata.Name)
		}
	}
	sort.Strings(out)
	return out
}
