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
// SubjectAccessReview against iam.openinfra.dev before acting (see authorize()), so it is
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
	"securitygroups", "faultinjections", "queries",
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

// ── CR types (read side) ─────────────────────────────────────────────────────────

type policyStatement struct {
	Effect    string   `json:"effect,omitempty"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources,omitempty"`
}

type crdPolicy struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Description string            `json:"description"`
		Statements  []policyStatement `json:"statements"`
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
	} `json:"metadata"`
	Spec struct {
		Description string   `json:"description"`
		Policies    []string `json:"policies"`
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
	ClusterRole string            `json:"clusterRole"`
	RuleCount   int               `json:"ruleCount"`
	Ready       bool              `json:"ready"`
}

type iamRoleView struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Policies    []string `json:"policies"`
	ClusterRole string   `json:"clusterRole"`
	Ready       bool     `json:"ready"`
}

func policyView(p crdPolicy) iamPolicyView {
	return iamPolicyView{
		Name: p.Metadata.Name, Description: p.Spec.Description, Statements: p.Spec.Statements,
		ClusterRole: p.Status.ClusterRole, RuleCount: p.Status.RuleCount, Ready: p.Status.Ready,
	}
}

func roleView(r crdRole) iamRoleView {
	return iamRoleView{
		Name: r.Metadata.Name, Description: r.Spec.Description, Policies: r.Spec.Policies,
		ClusterRole: r.Status.ClusterRole, Ready: r.Status.Ready,
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
		if msg := validateStatements(in.Statements); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if !authorize(w, r, cs, auth, logger, "create", "iam.openinfra.dev", "policies", auth.ns, in.Name) {
			return
		}
		body := map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Policy",
			"metadata":   map[string]any{"name": in.Name, "namespace": auth.ns},
			"spec":       map[string]any{"description": in.Description, "statements": normStatements(in.Statements)},
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
		if msg := validateStatements(in.Statements); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if !authorize(w, r, cs, auth, logger, "update", "iam.openinfra.dev", "policies", auth.ns, name) {
			return
		}
		patch := map[string]any{"spec": map[string]any{
			"description": in.Description, "statements": normStatements(in.Statements),
		}}
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
			"spec":       map[string]any{"description": in.Description, "policies": cleanGroups(in.Policies)},
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
		patch := map[string]any{"spec": map[string]any{
			"description": in.Description, "policies": cleanGroups(in.Policies),
		}}
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
