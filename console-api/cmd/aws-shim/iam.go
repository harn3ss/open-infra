// IAM management front door for the aws-shim (polyhedron#168 / #174, Branch A) — the AWS IAM management
// verbs (roles, policies, users, access keys) over the platform's existing entities, with a faithful AWS
// IAM policy JSON → Cedar translation as the core.
//
// Speaks the AWS QUERY protocol (form-encoded request, XML response) — IAM has not migrated to JSON.
//
// ONE policy world, no second engine: a CreatePolicy translates the AWS PolicyDocument through
// policyengine.ImportAWS into the SAME Cedar Statement type the data plane already enforces, stored on a
// kind: Policy's spec.dataPlane. A role assumed via the STS doorway is then authorized by those translated
// policies in CLOSED/default-deny mode (internal/dataplaneauthz + internal/iam): the role's authority is
// EXACTLY its attached policies. That is why the probe must prove BOTH directions — a confused-deputy
// implementation would pass the allow assertion and fail the deny assertions.
//
// Translation fidelity guardrails: ImportAWS reports (never silently drops) anything it can't honor, and
// this handler REFUSES a policy with any unsupported part (MalformedPolicyDocument) rather than storing a
// policy that grants more or less than the JSON says. NotAction/NotResource — which ImportAWS drops
// silently — are rejected explicitly here.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const iamXMLNamespace = "https://iam.amazonaws.com/doc/2010-05-08/"

var (
	gvrPolicies = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "policies"}
	gvrRoles    = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "roles"}
	gvrUsers    = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "users"}
)

const maxKeysPerUser = 2

type iamHandler struct {
	cs      kubernetes.Interface
	dyn     dynamic.Interface
	keys    *awskeys.Store
	authz   *dataplaneauthz.Checker
	usersNS string // where kind: User/Role/Policy live
	account string
	region  string
	logger  *slog.Logger
}

func newIAMHandler(cs kubernetes.Interface, dyn dynamic.Interface, keys *awskeys.Store, authz *dataplaneauthz.Checker, usersNS, account, region string, logger *slog.Logger) *iamHandler {
	return &iamHandler{cs: cs, dyn: dyn, keys: keys, authz: authz, usersNS: usersNS, account: account, region: region, logger: logger}
}

func (h *iamHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", iamXMLNamespace)
}

// verbForIAMOp maps an IAM op to its coarse RBAC verb + the CRD resource it authorizes against, so IAM
// management is gated by the caller's existing k8s RBAC on the iam.openinfra.dev CRDs (no new authz surface).
func verbForIAMOp(op string) (verb, resource string, ok bool) {
	switch op {
	case "CreateRole", "PutRolePolicy", "AttachRolePolicy", "DetachRolePolicy":
		return "create", "roles", true
	case "GetRole", "ListRoles", "ListAttachedRolePolicies", "ListRolePolicies", "GetRolePolicy":
		return "get", "roles", true
	case "DeleteRole", "DeleteRolePolicy":
		return "delete", "roles", true
	case "CreatePolicy", "CreatePolicyVersion":
		return "create", "policies", true
	case "GetPolicy", "ListPolicies", "SimulatePrincipalPolicy", "GetPolicyVersion", "ListPolicyVersions":
		return "get", "policies", true
	case "DeletePolicy":
		return "delete", "policies", true
	case "CreateUser", "CreateAccessKey", "UpdateAccessKey", "TagUser":
		return "create", "users", true
	case "GetUser", "ListUsers", "ListAccessKeys":
		return "get", "users", true
	case "DeleteUser", "DeleteAccessKey":
		return "delete", "users", true
	}
	return "", "", false
}

func (h *iamHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := r.PostFormValue("Action")
	if op == "" {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID, "no Action in the request.", iamXMLNamespace)
		return
	}
	verb, resource, known := verbForIAMOp(op)
	if !known {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID, "IAM "+op+" is not implemented by the open-infra shim.", iamXMLNamespace)
		return
	}
	if h.dyn == nil {
		writeQueryError(w, http.StatusInternalServerError, "ServiceFailure", requestID, "the IAM control plane is not configured on this shim (no dynamic client).", iamXMLNamespace)
		return
	}
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// Coarse authz: the caller must hold k8s RBAC on the iam.openinfra.dev CRD (impersonated SAR). IAM
	// management is admin-level; this ties it to the same RBAC the console's IAM pages use.
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "iam.openinfra.dev", resource, h.usersNS, ""); !allowed {
		h.audit(ctx, op, "", "deny", reason)
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, iamXMLNamespace)
		return
	}

	switch op {
	case "CreateRole":
		h.createRole(ctx, w, r, requestID)
	case "GetRole":
		h.getRole(ctx, w, r, requestID)
	case "DeleteRole":
		h.deleteRole(ctx, w, r, requestID)
	case "ListRoles":
		h.listRoles(ctx, w, requestID)
	case "CreatePolicy":
		h.createPolicy(ctx, w, r, requestID)
	case "GetPolicy":
		h.getPolicy(ctx, w, r, requestID)
	case "DeletePolicy":
		h.deletePolicy(ctx, w, r, requestID)
	case "ListPolicies":
		h.listPolicies(ctx, w, requestID)
	case "AttachRolePolicy":
		h.attachRolePolicy(ctx, w, r, requestID, true)
	case "DetachRolePolicy":
		h.attachRolePolicy(ctx, w, r, requestID, false)
	case "ListAttachedRolePolicies":
		h.listAttachedRolePolicies(ctx, w, r, requestID)
	case "PutRolePolicy":
		h.putRolePolicy(ctx, w, r, requestID)
	case "CreateUser":
		h.createUser(ctx, w, r, requestID)
	case "GetUser":
		h.getUser(ctx, w, r, requestID)
	case "DeleteUser":
		h.deleteUser(ctx, w, r, requestID)
	case "ListUsers":
		h.listUsers(ctx, w, requestID)
	case "CreateAccessKey":
		h.createAccessKey(ctx, w, r, requestID)
	case "DeleteAccessKey":
		h.deleteAccessKey(ctx, w, r, requestID)
	case "ListAccessKeys":
		h.listAccessKeys(ctx, w, r, requestID)
	case "UpdateAccessKey":
		h.updateAccessKey(ctx, w, r, requestID)
	case "SimulatePrincipalPolicy":
		h.simulatePrincipalPolicy(ctx, w, r, requestID)
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID, "IAM "+op+" is recognized but not implemented.", iamXMLNamespace)
	}
}

// --- roles ---

func (h *iamHandler) createRole(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := r.PostFormValue("RoleName")
	if name == "" {
		h.malformed(w, requestID, "CreateRole requires RoleName.")
		return
	}
	trust, err := parseTrustPolicy(r.PostFormValue("AssumeRolePolicyDocument"))
	if err != nil {
		h.malformed(w, requestID, "AssumeRolePolicyDocument: "+err.Error())
		return
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "Role",
		"metadata":   map[string]any{"name": name, "namespace": h.usersNS},
		"spec":       map[string]any{"description": r.PostFormValue("Description"), "trust": toAny(trust), "policies": []any{}},
	}}
	if _, err := h.dyn.Resource(gvrRoles).Namespace(h.usersNS).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if isAlreadyExists(err) {
			h.conflict(w, requestID, "EntityAlreadyExists", "Role with name "+name+" already exists.")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateRole", name, "allow", "")
	h.writeResult(w, requestID, "CreateRole", "<Role>"+h.roleXML(name, r.PostFormValue("AssumeRolePolicyDocument"))+"</Role>")
}

func (h *iamHandler) getRole(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := r.PostFormValue("RoleName")
	u, err := h.dyn.Resource(gvrRoles).Namespace(h.usersNS).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		h.noSuchEntity(w, requestID, "Role "+name+" not found.")
		return
	}
	_ = u
	h.writeResult(w, requestID, "GetRole", "<Role>"+h.roleXML(name, "")+"</Role>")
}

func (h *iamHandler) deleteRole(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := r.PostFormValue("RoleName")
	if err := h.dyn.Resource(gvrRoles).Namespace(h.usersNS).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "Role "+name+" not found.")
		return
	}
	h.audit(ctx, "DeleteRole", name, "allow", "")
	h.writeResult(w, requestID, "DeleteRole", "")
}

func (h *iamHandler) listRoles(ctx context.Context, w http.ResponseWriter, requestID string) {
	list, err := h.dyn.Resource(gvrRoles).Namespace(h.usersNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<Roles>")
	for _, it := range list.Items {
		b.WriteString("<member>" + h.roleXML(it.GetName(), "") + "</member>")
	}
	b.WriteString("</Roles><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListRoles", b.String())
}

// --- policies ---

func (h *iamHandler) createPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := r.PostFormValue("PolicyName")
	doc := r.PostFormValue("PolicyDocument")
	if name == "" || doc == "" {
		h.malformed(w, requestID, "CreatePolicy requires PolicyName and PolicyDocument.")
		return
	}
	stmts, spec, ok := h.translateOrRefuse(w, requestID, doc, nil)
	if !ok {
		return
	}
	_ = stmts
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "Policy",
		"metadata":   map[string]any{"name": name, "namespace": h.usersNS},
		"spec": map[string]any{
			"description": r.PostFormValue("Description"),
			"statements":  []any{}, // control-plane statements: none (this is a data-plane identity policy)
			"dataPlane":   map[string]any{"appliesTo": []any{}, "statements": spec},
		},
	}}
	if _, err := h.dyn.Resource(gvrPolicies).Namespace(h.usersNS).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if isAlreadyExists(err) {
			h.conflict(w, requestID, "EntityAlreadyExists", "Policy "+name+" already exists.")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreatePolicy", name, "allow", "")
	h.writeResult(w, requestID, "CreatePolicy", "<Policy>"+h.policyXML(name)+"</Policy>")
}

func (h *iamHandler) getPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := policyNameFromArn(r.PostFormValue("PolicyArn"))
	if _, err := h.dyn.Resource(gvrPolicies).Namespace(h.usersNS).Get(ctx, name, metav1.GetOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "Policy "+name+" not found.")
		return
	}
	h.writeResult(w, requestID, "GetPolicy", "<Policy>"+h.policyXML(name)+"</Policy>")
}

func (h *iamHandler) deletePolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := policyNameFromArn(r.PostFormValue("PolicyArn"))
	if err := h.dyn.Resource(gvrPolicies).Namespace(h.usersNS).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "Policy "+name+" not found.")
		return
	}
	h.audit(ctx, "DeletePolicy", name, "allow", "")
	h.writeResult(w, requestID, "DeletePolicy", "")
}

func (h *iamHandler) listPolicies(ctx context.Context, w http.ResponseWriter, requestID string) {
	list, err := h.dyn.Resource(gvrPolicies).Namespace(h.usersNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<Policies>")
	for _, it := range list.Items {
		b.WriteString("<member>" + h.policyXML(it.GetName()) + "</member>")
	}
	b.WriteString("</Policies><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListPolicies", b.String())
}

// --- attachment ---

func (h *iamHandler) attachRolePolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, attach bool) {
	role := r.PostFormValue("RoleName")
	pol := policyNameFromArn(r.PostFormValue("PolicyArn"))
	if role == "" || pol == "" {
		h.malformed(w, requestID, "requires RoleName and PolicyArn.")
		return
	}
	// get→modify→update, retried on the optimistic-concurrency conflict (concurrent attach/detach on the
	// same role race on spec.policies).
	var updErr error
	for attempt := 0; attempt < 4; attempt++ {
		u, err := h.dyn.Resource(gvrRoles).Namespace(h.usersNS).Get(ctx, role, metav1.GetOptions{})
		if err != nil {
			h.noSuchEntity(w, requestID, "Role "+role+" not found.")
			return
		}
		cur, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "policies")
		next := cur[:0:0]
		next = append(next, cur...)
		if attach {
			if !containsStr(next, pol) {
				next = append(next, pol)
			}
		} else {
			out := next[:0]
			for _, p := range next {
				if p != pol {
					out = append(out, p)
				}
			}
			next = out
		}
		_ = unstructured.SetNestedStringSlice(u.Object, next, "spec", "policies")
		if _, updErr = h.dyn.Resource(gvrRoles).Namespace(h.usersNS).Update(ctx, u, metav1.UpdateOptions{}); updErr == nil {
			break
		}
		if !apierrors.IsConflict(updErr) {
			break
		}
	}
	if updErr != nil {
		h.internal(w, requestID, updErr)
		return
	}
	action := "AttachRolePolicy"
	if !attach {
		action = "DetachRolePolicy"
	}
	h.audit(ctx, action, role, "allow", "policy="+pol)
	h.writeResult(w, requestID, action, "")
}

func (h *iamHandler) listAttachedRolePolicies(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	role := r.PostFormValue("RoleName")
	u, err := h.dyn.Resource(gvrRoles).Namespace(h.usersNS).Get(ctx, role, metav1.GetOptions{})
	if err != nil {
		h.noSuchEntity(w, requestID, "Role "+role+" not found.")
		return
	}
	pols, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "policies")
	var b strings.Builder
	b.WriteString("<AttachedPolicies>")
	for _, p := range pols {
		b.WriteString("<member><PolicyName>" + xmlEscape(p) + "</PolicyName><PolicyArn>" + xmlEscape(h.policyArn(p)) + "</PolicyArn></member>")
	}
	b.WriteString("</AttachedPolicies><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListAttachedRolePolicies", b.String())
}

func (h *iamHandler) putRolePolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	role := r.PostFormValue("RoleName")
	polName := r.PostFormValue("PolicyName")
	doc := r.PostFormValue("PolicyDocument")
	if role == "" || polName == "" || doc == "" {
		h.malformed(w, requestID, "PutRolePolicy requires RoleName, PolicyName and PolicyDocument.")
		return
	}
	if _, err := h.dyn.Resource(gvrRoles).Namespace(h.usersNS).Get(ctx, role, metav1.GetOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "Role "+role+" not found.")
		return
	}
	_, spec, ok := h.translateOrRefuse(w, requestID, doc, nil)
	if !ok {
		return
	}
	// An inline role policy is a Policy whose dataPlane appliesTo the role directly.
	inlineName := "role-" + role + "-" + polName
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "Policy",
		"metadata":   map[string]any{"name": inlineName, "namespace": h.usersNS},
		"spec": map[string]any{
			"description": "inline policy for role " + role,
			"statements":  []any{},
			"dataPlane":   map[string]any{"appliesTo": []any{"Role::" + role}, "statements": spec},
		},
	}}
	_, err := h.dyn.Resource(gvrPolicies).Namespace(h.usersNS).Create(ctx, obj, metav1.CreateOptions{})
	if isAlreadyExists(err) {
		// update in place
		existing, gerr := h.dyn.Resource(gvrPolicies).Namespace(h.usersNS).Get(ctx, inlineName, metav1.GetOptions{})
		if gerr == nil {
			_ = unstructured.SetNestedField(existing.Object, map[string]any{"appliesTo": []any{"Role::" + role}, "statements": spec}, "spec", "dataPlane")
			_, err = h.dyn.Resource(gvrPolicies).Namespace(h.usersNS).Update(ctx, existing, metav1.UpdateOptions{})
		} else {
			err = gerr
		}
	}
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "PutRolePolicy", role, "allow", "policy="+polName)
	h.writeResult(w, requestID, "PutRolePolicy", "")
}

// --- users ---

func (h *iamHandler) createUser(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := r.PostFormValue("UserName")
	if name == "" {
		h.malformed(w, requestID, "CreateUser requires UserName.")
		return
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "User",
		"metadata":   map[string]any{"name": name, "namespace": h.usersNS},
		"spec":       map[string]any{"displayName": name, "source": "local", "groups": []any{}},
	}}
	if _, err := h.dyn.Resource(gvrUsers).Namespace(h.usersNS).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if isAlreadyExists(err) {
			h.conflict(w, requestID, "EntityAlreadyExists", "User "+name+" already exists.")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateUser", name, "allow", "")
	h.writeResult(w, requestID, "CreateUser", "<User>"+h.userXML(name)+"</User>")
}

func (h *iamHandler) getUser(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := r.PostFormValue("UserName")
	if _, err := h.dyn.Resource(gvrUsers).Namespace(h.usersNS).Get(ctx, name, metav1.GetOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "User "+name+" not found.")
		return
	}
	h.writeResult(w, requestID, "GetUser", "<User>"+h.userXML(name)+"</User>")
}

func (h *iamHandler) deleteUser(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	name := r.PostFormValue("UserName")
	if err := h.dyn.Resource(gvrUsers).Namespace(h.usersNS).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "User "+name+" not found.")
		return
	}
	h.audit(ctx, "DeleteUser", name, "allow", "")
	h.writeResult(w, requestID, "DeleteUser", "")
}

func (h *iamHandler) listUsers(ctx context.Context, w http.ResponseWriter, requestID string) {
	list, err := h.dyn.Resource(gvrUsers).Namespace(h.usersNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<Users>")
	for _, it := range list.Items {
		b.WriteString("<member>" + h.userXML(it.GetName()) + "</member>")
	}
	b.WriteString("</Users><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListUsers", b.String())
}

// --- access keys (reuse the shared awskeys.Store — the key genuinely authenticates through the shim) ---

func (h *iamHandler) createAccessKey(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	user := r.PostFormValue("UserName")
	if user == "" {
		h.malformed(w, requestID, "CreateAccessKey requires UserName.")
		return
	}
	if h.keys == nil {
		writeQueryError(w, http.StatusInternalServerError, "ServiceFailure", requestID, "access-key store not configured.", iamXMLNamespace)
		return
	}
	if _, err := h.dyn.Resource(gvrUsers).Namespace(h.usersNS).Get(ctx, user, metav1.GetOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "User "+user+" not found.")
		return
	}
	if existing, err := h.keys.List(ctx, user); err == nil && len(existing) >= maxKeysPerUser {
		h.conflict(w, requestID, "LimitExceeded", "Cannot exceed quota of "+itoa(maxKeysPerUser)+" access keys for user "+user+".")
		return
	}
	id, secret, err := awskeys.GenerateKeyPair()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if err := h.keys.Put(ctx, awskeys.Key{AccessKeyID: id, SecretKey: secret, Owner: user}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateAccessKey", user, "allow", "accessKeyId="+id)
	body := "<AccessKey><UserName>" + xmlEscape(user) + "</UserName><AccessKeyId>" + xmlEscape(id) +
		"</AccessKeyId><Status>Active</Status><SecretAccessKey>" + xmlEscape(secret) +
		"</SecretAccessKey><CreateDate>" + time.Now().UTC().Format(time.RFC3339) + "</CreateDate></AccessKey>"
	h.writeResult(w, requestID, "CreateAccessKey", body)
}

func (h *iamHandler) listAccessKeys(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	user := r.PostFormValue("UserName")
	metas, err := h.keys.List(ctx, user)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<AccessKeyMetadata>")
	for _, m := range metas {
		status := "Active"
		if m.Disabled {
			status = "Inactive"
		}
		b.WriteString("<member><UserName>" + xmlEscape(user) + "</UserName><AccessKeyId>" + xmlEscape(m.AccessKeyID) +
			"</AccessKeyId><Status>" + status + "</Status></member>")
	}
	b.WriteString("</AccessKeyMetadata><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListAccessKeys", b.String())
}

func (h *iamHandler) deleteAccessKey(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("AccessKeyId")
	if err := h.keys.Delete(ctx, id); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteAccessKey", r.PostFormValue("UserName"), "allow", "accessKeyId="+id)
	h.writeResult(w, requestID, "DeleteAccessKey", "")
}

func (h *iamHandler) updateAccessKey(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("AccessKeyId")
	status := r.PostFormValue("Status")
	var err error
	switch status {
	case "Inactive":
		err = h.keys.Revoke(ctx, id)
	case "Active":
		err = h.keys.Activate(ctx, id)
	default:
		h.malformed(w, requestID, "Status must be Active or Inactive.")
		return
	}
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeResult(w, requestID, "UpdateAccessKey", "")
}

// --- SimulatePrincipalPolicy (the honest self-check: run the Cedar query the data plane uses) ---

func (h *iamHandler) simulatePrincipalPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	src := r.PostFormValue("PolicySourceArn")
	pType, pID := principalFromArn(src)
	if pID == "" {
		h.malformed(w, requestID, "SimulatePrincipalPolicy requires a PolicySourceArn (a role or user ARN).")
		return
	}
	actions := queryList(r, "ActionNames")
	resources := queryList(r, "ResourceArns")
	if len(resources) == 0 {
		resources = []string{"*"}
	}
	if h.authz == nil {
		writeQueryError(w, http.StatusInternalServerError, "ServiceFailure", requestID, "data-plane authz not configured.", iamXMLNamespace)
		return
	}
	var b strings.Builder
	b.WriteString("<EvaluationResults>")
	for _, action := range actions {
		for _, res := range resources {
			rt, rid := arnToResourceShim(res)
			allowed, _, reason := h.authz.Authorize(ctx, pType, pID, nil, action, rt, rid, map[string]any{"authenticated": true})
			decision := "implicitDeny"
			if allowed {
				decision = "allowed"
			} else if strings.Contains(reason, "explicit") {
				decision = "explicitDeny"
			}
			b.WriteString("<member><EvalActionName>" + xmlEscape(action) + "</EvalActionName><EvalResourceName>" +
				xmlEscape(res) + "</EvalResourceName><EvalDecision>" + decision + "</EvalDecision></member>")
		}
	}
	b.WriteString("</EvaluationResults><IsTruncated>false</IsTruncated>")
	h.audit(ctx, "SimulatePrincipalPolicy", pID, "allow", "")
	h.writeResult(w, requestID, "SimulatePrincipalPolicy", b.String())
}

// --- translation ---

// translateOrRefuse parses an AWS PolicyDocument, rejects NotAction/NotResource explicitly, translates via
// policyengine.ImportAWS, and REFUSES (writes MalformedPolicyDocument, returns ok=false) on any error or any
// unsupported part — never storing a policy that grants more or less than the JSON says.
func (h *iamHandler) translateOrRefuse(w http.ResponseWriter, requestID, doc string, _ any) ([]policyengine.Statement, []any, bool) {
	if hasNotActionOrResource(doc) {
		h.malformed(w, requestID, "NotAction/NotResource are not supported by the open-infra IAM translator (they would silently change the grant); rewrite with Action/Resource.")
		return nil, nil, false
	}
	stmts, unsupported, err := policyengine.ImportAWS(doc)
	if err != nil {
		h.malformed(w, requestID, "PolicyDocument: "+err.Error())
		return nil, nil, false
	}
	if len(unsupported) > 0 {
		h.malformed(w, requestID, "PolicyDocument has parts the data plane cannot honor faithfully (refused rather than silently narrowed/widened): "+strings.Join(unsupported, "; "))
		return nil, nil, false
	}
	if len(stmts) == 0 {
		h.malformed(w, requestID, "PolicyDocument has no statements the data plane can honor.")
		return nil, nil, false
	}
	return stmts, statementsToSpecAny(stmts), true
}

// --- XML fragment builders ---

func (h *iamHandler) roleXML(name, assumeDoc string) string {
	s := "<RoleName>" + xmlEscape(name) + "</RoleName><RoleId>" + roleID(name) + "</RoleId><Arn>" + xmlEscape(h.roleArn(name)) +
		"</Arn><Path>/</Path><CreateDate>" + time.Now().UTC().Format(time.RFC3339) + "</CreateDate>"
	if assumeDoc != "" {
		s += "<AssumeRolePolicyDocument>" + xmlEscape(assumeDoc) + "</AssumeRolePolicyDocument>"
	}
	return s
}

func (h *iamHandler) policyXML(name string) string {
	return "<PolicyName>" + xmlEscape(name) + "</PolicyName><PolicyId>" + roleID(name) + "</PolicyId><Arn>" + xmlEscape(h.policyArn(name)) +
		"</Arn><Path>/</Path><DefaultVersionId>v1</DefaultVersionId><AttachmentCount>0</AttachmentCount><CreateDate>" +
		time.Now().UTC().Format(time.RFC3339) + "</CreateDate>"
}

func (h *iamHandler) userXML(name string) string {
	return "<UserName>" + xmlEscape(name) + "</UserName><UserId>" + roleID(name) + "</UserId><Arn>" + xmlEscape(h.userArn(name)) +
		"</Arn><Path>/</Path><CreateDate>" + time.Now().UTC().Format(time.RFC3339) + "</CreateDate>"
}

func (h *iamHandler) roleArn(n string) string   { return "arn:aws:iam::" + h.account + ":role/" + n }
func (h *iamHandler) policyArn(n string) string { return "arn:aws:iam::" + h.account + ":policy/" + n }
func (h *iamHandler) userArn(n string) string   { return "arn:aws:iam::" + h.account + ":user/" + n }

// --- response + error helpers (query protocol XML) ---

func (h *iamHandler) writeResult(w http.ResponseWriter, requestID, action, resultBody string) {
	var b strings.Builder
	b.WriteString(xmlHeader)
	b.WriteString(`<` + action + `Response xmlns="` + iamXMLNamespace + `">`)
	if resultBody != "" {
		b.WriteString(`<` + action + `Result>` + resultBody + `</` + action + `Result>`)
	}
	b.WriteString(`<ResponseMetadata><RequestId>` + xmlEscape(requestID) + `</RequestId></ResponseMetadata>`)
	b.WriteString(`</` + action + `Response>`)
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (h *iamHandler) malformed(w http.ResponseWriter, requestID, msg string) {
	writeQueryError(w, http.StatusBadRequest, "MalformedPolicyDocument", requestID, msg, iamXMLNamespace)
}

func (h *iamHandler) noSuchEntity(w http.ResponseWriter, requestID, msg string) {
	writeQueryError(w, http.StatusNotFound, "NoSuchEntity", requestID, msg, iamXMLNamespace)
}

func (h *iamHandler) conflict(w http.ResponseWriter, requestID, code, msg string) {
	writeQueryError(w, http.StatusConflict, code, requestID, msg, iamXMLNamespace)
}

func (h *iamHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("iam backend error", "error", err.Error())
	writeQueryError(w, http.StatusInternalServerError, "ServiceFailure", requestID, "An error occurred on the server side.", iamXMLNamespace)
}

func (h *iamHandler) audit(ctx context.Context, op, entity, decision, extra string) {
	args := []any{"service", "iam", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if entity != "" {
		args = append(args, "entity", entity)
	}
	if extra != "" {
		args = append(args, "detail", extra)
	}
	h.logger.InfoContext(ctx, "iam audit", args...)
}
