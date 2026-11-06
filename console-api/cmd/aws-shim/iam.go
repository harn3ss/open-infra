// IAM management front door for the aws-shim — the AWS IAM management verbs (users, groups, roles,
// managed and inline policies, permissions boundaries, access keys) over the platform's kind: User,
// Group, Role and Policy, in the caller's account.
//
// Speaks the AWS QUERY protocol (form-encoded request, XML response) — IAM has not migrated to JSON.
//
// ONE policy world, no second engine: CreatePolicy stores the AWS policy document as written on a kind:
// Policy's spec.document, which the one evaluator (internal/iamauthz) reads at every door — the aws-shim,
// the console, and the Kubernetes RBAC the IAM compiler generates from it. What each call writes is the
// shape the console and CloudFormation write (iam_model.go), so an attachment made here, there or by a
// stack is the same object. A role assumed via the STS doorway is authorized by exactly its policies,
// default deny.
//
// Translation fidelity guardrails: a document that is not a policy document is refused
// (MalformedPolicyDocument); a part of a valid one the evaluator cannot evaluate is stored as written (as
// on AWS) and never widens a grant — an Allow it cannot evaluate is dropped and reported, a Deny applies
// unconditionally.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
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
	usersNS string // the management account's IAM home: where its kind: User/Group/Role/Policy live
	account string
	region  string
	logger  *slog.Logger
	// cfn is the CloudFormation front door, whose stack records hold the instance profiles a stack made
	// (iam_instanceprofile.go); nil = none.
	cfn *cfnDoorway
}

func newIAMHandler(cs kubernetes.Interface, dyn dynamic.Interface, keys *awskeys.Store, authz *dataplaneauthz.Checker, usersNS, account, region string, logger *slog.Logger) *iamHandler {
	return &iamHandler{cs: cs, dyn: dyn, keys: keys, authz: authz, usersNS: usersNS, account: account, region: region, logger: logger}
}

func (h *iamHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", iamXMLNamespace)
}

// verbForIAMOp maps an IAM op to its coarse RBAC verb + the CRD resource it authorizes against in legacy
// mode, so IAM management is gated by the caller's k8s RBAC on the iam.openinfra.dev CRDs (no new authz
// surface). A write to a principal (attach, inline policy, boundary, membership) is create on its kind.
func verbForIAMOp(op string) (verb, resource string, ok bool) {
	switch op {
	case "CreateRole", "PutRolePolicy", "AttachRolePolicy", "DetachRolePolicy",
		"PutRolePermissionsBoundary", "DeleteRolePermissionsBoundary":
		return "create", "roles", true
	case "GetRole", "ListRoles", "ListAttachedRolePolicies", "ListRolePolicies", "GetRolePolicy":
		return "get", "roles", true
	// A stack's instance profiles (iam_instanceprofile.go): a profile is a container of roles.
	case "GetInstanceProfile", "ListInstanceProfiles", "ListInstanceProfilesForRole":
		return "get", "roles", true
	case "DeleteRole", "DeleteRolePolicy":
		return "delete", "roles", true
	case "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion":
		return "create", "policies", true
	case "GetPolicy", "ListPolicies", "SimulatePrincipalPolicy", "GetPolicyVersion", "ListPolicyVersions",
		"GetAccountAuthorizationDetails":
		return "get", "policies", true
	case "DeletePolicy", "DeletePolicyVersion":
		return "delete", "policies", true
	case "CreateUser", "CreateAccessKey", "UpdateAccessKey", "TagUser", "AttachUserPolicy", "DetachUserPolicy",
		"PutUserPolicy", "PutUserPermissionsBoundary", "DeleteUserPermissionsBoundary":
		return "create", "users", true
	case "GetUser", "ListUsers", "ListAccessKeys", "ListAttachedUserPolicies", "ListUserPolicies", "GetUserPolicy",
		"ListGroupsForUser":
		return "get", "users", true
	case "DeleteUser", "DeleteAccessKey", "DeleteUserPolicy":
		return "delete", "users", true
	case "CreateGroup", "AttachGroupPolicy", "DetachGroupPolicy", "PutGroupPolicy", "AddUserToGroup", "RemoveUserFromGroup":
		return "create", "groups", true
	case "GetGroup", "ListGroups", "ListAttachedGroupPolicies", "ListGroupPolicies", "GetGroupPolicy":
		return "get", "groups", true
	case "DeleteGroup", "DeleteGroupPolicy":
		return "delete", "groups", true
	// Login profiles and the account password policy (iam_loginprofile.go). ChangePassword is a user's own
	// self-service action, authorized in changePassword, not by this gate.
	case "CreateLoginProfile", "UpdateLoginProfile", "UpdateAccountPasswordPolicy":
		return "create", "users", true
	case "GetLoginProfile", "GetAccountPasswordPolicy":
		return "get", "users", true
	case "DeleteLoginProfile", "DeleteAccountPasswordPolicy":
		return "delete", "users", true
	case "ChangePassword":
		return "update", "users", true
	}
	return "", "", false
}

// iamResource is the (type, name) an IAM op is authorized on: the Role, Policy, User or Group it names
// (SimulatePrincipalPolicy: the principal being simulated; AddUserToGroup and RemoveUserFromGroup: the
// group, as AWS authorizes them). An op that names none (ListRoles, ListPolicies, ListUsers, an
// access-key op with no UserName) returns "" — checked on <Type>::*.
func iamResource(op string, r *http.Request) (string, string) {
	_, resource, _ := verbForIAMOp(op)
	switch op {
	case "SimulatePrincipalPolicy":
		if t, id := principalFromArn(r.PostFormValue("PolicySourceArn")); t != "" {
			return t, id
		}
		return "Role", ""
	case "CreatePolicy":
		return "Policy", r.PostFormValue("PolicyName")
	case "ListGroupsForUser":
		return "User", r.PostFormValue("UserName")
	case "GetAccountAuthorizationDetails":
		return "", ""
	}
	switch resource {
	case "roles":
		return "Role", r.PostFormValue("RoleName")
	case "policies":
		if a := r.PostFormValue("PolicyArn"); a != "" {
			return "Policy", policyNameFromArn(a)
		}
		return "Policy", ""
	case "groups":
		return "Group", r.PostFormValue("GroupName")
	}
	return "User", r.PostFormValue("UserName")
}

// iamActsOnCaller reports whether an IAM op that names no UserName acts on the calling user (AWS: the
// access-key operations and GetUser default to the caller).
func iamActsOnCaller(op string) bool {
	switch op {
	case "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey", "ListAccessKeys", "GetUser",
		"CreateLoginProfile", "GetLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile":
		return true
	}
	return false
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
	if op == "ChangePassword" {
		h.changePassword(ctx, w, r, claims, requestID) // a user's own password: authorized there
		return
	}
	if iamInstanceProfileOp(op) {
		h.serveInstanceProfile(ctx, w, r, op, requestID, claims) // on the profile's ARN, or the role: authorized there
		return
	}

	// iam:<Op> on the Role/Policy/User/Group it names (the List* ops on <Type>::*); a User's access-key or
	// GetUser op that names no user acts on the caller, as on AWS. A group is authorized on its ARN
	// (arn:aws:iam::<account>:group/<name>), which a policy names as written.
	resType, resID := iamResource(op, r)
	if resType == "User" && resID == "" && claims.AssumedRole == "" && iamActsOnCaller(op) {
		resID = claims.PrincipalID()
	}
	if resType == "Group" {
		resType, resID = arnType, h.scope(ctx).arn("group/"+orStar(resID))
	}
	// In legacy the coarse check first — the caller must hold k8s RBAC on the iam.openinfra.dev CRD
	// (impersonated SAR; IAM management is admin-level, the RBAC the console's IAM pages use) — then the
	// data-plane check (an assumed role's authority is its policy alone). In enforce IAM policy alone:
	// AWS's PowerUserAccess, which excludes iam:*, may not manage IAM here either.
	// A member account's IAM entities are its own (iamScope): the resource is in the caller's account.
	var inAccount []iamauthz.RequestOption
	if sc := h.scope(ctx); sc.ns != h.usersNS {
		inAccount = append(inAccount, iamauthz.WithResourceAccount(sc.account))
	}
	if ok, reason := decide(ctx, r, h.authz, claims, "iam:"+op, resType, resID,
		coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, verb, "iam.openinfra.dev", resource, h.usersNS, "",
			"iam:"+op, resType, resID), inAccount...); !ok {
		h.audit(ctx, op, resID, "deny", reason)
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
		h.listPolicies(ctx, w, r, requestID)
	case "CreatePolicyVersion":
		h.createPolicyVersion(ctx, w, r, requestID)
	case "GetPolicyVersion":
		h.getPolicyVersion(ctx, w, r, requestID)
	case "ListPolicyVersions":
		h.listPolicyVersions(ctx, w, r, requestID)
	case "DeletePolicyVersion":
		h.deletePolicyVersion(ctx, w, r, requestID)
	case "SetDefaultPolicyVersion":
		h.setDefaultPolicyVersion(ctx, w, r, requestID)
	case "AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy":
		h.attachPolicy(ctx, w, r, requestID, entityOf(op), true)
	case "DetachRolePolicy", "DetachUserPolicy", "DetachGroupPolicy":
		h.attachPolicy(ctx, w, r, requestID, entityOf(op), false)
	case "ListAttachedRolePolicies", "ListAttachedUserPolicies", "ListAttachedGroupPolicies":
		h.listAttachedPolicies(ctx, w, r, requestID, entityOf(op))
	case "PutRolePolicy", "PutUserPolicy", "PutGroupPolicy":
		h.putInlinePolicy(ctx, w, r, requestID, entityOf(op))
	case "GetRolePolicy", "GetUserPolicy", "GetGroupPolicy":
		h.getInlinePolicy(ctx, w, r, requestID, entityOf(op))
	case "DeleteRolePolicy", "DeleteUserPolicy", "DeleteGroupPolicy":
		h.deleteInlinePolicy(ctx, w, r, requestID, entityOf(op))
	case "ListRolePolicies", "ListUserPolicies", "ListGroupPolicies":
		h.listInlinePolicies(ctx, w, r, requestID, entityOf(op))
	case "PutRolePermissionsBoundary", "PutUserPermissionsBoundary":
		h.putBoundary(ctx, w, r, requestID, entityOf(op), true)
	case "DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary":
		h.putBoundary(ctx, w, r, requestID, entityOf(op), false)
	case "CreateGroup":
		h.createGroup(ctx, w, r, requestID)
	case "GetGroup":
		h.getGroup(ctx, w, r, requestID)
	case "DeleteGroup":
		h.deleteGroup(ctx, w, r, requestID)
	case "ListGroups":
		h.listGroups(ctx, w, requestID)
	case "AddUserToGroup":
		h.groupMembership(ctx, w, r, requestID, true)
	case "RemoveUserFromGroup":
		h.groupMembership(ctx, w, r, requestID, false)
	case "ListGroupsForUser":
		h.listGroupsForUser(ctx, w, r, requestID)
	case "GetAccountAuthorizationDetails":
		h.getAccountAuthorizationDetails(ctx, w, r, requestID)
	case "CreateUser":
		h.createUser(ctx, w, r, requestID)
	case "GetUser":
		h.getUser(ctx, w, r, requestID, claims)
	case "DeleteUser":
		h.deleteUser(ctx, w, r, requestID)
	case "ListUsers":
		h.listUsers(ctx, w, requestID)
	case "CreateAccessKey":
		h.createAccessKey(ctx, w, r, requestID)
	case "DeleteAccessKey":
		h.deleteAccessKey(ctx, w, r, requestID, claims)
	case "ListAccessKeys":
		h.listAccessKeys(ctx, w, r, requestID, claims)
	case "UpdateAccessKey":
		h.updateAccessKey(ctx, w, r, requestID, claims)
	case "SimulatePrincipalPolicy":
		h.simulatePrincipalPolicy(ctx, w, r, requestID, claims)
	case "CreateLoginProfile", "GetLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile",
		"GetAccountPasswordPolicy", "UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy":
		h.serveLoginProfile(ctx, w, r, op, requestID, claims)
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID, "IAM "+op+" is recognized but not implemented.", iamXMLNamespace)
	}
}

// entityOf is the principal kind an op's name carries (AttachUserPolicy: users).
func entityOf(op string) iamEntity {
	switch {
	case strings.Contains(op, "User"):
		return userEntity
	case strings.Contains(op, "Group"):
		return groupEntity
	}
	return roleEntity
}

func orStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// --- roles ---

func (h *iamHandler) createRole(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	name := r.PostFormValue("RoleName")
	if name == "" {
		h.malformed(w, requestID, "CreateRole requires RoleName.")
		return
	}
	trustDoc := r.PostFormValue("AssumeRolePolicyDocument")
	trust, err := parseTrustPolicy(trustDoc, sc.account)
	if err != nil {
		h.malformed(w, requestID, "AssumeRolePolicyDocument: "+err.Error())
		return
	}
	spec := map[string]any{"description": r.PostFormValue("Description"), "trust": toAny(trust), "policies": []any{}}
	if v := r.PostFormValue("MaxSessionDuration"); v != "" {
		secs, err := strconv.Atoi(v)
		if err != nil || secs < 3600 || secs > 43200 {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
				"MaxSessionDuration must be a number of seconds from 3600 to 43200.", iamXMLNamespace)
			return
		}
		spec["maxSessionDuration"] = int64(secs)
	}
	if pb := r.PostFormValue("PermissionsBoundary"); pb != "" {
		ref, err := h.boundaryRef(ctx, sc, pb)
		if err != nil {
			h.fail(w, requestID, err)
			return
		}
		spec["permissionBoundary"] = ref
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "Role",
		"metadata": map[string]any{"name": name, "namespace": sc.ns,
			"annotations": map[string]any{assumeRolePolicyAnnotation: trustDoc}},
		"spec": spec,
	}}
	if _, err := h.dyn.Resource(gvrRoles).Namespace(sc.ns).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if isAlreadyExists(err) {
			h.conflict(w, requestID, "EntityAlreadyExists", "Role with name "+name+" already exists.")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateRole", name, "allow", "")
	h.writeResult(w, requestID, "CreateRole", "<Role>"+h.roleXML(ctx, name, trustDoc)+"</Role>")
}

func (h *iamHandler) getRole(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	name := r.PostFormValue("RoleName")
	u, err := h.dyn.Resource(gvrRoles).Namespace(sc.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		h.noSuchEntity(w, requestID, "Role "+name+" not found.")
		return
	}
	h.writeResult(w, requestID, "GetRole", "<Role>"+h.roleXML(ctx, name, h.trustDocument(sc, u))+h.boundaryXML(ctx, sc, u)+"</Role>")
}

func (h *iamHandler) deleteRole(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	name := r.PostFormValue("RoleName")
	if err := h.dyn.Resource(gvrRoles).Namespace(sc.ns).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "Role "+name+" not found.")
		return
	}
	h.audit(ctx, "DeleteRole", name, "allow", "")
	h.writeResult(w, requestID, "DeleteRole", "")
}

func (h *iamHandler) listRoles(ctx context.Context, w http.ResponseWriter, requestID string) {
	sc := h.scope(ctx)
	list, err := h.dyn.Resource(gvrRoles).Namespace(sc.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<Roles>")
	for _, it := range list.Items {
		b.WriteString("<member>" + h.roleXML(ctx, it.GetName(), "") + "</member>")
	}
	b.WriteString("</Roles><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListRoles", b.String())
}

// --- users ---

func (h *iamHandler) createUser(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	name := r.PostFormValue("UserName")
	if name == "" {
		h.malformed(w, requestID, "CreateUser requires UserName.")
		return
	}
	// The user name root is the account's root user's, never an IAM user's (as the console and admission
	// refuse it): a kind: User named root would act as root does.
	if reservedUserName(name) {
		h.fail(w, requestID, invalidInputErr("The user name "+name+" is reserved for the account's root user."))
		return
	}
	spec := map[string]any{"displayName": name, "source": "local", "groups": []any{}}
	if pb := r.PostFormValue("PermissionsBoundary"); pb != "" {
		ref, err := h.boundaryRef(ctx, sc, pb)
		if err != nil {
			h.fail(w, requestID, err)
			return
		}
		spec["permissionBoundary"] = ref
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "User",
		"metadata":   map[string]any{"name": name, "namespace": sc.ns},
		"spec":       spec,
	}}
	if _, err := h.dyn.Resource(gvrUsers).Namespace(sc.ns).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if isAlreadyExists(err) {
			h.conflict(w, requestID, "EntityAlreadyExists", "User "+name+" already exists.")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateUser", name, "allow", "")
	h.writeResult(w, requestID, "CreateUser", "<User>"+h.userXML(ctx, name)+"</User>")
}

func (h *iamHandler) getUser(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	sc := h.scope(ctx)
	name := r.PostFormValue("UserName")
	if name == "" && claims.AssumedRole == "" {
		name = claims.PrincipalID()
	}
	u, err := h.dyn.Resource(gvrUsers).Namespace(sc.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		h.noSuchEntity(w, requestID, "User "+name+" not found.")
		return
	}
	h.writeResult(w, requestID, "GetUser", "<User>"+h.userXML(ctx, name)+h.boundaryXML(ctx, sc, u)+"</User>")
}

func (h *iamHandler) deleteUser(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	name := r.PostFormValue("UserName")
	if err := h.dyn.Resource(gvrUsers).Namespace(sc.ns).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "User "+name+" not found.")
		return
	}
	h.audit(ctx, "DeleteUser", name, "allow", "")
	h.writeResult(w, requestID, "DeleteUser", "")
}

func (h *iamHandler) listUsers(ctx context.Context, w http.ResponseWriter, requestID string) {
	sc := h.scope(ctx)
	list, err := h.dyn.Resource(gvrUsers).Namespace(sc.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var b strings.Builder
	b.WriteString("<Users>")
	for _, it := range list.Items {
		b.WriteString("<member>" + h.userXML(ctx, it.GetName()) + "</member>")
	}
	b.WriteString("</Users><IsTruncated>false</IsTruncated>")
	h.writeResult(w, requestID, "ListUsers", b.String())
}

// --- access keys (reuse the shared awskeys.Store — the key genuinely authenticates through the shim) ---

// keyAccount is the account an access key minted in sc records: a member account's id; nothing for the
// management account, whose keys are as they always were.
func (h *iamHandler) keyAccount(sc iamScope) string {
	if sc.ns == h.usersNS {
		return ""
	}
	return sc.account
}

// inScope reports whether a key is the caller's account's: a user of the same name in another account
// is another user, and its keys are not this account's to list, change or delete.
func (h *iamHandler) inScope(sc iamScope, m awskeys.Meta) bool {
	if acct := h.keyAccount(sc); acct != "" {
		return m.Account == acct
	}
	return m.Account == "" || m.Account == sc.account || m.Account == iamauthz.ManagementAccount
}

func (h *iamHandler) createAccessKey(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	user := r.PostFormValue("UserName")
	if user == "" {
		h.malformed(w, requestID, "CreateAccessKey requires UserName.")
		return
	}
	if h.keys == nil {
		writeQueryError(w, http.StatusInternalServerError, "ServiceFailure", requestID, "access-key store not configured.", iamXMLNamespace)
		return
	}
	if _, err := h.dyn.Resource(gvrUsers).Namespace(sc.ns).Get(ctx, user, metav1.GetOptions{}); err != nil {
		h.noSuchEntity(w, requestID, "User "+user+" not found.")
		return
	}
	if existing, err := h.keys.List(ctx, user); err == nil {
		n := 0
		for _, m := range existing {
			if h.inScope(sc, m) {
				n++
			}
		}
		if n >= maxKeysPerUser {
			h.conflict(w, requestID, "LimitExceeded", "Cannot exceed quota of "+itoa(maxKeysPerUser)+" access keys for user "+user+".")
			return
		}
	}
	id, secret, err := awskeys.GenerateKeyPair()
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if err := h.keys.Put(ctx, awskeys.Key{AccessKeyID: id, SecretKey: secret, Owner: user, Account: h.keyAccount(sc)}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateAccessKey", user, "allow", "accessKeyId="+id)
	body := "<AccessKey><UserName>" + xmlEscape(user) + "</UserName><AccessKeyId>" + xmlEscape(id) +
		"</AccessKeyId><Status>Active</Status><SecretAccessKey>" + xmlEscape(secret) +
		"</SecretAccessKey><CreateDate>" + time.Now().UTC().Format(time.RFC3339) + "</CreateDate></AccessKey>"
	h.writeResult(w, requestID, "CreateAccessKey", body)
}

// accessKeyUser is the user an access-key op acts for: UserName, or — as on AWS — the calling user when
// the request names none. A role session has no user of its own, so it must name one.
func (h *iamHandler) accessKeyUser(w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) (string, bool) {
	if user := r.PostFormValue("UserName"); user != "" {
		return user, true
	}
	if claims.AssumedRole != "" || claims.PrincipalID() == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"Must specify userName when calling with non-User credentials", iamXMLNamespace)
		return "", false
	}
	return claims.PrincipalID(), true
}

// ownedAccessKey is the AccessKeyId an op acts on, once it is known to be the named user's in the
// caller's account. A key another user (or another account's user of the same name) owns is
// NoSuchEntity, as on AWS: authority over one user's keys never reaches another's.
func (h *iamHandler) ownedAccessKey(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) (id, user string, ok bool) {
	user, ok = h.accessKeyUser(w, r, requestID, claims)
	if !ok {
		return "", "", false
	}
	if h.keys == nil {
		writeQueryError(w, http.StatusInternalServerError, "ServiceFailure", requestID, "access-key store not configured.", iamXMLNamespace)
		return "", "", false
	}
	id = r.PostFormValue("AccessKeyId")
	if m, found := h.keys.Describe(ctx, id); !found || m.Owner != user || !h.inScope(h.scope(ctx), m) {
		h.noSuchEntity(w, requestID, "The Access Key with id "+id+" cannot be found.")
		return "", "", false
	}
	return id, user, true
}

func (h *iamHandler) listAccessKeys(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	user, ok := h.accessKeyUser(w, r, requestID, claims)
	if !ok {
		return
	}
	if h.keys == nil {
		writeQueryError(w, http.StatusInternalServerError, "ServiceFailure", requestID, "access-key store not configured.", iamXMLNamespace)
		return
	}
	metas, err := h.keys.List(ctx, user)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	sc := h.scope(ctx)
	var b strings.Builder
	b.WriteString("<AccessKeyMetadata>")
	for _, m := range metas {
		if !h.inScope(sc, m) {
			continue
		}
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

func (h *iamHandler) deleteAccessKey(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	id, user, ok := h.ownedAccessKey(ctx, w, r, requestID, claims)
	if !ok {
		return
	}
	if err := h.keys.Delete(ctx, id); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "DeleteAccessKey", user, "allow", "accessKeyId="+id)
	h.writeResult(w, requestID, "DeleteAccessKey", "")
}

func (h *iamHandler) updateAccessKey(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	status := r.PostFormValue("Status")
	if status != "Inactive" && status != "Active" {
		h.malformed(w, requestID, "Status must be Active or Inactive.")
		return
	}
	id, user, ok := h.ownedAccessKey(ctx, w, r, requestID, claims)
	if !ok {
		return
	}
	var err error
	if status == "Inactive" {
		err = h.keys.Revoke(ctx, id)
	} else {
		err = h.keys.Activate(ctx, id)
	}
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "UpdateAccessKey", user, "allow", "accessKeyId="+id+" status="+status)
	h.writeResult(w, requestID, "UpdateAccessKey", "")
}

// --- SimulatePrincipalPolicy (the honest self-check: run the query the doors run) ---

// simulatePrincipalPolicy evaluates the principal's identity policies for each action and resource. In
// enforce it asks the one evaluator, as the doors do (the principal in the caller's account, a user with
// its groups); in legacy the data-plane checker, as before.
func (h *iamHandler) simulatePrincipalPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
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
	sc := h.scope(ctx)
	enforce := enforcing(ctx, h.authz, claims)
	var p iamauthz.Principal
	if enforce {
		p = h.simulatedPrincipal(ctx, sc, pType, pID)
	}
	var b strings.Builder
	b.WriteString("<EvaluationResults>")
	for _, action := range actions {
		for _, res := range resources {
			var allowed, explicit bool
			if enforce {
				d := h.authz.IAM().Authorize(ctx, p, action, res, map[string]any{"authenticated": "true", "username": pID})
				allowed, explicit = d.Allowed, d.ExplicitDeny
			} else {
				rt, rid := arnToResourceShim(res)
				var reason string
				allowed, _, reason = h.authz.Authorize(ctx, pType, pID, nil, action, rt, rid, map[string]any{"authenticated": true})
				explicit = strings.Contains(reason, "explicit")
			}
			decision := "implicitDeny"
			if allowed {
				decision = "allowed"
			} else if explicit {
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

// simulatedPrincipal is the principal a PolicySourceArn names in the caller's account: a role, or a user
// with the groups its kind: User lists (qualified by a member account's home, as principalOf does).
func (h *iamHandler) simulatedPrincipal(ctx context.Context, sc iamScope, pType, name string) iamauthz.Principal {
	id := name
	if sc.ns != h.usersNS {
		id = sc.ns + "/" + name
	}
	if pType == "Role" {
		return iamauthz.Principal{Account: sc.account, Type: iamauthz.Role, ID: id}
	}
	p := iamauthz.Principal{Account: sc.account, Type: iamauthz.User, ID: id}
	if u, err := h.dyn.Resource(gvrUsers).Namespace(sc.ns).Get(ctx, name, metav1.GetOptions{}); err == nil {
		groups, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "groups")
		for _, g := range groups {
			if sc.ns != h.usersNS {
				g = sc.ns + "/" + g
			}
			p.Groups = append(p.Groups, g)
		}
	}
	return p
}

// --- XML fragment builders ---

func (h *iamHandler) roleXML(ctx context.Context, name, assumeDoc string) string {
	sc := h.scope(ctx)
	s := "<Path>/</Path><RoleName>" + xmlEscape(name) + "</RoleName><RoleId>" + roleID(name) + "</RoleId><Arn>" + xmlEscape(sc.arn("role/"+name)) +
		"</Arn><CreateDate>" + time.Now().UTC().Format(time.RFC3339) + "</CreateDate>"
	if assumeDoc != "" {
		s += "<AssumeRolePolicyDocument>" + xmlEscape(encodeDocument(assumeDoc)) + "</AssumeRolePolicyDocument>"
	}
	return s
}

// policyXML is a stored Policy as IAM describes one: its IAM name and ARN (AWS's for a managed policy),
// default version, description and attachment count.
func (h *iamHandler) policyXML(ctx context.Context, sc iamScope, u *unstructured.Unstructured) string {
	name, arn := policyIdentity(sc, u)
	desc, _, _ := unstructured.NestedString(u.Object, "spec", "description")
	count := 0
	if !isAWSManaged(u) {
		count, _ = h.attachmentCount(ctx, sc, u.GetName())
	}
	created := u.GetCreationTimestamp().UTC()
	if created.IsZero() {
		created = time.Now().UTC()
	}
	s := "<PolicyName>" + xmlEscape(name) + "</PolicyName><PolicyId>" + roleID(name) + "</PolicyId><Arn>" + xmlEscape(arn) +
		"</Arn><Path>/</Path><DefaultVersionId>" + xmlEscape(defaultVersion(u)) + "</DefaultVersionId><AttachmentCount>" +
		strconv.Itoa(count) + "</AttachmentCount><IsAttachable>true</IsAttachable><CreateDate>" + created.Format(time.RFC3339) +
		"</CreateDate><UpdateDate>" + created.Format(time.RFC3339) + "</UpdateDate>"
	if desc != "" {
		s += "<Description>" + xmlEscape(desc) + "</Description>"
	}
	return s
}

func (h *iamHandler) userXML(ctx context.Context, name string) string {
	sc := h.scope(ctx)
	return "<Path>/</Path><UserName>" + xmlEscape(name) + "</UserName><UserId>" + roleID(name) + "</UserId><Arn>" + xmlEscape(sc.arn("user/"+name)) +
		"</Arn><CreateDate>" + time.Now().UTC().Format(time.RFC3339) + "</CreateDate>"
}

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
	if extra = strings.TrimSpace(extra); extra != "" {
		args = append(args, "detail", extra)
	}
	h.logger.InfoContext(ctx, "iam audit", args...)
}
