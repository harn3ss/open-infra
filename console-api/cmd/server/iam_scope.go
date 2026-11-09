package main

// The account a console IAM page manages.
//
// The AWS console's IAM pages manage the signed-in account's IAM: a role session switched into a member
// account manages that account's users, groups, roles, policies and credentials, never the management
// account's. Each account's IAM lives in its IAM home namespace (the management account's is the console's
// own namespace; a member account's is the namespace labelled as its home), exactly where the IAM API (the
// aws-shim's iamScope) keeps it. A page acts in its session's account through iamAuth: the console's
// authStore bound to that account's IAM home, so every read and write it makes lands there. The route gate
// decided the page's IAM action on that same account's ARN (callerAccount).
//
// What every account shares is the AWS-managed policy library: the kind: Policy objects labelled
// openinfra.dev/managed-policy in the management account's home. A member account sees and attaches them
// by name (a bare policy reference resolves to the account's own policy first, then the library, as the
// evaluator resolves it: iamauthz.ResolvePolicyRef), and never sees the management account's own policies.

import (
	"context"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// iamAuth is auth bound to the IAM home of the request's account: auth itself for the management account,
// a copy whose namespace is the member account's IAM home for a session switched into a member account.
// A member account with no IAM home the console can manage (unknown, suspended) is refused with
// AccessDenied, and nothing is read or written.
func iamAuth(w http.ResponseWriter, r *http.Request, auth *authStore) (*authStore, bool) {
	acct := callerAccount(r)
	if auth == nil || acct == iam.ManagementAccount {
		return auth, true
	}
	home, ok := accountHome(r.Context(), auth.cs, auth, acct)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"errorCode": "AccessDeniedException",
			"error": "account " + acct + " has no IAM this console can manage (it is suspended, or not an account of this organization)"})
		return nil, false
	}
	scoped := *auth
	scoped.ns, scoped.account, scoped.home = home, acct, auth.ns
	return &scoped, true
}

// accountID is the account whose IAM a manages.
func (a *authStore) accountID() string {
	if a.account == "" {
		return iam.ManagementAccount
	}
	return a.account
}

// member reports whether a manages a member account's IAM (not the management account's).
func (a *authStore) member() bool { return a.account != "" }

// iamHome is the management account's IAM home: where the AWS-managed policy library lives.
func (a *authStore) iamHome() string {
	if a.home == "" {
		return a.ns
	}
	return a.home
}

// keyAccount is the account an access key minted in a's account records: a member account's id, nothing
// for the management account (whose keys have always carried none), as the IAM API's keyAccount.
func (a *authStore) keyAccount() string { return a.account }

// keyInScope reports whether a stored key is a's account's: a user of the same name in another account is
// another user, and its keys are not this account's to list, change or delete (the IAM API's inScope).
func (a *authStore) keyInScope(m awskeys.Meta) bool {
	if a.member() {
		return m.Account == a.account
	}
	return m.Account == "" || m.Account == iam.ManagementAccount
}

// managedLibrary is the AWS-managed policies, from the management account's home: what a member account
// sees beside its own policies.
func (a *authStore) managedLibrary(ctx context.Context) []crdPolicy {
	if !a.member() {
		return nil
	}
	lib := *a
	lib.ns, lib.account, lib.home = a.home, "", ""
	var out []crdPolicy
	for _, p := range lib.listCRDPolicies(ctx) {
		if isManagedPolicy(p.Metadata.Labels) {
			out = append(out, p)
		}
	}
	return out
}

// managedPolicy is the AWS-managed policy name from the library, for a member account that has no policy
// of its own by that name.
func (a *authStore) managedPolicy(ctx context.Context, name string) (crdPolicy, bool) {
	if !a.member() {
		return crdPolicy{}, false
	}
	lib := *a
	lib.ns, lib.account, lib.home = a.home, "", ""
	p, ok := lib.crdPolicyByName(ctx, name)
	if !ok || !isManagedPolicy(p.Metadata.Labels) {
		return crdPolicy{}, false
	}
	return p, true
}

// specPolicyRefs is the policy references a principal's spec map attaches: its policies and boundary.
func specPolicyRefs(spec map[string]any) (policies []string, boundary string) {
	policies, _ = spec["policies"].([]string)
	boundary, _ = spec["permissionBoundary"].(string)
	return policies, boundary
}

// memberPolicyRefsOK refuses, in a member account, attaching a policy that is neither the account's own nor
// an AWS-managed one: another account's policy is not attachable, as on AWS (NoSuchEntity). The management
// account's pages are unchanged.
func (a *authStore) memberPolicyRefsOK(w http.ResponseWriter, r *http.Request, policies []string, boundary string) bool {
	if !a.member() {
		return true
	}
	refs := []string{}
	for _, ref := range append(append([]string{}, policies...), boundary) {
		if ref = strings.TrimSpace(ref); ref != "" {
			refs = append(refs, ref)
		}
	}
	missing, err := a.missingPolicy(r.Context(), refs)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not read the account's policies"})
		return false
	}
	if missing != "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"errorCode": "NoSuchEntity",
			"error": "Policy " + missing + " does not exist or is not attachable."})
		return false
	}
	return true
}

// memberPolicyShapeErr is why a member account's policy create (or update) is refused: its policy is an
// AWS policy document, as IAM's CreatePolicy takes it. The console's native statements and Cedar blocks are
// the management account's (they compose cluster-wide RBAC named for the policy alone).
func memberPolicyShapeErr(in policyReq, create bool) string {
	if len(in.Statements) > 0 || cedarHasStatements(in.DataPlane) || cedarHasStatements(in.ControlPlane) {
		return "a member account's policy is an AWS policy document; native statements and data-plane/control-plane blocks are not supported"
	}
	if in.Document != nil && strings.TrimSpace(*in.Document) == "" || create && in.Document == nil {
		return "a member account's policy needs its AWS policy document"
	}
	return ""
}
