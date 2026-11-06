package main

import (
	"context"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// iam:PassRole. Handing a kind: Role to something that will later act with its credentials (a
// VirtualMachine's instance role, a state machine's execution role) needs permission to pass that
// Role, as on AWS. Kubernetes expresses it as the custom RBAC verb `passrole` on roles.iam.openinfra.dev:
//   - objects a caller creates directly are checked at admission (platform/security/pass-role.yaml);
//   - objects the shim creates with its own identity (a state machine from CreateStateMachine) are
//     checked here, as the caller, before the shim writes anything.
// The built-in admins hold `passrole` on every Role; power users do not (AWS's PowerUserAccess
// excludes iam:PassRole). An assumed role needs iam:PassRole on Role::<name> in its policies.

// passRoleVerb is the RBAC verb the admission policy and this check ask for.
const passRoleVerb = "passrole"

// passRoleNamespace is the namespace a state machine's execution role is resolved in: the role
// resolver's (the IAM home namespace) for the management account, as always, and a member account's home
// — where its IAM roles live — for a member's. A role is passed only within its own account, as on AWS.
func (h *sfnHandler) passRoleNamespace(ctx context.Context) string {
	ns := h.rolesNS
	if ns == "" {
		ns = dataplaneauthz.DefaultHomeNamespace
	}
	return accountNamespace(ctx, ns)
}

// callerMayPassRole reports whether the caller may pass the Role roleNS/role. A User needs the RBAC verb
// (iam.CanDo, a SubjectAccessReview as the caller) and is then subject to any data-plane policy that
// governs iam for it; an assumed role is checked closed: its policies must allow iam:PassRole on the
// Role (default deny).
func callerMayPassRole(ctx context.Context, cs kubernetes.Interface, authz *dataplaneauthz.Checker, claims iam.Claims,
	roleNS, role string, r *http.Request) (bool, string) {
	if cs == nil && claims.AssumedRole == "" {
		return false, "iam:PassRole cannot be checked on this shim"
	}
	if ok, reason := decide(ctx, r, authz, claims, "iam:PassRole", "Role", role,
		coarseThenDataPlane(ctx, r, cs, authz, claims, passRoleVerb, "iam.openinfra.dev", "roles", roleNS, role,
			"iam:PassRole", "Role", role)); !ok {
		return false, "not authorized to perform iam:PassRole on role " + role + ": " + reason
	}
	return true, ""
}
