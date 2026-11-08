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

// passRoleVerbFor is the RBAC verb for passing a role to one service (iam:PassedToService): what the IAM
// compiler compiles a PassRole grant limited to that service into, and what the admission policies accept
// beside passrole (any service).
func passRoleVerbFor(service string) string { return passRoleVerb + ":" + service }

// callerMayPassRole reports whether the caller may pass the Role roleNS/role to service (a service
// principal, AWS's iam:PassedToService: lambda.amazonaws.com, states.amazonaws.com). IAM policy decides it
// with iam:PassedToService set, so AWSLambda_FullAccess's "PassRole where PassedToService is Lambda" passes
// a role to Lambda and to nothing else. In legacy a User needs the RBAC verb (iam.CanDo, a
// SubjectAccessReview as the caller: passrole, or passrole:<service>) and is then subject to any data-plane
// policy that governs iam for it; an assumed role is checked closed: its policies must allow iam:PassRole
// on the Role (default deny).
func callerMayPassRole(ctx context.Context, cs kubernetes.Interface, authz *dataplaneauthz.Checker, claims iam.Claims,
	roleNS, role, service string, r *http.Request) (bool, string) {
	if cs == nil && claims.AssumedRole == "" {
		return false, "iam:PassRole cannot be checked on this shim"
	}
	ctx = withPassedToService(ctx, service)
	if ok, reason := decide(ctx, r, authz, claims, "iam:PassRole", "Role", role, func() (bool, string) {
		ok, why := iam.CanDo(ctx, cs, claims, passRoleVerb, "iam.openinfra.dev", "roles", roleNS, role)
		if !ok {
			if ok2, _ := iam.CanDo(ctx, cs, claims, passRoleVerbFor(service), "iam.openinfra.dev", "roles", roleNS, role); ok2 {
				ok, why = true, ""
			}
		}
		if !ok {
			return false, why
		}
		if denied, why := dataPlaneDenied(ctx, authz, claims, "iam:PassRole", "Role", role, r); denied {
			return false, why
		}
		return true, ""
	}); !ok {
		return false, "not authorized to perform iam:PassRole on role " + role + ": " + reason
	}
	return true, ""
}
