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

// passRoleNamespace is the namespace a state machine's execution role is resolved in.
func (h *sfnHandler) passRoleNamespace() string {
	if h.rolesNS != "" {
		return h.rolesNS
	}
	return dataplaneauthz.DefaultHomeNamespace
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
	if ok, reason := iam.CanDo(ctx, cs, claims, passRoleVerb, "iam.openinfra.dev", "roles", roleNS, role); !ok {
		return false, "not authorized to perform iam:PassRole on role " + role + ": " + reason
	}
	if denied, reason := dataPlaneDenied(ctx, authz, claims, "iam:PassRole", "Role", role, r); denied {
		return false, "not authorized to perform iam:PassRole on role " + role + ": " + reason
	}
	return true, ""
}
