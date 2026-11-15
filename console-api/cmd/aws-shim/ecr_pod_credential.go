// The ECR credential an application's image is pulled with: its task execution role's, as ECS pulls a task's
// image with the task definition's ExecutionRoleArn.
//
// On AWS the ECS agent (or Fargate) pulls a task's image as the task's execution role, in the task's account:
// the role must trust ecs-tasks.amazonaws.com, and its policies (AmazonECSTaskExecutionRolePolicy:
// ecr:GetAuthorizationToken, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer) decide which repositories the
// image may come from. Here the node's kubelet asks the node's ECR credential provider
// (cmd/ecr-credential-provider) for each image's credential, handing it a token bound to the pod the image
// is for (the kubelet's service-account token for image pulls, audience openinfra-ecr-pull). The provider
// posts that token to POST /ecr/pod-credential, and:
//   - when the token is an application's own (app_role.go: its pod is one of the app's Deployment, running as
//     the app's ServiceAccount) and the app names an execution role (spec.executionRole), the answer is that
//     role's ECR credential, what GetAuthorizationToken gives the role's session: the registry's token
//     service then decides each repository on the role's policies, as ECR does. The role is a role of the
//     app's own account and must trust ecs-tasks.amazonaws.com, with no conditions (they are not evaluated
//     for the service); a role that may not ecr:GetAuthorizationToken gets none. Any of these refused is a
//     refusal (403), and the provider answers the kubelet with a credential the registry refuses, so the
//     pull fails as ECS's does, rather than fall back to the node's own;
//   - otherwise (any other pod, an app with no execution role) the answer is no credential (204), and the
//     node pulls as before with its own credential, which reaches the management account's images alone.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

const (
	// ecrPodPullAudience is the audience of the token the kubelet hands the ECR credential provider.
	ecrPodPullAudience = "openinfra-ecr-pull"
	// ecrPodPullTTL is how long an execution role's pull credential lasts. The kubelet caches it for less.
	ecrPodPullTTL = time.Hour
)

// ecrPodPull is what POST /ecr/pod-credential decides with.
type ecrPodPull struct {
	apps applicationIdentities // tokens of ecrPodPullAudience
	// roleOf finds a workload's role in its account (stsHandler.workloadRoleOf).
	roleOf  func(ctx context.Context, ns, account, home, roleName string) (resolvedRole, string, bool)
	iamHome string // the management account's IAM home: role principals are qualified by it
	account string // the management account's id
}

// servePodCredential handles POST /ecr/pod-credential: a pod-bound token in (Authorization: Bearer), the
// pod's application's execution-role ECR credential out ({"username":"AWS","password":…,"expiresAt":…}),
// 204 when the pod's image is pulled with the node's own credential, 403 when the pull must fail.
// In-cluster callers only.
func (h *ecrHandler) servePodCredential(w http.ResponseWriter, r *http.Request) {
	if refuseIfProxied(w, r) {
		return
	}
	if h.signer == nil || h.podPull == nil || h.podPull.apps == nil || h.podPull.roleOf == nil {
		writeDockerTokenError(w, http.StatusNotImplemented, "UNSUPPORTED", "execution-role image pulls are not configured on this shim")
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		w.WriteHeader(http.StatusNoContent) // a pod with no token: the node's own credential
		return
	}
	ctx := r.Context()
	app, ok := h.podPull.apps.applicationOf(ctx, strings.TrimSpace(token))
	if !ok || app.executionRole == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ctx = withPrincipal(ctx, "ServiceAccount::"+app.username)
	cred, expires, why := h.executionRoleCredential(ctx, r, app)
	if why != "" {
		h.audit(ctx, "PodCredential", app.namespace+"/"+app.name, "deny", why)
		writeDockerTokenError(w, http.StatusForbidden, "DENIED", "the task's execution role "+app.executionRole+
			" cannot pull its image: "+why)
		return
	}
	h.audit(ctx, "PodCredential", app.namespace+"/"+app.name, "allow", "as execution role "+app.executionRole)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"username": "AWS", "password": cred, "expiresAt": expires.UTC().Format(time.RFC3339),
	})
}

// executionRoleCredential is app's execution role's ECR credential, or why it has none.
func (h *ecrHandler) executionRoleCredential(ctx context.Context, r *http.Request, app applicationIdentity) (string, time.Time, string) {
	pp := h.podPull
	acct := app.account
	if acct == "" {
		acct = pp.account
	}
	if app.suspended {
		return "", time.Time{}, "the application's account is suspended"
	}
	roleName := roleNameOf(app.executionRole)
	// A role of the app's own account only, as for its task role.
	if a := awsidentity.AccountOfARN(app.executionRole); a != "" && a != acct {
		return "", time.Time{}, "it is a role of another account"
	}
	role, roleNS, ok := pp.roleOf(ctx, app.namespace, app.account, app.home, roleName)
	if !ok {
		return "", time.Time{}, "the role does not exist"
	}
	if !trustsService(role.trust, ecsTasksService) {
		return "", time.Time{}, "its trust policy does not name " + ecsTasksService
	}
	if trustConditioned(role.trustDoc) {
		return "", time.Time{}, "its trust policy has conditions, which are not evaluated for the ECS service"
	}
	// The role's session, as ECS names an execution role's: after the task.
	expires := time.Now().Add(ecrPodPullTTL)
	principal := dataplaneauthz.QualifiedName(pp.iamHome, roleNS, strings.ToLower(roleName))
	claims := iam.Claims{Sub: "assumed-role/" + roleName + "/" + podID(app.namespace, app.pod), Groups: role.groups,
		AssumedRole: principal, Account: app.account, SessionExpiry: expires}
	actx := withPrincipal(inAccountScope(withAccount(ctx, app.account, app.home)), claims.PrincipalType()+"::"+claims.PrincipalID())
	// The ECS agent calls ecr:GetAuthorizationToken as the role; one it may not call gets no credential.
	if ok, why := decide(actx, r, h.authz, claims, "ecr:GetAuthorizationToken", "Repository", ecrAnyRepository, func() (bool, string) {
		return allowedForAssumedRole(actx, h.authz, claims, "ecr:GetAuthorizationToken", "Repository", ecrAnyRepository, r)
	}); !ok {
		return "", time.Time{}, "it is not allowed ecr:GetAuthorizationToken (" + why + ")"
	}
	cred, err := h.signer.mintCaller(ecrCaller{Sub: claims.Sub, Groups: claims.Groups, AssumedRole: claims.AssumedRole,
		Account: app.account, Home: app.home}, ecrPodPullTTL)
	if err != nil {
		h.logger.Error("ecr: minting an execution role's pull credential", "err", err)
		return "", time.Time{}, "the credential could not be issued"
	}
	return cred, expires, ""
}
