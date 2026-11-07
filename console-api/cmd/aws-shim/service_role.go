// Service-assumed roles: a role an AWS service assumes for a workload that names it — Lambda for a function's
// execution role (lambda_role.go), ECS for a task's task role (app_role.go) — decided the same way for both.
//
// On AWS the role trusts the service (lambda.amazonaws.com, ecs-tasks.amazonaws.com), naming the role on the
// workload took iam:PassRole on it, and the service hands the workload the role's temporary credentials.
// Here the workload's pods run as its own ServiceAccount with a projected token for this shim's STS audience
// and the AWS SDK's web-identity environment, and the SDK calls sts:AssumeRoleWithWebIdentity with that
// token. Once the token is proven to be the workload's own (its pod is one of the workload's, read by owner
// references), the role is a kind: Role of the workload's own account — in the workload's namespace (where a
// CloudFormation stack puts the role it creates beside it), else in the account's IAM home (where the IAM API
// creates roles); a role ARN naming any other account is never the workload's. The role is assumed when its
// trust names the service and the workload names it, or when its trust names the workload's identity itself
// (system:serviceaccount:<namespace>:<serviceaccount>), or "*". The session is the workload's account's; like
// any web-identity session it carries no MFA context. A trust policy with conditions (aws:SourceArn,
// aws:SourceAccount, …) is not evaluated for the service, so the service's trust is not honoured on one: it
// fails closed rather than ignore a condition.
package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/metadata"
)

// serviceWorkload is a workload whose own web-identity token was proven, and the service that assumes a role
// for it.
type serviceWorkload struct {
	namespace string // the workload's namespace
	name      string // the workload's name (the default session name)
	role      string // the role it names: a role name or a role ARN ("" names none)
	username  string // its identity ServiceAccount's username
	// account is the workload's member account ("" for the management account's workload); home is that
	// member account's home namespace.
	account, home string
	suspended     bool
	service       string // the service principal a role trusts to be assumed for it
	serviceName   string // that service, as a message names it ("Lambda", "ECS")
	what          string // the workload, as a message names it ("function", "application")
}

// assumeServiceRole decides an AssumeRoleWithWebIdentity whose token is workload wl's own identity.
func (h *stsHandler) assumeServiceRole(w http.ResponseWriter, r *http.Request, wl serviceWorkload, sessionName, requestID string) {
	roleArn := r.PostFormValue("RoleArn")
	roleName := roleNameOf(roleArn)
	acct := wl.account
	if acct == "" {
		acct = h.account
	}
	who := trustCaller{kind: "ServiceAccount", name: wl.username, account: acct}
	deny := func(why string) {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			who.String()+" is not authorized to assume role "+roleName+" ("+why+")", stsXMLNamespace)
	}
	if wl.suspended {
		deny("the " + wl.what + "'s account is suspended")
		return
	}
	// A role of the workload's own account only: an ARN naming another account is never the workload's.
	if a := awsidentity.AccountOfARN(roleArn); a != "" && a != acct {
		deny("a role of another account")
		return
	}
	role, roleNS, ok := h.workloadRoleOf(r.Context(), wl.namespace, wl.account, wl.home, roleName)
	if !ok {
		// AWS answers AccessDenied (not "not found"), so a caller can't probe which roles exist.
		deny("not named by its trust policy")
		return
	}
	// The service assumes the role the workload names, when the role trusts the service (with no
	// conditions it would have to evaluate); any identity the role's trust names itself assumes it too.
	bySvc := trustsService(role.trust, wl.service) && namesRole(wl.role, roleName, acct)
	if bySvc && trustConditioned(role.trustDoc) {
		deny("its trust policy has conditions, which are not evaluated for the " + wl.serviceName + " service")
		return
	}
	if !bySvc && !trustedFrom(who, role.trust, acct) {
		deny("not named by its trust policy")
		return
	}
	if sessionName == "" {
		sessionName = wl.name
	}
	ttl, bad := sessionDuration(r, role, false)
	if bad != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, bad, stsXMLNamespace)
		return
	}
	// A web-identity session: in the workload's account, as its role (in roleNS), with no MFA context.
	akid, sk, tok, exp, err := h.minter.MintSession(awssts.Session{RoleName: roleName, Namespace: roleNS, Account: wl.account,
		Groups: role.groups, SessionName: sessionName, Caller: wl.username, Federated: true}, ttl, awssts.MaxDuration)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not mint credentials", stsXMLNamespace)
		return
	}
	h.writeWebIdentityIn(w, acct, roleName, sessionName, wl.username, akid, sk, tok, exp, requestID)
}

// workloadRoleOf finds a workload's role: in the workload's own namespace, else its account's IAM home (the
// management account's when account is ""). roleNS is the namespace the session records (the home's is ""
// for the management account).
func (h *stsHandler) workloadRoleOf(ctx context.Context, ns, account, home, roleName string) (role resolvedRole, roleNS string, ok bool) {
	in, canIn := h.roles.(roleResolverIn)
	if canIn {
		if role, ok = in.ResolveIn(ctx, ns, roleName); ok {
			return role, ns, true
		}
	}
	if account == "" {
		role, ok = h.roles.Resolve(ctx, roleName)
		return role, "", ok
	}
	if !canIn || home == "" {
		return resolvedRole{}, "", false
	}
	role, ok = in.ResolveIn(ctx, home, roleName)
	return role, home, ok
}

// namesRole reports whether a workload's role field (a function's spec.role, an application's
// spec.assumeRole) names role of account acct: by name, or by an ARN of that account (a role's object is
// its lower-cased AWS name, so the comparison ignores case).
func namesRole(spec, role, acct string) bool {
	if spec == "" {
		return false
	}
	if a := awsidentity.AccountOfARN(spec); strings.HasPrefix(spec, "arn:") && a != acct {
		return false
	}
	return strings.EqualFold(roleNameOf(spec), role)
}

// podDeployment follows a pod's controller chain by owner references — its controller a ReplicaSet, whose
// controller is a Deployment — and returns that Deployment's metadata. Owner references are set by the
// controllers that create the objects (a pod's by its ReplicaSet, a ReplicaSet's by its Deployment), and
// each reference's UID must be the object's, so a pod's labels alone are never the proof. The objects are
// read as metadata only: their specs carry the workload's environment. Fails closed.
func podDeployment(ctx context.Context, meta metadata.Interface, ns string, owners []metav1.OwnerReference) (*metav1.PartialObjectMetadata, bool) {
	rsRef := metav1.GetControllerOfNoCopy(&metav1.ObjectMeta{OwnerReferences: owners})
	if rsRef == nil || rsRef.Kind != "ReplicaSet" || rsRef.APIVersion != "apps/v1" {
		return nil, false
	}
	rs, err := meta.Resource(replicaSetsGVR).Namespace(ns).Get(ctx, rsRef.Name, metav1.GetOptions{})
	if err != nil || rs.UID != rsRef.UID {
		return nil, false
	}
	depRef := metav1.GetControllerOfNoCopy(rs)
	if depRef == nil || depRef.Kind != "Deployment" || depRef.APIVersion != "apps/v1" {
		return nil, false
	}
	dep, err := meta.Resource(deploymentsGVR).Namespace(ns).Get(ctx, depRef.Name, metav1.GetOptions{})
	if err != nil || dep.UID != depRef.UID {
		return nil, false
	}
	return dep, true
}
