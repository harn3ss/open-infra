// Lambda execution roles: a kind: Function's spec.role, assumed for the function the way Lambda assumes a
// function's role.
//
// On AWS a function's execution role trusts the Lambda service (lambda.amazonaws.com); Lambda assumes it
// and hands the function its temporary credentials. Here the function composition runs the function's
// pods as their own ServiceAccount, fn-<function>, with a projected token for this shim's STS audience and
// the AWS SDK's web-identity environment (AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE). The SDK calls
// sts:AssumeRoleWithWebIdentity with that token, and this file decides it: the token's ServiceAccount is the
// identity of the function, so the role it may assume on Lambda's trust is the one that function names.
//
// The identity is the function's own and cannot be borrowed. ServiceAccount names are predictable, and
// another workload can run as a ServiceAccount of a chosen name (an Application runs as one named after
// it), so a token for fn-<function> is not enough. The token must also be bound to a pod (the API server
// says which, in the TokenReview), and that pod must be one Knative runs for that function: its controller
// chain (pod → ReplicaSet → Deployment) ends at a Knative Revision, the Deployment carrying Knative's
// serving.knative.dev/service=<function> label — owner references only the controllers that create those
// objects set, so a pod's own labels are never the proof — and it must run as that ServiceAccount, which
// carries the composition's openinfra.dev/function=<function> label. The kind: Function of that name
// in the pod's namespace then names the role (its spec.role, whose naming took iam:PassRole on it).
//
// The role is a kind: Role of the function's own account: in the function's namespace (where a
// CloudFormation stack puts the role it creates beside its function), else in the account's IAM home
// (where the IAM API creates roles). A role ARN naming any other account is never the function's. The role
// is assumed when its trust names lambda.amazonaws.com and the function's spec.role names it, or when its
// trust names the function's identity itself (system:serviceaccount:<namespace>:fn-<function>), or "*".
// The session is the function's account's, named after the function (assumed-role/<role>/<function>), as
// Lambda names it.
package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	// fnIdentityPrefix names a function's identity ServiceAccount: fn-<function> (function-composition.yaml).
	fnIdentityPrefix = "fn-"
	// fnIdentityLabel is the label the function composition puts on that ServiceAccount: the function's name.
	fnIdentityLabel = "openinfra.dev/function"
	// knativeServiceLabel is the label Knative puts on every pod of a Knative Service's revisions.
	knativeServiceLabel = "serving.knative.dev/service"
	// lambdaService is the service principal a Lambda execution role trusts.
	lambdaService = "lambda.amazonaws.com"
)

// functionIdentity is the Lambda function a web-identity token is the execution identity of.
type functionIdentity struct {
	namespace string // the function's namespace
	name      string // the kind: Function's name
	role      string // its spec.role: a role name or a role ARN
	username  string // the identity's ServiceAccount username
	// account is the function's member account ("" for the management account's function); home is that
	// member account's home namespace.
	account, home string
	suspended     bool
}

// functionIdentities resolves a web-identity token to the function it is the identity of; ok=false when it
// is not a function's own (any other workload's, or a pod that merely runs as the ServiceAccount).
type functionIdentities interface {
	functionOf(ctx context.Context, token string) (functionIdentity, bool)
}

// isFunctionIdentity reports whether a ServiceAccount username names a function identity ServiceAccount.
func isFunctionIdentity(username string) bool {
	_, sa, ok := splitSAUsername(username)
	return ok && strings.HasPrefix(sa, fnIdentityPrefix) && len(sa) > len(fnIdentityPrefix)
}

// splitSAUsername splits "system:serviceaccount:<ns>:<sa>".
func splitSAUsername(u string) (ns, sa string, ok bool) {
	const pfx = "system:serviceaccount:"
	if !strings.HasPrefix(u, pfx) {
		return "", "", false
	}
	ns, sa, ok = strings.Cut(strings.TrimPrefix(u, pfx), ":")
	return ns, sa, ok && ns != "" && sa != ""
}

// k8sFunctionIdentities verifies the token with a TokenReview (the shim's STS audience, as the workload
// identity path does), then reads the pod it is bound to, the ServiceAccount and the kind: Function. Fails
// closed on any error.
type k8sFunctionIdentities struct {
	cs       kubernetes.Interface
	dyn      dynamic.Interface
	audience string
	accounts vmAccounts // the accounts directory; nil: every function is the management account's
}

func (f *k8sFunctionIdentities) functionOf(ctx context.Context, token string) (functionIdentity, bool) {
	out, err := f.cs.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{f.audience}}}, metav1.CreateOptions{})
	if err != nil || !out.Status.Authenticated {
		return functionIdentity{}, false
	}
	u := out.Status.User.Username
	ns, sa, ok := splitSAUsername(u)
	if !ok || !isFunctionIdentity(u) {
		return functionIdentity{}, false
	}
	fn := strings.TrimPrefix(sa, fnIdentityPrefix)
	podName, podUID := firstExtra(out.Status.User.Extra, extraPodName), firstExtra(out.Status.User.Extra, extraPodUID)
	if podName == "" || podUID == "" {
		return functionIdentity{}, false // not a pod-bound token: no pod to check it against
	}
	pod, err := f.cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != podUID || pod.Labels[knativeServiceLabel] != fn || pod.Spec.ServiceAccountName != sa {
		return functionIdentity{}, false
	}
	if !f.knativeRevisionPod(ctx, ns, fn, pod.OwnerReferences) {
		return functionIdentity{}, false
	}
	acct, err := f.cs.CoreV1().ServiceAccounts(ns).Get(ctx, sa, metav1.GetOptions{})
	if err != nil || acct.Labels[fnIdentityLabel] != fn {
		return functionIdentity{}, false
	}
	claim, err := f.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, fn, metav1.GetOptions{})
	if err != nil {
		return functionIdentity{}, false
	}
	role, _, _ := unstructured.NestedString(claim.Object, "spec", "role")
	id := functionIdentity{namespace: ns, name: fn, role: role, username: u}
	if f.accounts != nil {
		if f.accounts.AccountOf(ns) == "" {
			return functionIdentity{}, false // a platform namespace is no account's
		}
		id.account, id.home = vmMemberAccount(f.accounts, ns)
		id.suspended = id.account != "" && f.accounts.Suspended(id.account)
	}
	return id, true
}

// knativeRevisionPod reports whether a pod with these owner references is one Knative runs for function
// fn: its controller is a ReplicaSet whose controller is a Deployment whose controller is a Knative
// Revision, and that Deployment carries Knative's serving.knative.dev/service=<fn>. Owner references are
// set by the controllers that create the objects (a pod's by its ReplicaSet, a ReplicaSet's by its
// Deployment, the Deployment's by Knative), so a pod's labels alone are never the proof. Fails closed.
func (f *k8sFunctionIdentities) knativeRevisionPod(ctx context.Context, ns, fn string, owners []metav1.OwnerReference) bool {
	rsRef := metav1.GetControllerOfNoCopy(&metav1.ObjectMeta{OwnerReferences: owners})
	if rsRef == nil || rsRef.Kind != "ReplicaSet" || rsRef.APIVersion != "apps/v1" {
		return false
	}
	rs, err := f.cs.AppsV1().ReplicaSets(ns).Get(ctx, rsRef.Name, metav1.GetOptions{})
	if err != nil || rs.UID != rsRef.UID {
		return false
	}
	depRef := metav1.GetControllerOfNoCopy(rs)
	if depRef == nil || depRef.Kind != "Deployment" || depRef.APIVersion != "apps/v1" {
		return false
	}
	dep, err := f.cs.AppsV1().Deployments(ns).Get(ctx, depRef.Name, metav1.GetOptions{})
	if err != nil || dep.UID != depRef.UID || dep.Labels[knativeServiceLabel] != fn {
		return false
	}
	revRef := metav1.GetControllerOfNoCopy(dep)
	return revRef != nil && revRef.Kind == "Revision" && revRef.APIVersion == "serving.knative.dev/v1"
}

// namesRole reports whether a function's spec.role names role of account acct: by name, or by an ARN of
// that account (a role's object is its lower-cased AWS name, so the comparison ignores case).
func namesRole(spec, role, acct string) bool {
	if spec == "" {
		return false
	}
	if a := awsidentity.AccountOfARN(spec); strings.HasPrefix(spec, "arn:") && a != acct {
		return false
	}
	return strings.EqualFold(roleNameOf(spec), role)
}

// assumeFunctionRole decides an AssumeRoleWithWebIdentity whose token is function fn's own identity.
func (h *stsHandler) assumeFunctionRole(w http.ResponseWriter, r *http.Request, fn functionIdentity, sessionName, requestID string) {
	roleArn := r.PostFormValue("RoleArn")
	roleName := roleNameOf(roleArn)
	acct := fn.account
	if acct == "" {
		acct = h.account
	}
	who := trustCaller{kind: "ServiceAccount", name: fn.username, account: acct}
	deny := func(why string) {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			who.String()+" is not authorized to assume role "+roleName+" ("+why+")", stsXMLNamespace)
	}
	if fn.suspended {
		deny("the function's account is suspended")
		return
	}
	// A role of the function's own account only: an ARN naming another account is never the function's.
	if a := awsidentity.AccountOfARN(roleArn); a != "" && a != acct {
		deny("a role of another account")
		return
	}
	role, roleNS, ok := h.functionRoleOf(r.Context(), fn, roleName)
	if !ok {
		// AWS answers AccessDenied (not "not found"), so a caller can't probe which roles exist.
		deny("not named by its trust policy")
		return
	}
	// Lambda assumes the role the function names, when the role trusts Lambda; any identity the role's
	// trust names itself assumes it too.
	if !(trustsService(role.trust, lambdaService) && namesRole(fn.role, roleName, acct)) && !trustedFrom(who, role.trust, acct) {
		deny("not named by its trust policy")
		return
	}
	if sessionName == "" {
		sessionName = fn.name
	}
	ttl, bad := sessionDuration(r, role, false)
	if bad != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, bad, stsXMLNamespace)
		return
	}
	akid, sk, tok, exp, err := h.minter.MintInAccount(fn.account, roleNS, roleName, role.groups, sessionName, fn.username, ttl)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not mint credentials", stsXMLNamespace)
		return
	}
	h.writeWebIdentityIn(w, acct, roleName, sessionName, fn.username, akid, sk, tok, exp, requestID)
}

// functionRoleOf finds a function's role: in the function's own namespace, else its account's IAM home.
// roleNS is the namespace the session records (the home's is "" for the management account).
func (h *stsHandler) functionRoleOf(ctx context.Context, fn functionIdentity, roleName string) (role resolvedRole, roleNS string, ok bool) {
	in, canIn := h.roles.(roleResolverIn)
	if canIn {
		if role, ok = in.ResolveIn(ctx, fn.namespace, roleName); ok {
			return role, fn.namespace, true
		}
	}
	if fn.account == "" {
		role, ok = h.roles.Resolve(ctx, roleName)
		return role, "", ok
	}
	if !canIn || fn.home == "" {
		return resolvedRole{}, "", false
	}
	role, ok = in.ResolveIn(ctx, fn.home, roleName)
	return role, fn.home, ok
}

// writeWebIdentityIn is writeWebIdentity for a role of account acct: the session's ARN is that account's.
func (h *stsHandler) writeWebIdentityIn(w http.ResponseWriter, acct, role, session, subject, akid, sk, token string, exp time.Time, requestID string) {
	var resp assumeRoleWithWebIdentityResponse
	resp.Result.Credentials.AccessKeyId = akid
	resp.Result.Credentials.SecretAccessKey = sk
	resp.Result.Credentials.SessionToken = token
	resp.Result.Credentials.Expiration = exp.UTC().Format(time.RFC3339)
	resp.Result.AssumedRoleUser.Arn = h.identIn(acct).STSARN("assumed-role/" + role + "/" + session)
	resp.Result.AssumedRoleUser.AssumedRoleId = role + ":" + session
	resp.Result.SubjectFromWebIdentityToken = subject
	resp.Result.Provider = "openinfra:serviceaccount"
	resp.ResponseMetadata.RequestId = requestID
	out, err := xml.Marshal(resp)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "internal error", stsXMLNamespace)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}
