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
// says which, in the TokenReview; it issues a pod-bound token only for the pod's own ServiceAccount), and
// that pod must be one Knative runs for that function: its controller chain (pod → ReplicaSet → Deployment)
// ends at a Knative Revision, the Deployment carrying Knative's serving.knative.dev/service=<function> label
// — owner references only the controllers that create those objects set, so a pod's own labels are never
// the proof. The ServiceAccount carries the composition's openinfra.dev/function=<function> label. The
// kind: Function of that name in the pod's namespace then names the role (its spec.role, whose naming took
// iam:PassRole on it).
//
// The pod, its ReplicaSet and its Deployment are read as METADATA only (PartialObjectMetadata: name, UID,
// labels, owner references): their specs carry the function's environment, which may hold secret values,
// and the shim never asks for it.
//
// The role is a kind: Role of the function's own account: in the function's namespace (where a
// CloudFormation stack puts the role it creates beside its function), else in the account's IAM home
// (where the IAM API creates roles). A role ARN naming any other account is never the function's. The role
// is assumed when its trust names lambda.amazonaws.com and the function's spec.role names it, or when its
// trust names the function's identity itself (system:serviceaccount:<namespace>:fn-<function>), or "*".
// The session is the function's account's, named after the function (assumed-role/<role>/<function>), as
// Lambda names it; like any web-identity session it carries no MFA context. A trust policy with conditions
// (aws:SourceArn, aws:SourceAccount, …) is not evaluated for the Lambda service, so Lambda's trust is not
// honoured on one: it fails closed rather than ignore a condition.
package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
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
// identity path does), then reads the metadata of the pod it is bound to and of that pod's controllers, the
// ServiceAccount and the kind: Function. Fails closed on any error.
type k8sFunctionIdentities struct {
	cs       kubernetes.Interface
	dyn      dynamic.Interface
	meta     metadata.Interface // metadata-only reads of the pod, its ReplicaSet and its Deployment
	audience string
	accounts vmAccounts // the accounts directory; nil: every function is the management account's
}

var (
	podsGVR        = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	replicaSetsGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	deploymentsGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
)

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
	// A pod-bound token is issued only for the pod's own ServiceAccount, so the pod runs as sa.
	pod, err := f.meta.Resource(podsGVR).Namespace(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != podUID || pod.Labels[knativeServiceLabel] != fn {
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
	dep, ok := podDeployment(ctx, f.meta, ns, owners)
	if !ok || dep.Labels[knativeServiceLabel] != fn {
		return false
	}
	revRef := metav1.GetControllerOfNoCopy(dep)
	return revRef != nil && revRef.Kind == "Revision" && revRef.APIVersion == "serving.knative.dev/v1"
}

// assumeFunctionRole decides an AssumeRoleWithWebIdentity whose token is function fn's own identity: Lambda
// assumes the role its spec.role names when the role trusts lambda.amazonaws.com (service_role.go).
func (h *stsHandler) assumeFunctionRole(w http.ResponseWriter, r *http.Request, fn functionIdentity, sessionName, requestID string) {
	h.assumeServiceRole(w, r, serviceWorkload{namespace: fn.namespace, name: fn.name, role: fn.role, username: fn.username,
		account: fn.account, home: fn.home, suspended: fn.suspended,
		service: lambdaService, serviceName: "Lambda", what: "function"}, sessionName, requestID)
}

// trustConditioned reports whether a trust policy, as written, has a statement with a Condition (or does not
// parse, which never widens a trust).
func trustConditioned(doc string) bool {
	if doc == "" {
		return false
	}
	var d struct {
		Statement json.RawMessage
	}
	if json.Unmarshal([]byte(doc), &d) != nil {
		return true
	}
	var many []map[string]json.RawMessage
	if json.Unmarshal(d.Statement, &many) != nil {
		var one map[string]json.RawMessage
		if json.Unmarshal(d.Statement, &one) != nil {
			return true
		}
		many = []map[string]json.RawMessage{one}
	}
	for _, st := range many {
		if _, ok := st["Condition"]; ok {
			return true
		}
	}
	return false
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
