// ECS task roles: a kind: Application's spec.assumeRole, assumed for the application the way ECS assumes a
// task's role.
//
// On AWS a task role trusts the ECS tasks service (ecs-tasks.amazonaws.com); ECS assumes it for every task
// of a task definition that names it (TaskRoleArn, whose naming took iam:PassRole) and hands the task its
// temporary credentials. An Application is an ECS service and its pods are its tasks: the application
// composition runs them as the app's own ServiceAccount, named after the app, with a projected token for
// this shim's STS audience and the AWS SDK's web-identity environment (AWS_ROLE_ARN in the app's account,
// AWS_WEB_IDENTITY_TOKEN_FILE). The SDK calls sts:AssumeRoleWithWebIdentity with that token, and this file
// decides when the token is the app's own: the role it may assume on ECS's trust is the one that app names,
// in the app's account (service_role.go).
//
// The identity is the app's own and cannot be borrowed. ServiceAccount names are predictable and any pod of
// the namespace may run as one, so a token for the app's ServiceAccount is not enough. The token must be
// bound to a pod (the API server says which, in the TokenReview; it issues a pod-bound token only for the
// pod's own ServiceAccount), and that pod must be one of the app's Deployment: its controller chain
// (pod → ReplicaSet → Deployment, by owner references, which only the controllers that create those objects
// set) ends at the Deployment the composition renders for the app — named after the app, labelled with it,
// and run by no controller of its own (provider-kubernetes applies it and sets no owner reference, so a
// Deployment a Knative Revision or any other controller runs is never an app's). The pod and the
// ServiceAccount carry the composition's labels for the app (app.kubernetes.io/name, and on the
// ServiceAccount openinfra.dev/application). The kind: Application of that name in the pod's namespace then
// names the role (its spec.assumeRole, whose naming took iam:PassRole on it — pass-role.yaml).
//
// The pod, its ReplicaSet and its Deployment are read as METADATA only (name, UID, labels, owner
// references): their specs carry the app's environment, which may hold secret values.
//
// A token that is not an app's own — any other workload's, a pod that merely runs as the ServiceAccount, an
// app whose ServiceAccount the composition has not labelled yet — is decided as before, by the role's trust
// naming it (sts.go). The session is named by the request's RoleSessionName (the composition sets the pod's
// name, as ECS names a task role's session after the task), else after the app.
package main

import (
	"context"
	"net/http"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
)

const (
	// appIdentityLabel is the label the application composition puts on an app's identity ServiceAccount:
	// the app's name.
	appIdentityLabel = "openinfra.dev/application"
	// appNameLabel is the label the composition puts on an app's Deployment and its pods: the app's name.
	appNameLabel = "app.kubernetes.io/name"
	// ecsTasksService is the service principal an ECS task role trusts.
	ecsTasksService = "ecs-tasks.amazonaws.com"
)

// applicationIdentity is the Application a web-identity token is the identity of.
type applicationIdentity struct {
	namespace string // the app's namespace
	name      string // the kind: Application's name (its ServiceAccount's and its Deployment's)
	role      string // its spec.assumeRole: a role name or a role ARN
	username  string // the identity's ServiceAccount username
	// account is the app's member account ("" for the management account's app); home is that member
	// account's home namespace.
	account, home string
	suspended     bool
}

// applicationIdentities resolves a web-identity token to the Application it is the identity of; ok=false
// when it is not an app's own (any other workload's, or a pod that merely runs as the ServiceAccount).
type applicationIdentities interface {
	applicationOf(ctx context.Context, token string) (applicationIdentity, bool)
}

// k8sApplicationIdentities verifies the token with a TokenReview (the shim's STS audience), then reads the
// app's identity ServiceAccount, the metadata of the pod the token is bound to and of that pod's
// controllers, and the kind: Application. Fails closed on any error.
type k8sApplicationIdentities struct {
	cs       kubernetes.Interface
	dyn      dynamic.Interface
	meta     metadata.Interface // metadata-only reads of the pod, its ReplicaSet and its Deployment
	audience string
	accounts vmAccounts // the accounts directory; nil: every app is the management account's
}

func (a *k8sApplicationIdentities) applicationOf(ctx context.Context, token string) (applicationIdentity, bool) {
	out, err := a.cs.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{a.audience}}}, metav1.CreateOptions{})
	if err != nil || !out.Status.Authenticated {
		return applicationIdentity{}, false
	}
	u := out.Status.User.Username
	ns, sa, ok := splitSAUsername(u)
	if !ok {
		return applicationIdentity{}, false
	}
	podName, podUID := firstExtra(out.Status.User.Extra, extraPodName), firstExtra(out.Status.User.Extra, extraPodUID)
	if podName == "" || podUID == "" {
		return applicationIdentity{}, false // not a pod-bound token: no pod to check it against
	}
	// The app's identity ServiceAccount is labelled with the app by the composition; any other
	// ServiceAccount is no app's identity (and costs no further read).
	acct, err := a.cs.CoreV1().ServiceAccounts(ns).Get(ctx, sa, metav1.GetOptions{})
	if err != nil || acct.Labels[appIdentityLabel] != sa {
		return applicationIdentity{}, false
	}
	// A pod-bound token is issued only for the pod's own ServiceAccount, so the pod runs as sa.
	pod, err := a.meta.Resource(podsGVR).Namespace(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != podUID || pod.Labels[appNameLabel] != sa {
		return applicationIdentity{}, false
	}
	dep, ok := podDeployment(ctx, a.meta, ns, pod.OwnerReferences)
	if !ok || dep.Name != sa || dep.Labels[appNameLabel] != sa || metav1.GetControllerOfNoCopy(dep) != nil {
		return applicationIdentity{}, false
	}
	claim, err := a.dyn.Resource(applicationGVR).Namespace(ns).Get(ctx, sa, metav1.GetOptions{})
	if err != nil {
		return applicationIdentity{}, false
	}
	role, _, _ := unstructured.NestedString(claim.Object, "spec", "assumeRole")
	id := applicationIdentity{namespace: ns, name: sa, role: role, username: u}
	if a.accounts != nil {
		if a.accounts.AccountOf(ns) == "" {
			return applicationIdentity{}, false // a platform namespace is no account's
		}
		id.account, id.home = vmMemberAccount(a.accounts, ns)
		id.suspended = id.account != "" && a.accounts.Suspended(id.account)
	}
	return id, true
}

// assumeApplicationRole decides an AssumeRoleWithWebIdentity whose token is application app's own identity:
// ECS assumes the role its spec.assumeRole names when the role trusts ecs-tasks.amazonaws.com
// (service_role.go).
func (h *stsHandler) assumeApplicationRole(w http.ResponseWriter, r *http.Request, app applicationIdentity, sessionName, requestID string) {
	h.assumeServiceRole(w, r, serviceWorkload{namespace: app.namespace, name: app.name, role: app.role, username: app.username,
		account: app.account, home: app.home, suspended: app.suspended,
		service: ecsTasksService, serviceName: "ECS", what: "application"}, sessionName, requestID)
}
