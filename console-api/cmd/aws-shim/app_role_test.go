package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"
)

// --- the identity: a token is an app's own only when its pod is one of the app's Deployment ---

// appPod is a pod of app's Deployment, as the composition renders it (Deployment <app>, labelled with the
// app, owned by no controller) and the ReplicaSet controller runs it. It returns the pod, its ReplicaSet and
// its Deployment.
func appPod(ns, name, uid, app, sa string) []runtime.Object {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: app, UID: types.UID("dep-" + uid),
		Labels: map[string]string{appNameLabel: app}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: app + "-" + uid, UID: types.UID("rs-" + uid),
		Labels: map[string]string{appNameLabel: app}, OwnerReferences: controller("apps/v1", "Deployment", dep.Name, string(dep.UID))}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid),
		Labels: map[string]string{appNameLabel: app}, OwnerReferences: controller("apps/v1", "ReplicaSet", rs.Name, string(rs.UID))},
		Spec: corev1.PodSpec{ServiceAccountName: sa}}
	return []runtime.Object{pod, rs, dep}
}

func appSA(ns, name, app string) *corev1.ServiceAccount {
	labels := map[string]string{appNameLabel: name}
	if app != "" {
		labels[appIdentityLabel] = app
	}
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels}}
}

func appClaim(ns, name, role string) *unstructured.Unstructured {
	spec := map[string]any{"image": "ghcr.io/me/app:1"}
	if role != "" {
		spec["assumeRole"] = role
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Application",
		"metadata": map[string]any{"namespace": ns, "name": name}, "spec": spec}}
}

func applicationIdentitiesWith(t *testing.T, tokens map[string]reviewedToken, objs []runtime.Object, claims ...*unstructured.Unstructured) *k8sApplicationIdentities {
	t.Helper()
	// Pods, ReplicaSets and Deployments are served as metadata only, as the shim reads them; anything else
	// (the ServiceAccounts) through the typed client.
	var typed, metas []runtime.Object
	for _, o := range objs {
		var om metav1.ObjectMeta
		var tm metav1.TypeMeta
		switch v := o.(type) {
		case *corev1.Pod:
			om, tm = v.ObjectMeta, metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}
		case *appsv1.ReplicaSet:
			om, tm = v.ObjectMeta, metav1.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"}
		case *appsv1.Deployment:
			om, tm = v.ObjectMeta, metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}
		default:
			typed = append(typed, o)
			continue
		}
		metas = append(metas, &metav1.PartialObjectMetadata{TypeMeta: tm, ObjectMeta: om})
	}
	scheme := runtime.NewScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	md := metadatafake.NewSimpleMetadataClient(scheme, metas...)
	cs := fake.NewSimpleClientset(typed...)
	cs.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		tr := a.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		out := tr.DeepCopy()
		if len(tr.Spec.Audiences) != 1 || tr.Spec.Audiences[0] != "sts.openinfra" {
			return true, out, nil // a token is reviewed for the STS audience only
		}
		if rt, ok := tokens[tr.Spec.Token]; ok {
			out.Status.Authenticated = true
			out.Status.User.Username = rt.user
			out.Status.User.Extra = map[string]authnv1.ExtraValue{}
			if rt.podName != "" {
				out.Status.User.Extra[extraPodName] = authnv1.ExtraValue{rt.podName}
			}
			if rt.podID != "" {
				out.Status.User.Extra[extraPodUID] = authnv1.ExtraValue{rt.podID}
			}
		}
		return true, out, nil
	})
	dobjs := make([]runtime.Object, 0, len(claims))
	for _, c := range claims {
		dobjs = append(dobjs, c)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{applicationGVR: "ApplicationList"}, dobjs...)
	return &k8sApplicationIdentities{cs: cs, dyn: dyn, meta: md, audience: "sts.openinfra", accounts: testDirectory()}
}

// Only a pod of the app's own Deployment, running as the app's identity ServiceAccount, is the app. A pod
// of another Deployment running as that ServiceAccount (one made by hand, or a Deployment named after the
// app that a Knative Revision runs), a pod with no controllers, a token not bound to a pod, a ServiceAccount
// the composition did not label, an app that no longer exists and an app in a platform namespace are not.
func TestApplicationIdentity_OnlyTheAppsOwnPod(t *testing.T) {
	const ns, sa = "shop", "web"
	user := "system:serviceaccount:" + ns + ":" + sa
	tokens := map[string]reviewedToken{
		"app-pod":          {user: user, podName: "web-6c8d-abc", podID: "uid-app"},
		"handmade-dep":     {user: user, podName: "web-copy-1-xyz", podID: "uid-copy"},
		"revision-dep":     {user: "system:serviceaccount:shop:svc", podName: "svc-00001-deployment-1-a", podID: "uid-rev"},
		"unlabelled-pod":   {user: user, podName: "web-6c8d-nolbl", podID: "uid-nolbl"},
		"unlabelled-dep":   {user: "system:serviceaccount:shop:api", podName: "api-1-a", podID: "uid-api"},
		"bare-pod":         {user: user, podName: "web-bare", podID: "uid-bare"},
		"wrong-uid":        {user: user, podName: "web-6c8d-abc", podID: "uid-other"},
		"unbound":          {user: user},
		"unlabelled-sa":    {user: "system:serviceaccount:shop:handmade", podName: "handmade-1-a", podID: "uid-hand"},
		"no-such-app":      {user: "system:serviceaccount:shop:gone", podName: "gone-1-a", podID: "uid-gone"},
		"platform-ns":      {user: "system:serviceaccount:knative-serving:x", podName: "x-1-a", podID: "uid-x"},
		"roleless":         {user: "system:serviceaccount:shop:plain", podName: "plain-1-a", podID: "uid-plain"},
		"function-sa":      {user: "system:serviceaccount:shop:fn-orders", podName: "fn-orders-1-a", podID: "uid-fn"},
		"not-an-sa":        {user: "alice", podName: "web-6c8d-abc", podID: "uid-app"},
		"reviewed-elsewhr": {user: user, podName: "web-6c8d-abc"},
	}
	var objs []runtime.Object
	objs = append(objs, appPod(ns, "web-6c8d-abc", "uid-app", "web", sa)...)
	// A Deployment made by hand, its pods running as the app's ServiceAccount and carrying the app's label.
	copyObjs := appPod(ns, "web-copy-1-xyz", "uid-copy", "web-copy", sa)
	copyObjs[0].(*corev1.Pod).Labels[appNameLabel] = "web"
	objs = append(objs, copyObjs...)
	// A Deployment named after an app (svc) but run by a Knative Revision.
	revObjs := appPod(ns, "svc-00001-deployment-1-a", "uid-rev", "svc", "svc")
	revObjs[2].(*appsv1.Deployment).OwnerReferences = controller("serving.knative.dev/v1", "Revision", "svc-00001", "rev-1")
	objs = append(objs, revObjs...)
	// The app's pod without the app's label (owner chain intact).
	nolbl := appPod(ns, "web-6c8d-nolbl", "uid-nolbl", "web", sa)
	delete(nolbl[0].(*corev1.Pod).Labels, appNameLabel)
	objs = append(objs, nolbl[0])
	// An app (api) whose Deployment lost its label.
	apiObjs := appPod(ns, "api-1-a", "uid-api", "api", "api")
	delete(apiObjs[2].(*appsv1.Deployment).Labels, appNameLabel)
	objs = append(objs, apiObjs...)
	objs = append(objs, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "web-bare", UID: "uid-bare", Labels: map[string]string{appNameLabel: "web"}}})
	objs = append(objs, appPod(ns, "handmade-1-a", "uid-hand", "handmade", "handmade")...)
	objs = append(objs, appPod(ns, "gone-1-a", "uid-gone", "gone", "gone")...)
	objs = append(objs, appPod("knative-serving", "x-1-a", "uid-x", "x", "x")...)
	objs = append(objs, appPod(ns, "plain-1-a", "uid-plain", "plain", "plain")...)
	objs = append(objs, appPod(ns, "fn-orders-1-a", "uid-fn", "fn-orders", "fn-orders")...)
	objs = append(objs, appSA(ns, sa, "web"), appSA(ns, "svc", "svc"), appSA(ns, "api", "api"), appSA(ns, "handmade", ""),
		appSA(ns, "gone", "gone"), appSA("knative-serving", "x", "x"), appSA(ns, "plain", "plain"), fnSA(ns, "fn-orders", "orders"))
	a := applicationIdentitiesWith(t, tokens, objs,
		appClaim(ns, "web", "web-reader"), appClaim(ns, "svc", "web-reader"), appClaim(ns, "api", "web-reader"),
		appClaim(ns, "handmade", "web-reader"), appClaim("knative-serving", "x", "web-reader"), appClaim(ns, "plain", ""))
	for tok, want := range map[string]bool{
		"app-pod":      true,
		"handmade-dep": false, "revision-dep": false, "unlabelled-pod": false, "unlabelled-dep": false, "bare-pod": false,
		"wrong-uid": false, "unbound": false, "unlabelled-sa": false, "no-such-app": false, "platform-ns": false,
		"function-sa": false, "not-an-sa": false, "reviewed-elsewhr": false, "unknown": false,
	} {
		id, ok := a.applicationOf(context.Background(), tok)
		if ok != want {
			t.Errorf("token %q: application identity = %v, want %v (%+v)", tok, ok, want, id)
		}
	}
	// An app with no task role is its identity, but names no role (so no ECS-trusting role is its).
	if id, ok := a.applicationOf(context.Background(), "roleless"); !ok || id.role != "" {
		t.Errorf("a role-less app: %+v %v", id, ok)
	}
	id, _ := a.applicationOf(context.Background(), "app-pod")
	if id.namespace != ns || id.name != "web" || id.role != "web-reader" || id.username != user || id.account != "" {
		t.Errorf("the app's identity: %+v", id)
	}
}

// A member account's app is that account's, with its home; a suspended account's app is marked so.
func TestApplicationIdentity_MemberAccount(t *testing.T) {
	user := "system:serviceaccount:" + memberHome + ":web"
	a := applicationIdentitiesWith(t, map[string]reviewedToken{"t": {user: user, podName: "web-1-a", podID: "u"},
		"s": {user: "system:serviceaccount:team-b:web", podName: "web-1-b", podID: "v"}},
		append(append(appPod(memberHome, "web-1-a", "u", "web", "web"), appSA(memberHome, "web", "web"), appSA("team-b", "web", "web")),
			appPod("team-b", "web-1-b", "v", "web", "web")...),
		appClaim(memberHome, "web", "reader"), appClaim("team-b", "web", "reader"))
	id, ok := a.applicationOf(context.Background(), "t")
	if !ok || id.account != testMember || id.home != memberHome || id.suspended {
		t.Fatalf("a member account's app: %+v %v", id, ok)
	}
	if id, ok := a.applicationOf(context.Background(), "s"); !ok || !id.suspended {
		t.Errorf("a suspended account's app: %+v %v", id, ok)
	}
}

// --- the assume: ECS's trust, the app's own role, its own account ---

type fakeApplications map[string]applicationIdentity // token -> the app it is the identity of

func (f fakeApplications) applicationOf(_ context.Context, tok string) (applicationIdentity, bool) {
	id, ok := f[tok]
	return id, ok
}

func applicationSTS(t *testing.T, mgmt, member fakeRoles, apps fakeApplications, reviewer fakeReviewer) *stsHandler {
	t.Helper()
	return &stsHandler{account: testMgmt, minter: testMinter(t), roles: fakeRolesIn{fakeRoles: mgmt, in: member},
		webID: reviewer, applications: apps, accounts: testDirectory(), logger: discardLogger()}
}

const webUser = "system:serviceaccount:shop:web"

func webApp() applicationIdentity {
	return applicationIdentity{namespace: "shop", name: "web", role: "web-reader", username: webUser}
}

var ecsTrust = []string{"Service::ecs-tasks.amazonaws.com"}

// The app's identity assumes the role its spec.assumeRole names when the role trusts ecs-tasks.amazonaws.com:
// a session of the role in the app's account, named by the request (the pod, as the composition sets it),
// else after the app.
func TestApplicationRole_ECSTrustedRoleTheAppNames(t *testing.T) {
	h := applicationSTS(t, fakeRoles{"web-reader": {trust: ecsTrust, groups: []string{"openinfra:users"}}},
		nil, fakeApplications{"tok": webApp()}, fakeReviewer{"tok": webUser})
	w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/web-reader", "tok", "web-6c8d-abc")
	if w.Code != http.StatusOK {
		t.Fatalf("the app's own role: %d %s", w.Code, w.Body)
	}
	var resp assumeRoleWithWebIdentityResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if got := resp.Result.AssumedRoleUser.Arn; got != "arn:aws:sts::"+testMgmt+":assumed-role/web-reader/web-6c8d-abc" {
		t.Errorf("session ARN %q", got)
	}
	sess, ok := h.minter.Verify(resp.Result.Credentials.AccessKeyId, resp.Result.Credentials.SessionToken)
	if !ok || sess.RoleName != "web-reader" || sess.Account != "" || sess.Caller != webUser || !sess.Federated || sess.MFA {
		t.Errorf("the session: %+v %v", sess, ok)
	}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/web-reader", "tok", ""); !strings.Contains(w.Body.String(), "assumed-role/web-reader/web<") {
		t.Errorf("default session name: %s", w.Body)
	}
	// An ARN in the app's spec names the role too, in any case (the role's object is its lower-cased name).
	app := webApp()
	app.role = "arn:aws:iam::" + testMgmt + ":role/Web-Reader"
	h.applications = fakeApplications{"tok": app}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/web-reader", "tok", ""); w.Code != http.StatusOK {
		t.Errorf("a spec ARN naming the role: %d %s", w.Code, w.Body)
	}
}

// ECS's trust admits only the role the app names: not another app's role, nor this one's for any other
// workload. A pod that runs as the identity but is not the app's falls to the ordinary path, where a
// service's trust names nobody. Lambda's trust is a function's, never an app's.
func TestApplicationRole_ECSTrustIsOnlyTheAppsOwnRole(t *testing.T) {
	roles := fakeRoles{
		"web-reader":    {trust: ecsTrust},
		"billing-write": {trust: ecsTrust},
		"lambda-role":   {trust: []string{"Service::lambda.amazonaws.com"}},
	}
	h := applicationSTS(t, roles, nil, fakeApplications{"tok": webApp()},
		fakeReviewer{"tok": webUser, "borrowed": webUser, "other": "system:serviceaccount:shop:api"})
	for _, c := range []struct{ role, tok, why string }{
		{"billing-write", "tok", "another app's role"},
		{"web-reader", "borrowed", "a pod that only runs as the identity"},
		{"web-reader", "other", "another workload"},
	} {
		if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/"+c.role, c.tok, ""); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("%s must be AccessDenied, got %d %s", c.why, w.Code, w.Body)
		}
	}
	app := webApp()
	app.role = "lambda-role"
	h.applications = fakeApplications{"tok": app}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/lambda-role", "tok", ""); w.Code != http.StatusForbidden {
		t.Errorf("a Lambda-trusting role is no app's task role: %d %s", w.Code, w.Body)
	}
	// And ECS's trust is no function's execution role.
	fh := functionSTS(t, fakeRoles{"orders-reader": {trust: ecsTrust}}, nil, fakeFunctions{"tok": ordersFunction()}, fakeReviewer{"tok": ordersUser})
	if w := fnWebIdentity(fh, "arn:aws:iam::"+testMgmt+":role/orders-reader", "tok", ""); w.Code != http.StatusForbidden {
		t.Errorf("an ECS-trusting role is no function's execution role: %d %s", w.Code, w.Body)
	}
}

// A role whose trust names the app's identity itself (the IRSA form) is assumable by the app, as before —
// beside the app, in its account's IAM home, or (for the management account) the IAM home; a role trusting
// neither ECS nor the identity is not.
func TestApplicationRole_ExplicitIdentityTrust(t *testing.T) {
	h := applicationSTS(t, fakeRoles{
		"explicit": {trust: []string{webUser}},
		"ec2-only": {trust: []string{"vm"}},
		"other-sa": {trust: []string{"system:serviceaccount:shop:api"}},
	}, fakeRoles{"shop/beside": {trust: []string{webUser}}}, fakeApplications{"tok": webApp()}, fakeReviewer{"tok": webUser})
	for _, role := range []string{"explicit", "beside"} {
		if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/"+role, "tok", ""); w.Code != http.StatusOK {
			t.Errorf("a role %s trusting the identity: %d %s", role, w.Code, w.Body)
		}
	}
	for _, role := range []string{"ec2-only", "other-sa"} {
		app := webApp()
		app.role = role
		h.applications = fakeApplications{"tok": app}
		if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/"+role, "tok", ""); w.Code != http.StatusForbidden {
			t.Errorf("role %s trusts neither ECS nor the identity: %d %s", role, w.Code, w.Body)
		}
	}
}

// ECS's trust is not honoured on a trust policy with conditions (aws:SourceArn, aws:SourceAccount, …): they
// are not evaluated for the ECS service, so the assume fails closed rather than ignore them.
func TestApplicationRole_ConditionedECSTrustFailsClosed(t *testing.T) {
	plain := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	conditioned := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole",` +
		`"Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:ecs:us-east-1:` + testMgmt + `:*"}}}]}`
	h := applicationSTS(t, nil, nil, fakeApplications{"tok": webApp()}, fakeReviewer{"tok": webUser})
	h.roles = fakeTrustDocRoles{"web-reader": {trust: ecsTrust, doc: plain}}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/web-reader", "tok", ""); w.Code != http.StatusOK {
		t.Fatalf("an unconditioned ECS trust: %d %s", w.Code, w.Body)
	}
	h.roles = fakeTrustDocRoles{"web-reader": {trust: ecsTrust, doc: conditioned}}
	w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/web-reader", "tok", "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not evaluated for the ECS service") {
		t.Fatalf("a conditioned ECS trust must fail closed: %d %s", w.Code, w.Body)
	}
}

// The role is the app's account's: one in the app's namespace first (a stack's role beside its app), else
// the account's IAM home; never another account's — not even one whose trust names the app's identity.
func TestApplicationRole_OwnAccountOnly(t *testing.T) {
	app := applicationIdentity{namespace: "team-a-web", name: "web", role: "arn:aws:iam::" + testMember + ":role/Reader",
		username: "system:serviceaccount:team-a-web:web", account: testMember, home: memberHome}
	h := applicationSTS(t, fakeRoles{"Reader": {trust: ecsTrust}, "mgmt-explicit": {trust: []string{app.username}}},
		fakeRoles{memberHome + "/Reader": {trust: ecsTrust}, "team-a-web/Local": {trust: ecsTrust}},
		fakeApplications{"tok": app}, fakeReviewer{"tok": app.username})

	w := fnWebIdentity(h, "arn:aws:iam::"+testMember+":role/Reader", "tok", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "arn:aws:sts::"+testMember+":assumed-role/Reader/web") {
		t.Fatalf("a member account's app assumes its account's role: %d %s", w.Code, w.Body)
	}
	var resp assumeRoleWithWebIdentityResponse
	_ = xml.Unmarshal(w.Body.Bytes(), &resp)
	if sess, ok := h.minter.Verify(resp.Result.Credentials.AccessKeyId, resp.Result.Credentials.SessionToken); !ok ||
		sess.Account != testMember || sess.Namespace != memberHome {
		t.Errorf("the session acts in the member account, as its home's role: %+v", sess)
	}
	// The management account's role of the same name is another account's; so is a management role whose
	// trust names the app's identity (the app is the member account's).
	for _, role := range []string{"Reader", "mgmt-explicit"} {
		if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/"+role, "tok", ""); w.Code != http.StatusForbidden {
			t.Errorf("another account's role %s must be AccessDenied: %d %s", role, w.Code, w.Body)
		}
	}
	// A role in the app's own namespace (a stack's) is found first.
	app.role = "Local"
	h.applications = fakeApplications{"tok": app}
	w = fnWebIdentity(h, "arn:aws:iam::"+testMember+":role/Local", "tok", "")
	_ = xml.Unmarshal(w.Body.Bytes(), &resp)
	if sess, ok := h.minter.Verify(resp.Result.Credentials.AccessKeyId, resp.Result.Credentials.SessionToken); w.Code != http.StatusOK || !ok ||
		sess.Namespace != "team-a-web" {
		t.Errorf("a role beside the app: %d %s %+v", w.Code, w.Body, sess)
	}
	// A suspended account's app gets nothing.
	app.suspended = true
	h.applications = fakeApplications{"tok": app}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMember+":role/Local", "tok", ""); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "account is suspended") {
		t.Errorf("a suspended account's app: %d %s", w.Code, w.Body)
	}
}

// The session the app gets acts as its role at the data plane, in its account: the authenticator turns it
// into the role's principal (the home's bare name; a role beside the app as <ns>/<name>).
func TestApplicationRole_SessionActsAsTheRole(t *testing.T) {
	claimsOf := func(h *stsHandler, role string) (c struct{ role, sub, account string }) {
		t.Helper()
		w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/"+role, "tok", "")
		var resp assumeRoleWithWebIdentityResponse
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%v: %s", err, w.Body)
		}
		sess, ok := h.minter.Verify(resp.Result.Credentials.AccessKeyId, resp.Result.Credentials.SessionToken)
		if !ok {
			t.Fatalf("the session must verify: %s", w.Body)
		}
		a := &authenticator{sts: h.minter, home: "open-infra-console", dir: accounts.NewDirectory(testMgmt)}
		cl, ok := a.sessionClaims(context.Background(), sess)
		if !ok {
			t.Fatal("the session must authenticate")
		}
		c.role, c.sub, c.account = cl.AssumedRole, cl.Sub, cl.Account
		return c
	}
	h := applicationSTS(t, fakeRoles{"web-reader": {trust: ecsTrust, groups: []string{"openinfra:users"}}},
		nil, fakeApplications{"tok": webApp()}, fakeReviewer{"tok": webUser})
	if c := claimsOf(h, "web-reader"); c.role != "web-reader" || c.sub != "assumed-role/web-reader/web" || c.account != "" {
		t.Errorf("a home role's session: %+v", c)
	}
	h = applicationSTS(t, fakeRoles{"web-reader": {trust: ecsTrust}}, fakeRoles{"shop/web-reader": {trust: ecsTrust}},
		fakeApplications{"tok": webApp()}, fakeReviewer{"tok": webUser})
	if c := claimsOf(h, "web-reader"); c.role != "shop/web-reader" || c.account != "" {
		t.Errorf("a role beside the app: %+v", c)
	}
}

// With task roles off (or a token the shim cannot place), an app's token is decided as any workload's, by
// the role's trust naming it, in the IAM home — as before.
func TestApplicationRole_DisabledFallsBackToTrust(t *testing.T) {
	h := applicationSTS(t, fakeRoles{"web-reader": {trust: ecsTrust}, "explicit": {trust: []string{webUser}}},
		nil, nil, fakeReviewer{"tok": webUser})
	h.applications = nil
	if w := fnWebIdentity(h, "web-reader", "tok", ""); w.Code != http.StatusForbidden {
		t.Errorf("with task roles off, ECS's trust names nobody: %d %s", w.Code, w.Body)
	}
	if w := fnWebIdentity(h, "explicit", "tok", ""); w.Code != http.StatusOK {
		t.Errorf("an explicit identity trust still works: %d %s", w.Code, w.Body)
	}
	// An app path that does not recognize the token leaves it to the trust, too.
	h.applications = fakeApplications{}
	if w := fnWebIdentity(h, "explicit", "tok", ""); w.Code != http.StatusOK {
		t.Errorf("an unrecognized token still meets an explicit trust: %d %s", w.Code, w.Body)
	}
}

// End to end over the real identity check: the app's own pod gets its ECS-trusted role; a hand-made pod
// running as the app's ServiceAccount does not.
func TestApplicationRole_EndToEnd(t *testing.T) {
	const ns = "shop"
	tokens := map[string]reviewedToken{
		"own":      {user: webUser, podName: "web-6c8d-abc", podID: "uid-app"},
		"handmade": {user: webUser, podName: "web-copy-1-xyz", podID: "uid-copy"},
	}
	objs := appPod(ns, "web-6c8d-abc", "uid-app", "web", "web")
	copyObjs := appPod(ns, "web-copy-1-xyz", "uid-copy", "web-copy", "web")
	copyObjs[0].(*corev1.Pod).Labels[appNameLabel] = "web"
	objs = append(append(objs, copyObjs...), appSA(ns, "web", "web"))
	ids := applicationIdentitiesWith(t, tokens, objs, appClaim(ns, "web", "web-reader"))
	h := applicationSTS(t, fakeRoles{"web-reader": {trust: ecsTrust}}, nil, nil,
		fakeReviewer{"own": webUser, "handmade": webUser})
	h.applications = ids
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/web-reader", "own", "web-6c8d-abc"); w.Code != http.StatusOK {
		t.Fatalf("the app's own pod: %d %s", w.Code, w.Body)
	}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/web-reader", "handmade", ""); w.Code != http.StatusForbidden {
		t.Errorf("a hand-made pod running as the app's ServiceAccount: %d %s", w.Code, w.Body)
	}
}
