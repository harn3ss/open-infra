package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
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

// --- the identity: a token is a function's own only when Knative runs its pod for that function ---

func fnPod(ns, name, uid, service, sa string) *corev1.Pod {
	labels := map[string]string{}
	if service != "" {
		labels[knativeServiceLabel] = service
	}
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid), Labels: labels},
		Spec: corev1.PodSpec{ServiceAccountName: sa}}
}

func controller(apiVersion, kind, name, uid string) []metav1.OwnerReference {
	yes := true
	return []metav1.OwnerReference{{APIVersion: apiVersion, Kind: kind, Name: name, UID: types.UID(uid), Controller: &yes}}
}

// revisionPod is a pod Knative runs for function fn: owned by a ReplicaSet, owned by a Deployment that a
// Knative Revision owns and Knative labels with the function. It returns the pod, its ReplicaSet and its
// Deployment.
func revisionPod(ns, name, uid, fn, sa string) []runtime.Object {
	rev := fn + "-" + uid // a revision per pod here, so two pods of one function have their own chains
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: rev + "-deployment", UID: types.UID("dep-" + uid),
		Labels: map[string]string{knativeServiceLabel: fn}, OwnerReferences: controller("serving.knative.dev/v1", "Revision", rev, "rev-"+uid)}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: rev + "-deployment-" + uid, UID: types.UID("rs-" + uid),
		OwnerReferences: controller("apps/v1", "Deployment", dep.Name, string(dep.UID))}}
	pod := fnPod(ns, name, uid, fn, sa)
	pod.OwnerReferences = controller("apps/v1", "ReplicaSet", rs.Name, string(rs.UID))
	return []runtime.Object{pod, rs, dep}
}

func fnSA(ns, name, function string) *corev1.ServiceAccount {
	labels := map[string]string{}
	if function != "" {
		labels[fnIdentityLabel] = function
	}
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels}}
}

func roleFnClaim(ns, name, role string) *unstructured.Unstructured {
	spec := map[string]any{"image": "ghcr.io/me/app:1"}
	if role != "" {
		spec["role"] = role
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Function",
		"metadata": map[string]any{"namespace": ns, "name": name}, "spec": spec}}
}

func functionIdentitiesWith(t *testing.T, tokens map[string]reviewedToken, objs []runtime.Object, claims ...*unstructured.Unstructured) *k8sFunctionIdentities {
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
		map[schema.GroupVersionResource]string{functionClaimGVR: "FunctionList"}, dobjs...)
	return &k8sFunctionIdentities{cs: cs, dyn: dyn, meta: md, audience: "sts.openinfra", accounts: testDirectory()}
}

// Only a pod Knative runs for the function, as its identity ServiceAccount, is the function. Another pod
// running as fn-<function> (an Application named fn-<function> runs as a ServiceAccount of that name), a
// pod that carries Knative's label but whose controllers are not a Knative Revision's, a token not bound to
// a pod, a ServiceAccount the composition did not label, and a function in a platform namespace are not.
func TestFunctionIdentity_OnlyTheFunctionsOwnPod(t *testing.T) {
	const ns, sa = "shop", "fn-orders"
	user := "system:serviceaccount:" + ns + ":" + sa
	tokens := map[string]reviewedToken{
		"revision-pod":     {user: user, podName: "orders-00001-deployment-7f9-abc", podID: "uid-rev"},
		"app-pod":          {user: user, podName: "fn-orders-6c8d-xyz", podID: "uid-app"},
		"labelled-app-pod": {user: user, podName: "fn-orders-6c8d-lbl", podID: "uid-lbl"},
		"unowned-pod":      {user: user, podName: "orders-bare", podID: "uid-bare"},
		"wrong-uid":        {user: user, podName: "orders-00001-deployment-7f9-abc", podID: "uid-other"},
		"other-functions":  {user: user, podName: "billing-00001-deployment-1-a", podID: "uid-billing"},
		"unbound":          {user: user},
		"not-an-identity":  {user: "system:serviceaccount:shop:orders", podName: "orders-00001-deployment-7f9-abc", podID: "uid-rev"},
		"unlabelled-sa":    {user: "system:serviceaccount:shop:fn-handmade", podName: "handmade-00001-deployment-1-a", podID: "uid-hand"},
		"roleless":         {user: "system:serviceaccount:shop:fn-plain", podName: "plain-00001-deployment-1-a", podID: "uid-plain"},
		"no-such-function": {user: "system:serviceaccount:shop:fn-gone", podName: "gone-00001-deployment-1-a", podID: "uid-gone"},
		"platform-ns":      {user: "system:serviceaccount:knative-serving:fn-x", podName: "x-00001-deployment-1-a", podID: "uid-x"},
	}
	var objs []runtime.Object
	objs = append(objs, revisionPod(ns, "orders-00001-deployment-7f9-abc", "uid-rev", "orders", sa)...)
	objs = append(objs, revisionPod(ns, "billing-00001-deployment-1-a", "uid-billing", "billing", sa)...)
	objs = append(objs, revisionPod(ns, "handmade-00001-deployment-1-a", "uid-hand", "handmade", "fn-handmade")...)
	objs = append(objs, revisionPod(ns, "plain-00001-deployment-1-a", "uid-plain", "plain", "fn-plain")...)
	objs = append(objs, revisionPod(ns, "gone-00001-deployment-1-a", "uid-gone", "gone", "fn-gone")...)
	objs = append(objs, revisionPod("knative-serving", "x-00001-deployment-1-a", "uid-x", "x", "fn-x")...)
	// An Application's pod: its Deployment is owned by no Revision. Once without Knative's label, once with it.
	appDep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "fn-orders", UID: "uid-appdep",
		Labels: map[string]string{knativeServiceLabel: "orders"}}}
	appRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "fn-orders-6c8d", UID: "uid-apprs",
		OwnerReferences: controller("apps/v1", "Deployment", "fn-orders", "uid-appdep")}}
	appPod := fnPod(ns, "fn-orders-6c8d-xyz", "uid-app", "", sa)
	appPod.OwnerReferences = controller("apps/v1", "ReplicaSet", appRS.Name, string(appRS.UID))
	lblPod := fnPod(ns, "fn-orders-6c8d-lbl", "uid-lbl", "orders", sa)
	lblPod.OwnerReferences = appPod.OwnerReferences
	objs = append(objs, appDep, appRS, appPod, lblPod, fnPod(ns, "orders-bare", "uid-bare", "orders", sa))
	objs = append(objs, fnSA(ns, sa, "orders"), fnSA(ns, "fn-handmade", ""), fnSA(ns, "fn-plain", "plain"), fnSA(ns, "fn-gone", "gone"),
		fnSA("knative-serving", "fn-x", "x"))
	f := functionIdentitiesWith(t, tokens, objs,
		roleFnClaim(ns, "orders", "orders-reader"), roleFnClaim(ns, "handmade", "orders-reader"), roleFnClaim(ns, "plain", ""),
		roleFnClaim("knative-serving", "x", "orders-reader"))
	for tok, want := range map[string]bool{
		"revision-pod": true,
		"app-pod":      false, "labelled-app-pod": false, "unowned-pod": false, "wrong-uid": false, "other-functions": false,
		"unbound": false, "not-an-identity": false, "unlabelled-sa": false, "no-such-function": false,
		"platform-ns": false, "unknown": false,
	} {
		id, ok := f.functionOf(context.Background(), tok)
		if ok != want {
			t.Errorf("token %q: function identity = %v, want %v (%+v)", tok, ok, want, id)
		}
	}
	// A role-less function is its identity, but names no role (so no Lambda-trusting role is its).
	if id, ok := f.functionOf(context.Background(), "roleless"); !ok || id.role != "" {
		t.Errorf("a role-less function: %+v %v", id, ok)
	}
	id, _ := f.functionOf(context.Background(), "revision-pod")
	if id.namespace != ns || id.name != "orders" || id.role != "orders-reader" || id.username != user || id.account != "" {
		t.Errorf("the function's identity: %+v", id)
	}
}

// A member account's function is that account's, with its home.
func TestFunctionIdentity_MemberAccount(t *testing.T) {
	user := "system:serviceaccount:" + memberHome + ":fn-orders"
	f := functionIdentitiesWith(t, map[string]reviewedToken{"t": {user: user, podName: "orders-00001-deployment-1-a", podID: "u"}},
		append(revisionPod(memberHome, "orders-00001-deployment-1-a", "u", "orders", "fn-orders"), fnSA(memberHome, "fn-orders", "orders")),
		roleFnClaim(memberHome, "orders", "reader"))
	id, ok := f.functionOf(context.Background(), "t")
	if !ok || id.account != testMember || id.home != memberHome || id.suspended {
		t.Fatalf("a member account's function: %+v %v", id, ok)
	}
}

// --- the assume: Lambda's trust, the function's own role, its own account ---

type fakeFunctions map[string]functionIdentity // token -> the function it is the identity of

func (f fakeFunctions) functionOf(_ context.Context, tok string) (functionIdentity, bool) {
	id, ok := f[tok]
	return id, ok
}

func functionSTS(t *testing.T, mgmt, member fakeRoles, fns fakeFunctions, reviewer fakeReviewer) *stsHandler {
	t.Helper()
	return &stsHandler{account: testMgmt, minter: testMinter(t), roles: fakeRolesIn{fakeRoles: mgmt, in: member},
		webID: reviewer, functions: fns, accounts: testDirectory(), logger: discardLogger()}
}

func fnWebIdentity(h *stsHandler, roleArn, token, session string) *httptest.ResponseRecorder {
	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn}, "WebIdentityToken": {token}}
	if session != "" {
		form.Set("RoleSessionName", session)
	}
	req := httptest.NewRequest("POST", "http://sts.local/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{}, "rid")
	return w
}

const (
	ordersUser = "system:serviceaccount:shop:fn-orders"
	appUser    = "system:serviceaccount:shop:web"
)

func ordersFunction() functionIdentity {
	return functionIdentity{namespace: "shop", name: "orders", role: "orders-reader", username: ordersUser}
}

// The function's identity assumes the role its spec.role names when the role trusts lambda.amazonaws.com:
// a session of the role in the function's account, named after the function, as Lambda's is.
func TestFunctionRole_LambdaTrustedRoleTheFunctionNames(t *testing.T) {
	h := functionSTS(t, fakeRoles{"orders-reader": {trust: []string{"Service::lambda.amazonaws.com"}, groups: []string{"openinfra:users"}}},
		nil, fakeFunctions{"tok": ordersFunction()}, fakeReviewer{"tok": ordersUser})
	w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/orders-reader", "tok", "orders")
	if w.Code != http.StatusOK {
		t.Fatalf("the function's own role: %d %s", w.Code, w.Body)
	}
	var resp assumeRoleWithWebIdentityResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if got := resp.Result.AssumedRoleUser.Arn; got != "arn:aws:sts::"+testMgmt+":assumed-role/orders-reader/orders" {
		t.Errorf("session ARN %q", got)
	}
	sess, ok := h.minter.Verify(resp.Result.Credentials.AccessKeyId, resp.Result.Credentials.SessionToken)
	if !ok || sess.RoleName != "orders-reader" || sess.Account != "" || sess.Caller != ordersUser || !sess.Federated {
		t.Errorf("the session: %+v %v", sess, ok)
	}
	// With no RoleSessionName the session is still the function's.
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/orders-reader", "tok", ""); !strings.Contains(w.Body.String(), "assumed-role/orders-reader/orders<") {
		t.Errorf("default session name: %s", w.Body)
	}
}

// Lambda's trust admits only the role the function names: not another function's role, nor this one's for
// any other workload. A pod that runs as the identity but is not the function's falls to the ordinary path,
// where a service's trust names nobody.
func TestFunctionRole_LambdaTrustIsOnlyTheFunctionsOwnRole(t *testing.T) {
	roles := fakeRoles{
		"orders-reader":  {trust: []string{"Service::lambda.amazonaws.com"}},
		"billing-writer": {trust: []string{"Service::lambda.amazonaws.com"}},
	}
	h := functionSTS(t, roles, nil, fakeFunctions{"tok": ordersFunction()},
		fakeReviewer{"tok": ordersUser, "borrowed": ordersUser, "app": appUser})
	for _, c := range []struct{ role, tok, why string }{
		{"billing-writer", "tok", "another function's role"},
		{"orders-reader", "borrowed", "a pod that only runs as the identity"},
		{"orders-reader", "app", "another workload"},
	} {
		if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/"+c.role, c.tok, ""); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("%s must be AccessDenied, got %d %s", c.why, w.Code, w.Body)
		}
	}
}

// A role whose trust names the function's identity itself is assumable by the function, as before; a role
// trusting neither Lambda nor the identity is not.
func TestFunctionRole_ExplicitIdentityTrust(t *testing.T) {
	h := functionSTS(t, fakeRoles{
		"explicit": {trust: []string{ordersUser}},
		"ec2-only": {trust: []string{"vm"}},
		"named":    {trust: []string{"Service::states.amazonaws.com"}},
	}, nil, fakeFunctions{"tok": ordersFunction()}, fakeReviewer{"tok": ordersUser})
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/explicit", "tok", ""); w.Code != http.StatusOK {
		t.Fatalf("a role trusting the identity: %d %s", w.Code, w.Body)
	}
	f := ordersFunction()
	f.role = "named"
	h.functions = fakeFunctions{"tok": f}
	for _, role := range []string{"ec2-only", "named"} {
		if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/"+role, "tok", ""); w.Code != http.StatusForbidden {
			t.Errorf("role %s trusts neither Lambda nor the identity: %d %s", role, w.Code, w.Body)
		}
	}
}

// Lambda's trust is not honoured on a trust policy with conditions (aws:SourceArn, aws:SourceAccount, …):
// they are not evaluated for the Lambda service, so the assume fails closed rather than ignore them. A
// policy without conditions is honoured.
func TestFunctionRole_ConditionedLambdaTrustFailsClosed(t *testing.T) {
	lambda := []string{"Service::lambda.amazonaws.com"}
	plain := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	conditioned := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole",` +
		`"Condition":{"StringEquals":{"aws:SourceAccount":"` + testMgmt + `"}}}}`
	h := functionSTS(t, nil, nil, fakeFunctions{"tok": ordersFunction()}, fakeReviewer{"tok": ordersUser})
	h.roles = fakeTrustDocRoles{"orders-reader": {trust: lambda, doc: plain}}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/orders-reader", "tok", ""); w.Code != http.StatusOK {
		t.Fatalf("an unconditioned Lambda trust: %d %s", w.Code, w.Body)
	}
	h.roles = fakeTrustDocRoles{"orders-reader": {trust: lambda, doc: conditioned}}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/orders-reader", "tok", ""); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "conditions") {
		t.Fatalf("a conditioned Lambda trust must fail closed: %d %s", w.Code, w.Body)
	}
	for doc, want := range map[string]bool{"": false, plain: false, conditioned: true, "not json": true} {
		if got := trustConditioned(doc); got != want {
			t.Errorf("trustConditioned(%q) = %v", doc, got)
		}
	}
}

// fakeTrustDocRoles resolves roles carrying their trust policy as written.
type fakeTrustDocRoles map[string]struct {
	trust []string
	doc   string
}

func (f fakeTrustDocRoles) Resolve(_ context.Context, name string) (resolvedRole, bool) {
	r, ok := f[name]
	return resolvedRole{trust: r.trust, trustDoc: r.doc, groups: []string{"openinfra:users"}}, ok
}

// The role is the function's account's: one in the function's namespace first (a stack's role beside its
// function), else the account's IAM home; never another account's.
func TestFunctionRole_OwnAccountOnly(t *testing.T) {
	lambda := []string{"Service::lambda.amazonaws.com"}
	fn := functionIdentity{namespace: "team-a-batch", name: "orders", role: "arn:aws:iam::" + testMember + ":role/Reader",
		username: "system:serviceaccount:team-a-batch:fn-orders", account: testMember, home: memberHome}
	h := functionSTS(t, fakeRoles{"Reader": {trust: lambda}},
		fakeRoles{memberHome + "/Reader": {trust: lambda}, "team-a-batch/Local": {trust: lambda}},
		fakeFunctions{"tok": fn}, fakeReviewer{"tok": fn.username})

	w := fnWebIdentity(h, "arn:aws:iam::"+testMember+":role/Reader", "tok", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "arn:aws:sts::"+testMember+":assumed-role/Reader/orders") {
		t.Fatalf("a member account's function assumes its account's role: %d %s", w.Code, w.Body)
	}
	var resp assumeRoleWithWebIdentityResponse
	_ = xml.Unmarshal(w.Body.Bytes(), &resp)
	if sess, ok := h.minter.Verify(resp.Result.Credentials.AccessKeyId, resp.Result.Credentials.SessionToken); !ok ||
		sess.Account != testMember || sess.Namespace != memberHome {
		t.Errorf("the session acts in the member account, as its home's role: %+v", sess)
	}
	// The management account's role of the same name is another account's.
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMgmt+":role/Reader", "tok", ""); w.Code != http.StatusForbidden {
		t.Errorf("another account's role must be AccessDenied: %d %s", w.Code, w.Body)
	}
	// A role in the function's own namespace (a stack's) is found first.
	fn.role = "Local"
	h.functions = fakeFunctions{"tok": fn}
	w = fnWebIdentity(h, "arn:aws:iam::"+testMember+":role/Local", "tok", "")
	_ = xml.Unmarshal(w.Body.Bytes(), &resp)
	if sess, ok := h.minter.Verify(resp.Result.Credentials.AccessKeyId, resp.Result.Credentials.SessionToken); w.Code != http.StatusOK || !ok ||
		sess.Namespace != "team-a-batch" {
		t.Errorf("a role beside the function: %d %s %+v", w.Code, w.Body, sess)
	}
	// A suspended account's function gets nothing.
	fn.suspended = true
	h.functions = fakeFunctions{"tok": fn}
	if w := fnWebIdentity(h, "arn:aws:iam::"+testMember+":role/Local", "tok", ""); w.Code != http.StatusForbidden {
		t.Errorf("a suspended account's function: %d %s", w.Code, w.Body)
	}
}

// The session the function gets acts as its role at the data plane, in its account: the authenticator
// turns it into the role's principal (the home's bare name; a role beside the function as <ns>/<name>).
func TestFunctionRole_SessionActsAsTheRole(t *testing.T) {
	lambda := []string{"Service::lambda.amazonaws.com"}
	claimsOf := func(h *stsHandler, role string) iam.Claims {
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
		c, ok := a.sessionClaims(context.Background(), sess)
		if !ok {
			t.Fatal("the session must authenticate")
		}
		return c
	}
	// A role of the IAM home: the role's own principal, in the management account (Account "").
	h := functionSTS(t, fakeRoles{"orders-reader": {trust: lambda, groups: []string{"openinfra:users"}}},
		nil, fakeFunctions{"tok": ordersFunction()}, fakeReviewer{"tok": ordersUser})
	if c := claimsOf(h, "orders-reader"); c.AssumedRole != "orders-reader" || c.Sub != "assumed-role/orders-reader/orders" || c.Account != "" {
		t.Errorf("a home role's session: %+v", c)
	}
	// A role beside the function, in its namespace: that Role's principal, never the home's of that name.
	h = functionSTS(t, fakeRoles{"orders-reader": {trust: lambda}}, fakeRoles{"shop/orders-reader": {trust: lambda}},
		fakeFunctions{"tok": ordersFunction()}, fakeReviewer{"tok": ordersUser})
	if c := claimsOf(h, "orders-reader"); c.AssumedRole != "shop/orders-reader" || c.Account != "" {
		t.Errorf("a role beside the function: %+v", c)
	}
}

// A role-less function's identity, or a function the shim cannot place (no function identities), is
// decided as any workload's: by the role's trust naming it.
func TestFunctionRole_DisabledFallsBackToTrust(t *testing.T) {
	h := functionSTS(t, fakeRoles{"orders-reader": {trust: []string{"Service::lambda.amazonaws.com"}}, "explicit": {trust: []string{ordersUser}}},
		nil, nil, fakeReviewer{"tok": ordersUser})
	h.functions = nil
	if w := fnWebIdentity(h, "orders-reader", "tok", ""); w.Code != http.StatusForbidden {
		t.Errorf("with execution roles off, Lambda's trust names nobody: %d %s", w.Code, w.Body)
	}
	if w := fnWebIdentity(h, "explicit", "tok", ""); w.Code != http.StatusOK {
		t.Errorf("an explicit identity trust still works: %d %s", w.Code, w.Body)
	}
}

func TestNamesRole(t *testing.T) {
	for _, c := range []struct {
		spec, role, acct string
		want             bool
	}{
		{"orders-reader", "orders-reader", testMgmt, true},
		{"OrdersReader", "ordersreader", testMgmt, true},
		{"arn:aws:iam::" + testMgmt + ":role/service-role/OrdersReader", "OrdersReader", testMgmt, true},
		{"arn:aws:iam::" + testMember + ":role/OrdersReader", "OrdersReader", testMgmt, false},
		{"", "orders-reader", testMgmt, false},
		{"other", "orders-reader", testMgmt, false},
	} {
		if got := namesRole(c.spec, c.role, c.acct); got != c.want {
			t.Errorf("namesRole(%q, %q, %q) = %v", c.spec, c.role, c.acct, got)
		}
	}
	if !isFunctionIdentity(ordersUser) || isFunctionIdentity("system:serviceaccount:shop:fn-") ||
		isFunctionIdentity("system:serviceaccount:shop:orders") || isFunctionIdentity("openinfra:fn-x") {
		t.Error("isFunctionIdentity")
	}
}
