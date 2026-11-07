package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/proxy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"
)

// A tenant gets no Kubernetes access. Through the console, an account's principals reach their resources
// only as AWS actions: the console's resource API (/api/k8s) and the watch stream answer a resource type's
// own action, and every raw Kubernetes object — Secrets, Pods and their logs and exec, ServiceAccount
// tokens, Nodes, Namespaces, RBAC, CRDs, the composites, other groups' objects, anything unmapped — is
// refused before it reaches the API server, whatever the principal's policy: no policy, AWS's
// ReadOnlyAccess or PowerUserAccess, and a member account's AdministratorAccess (its users, roles and root
// alike). Only the management account's administrator is the operator. The policies are the platform's
// own AWS managed policies, read from their manifests.
//
// That no IAM credential is a Kubernetes identity at all (the API server authenticates none of them, and
// the kubeconfig EKS writes is refused) is proved live by probe/aws-shim-eks-tenant-refused.sh.
func TestTenantKubernetesAccessIsRefused(t *testing.T) {
	docs := managedPolicyDocs(t, "aws-administratoraccess", "aws-poweruseraccess", "aws-readonlyaccess")
	const member = "900000000001"
	w := testWorld(t, docs, map[string][]string{
		"User::poweruser": {"aws-poweruseraccess"}, "User::reader": {"aws-readonlyaccess"},
		"User::madmin": {"aws-administratoraccess"}, "Role::OrganizationAccountAccessRole": {"aws-administratoraccess"},
		"User::admin": {"aws-administratoraccess"},
	})
	z := newTestAuthz(t, iamauthz.ModeEnforce, w, true) // RBAC would allow everything: IAM policy must refuse
	z.cs = fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-b", Labels: map[string]string{accounts.LabelAccountID: member}}},
	)
	inAccount := func(c sessionClaims, acct string) sessionClaims { c.Account = acct; return c }
	role := userClaims("alice")
	role.AssumedRole = "OrganizationAccountAccessRole"
	memberRoot := rootClaims()
	memberRoot.Sub = "member-root"

	tenants := []struct {
		name string
		c    sessionClaims
		ns   string // a namespace of the principal's own account
	}{
		{"a user with no policy", userClaims("nobody"), "team"},
		{"ReadOnlyAccess", userClaims("reader"), "team"},
		{"PowerUserAccess", userClaims("poweruser"), "team"},
		{"a member account's AdministratorAccess user", inAccount(userClaims("madmin"), member), "team-b"},
		{"a member account's administrator role session", inAccount(role, member), "team-b"},
	}
	raw := func(ns string) [][2]string {
		return [][2]string{
			{http.MethodGet, "/api/k8s/api/v1/namespaces/" + ns + "/secrets"},
			{http.MethodGet, "/api/k8s/api/v1/namespaces/" + ns + "/secrets/db-password"},
			{http.MethodGet, "/api/k8s/api/v1/namespaces/" + ns + "/configmaps"},
			{http.MethodGet, "/api/k8s/api/v1/namespaces/" + ns + "/pods"},
			{http.MethodGet, "/api/k8s/api/v1/namespaces/" + ns + "/pods/p/log"},
			{http.MethodPost, "/api/k8s/api/v1/namespaces/" + ns + "/pods/p/exec"},
			{http.MethodPost, "/api/k8s/api/v1/namespaces/" + ns + "/serviceaccounts/default/token"},
			{http.MethodPost, "/api/k8s/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns + "/rolebindings"},
			{http.MethodGet, "/api/k8s/apis/apps/v1/namespaces/" + ns + "/deployments"},
			{http.MethodGet, "/api/k8s/apis/kubevirt.io/v1/namespaces/" + ns + "/virtualmachineinstances"},
			{http.MethodGet, "/api/k8s/api/v1/nodes"},
			{http.MethodGet, "/api/k8s/api/v1/namespaces"},
			{http.MethodDelete, "/api/k8s/api/v1/namespaces/" + ns},
			{http.MethodGet, "/api/k8s/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"},
			{http.MethodGet, "/api/k8s/apis/apiextensions.k8s.io/v1/customresourcedefinitions"},
			{http.MethodGet, "/api/k8s/apis/openinfra.dev/v1/xbuckets"},                              // a claim's composite
			{http.MethodGet, "/api/k8s/apis/organizations.openinfra.dev/v1/accounts"},                // the organization's accounts
			{http.MethodGet, "/api/k8s/apis/openinfra.dev/v1/namespaces/" + ns + "/frobnicators"},    // a kind the table does not map
			{http.MethodGet, "/api/k8s/apis/openinfra.dev/v1/namespaces/" + ns + "/buckets/b/proxy"}, // a subresource the table does not map
			{http.MethodGet, "/api/k8s/metrics"},                                                     // not a Kubernetes API request
		}
	}
	forwarded := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded++; w.WriteHeader(http.StatusOK) })
	resources := z.proxyHandler(k8sPrefix, next)
	watch := z.watchHandler(next)
	for _, tn := range tenants {
		for _, rq := range raw(tn.ns) {
			before := forwarded
			got := serve(resources, as(httptest.NewRequest(rq[0], rq[1], strings.NewReader("{}")), tn.c))
			if got.Code != http.StatusForbidden || errorCode(t, got) != "AccessDeniedException" || forwarded != before {
				t.Errorf("%s: %s %s answered %d (%s), forwarded=%v; want the gate's AccessDeniedException",
					tn.name, rq[0], rq[1], got.Code, strings.TrimSpace(got.Body.String()), forwarded != before)
			}
		}
		for _, p := range []string{"/api/v1/namespaces/" + tn.ns + "/secrets", "/api/v1/pods", "/api/v1/nodes"} {
			before := forwarded
			got := serve(watch, as(httptest.NewRequest(http.MethodGet, "/api/watch?path="+url.QueryEscape(p), nil), tn.c))
			if got.Code != http.StatusForbidden || forwarded != before {
				t.Errorf("%s: watching %s answered %d, want 403", tn.name, p, got.Code)
			}
		}
		if z.isOperator(as(httptest.NewRequest(http.MethodGet, "/", nil), tn.c), tn.c, z.principal(tn.c), iamauthz.ModeEnforce) {
			t.Errorf("%s is shown the operator's cluster views", tn.name)
		}
	}

	// A member account's root is its own account's root user: never the platform's operator, never the
	// console's break-glass root (which alone reaches what no IAM action maps).
	mroot := inAccount(memberRoot, member)
	if p := z.principal(mroot); p.Type != iamauthz.Root || p.AccountID() != member {
		t.Fatalf("the member root fixture is %+v", p)
	}
	for _, rq := range raw("team-b") {
		if rq[1] == "/api/k8s/metrics" {
			continue // not a Kubernetes API request: refused before any principal is asked (above)
		}
		if ok, _, action, _ := z.authorizeKubernetes(as(httptest.NewRequest(rq[0], rq[1], nil), mroot), mustParse(t, rq[0], rq[1]), nil); ok {
			t.Errorf("a member account's root reached %s %s (%s)", rq[0], rq[1], action)
		}
	}
	if z.unrestrictedWatcher(as(httptest.NewRequest(http.MethodGet, "/", nil), mroot)) {
		t.Error("a member account's root may watch the whole cluster")
	}

	// What a tenant does reach is its resources, as its policy's AWS actions allow.
	for _, c := range []struct {
		name   string
		claims sessionClaims
		path   string
	}{
		{"ReadOnlyAccess lists buckets", userClaims("reader"), "/api/k8s/apis/openinfra.dev/v1/namespaces/team/buckets"},
		{"PowerUserAccess lists functions", userClaims("poweruser"), "/api/k8s/apis/openinfra.dev/v1/namespaces/team/functions"},
		{"a member administrator lists its account's tables", inAccount(userClaims("madmin"), member), "/api/k8s/apis/openinfra.dev/v1/namespaces/team-b/tables"},
	} {
		before := forwarded
		if got := serve(resources, as(httptest.NewRequest(http.MethodGet, c.path, nil), c.claims)); got.Code != http.StatusOK || forwarded != before+1 {
			t.Errorf("%s: %d %s, want it forwarded", c.name, got.Code, got.Body)
		}
	}
	if got := serve(resources, as(httptest.NewRequest(http.MethodDelete, "/api/k8s/apis/openinfra.dev/v1/namespaces/team/buckets/b", nil), userClaims("reader"))); got.Code != http.StatusForbidden ||
		!strings.Contains(got.Body.String(), "s3:DeleteBucket") {
		t.Errorf("ReadOnlyAccess deleting a bucket: %d %s, want AccessDenied on s3:DeleteBucket", got.Code, got.Body)
	}

	// The operator surface exists — for the management account's administrator alone.
	admin := userClaims("admin")
	for _, rq := range raw("team")[:15] {
		before := forwarded
		if got := serve(resources, as(httptest.NewRequest(rq[0], rq[1], strings.NewReader("{}")), admin)); got.Code != http.StatusOK || forwarded != before+1 {
			t.Errorf("the management administrator: %s %s answered %d %s", rq[0], rq[1], got.Code, got.Body)
		}
	}
	if !z.isOperator(as(httptest.NewRequest(http.MethodGet, "/", nil), admin), admin, z.principal(admin), iamauthz.ModeEnforce) {
		t.Error("the management account's administrator is not shown the operator's views")
	}
}

// mustParse is the Kubernetes request a console proxy path is.
func mustParse(t *testing.T, method, path string) proxy.Request {
	t.Helper()
	u, _ := url.Parse(path)
	k, ok := proxy.ParseRequest(method, strings.TrimPrefix(u.Path, k8sPrefix), u.Query())
	if !ok {
		t.Fatalf("%s %s is not a Kubernetes API request", method, path)
	}
	return k
}

// managedPolicyDocs reads the platform's AWS managed policies' documents from their manifests, by object name.
func managedPolicyDocs(t *testing.T, names ...string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../../platform/abstraction/managed-policies/aws-managed-policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string]string{}
	for _, doc := range regexp.MustCompile(`(?m)^---\s*$`).Split(string(raw), -1) {
		var p struct {
			Metadata struct{ Name string } `json:"metadata"`
			Spec     struct {
				Document json.RawMessage `json:"document"`
			} `json:"spec"`
		}
		if yaml.Unmarshal([]byte(doc), &p) != nil || !want[p.Metadata.Name] {
			continue
		}
		out[p.Metadata.Name] = string(p.Spec.Document)
	}
	for _, n := range names {
		if out[n] == "" {
			t.Fatalf("managed policy %s not found in its manifest", n)
		}
	}
	return out
}
