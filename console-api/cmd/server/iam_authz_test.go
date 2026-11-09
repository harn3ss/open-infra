package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/awsaction"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/k8s"
	"github.com/harn3ss/open-infra/console-api/internal/proxy"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

// ── fixtures ──────────────────────────────────────────────────────────────────────

// testWorld is an IAM policy world: AWS JSON documents by name, attached to principals by key
// ("User::<name>", "Group::<name>").
func testWorld(t *testing.T, docs map[string]string, attach map[string][]string) iamauthz.World {
	t.Helper()
	w := iamauthz.World{Attach: attach, Boundary: map[string]string{}, Inline: map[string][]iamauthz.Policy{}, Enforce: map[string]bool{}}
	for name, doc := range docs {
		stmts, _, err := iamauthz.CompileDocument(doc)
		if err != nil {
			t.Fatalf("policy %s: %v", name, err)
		}
		w.Docs = append(w.Docs, iamauthz.Policy{Name: name, Statements: stmts})
	}
	return w
}

// newTestAuthz is the console's gate over a static policy world in mode, with SubjectAccessReviews
// answered by sarAllowed (the legacy decision).
func newTestAuthz(t *testing.T, mode iamauthz.Mode, w iamauthz.World, sarAllowed bool) *consoleAuthz {
	t.Helper()
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: sarAllowed, Reason: "rbac"}}, nil
	})
	ev := iamauthz.New(func(context.Context) (iamauthz.World, error) { return w, nil }, time.Minute,
		iamauthz.WithMode(mode), iamauthz.WithLogger(testLogger()))
	z := &consoleAuthz{reg: awsaction.NewRegistry(), eval: ev, auth: &authStore{mode: "local", cs: cs, ns: "open-infra-console"},
		cs: cs, logger: testLogger(), nsCache: map[string]nsAccountEntry{}}
	prev := consoleIAM
	consoleIAM = z
	t.Cleanup(func() { consoleIAM = prev })
	return z
}

func userClaims(name string, groups ...string) sessionClaims {
	c := sessionClaims{}
	c.Sub, c.Role, c.Groups = name, "poweruser", groups
	return c
}

func rootClaims() sessionClaims {
	c := sessionClaims{}
	c.Sub, c.Role = "root", "root"
	return c
}

func as(r *http.Request, c sessionClaims) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxUser{}, c))
}

// testRoutes is a router with a handful of gated routes over stub handlers (200 "ok").
func testRoutes(z *consoleAuthz) chi.Router {
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
	r := chi.NewRouter()
	r.Route("/api", func(api chi.Router) {
		z.handle(api, apiPrefix, http.MethodGet, "/buckets", 0, "s3:ListAllMyBuckets", nil, ok)
		z.handle(api, apiPrefix, http.MethodDelete, "/buckets/{bucket}", 0, "s3:DeleteBucket", bucketARN, ok)
		z.handle(api, apiPrefix, http.MethodGet, "/iam/users", 0, "iam:ListUsers", nil, ok)
		z.handle(api, apiPrefix, http.MethodPost, "/functions/{namespace}/{name}/invoke", 0, "lambda:InvokeFunction", z.kindARN("Function"), ok)
		z.handleDynamic(api, apiPrefix, http.MethodPost, "/iam/users/{name}/password", 0, "password", func(r *http.Request) (string, string) {
			name := chi.URLParam(r, "name")
			arn := iamEntityARN("user", callerAccount(r), name)
			if c, ok := claimsFrom(r); ok && c.Sub == name {
				return "iam:ChangePassword", arn
			}
			return "iam:UpdateLoginProfile", arn
		}, ok)
	})
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m["errorCode"]
}

const (
	s3ReadDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListAllMyBuckets","s3:ListBucket"],"Resource":"*"}]}`
	adminDoc  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	// AWS's PowerUserAccess: everything except IAM, Organizations and Account management.
	powerUserDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},
		{"Effect":"Allow","Action":["iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization","account:ListRegions"],"Resource":"*"}]}`
	selfPasswordDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ChangePassword","Resource":"arn:aws:iam::000000000000:user/alice"}]}`
)

// ── route coverage ───────────────────────────────────────────────────────────────

// Every route the console serves has an IAM action (or a recorded reason it needs none), and every
// recorded route is one the router serves: no route can go unauthorized, and the table can't drift.
func TestConsoleRoutes_EveryRouteHasAnIAMAction(t *testing.T) {
	t.Setenv("GRAFANA_PROXY_TARGET", "http://127.0.0.1:1")
	cfg := &rest.Config{Host: "http://127.0.0.1:1"}
	host, _ := url.Parse(cfg.Host)
	var ci kubernetes.Interface = kubernetes.NewForConfigOrDie(cfg)
	client := &k8s.Client{Config: cfg, Transport: http.DefaultTransport, Host: host, Clientset: &ci}
	prev := consoleIAM
	t.Cleanup(func() { consoleIAM = prev })
	router, z := buildRouter(client, &authStore{mode: "local", sessionKey: []byte("k")}, testLogger())

	if missing := z.reg.Uncovered(router); len(missing) > 0 {
		t.Fatalf("routes with no IAM action: %v", missing)
	}
	served := map[string]bool{}
	_ = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		served[method+" "+route] = true
		return nil
	})
	gated := 0
	for _, rt := range z.reg.Routes() {
		if !served[rt.Method+" "+rt.Path] {
			t.Errorf("the route table names %s %s, which the router does not serve", rt.Method, rt.Path)
		}
		if !strings.HasPrefix(rt.Action, "per-request: ") {
			gated++
			if !strings.Contains(rt.Action, ":") {
				t.Errorf("%s %s: action %q is not service:Action", rt.Method, rt.Path, rt.Action)
			}
		}
	}
	if gated < 88 {
		t.Errorf("only %d routes carry a fixed IAM action; the table lost routes", gated)
	}
	perRequest := len(z.reg.Routes()) - gated
	t.Logf("route table: %d served; %d with a fixed IAM action, %d decided per request (proxy, watch, Grafana, self-service), %d public",
		len(served), gated, perRequest, len(served)-gated-perRequest)
}

// ── the route gate, per mode ─────────────────────────────────────────────────────

func TestConsoleGate_EnforceDecidesByIAMPolicy(t *testing.T) {
	w := testWorld(t, map[string]string{"s3-read": s3ReadDoc}, map[string][]string{"User::reader": {"s3-read"}})
	z := newTestAuthz(t, iamauthz.ModeEnforce, w, true) // RBAC would allow everything: IAM must decide
	h := testRoutes(z)

	if got := serve(h, as(httptest.NewRequest(http.MethodGet, "/api/buckets", nil), userClaims("reader"))); got.Code != 200 {
		t.Errorf("a reader listing buckets: %d %s", got.Code, got.Body)
	}
	got := serve(h, as(httptest.NewRequest(http.MethodDelete, "/api/buckets/b", nil), userClaims("reader")))
	if got.Code != 403 || errorCode(t, got) != "AccessDeniedException" {
		t.Errorf("a reader deleting a bucket: %d %s, want 403 AccessDeniedException", got.Code, got.Body)
	}
	if !strings.Contains(got.Body.String(), "s3:DeleteBucket on resource: arn:aws:s3:::b") {
		t.Errorf("the denial must name the action and ARN: %s", got.Body)
	}
	if got := serve(h, as(httptest.NewRequest(http.MethodGet, "/api/iam/users", nil), userClaims("reader"))); got.Code != 403 {
		t.Errorf("a reader listing IAM users: %d, want 403", got.Code)
	}
}

// A principal with no policy is denied everywhere when IAM policy decides — even when its RBAC tier
// (the implicit users group, a poweruser role) would have allowed it.
func TestConsoleGate_NoPolicyIsDeniedEverywhere(t *testing.T) {
	z := newTestAuthz(t, iamauthz.ModeEnforce, testWorld(t, nil, nil), true)
	h := testRoutes(z)
	for _, rq := range []struct{ method, path string }{
		{http.MethodGet, "/api/buckets"}, {http.MethodDelete, "/api/buckets/b"}, {http.MethodGet, "/api/iam/users"},
		{http.MethodPost, "/api/functions/team/fn/invoke"}, {http.MethodPost, "/api/iam/users/nobody/password"},
	} {
		if got := serve(h, as(httptest.NewRequest(rq.method, rq.path, nil), userClaims("nobody"))); got.Code != 403 {
			t.Errorf("%s %s by a principal with no policy: %d, want 403", rq.method, rq.path, got.Code)
		}
	}
	// The proxy and the watch stream too.
	nextHit := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextHit = true })
	for _, p := range []string{"/api/k8s/apis", "/api/k8s/api/v1/namespaces/team/pods", "/api/k8s/apis/openinfra.dev/v1/namespaces/team/buckets"} {
		if got := serve(z.proxyHandler(k8sPrefix, next), as(httptest.NewRequest(http.MethodGet, p, nil), userClaims("nobody"))); got.Code != 403 {
			t.Errorf("proxy %s by a principal with no policy: %d, want 403", p, got.Code)
		}
	}
	if got := serve(z.watchHandler(next), as(httptest.NewRequest(http.MethodGet, "/api/watch?path=/api/v1/namespaces/team/pods", nil), userClaims("nobody"))); got.Code != 403 {
		t.Errorf("watch by a principal with no policy: %d, want 403", got.Code)
	}
	if nextHit {
		t.Error("a denied request reached the upstream")
	}
}

// Legacy is today's behaviour: the route gate passes and the handler's own checks decide; shadow
// computes IAM's answer but still returns legacy's.
func TestConsoleGate_LegacyAndShadowChangeNothing(t *testing.T) {
	for _, mode := range []iamauthz.Mode{iamauthz.ModeLegacy, iamauthz.ModeShadow} {
		z := newTestAuthz(t, mode, testWorld(t, nil, nil), true)
		h := testRoutes(z)
		if got := serve(h, as(httptest.NewRequest(http.MethodDelete, "/api/buckets/b", nil), userClaims("nobody"))); got.Code != 200 {
			t.Errorf("%s: a policy-less user reaches the handler (its own checks decide): got %d", mode, got.Code)
		}
		if z.enforced(as(httptest.NewRequest(http.MethodGet, "/", nil), userClaims("nobody"))) {
			t.Errorf("%s must not report enforce", mode)
		}
	}
}

// A canary-labelled user is in enforce while the platform runs shadow.
func TestConsoleGate_CanaryIsEnforced(t *testing.T) {
	w := testWorld(t, nil, nil)
	w.Enforce["User::canary"] = true
	z := newTestAuthz(t, iamauthz.ModeShadow, w, true)
	h := testRoutes(z)
	if got := serve(h, as(httptest.NewRequest(http.MethodGet, "/api/buckets", nil), userClaims("canary"))); got.Code != 403 {
		t.Errorf("a canary with no policy: %d, want 403", got.Code)
	}
	if got := serve(h, as(httptest.NewRequest(http.MethodGet, "/api/buckets", nil), userClaims("other"))); got.Code != 200 {
		t.Errorf("a non-canary user in shadow: %d, want 200 (legacy decides)", got.Code)
	}
}

// Root is the account's root user: allowed everywhere in every mode, even with RBAC denying, and the
// proxy keeps acting as its break-glass identity.
func TestConsoleGate_RootIsNeverLockedOut(t *testing.T) {
	for _, mode := range []iamauthz.Mode{iamauthz.ModeLegacy, iamauthz.ModeShadow, iamauthz.ModeEnforce} {
		z := newTestAuthz(t, mode, testWorld(t, nil, nil), false)
		h := testRoutes(z)
		for _, rq := range []struct{ method, path string }{
			{http.MethodGet, "/api/buckets"}, {http.MethodDelete, "/api/buckets/b"}, {http.MethodGet, "/api/iam/users"},
			{http.MethodPost, "/api/iam/users/alice/password"},
		} {
			if got := serve(h, as(httptest.NewRequest(rq.method, rq.path, nil), rootClaims())); got.Code != 200 {
				t.Errorf("%s: root %s %s: %d", mode, rq.method, rq.path, got.Code)
			}
		}
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
		for _, p := range []string{"/api/k8s/apis", "/api/k8s/apis/openinfra.dev/v1/namespaces/x/frobnicators", "/api/k8s/api/v1/secrets"} {
			if got := serve(z.proxyHandler(k8sPrefix, next), as(httptest.NewRequest(http.MethodGet, p, nil), rootClaims())); got.Code != 200 {
				t.Errorf("%s: root through the proxy %s: %d", mode, p, got.Code)
			}
		}
		id, ok := z.proxyIdentity(as(httptest.NewRequest(http.MethodGet, "/", nil), rootClaims()))
		if !ok || id.User != "openinfra:000000000000:root" || len(id.Groups) != 0 {
			t.Errorf("%s: root must act as its break-glass identity (openinfra:000000000000:root, in no group), got %+v", mode, id)
		}
		// The handlers' own check (authz.go) for root.
		r := as(httptest.NewRequest(http.MethodGet, "/", nil), rootClaims())
		if mode == iamauthz.ModeEnforce {
			if ok, why := z.authorizeKubernetesVerb(r, z.cs, rootClaims(), "delete", "", "secrets", "kube-system", "x"); !ok {
				t.Errorf("enforce: root's handler check: %s", why)
			}
		}
	}
}

// ── the proxy ────────────────────────────────────────────────────────────────────

func TestConsoleProxy_MapsKubernetesRequestsToAWSActions(t *testing.T) {
	listBuckets, _, _ := awsaction.ForKubernetes("list", "openinfra.dev", "buckets", "team", "", iam.ManagementAccount)
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["` + listBuckets + `","openinfra:DescribeAPIs"],"Resource":"*"}]}`
	w := testWorld(t, map[string]string{"lister": doc}, map[string][]string{"User::alice": {"lister"}})
	z := newTestAuthz(t, iamauthz.ModeEnforce, w, true)
	hits := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++; w.WriteHeader(200) })
	h := z.proxyHandler(k8sPrefix, next)
	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/k8s/apis/openinfra.dev/v1/namespaces/team/buckets", 200},
		{http.MethodGet, "/api/k8s/apis", 200}, // discovery: openinfra:DescribeAPIs
		{http.MethodDelete, "/api/k8s/apis/openinfra.dev/v1/namespaces/team/buckets/b", 403},
		{http.MethodGet, "/api/k8s/api/v1/namespaces/team/secrets", 403},                     // operator surface
		{http.MethodGet, "/api/k8s/apis/openinfra.dev/v1/namespaces/team/frobnicators", 403}, // unmapped openinfra kind
		{http.MethodGet, "/api/k8s/metrics", 403},                                            // not a Kubernetes API path
	}
	for _, c := range cases {
		if got := serve(h, as(httptest.NewRequest(c.method, c.path, nil), userClaims("alice"))); got.Code != c.want {
			t.Errorf("%s %s: %d, want %d (%s)", c.method, c.path, got.Code, c.want, got.Body)
		}
	}
	if hits != 2 {
		t.Errorf("forwarded %d requests, want the 2 allowed ones", hits)
	}
	// In enforce the proxy acts as the principal's account identity, with no group tiers.
	id, _ := z.proxyIdentity(as(httptest.NewRequest(http.MethodGet, "/", nil), userClaims("alice", "openinfra:admins")))
	if id.User != "openinfra:000000000000:alice" || len(id.Groups) != 0 {
		t.Errorf("enforce identity: %+v", id)
	}
	t.Setenv("IAM_PROXY_IDENTITY", "legacy")
	id, _ = z.proxyIdentity(as(httptest.NewRequest(http.MethodGet, "/", nil), userClaims("alice", "openinfra:admins")))
	if id.User != "openinfra:alice" || len(id.Groups) == 0 {
		t.Errorf("IAM_PROXY_IDENTITY=legacy keeps the legacy identity: %+v", id)
	}
}

func TestConsoleProxy_LegacyForwardsAsBefore(t *testing.T) {
	z := newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), false)
	hits := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++; w.WriteHeader(200) })
	for _, p := range []string{"/api/k8s/apis/openinfra.dev/v1/namespaces/team/frobnicators", "/api/k8s/metrics", "/api/k8s/api/v1/secrets"} {
		serve(z.proxyHandler(k8sPrefix, next), as(httptest.NewRequest(http.MethodGet, p, nil), userClaims("nobody")))
	}
	if hits != 3 {
		t.Errorf("legacy forwarded %d of 3 (the API server's RBAC decides them, as before)", hits)
	}
	id, _ := z.proxyIdentity(as(httptest.NewRequest(http.MethodGet, "/", nil), userClaims("alice", "openinfra:admins")))
	if id.User != "openinfra:alice" || len(id.Groups) == 0 {
		t.Errorf("legacy identity: %+v", id)
	}
}

// The watch stream read with the console's ServiceAccount and no check; now a SubjectAccessReview of
// watch as the user decides in legacy, and IAM policy in enforce.
func TestConsoleWatch_IsAuthorizedAsTheUser(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	path := "/api/watch?path=" + url.QueryEscape("/api/v1/namespaces/team/pods")
	z := newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), false)
	if got := serve(z.watchHandler(next), as(httptest.NewRequest(http.MethodGet, path, nil), userClaims("alice"))); got.Code != 403 {
		t.Errorf("legacy: RBAC refuses watch, yet %d", got.Code)
	}
	z = newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), true)
	if got := serve(z.watchHandler(next), as(httptest.NewRequest(http.MethodGet, path, nil), userClaims("alice"))); got.Code != 200 {
		t.Errorf("legacy: RBAC allows watch, yet %d", got.Code)
	}
	w := testWorld(t, map[string]string{"admin": adminDoc}, map[string][]string{"User::admin": {"admin"}})
	z = newTestAuthz(t, iamauthz.ModeEnforce, w, false)
	if got := serve(z.watchHandler(next), as(httptest.NewRequest(http.MethodGet, path, nil), userClaims("admin"))); got.Code != 200 {
		t.Errorf("enforce: AdministratorAccess watching pods: %d", got.Code)
	}
}

// ── IAM's own actions ────────────────────────────────────────────────────────────

// Your own password is iam:ChangePassword (AWS's self-service action); another user's is
// iam:UpdateLoginProfile.
func TestConsoleIAM_PasswordIsChangePasswordOnSelf(t *testing.T) {
	w := testWorld(t, map[string]string{"self-pw": selfPasswordDoc}, map[string][]string{"User::alice": {"self-pw"}})
	z := newTestAuthz(t, iamauthz.ModeEnforce, w, true)
	h := testRoutes(z)
	if got := serve(h, as(httptest.NewRequest(http.MethodPost, "/api/iam/users/alice/password", nil), userClaims("alice"))); got.Code != 200 {
		t.Errorf("alice changing her own password: %d %s", got.Code, got.Body)
	}
	got := serve(h, as(httptest.NewRequest(http.MethodPost, "/api/iam/users/bob/password", nil), userClaims("alice")))
	if got.Code != 403 || !strings.Contains(got.Body.String(), "iam:UpdateLoginProfile") {
		t.Errorf("alice setting bob's password: %d %s, want 403 on iam:UpdateLoginProfile", got.Code, got.Body)
	}
}

// PowerUserAccess is denied IAM writes: attaching a policy, adding to a group, setting a boundary.
func TestConsoleIAM_PowerUserCannotChangeAttachments(t *testing.T) {
	w := testWorld(t, map[string]string{"PowerUserAccess": powerUserDoc}, map[string][]string{"User::pu": {"PowerUserAccess"}})
	newTestAuthz(t, iamauthz.ModeEnforce, w, true)
	for _, c := range []attachmentChange{
		{kind: "user", name: "pu", policiesAdded: true},
		{kind: "user", name: "pu", groupsAdded: []string{"admins"}},
		{kind: "user", name: "other", boundaryDeleted: true},
		{kind: "group", name: "g", inlinePut: true},
		{kind: "role", name: "r", trustChanged: true},
	} {
		rec := httptest.NewRecorder()
		if requireChange(rec, as(httptest.NewRequest(http.MethodPatch, "/", nil), userClaims("pu")), c) {
			t.Errorf("PowerUserAccess was allowed %+v", c)
		}
		if rec.Code != 403 {
			t.Errorf("%+v: %d, want 403", c, rec.Code)
		}
	}
	// …while the change actions pass in legacy (the handler's own checks decide, as before).
	newTestAuthz(t, iamauthz.ModeLegacy, w, true)
	if !requireChange(httptest.NewRecorder(), as(httptest.NewRequest(http.MethodPatch, "/", nil), userClaims("pu")), attachmentChange{kind: "user", name: "pu", policiesAdded: true}) {
		t.Error("legacy must not add IAM checks")
	}
}

// In enforce a handler's SubjectAccessReview defers to the route gate that already decided (and fails
// closed when there was none); in legacy it is the SubjectAccessReview, unchanged.
func TestConsoleHandlerCheck_FollowsTheMode(t *testing.T) {
	z := newTestAuthz(t, iamauthz.ModeEnforce, testWorld(t, nil, nil), false)
	r := as(httptest.NewRequest(http.MethodGet, "/", nil), userClaims("nobody"))
	if ok, _ := z.authorizeKubernetesVerb(r, z.cs, userClaims("nobody"), "update", "openinfra.dev", "applications", "team", "db"); ok {
		t.Error("enforce, no route decision, no policy: must deny")
	}
	r = r.WithContext(withRouteAuthorized(r.Context()))
	if ok, _ := z.authorizeKubernetesVerb(r, z.cs, userClaims("nobody"), "update", "openinfra.dev", "applications", "team", "db"); !ok {
		t.Error("enforce, the route gate already allowed: the handler check defers to it")
	}
	z = newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), true)
	r = as(httptest.NewRequest(http.MethodGet, "/", nil), userClaims("nobody"))
	if ok, _ := z.authorizeKubernetesVerb(r, z.cs, userClaims("nobody"), "update", "openinfra.dev", "applications", "team", "db"); !ok {
		t.Error("legacy: the SubjectAccessReview decides (allowed here)")
	}
}

func TestConsoleIAM_DocumentsAreValidatedAsIAMDoes(t *testing.T) {
	if _, msg := checkDocument(s3ReadDoc); msg != "" {
		t.Errorf("a valid document refused: %s", msg)
	}
	for _, bad := range []string{"", "{", `{"Version":"2012-10-17"}`, `{"Statement":[{"Effect":"Maybe","Action":"s3:*","Resource":"*"}]}`} {
		if _, msg := checkDocument(bad); !strings.HasPrefix(msg, "MalformedPolicyDocument") {
			t.Errorf("%q accepted (%q)", bad, msg)
		}
	}
	if m := policyErr("MalformedPolicyDocument: bad"); m["errorCode"] != "MalformedPolicyDocument" || m["error"] != "bad" {
		t.Errorf("policyErr: %v", m)
	}
	if _, msg := checkInline([]inlinePolicy{{Name: "a", Document: s3ReadDoc}, {Name: "a", Document: s3ReadDoc}}); msg == "" {
		t.Error("two inline policies with one name must be refused")
	}
	added, removed := setDiff([]string{"a", "b"}, []string{"b", "c"})
	if len(added) != 1 || added[0] != "c" || len(removed) != 1 || removed[0] != "a" {
		t.Errorf("setDiff: +%v -%v", added, removed)
	}
}

// A role's trust admits the caller by name, ARN, typed name, its account, or anyone — nothing else; and
// another account's role admits it only by "*", its account or its ARN: a bare name there is that
// account's own user.
func TestSwitchRole_TrustNamesTheCaller(t *testing.T) {
	alice := iamauthz.Principal{Type: iamauthz.User, ID: "alice"}
	for _, trust := range [][]string{{"*"}, {"alice"}, {"User::alice"}, {"arn:aws:iam::000000000000:user/alice"},
		{"arn:aws:iam::000000000000:root"}, {"000000000000"}} {
		if !trusts(trust, alice, "alice", "000000000000") {
			t.Errorf("trust %v must admit alice", trust)
		}
	}
	for _, trust := range [][]string{{}, {"bob"}, {"arn:aws:iam::900000000001:root"}, {"Role::alice"}} {
		if trusts(trust, alice, "alice", "000000000000") {
			t.Errorf("trust %v must not admit alice", trust)
		}
	}
	for _, trust := range [][]string{{"*"}, {"arn:aws:iam::000000000000:user/alice"}, {"arn:aws:iam::000000000000:root"}, {"000000000000"}} {
		if !trusts(trust, alice, "alice", "900000000002") {
			t.Errorf("another account's trust %v must admit alice", trust)
		}
	}
	for _, trust := range [][]string{{"alice"}, {"User::alice"}, {"arn:aws:iam::900000000002:user/alice"}} {
		if trusts(trust, alice, "alice", "900000000002") {
			t.Errorf("another account's trust %v names its own user, not alice of the management account", trust)
		}
	}
	root := iamauthz.Principal{Type: iamauthz.Root}
	if !trusts([]string{"arn:aws:iam::000000000000:root"}, root, "root", "000000000000") || trusts([]string{"root"}, root, "root", "000000000000") {
		t.Error("root is admitted by its account, not by a user name")
	}
}

// switchRoleRouter is the console's Switch role route over a fixed set of roles ("<account>/<role>" →
// its trust), behind the gate z, with sessions signed by auth.
func switchRoleRouter(z *consoleAuthz, roles map[string][]string) (http.Handler, *authStore) {
	auth := &authStore{mode: "local", sessionKey: []byte("k"), cs: z.cs, ns: "open-infra-console", logger: testLogger()}
	z.auth = auth
	find := func(_ context.Context, account, name string) (string, crdRole, bool) {
		trust, ok := roles[account+"/"+name]
		if !ok {
			return "", crdRole{}, false
		}
		var role crdRole
		role.Metadata.Name, role.Spec.Trust = name, trust
		return "home-" + account, role, true
	}
	router := chi.NewRouter()
	router.Route("/api", func(api chi.Router) {
		api.Use(auth.requireAuth)
		z.handleDecided(api, apiPrefix, http.MethodPost, "/sts/switch-role", 0, "sts:AssumeRole on the role",
			z.switchRoleQuestion(find), handleSwitchRole(find, auth, testLogger()))
	})
	return router, auth
}

// switchRole posts a Switch role as the console UI does, signed in as c.
func switchRole(t *testing.T, router http.Handler, auth *authStore, c sessionClaims, account, role string) *httptest.ResponseRecorder {
	t.Helper()
	tok, err := auth.issueClaims(c.Claims)
	if err != nil {
		t.Fatalf("sign a session: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/sts/switch-role",
		strings.NewReader(`{"account":"`+account+`","roleName":"`+role+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(csrfHeader, "1")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec
}

// Switch role is decided as AWS decides sts:AssumeRole: another account's role needs both its trust and
// the caller's own policy, a trust naming the caller in its own account is enough on its own, and an
// account's root user cannot switch. The management account's administrator reaches a member account's
// OrganizationAccountAccessRole (it was refused by the gate whatever the trust said).
func TestSwitchRole_DecidedAsAssumeRole(t *testing.T) {
	const member = "900000000002"
	denyAssume := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}]}`
	w := testWorld(t, map[string]string{"AdministratorAccess": adminDoc, "DenyAssume": denyAssume}, map[string][]string{
		"User::admin":   {"AdministratorAccess"},
		"User::alice":   {"AdministratorAccess"},
		"User::denied":  {"DenyAssume"},
		"Group::admins": {"AdministratorAccess"},
	})
	roles := map[string][]string{
		member + "/organizationaccountaccessrole": {"arn:aws:iam::000000000000:root"},
		member + "/team-alice":                    {"alice"}, // the member account's own alice
		"000000000000/ops":                        {"nobody", "denied"},
		"000000000000/delegated":                  {"arn:aws:iam::000000000000:root"},
		"000000000000/untrusted":                  {"someone-else"},
	}
	for _, tc := range []struct {
		name          string
		who           sessionClaims
		account, role string
		want          int
	}{
		{"an administrator switches into a member account's OrganizationAccountAccessRole", userClaims("admin"), member, "organizationaccountaccessrole", 200},
		{"…and so does a member of the admins group", userClaims("carol", "admins"), member, "organizationaccountaccessrole", 200},
		{"a user no policy allows is refused another account's role, though its trust names the account", userClaims("nobody"), member, "organizationaccountaccessrole", 403},
		{"another account's bare name is that account's user, not the caller", userClaims("alice"), member, "team-alice", 403},
		{"a role that is not there is refused like one whose trust does not name the caller", userClaims("admin"), member, "missing", 403},
		{"in its own account a trust naming the caller is enough, with no policy", userClaims("nobody"), "000000000000", "ops", 200},
		{"…but an explicit Deny in the caller's policy refuses it", userClaims("denied"), "000000000000", "ops", 403},
		{"a trust naming the account needs the caller's policy", userClaims("nobody"), "000000000000", "delegated", 403},
		{"…which an administrator has", userClaims("admin"), "000000000000", "delegated", 200},
		{"the caller's policy alone does not reach a role whose trust does not name it", userClaims("admin"), "000000000000", "untrusted", 403},
		{"an account's root user cannot switch roles", rootClaims(), member, "organizationaccountaccessrole", 403},
	} {
		z := newTestAuthz(t, iamauthz.ModeEnforce, w, false)
		router, auth := switchRoleRouter(z, roles)
		rec := switchRole(t, router, auth, tc.who, tc.account, tc.role)
		if rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body.String(), tc.want)
			continue
		}
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		switch tc.want {
		case 403:
			if body["errorCode"] != "AccessDeniedException" || body["action"] != "sts:AssumeRole" ||
				body["resource"] != "arn:aws:iam::"+tc.account+":role/"+tc.role {
				t.Errorf("%s: the refusal is not AWS's AccessDenied for sts:AssumeRole on the role: %v", tc.name, body)
			}
		case 200:
			if body["arn"] != "arn:aws:sts::"+tc.account+":assumed-role/"+tc.role+"/"+tc.who.Sub {
				t.Errorf("%s: the session is %q, want the role's in its account", tc.name, body["arn"])
			}
		}
	}
}

// A console role session is only valid while IAM policy decides it: after a rollback to legacy every
// check refuses it (the legacy checks would otherwise pass an assumed-role session).
func TestSwitchRole_RoleSessionEndsOutsideEnforce(t *testing.T) {
	role := userClaims("alice")
	role.AssumedRole, role.Account = "ops", "000000000000"
	for _, mode := range []iamauthz.Mode{iamauthz.ModeLegacy, iamauthz.ModeShadow} {
		z := newTestAuthz(t, mode, testWorld(t, nil, nil), true)
		r := as(httptest.NewRequest(http.MethodGet, "/", nil), role)
		if ok, _ := z.decide(r, "s3:ListAllMyBuckets", "*", allowLegacy); ok {
			t.Errorf("%s: a role session passed the gate", mode)
		}
		if ok, _ := z.authorizeKubernetesVerb(r, z.cs, role, "get", "", "pods", "x", ""); ok {
			t.Errorf("%s: a role session passed a handler check", mode)
		}
	}
	w := testWorld(t, map[string]string{"admin": adminDoc}, map[string][]string{"Role::ops": {"admin"}})
	z := newTestAuthz(t, iamauthz.ModeEnforce, w, false)
	if ok, why := z.decide(as(httptest.NewRequest(http.MethodGet, "/", nil), role), "s3:ListAllMyBuckets", "*", allowLegacy); !ok {
		t.Errorf("enforce: the role's own policy decides its session: %s", why)
	}
	if p := z.principal(role); p.Type != iamauthz.Role || p.ARN() != "arn:aws:sts::000000000000:assumed-role/ops/alice" {
		t.Errorf("the session is the role's: %+v %s", p, p.ARN())
	}
}

func TestSwitchRole_AccountHome(t *testing.T) {
	auth := &authStore{ns: "open-infra-console"}
	if home, ok := accountHome(context.Background(), fake.NewSimpleClientset(), auth, "000000000000"); !ok || home != "open-infra-console" {
		t.Errorf("the management account's home is the console namespace: %q %v", home, ok)
	}
	if _, ok := accountHome(context.Background(), fake.NewSimpleClientset(), auth, "900000000001"); ok {
		t.Error("an account with no home namespace has no roles to switch to")
	}
	home := func(name, account string, extra ...string) *corev1.Namespace {
		l := map[string]string{accounts.LabelAccountID: account, accounts.LabelAccountHome: "true"}
		for i := 0; i+1 < len(extra); i += 2 {
			l[extra[i]] = extra[i+1]
		}
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: l}}
	}
	cs := fake.NewSimpleClientset(
		home("team-b", "900000000002"),
		home("team-c", "900000000003", accounts.LabelAccountStatus, accounts.StatusSuspended),
		home("kube-system", "900000000004"),
	)
	if h, ok := accountHome(context.Background(), cs, auth, "900000000002"); !ok || h != "team-b" {
		t.Errorf("a member account's home is its labelled home namespace: %q %v", h, ok)
	}
	if _, ok := accountHome(context.Background(), cs, auth, "900000000003"); ok {
		t.Error("a suspended account's roles must not be assumable")
	}
	if _, ok := accountHome(context.Background(), cs, auth, "900000000004"); ok {
		t.Error("a platform namespace is no account's home")
	}
}

// The gate reads a create's resource from the body and gives it back intact to the handler.
// A route whose handler takes its resource from the query string or the body is authorized on that
// resource's ARN, as AWS authorizes the API call: deleting or restoring a snapshot is decided on the
// snapshot, so a policy that allows it on one snapshot does not reach another, and one that allows only
// reads (rds:DescribeDBSnapshots) is denied the delete.
func TestConsoleRoutes_SnapshotRoutesAreDecidedOnTheSnapshot(t *testing.T) {
	cfg := &rest.Config{Host: "http://127.0.0.1:1"}
	host, _ := url.Parse(cfg.Host)
	var ci kubernetes.Interface = kubernetes.NewForConfigOrDie(cfg)
	client := &k8s.Client{Config: cfg, Transport: http.DefaultTransport, Host: host, Clientset: &ci}
	prev := consoleIAM
	t.Cleanup(func() { consoleIAM = prev })
	_, z := buildRouter(client, &authStore{mode: "local", sessionKey: []byte("k")}, testLogger())
	z.cs = fake.NewSimpleClientset() // the namespaces carry no account label: the management account's
	routes := map[string]awsaction.Route{}
	for _, rt := range z.reg.Routes() {
		routes[rt.Method+" "+rt.Path] = rt
	}
	for _, tc := range []struct {
		route, action string
		req           *http.Request
		want          string
	}{
		{"DELETE /api/snapshots", "rds:DeleteDBSnapshot",
			httptest.NewRequest(http.MethodDelete, "/api/snapshots?namespace=default&name=orders&id=snap-1", nil),
			"arn:aws:rds:us-east-1:000000000000:snapshot:snap-1"},
		{"POST /api/snapshots/restore", "rds:RestoreDBInstanceFromDBSnapshot",
			httptest.NewRequest(http.MethodPost, "/api/snapshots/restore", strings.NewReader(`{"namespace":"default","id":"snap-1","target":"orders-2"}`)),
			"arn:aws:rds:us-east-1:000000000000:snapshot:snap-1"},
		{"DELETE /api/vm-snapshots", "ec2:DeleteSnapshot",
			httptest.NewRequest(http.MethodDelete, "/api/vm-snapshots?namespace=default&id=snap-1", nil),
			"arn:aws:ec2:us-east-1:000000000000:snapshot/snap-1"},
		{"POST /api/vm-snapshots/restore", "ec2:RunInstances",
			httptest.NewRequest(http.MethodPost, "/api/vm-snapshots/restore", strings.NewReader(`{"namespace":"default","id":"snap-1","target":"web-2"}`)),
			"arn:aws:ec2:us-east-1:000000000000:snapshot/snap-1"},
	} {
		rt, ok := routes[tc.route]
		if !ok || rt.Action != tc.action {
			t.Errorf("%s: route %+v, want action %s", tc.route, rt, tc.action)
			continue
		}
		if rt.ARN == nil {
			t.Errorf("%s: authorized on \"*\", want %s", tc.route, tc.want)
			continue
		}
		if got := rt.ARN(tc.req); got != tc.want {
			t.Errorf("%s: ARN %s, want %s", tc.route, got, tc.want)
		}
	}

	// Decided on that ARN, in enforce.
	snap1 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rds:DeleteDBSnapshot","Resource":"arn:aws:rds:us-east-1:000000000000:snapshot:snap-1"}]}`
	reads := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rds:DescribeDBSnapshots","Resource":"*"}]}`
	w := testWorld(t, map[string]string{"snap1": snap1, "reads": reads},
		map[string][]string{"User::owner": {"snap1"}, "User::reader": {"reads"}})
	ez := newTestAuthz(t, iamauthz.ModeEnforce, w, true)
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
	r := chi.NewRouter()
	r.Route("/api", func(api chi.Router) {
		ez.handle(api, apiPrefix, http.MethodDelete, "/snapshots", 0, "rds:DeleteDBSnapshot", ez.snapshotARN("rds", false), ok)
	})
	del := func(c sessionClaims, id string) *httptest.ResponseRecorder {
		return serve(r, as(httptest.NewRequest(http.MethodDelete, "/api/snapshots?namespace=default&name=orders&id="+id, nil), c))
	}
	if got := del(userClaims("owner"), "snap-1"); got.Code != 200 {
		t.Errorf("deleting the snapshot the policy names: %d %s", got.Code, got.Body)
	}
	if got := del(userClaims("owner"), "snap-2"); got.Code != 403 || errorCode(t, got) != "AccessDeniedException" ||
		!strings.Contains(got.Body.String(), "rds:DeleteDBSnapshot on resource: arn:aws:rds:us-east-1:000000000000:snapshot:snap-2") {
		t.Errorf("deleting another snapshot: %d %s, want AccessDenied on its ARN", got.Code, got.Body)
	}
	if got := del(userClaims("reader"), "snap-1"); got.Code != 403 || errorCode(t, got) != "AccessDeniedException" {
		t.Errorf("a reader deleting a snapshot: %d %s, want 403 AccessDeniedException", got.Code, got.Body)
	}
}

func TestPeekBodyRestoresTheBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"reports","x":1}`))
	if got := peekBody(r, "name"); got != "reports" {
		t.Errorf("peekBody = %q", got)
	}
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil || m["name"] != "reports" {
		t.Errorf("the handler must still read the body: %v %v", m, err)
	}
	_ = proxy.Request{}
}

// The gate reads a body's resource as the handler's decoder will, and refuses a body it cannot read
// unambiguously: encoding/json matches keys ignoring case and the last match wins, so {"id":"a","ID":"b"}
// would be decided on snap a and restored from snap b (and, with namespace, in another account), and a
// body past maxPeek would be decided on "*" while the handler acted on the snapshot it names.
func TestConsoleGate_ReadsTheBodyAsTheHandlerDoes(t *testing.T) {
	snap1 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"arn:aws:ec2:us-east-1:000000000000:snapshot/snap-1"}]}`
	w := testWorld(t, map[string]string{"snap1": snap1}, map[string][]string{"User::owner": {"snap1"}})
	ez := newTestAuthz(t, iamauthz.ModeEnforce, w, true)
	var restored string
	h := func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID, Namespace, Target string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		restored = in.ID
		_, _ = w.Write([]byte("ok"))
	}
	rt := chi.NewRouter()
	rt.Route("/api", func(api chi.Router) {
		ez.handle(api, apiPrefix, http.MethodPost, "/vm-snapshots/restore", 0, "ec2:RunInstances", ez.snapshotARN("ec2", true), h)
	})
	post := func(body string) *httptest.ResponseRecorder {
		restored = ""
		return serve(rt, as(httptest.NewRequest(http.MethodPost, "/api/vm-snapshots/restore", strings.NewReader(body)), userClaims("owner")))
	}

	if got := post(`{"namespace":"default","id":"snap-1","target":"web-2"}`); got.Code != 200 || restored != "snap-1" {
		t.Fatalf("restoring the snapshot the policy names: %d %s", got.Code, got.Body)
	}
	// The handler's decoder reads "ID" as id: so does the gate.
	if got := post(`{"namespace":"default","ID":"snap-2","target":"web-2"}`); got.Code != 403 || restored != "" {
		t.Errorf(`"ID" spelled differently: %d %s (restored %q), want AccessDenied on snap-2`, got.Code, got.Body, restored)
	}
	for _, body := range []string{
		`{"namespace":"default","id":"snap-1","ID":"snap-2","target":"web-2"}`,
		`{"namespace":"default","Id":"snap-1","id":"snap-2","target":"web-2"}`,
		`{"namespace":"default","Namespace":"other","id":"snap-1","target":"web-2"}`,
	} {
		if got := post(body); got.Code != 400 || restored != "" {
			t.Errorf("%s: %d %s (restored %q), want 400 and nothing restored", body, got.Code, got.Body, restored)
		}
	}
	big := `{"namespace":"default","id":"snap-2","target":"web-2","pad":"` + strings.Repeat("x", maxPeek) + `"}`
	if got := post(big); got.Code != 400 || restored != "" {
		t.Errorf("a body past maxPeek: %d (restored %q), want 400 and nothing restored", got.Code, restored)
	}
}
