package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/awsaction"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/k8s"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

// A route with an IAM action in the route table is only a promise: these tests hold every one of them to
// it. Each fixed-action route is called through the console's real router, signed in with a real session
// cookie, with IAM policy deciding: a principal no policy allows must get the gate's own AccessDenied,
// naming the route's action and resource, with nothing behind the gate reached; AdministratorAccess must
// get past the gate. A route registered but mounted without its gate, gated on another action, or whose
// ARN cannot be built fails here by name.

// A request names a made-up resource everywhere a route reads one — its path parameters, its query and,
// for a write, its JSON body — so every route's ARN function builds a real ARN rather than "*".
const (
	routeTestValue = "route-test"
	routeTestQuery = "namespace=route-test&name=route-test&id=snap-route-test&key=route-test.txt"
	routeTestBody  = `{"name":"route-test","namespace":"route-test","id":"snap-route-test","subject":"route-test.events","deviceName":"route-test","target":"route-test-2"}`

	// A request's own deadline, so a handler waiting on an upstream gives up, and how long the check
	// waits for an answer before it calls the route hung.
	routeTestDeadline = 5 * time.Second
	routeTestHang     = 15 * time.Second
)

var routeParam = regexp.MustCompile(`\{([^}:]+)(?::[^}]*)?\}`)

// routeProbe calls a router's fixed-action routes as the console's UI does: the route's method, its path
// with every {param} filled, the session cookie and the CSRF header.
type routeProbe struct {
	router http.Handler
	z      *consoleAuthz // the router's gate: its route table, and the ARN and decision it gives
	auth   *authStore    // signs the sessions
	// reached counts calls behind the gate (handlers, the upstreams they call); nil when not observable.
	reached func() int64
}

// fixedActionRoutes are the routes whose IAM action the table names (not decided per request).
func fixedActionRoutes(reg *awsaction.Registry) []awsaction.Route {
	var out []awsaction.Route
	for _, rt := range reg.Routes() {
		if !strings.HasPrefix(rt.Action, "per-request: ") {
			out = append(out, rt)
		}
	}
	return out
}

// session signs a session for a plain (non-root) user, as sign-in does.
func (p routeProbe) session(t *testing.T, user string) (string, sessionClaims) {
	t.Helper()
	tok, err := p.auth.issueClaims(iam.Claims{Sub: user, Role: "poweruser", MFA: iam.NoMFA()})
	if err != nil {
		t.Fatalf("sign a session for %s: %v", user, err)
	}
	c, ok := p.auth.parse(tok)
	if !ok {
		t.Fatalf("the session signed for %s does not verify", user)
	}
	return tok, c
}

// routeRequest is the call of rt, and the path parameters it fills.
func routeRequest(rt awsaction.Route) (*http.Request, map[string]string) {
	params := map[string]string{}
	path := routeParam.ReplaceAllStringFunc(rt.Path, func(m string) string {
		params[routeParam.FindStringSubmatch(m)[1]] = routeTestValue
		return url.PathEscape(routeTestValue)
	})
	var r *http.Request
	switch rt.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		r = httptest.NewRequest(rt.Method, path+"?"+routeTestQuery, strings.NewReader(routeTestBody))
		r.Header.Set("Content-Type", "application/json")
	default:
		r = httptest.NewRequest(rt.Method, path+"?"+routeTestQuery, nil)
	}
	return r, params
}

// call serves rt to the router as the session tok, within routeTestHang. A panic or a hang is the problem.
func (p routeProbe) call(rt awsaction.Route, tok string) (*httptest.ResponseRecorder, string) {
	r, _ := routeRequest(rt)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	r.Header.Set(csrfHeader, "1")
	ctx, cancel := context.WithTimeout(r.Context(), routeTestDeadline)
	defer cancel()
	r = r.WithContext(ctx)

	rec := httptest.NewRecorder()
	done := make(chan string, 1)
	go func() {
		defer func() {
			if v := recover(); v != nil {
				done <- fmt.Sprintf("panicked: %v", v)
			}
		}()
		p.router.ServeHTTP(rec, r)
		done <- ""
	}()
	select {
	case problem := <-done:
		return rec, problem
	case <-time.After(routeTestHang):
		return nil, fmt.Sprintf("no answer within %s", routeTestHang) // rec stays with the hung handler
	}
}

// gateDenial is what rt's gate answers c, built from the route table's own entry: its action, its ARN
// function over the same request, and the evaluator's decision. The problem is set when it cannot be
// built, or when c is allowed (there is then no denial to check).
func (p routeProbe) gateDenial(rt awsaction.Route, c sessionClaims) (want *httptest.ResponseRecorder, arn, problem string) {
	r, params := routeRequest(rt)
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	r = as(r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx)), c)
	arn = "*"
	if rt.ARN != nil {
		func() {
			defer func() {
				if v := recover(); v != nil {
					problem = fmt.Sprintf("its ARN function panics: %v", v)
				}
			}()
			arn = rt.ARN(r)
		}()
		if problem != "" {
			return nil, "", problem
		}
	}
	ok, reason := p.z.decide(r, rt.Action, arn, allowLegacy)
	if ok {
		return nil, arn, fmt.Sprintf("%s on %s is allowed for %s, so its denial cannot be checked", rt.Action, arn, c.Sub)
	}
	want = httptest.NewRecorder()
	writeAccessDenied(want, rt.Action, arn, reason)
	return want, arn, ""
}

// deniedBy reads an AccessDenied answer: the action it names ("" when it is not one).
func deniedBy(rec *httptest.ResponseRecorder) (action, msg string) {
	var m map[string]string
	if rec.Code != http.StatusForbidden || json.Unmarshal(rec.Body.Bytes(), &m) != nil || m["errorCode"] != "AccessDeniedException" {
		return "", ""
	}
	return m["action"], m["error"]
}

// bodyRefused reports whether an answer is the gate's refusal of a body it cannot read (writeBodyRefused),
// which comes before the decision.
func bodyRefused(rec *httptest.ResponseRecorder) bool {
	var m map[string]string
	return rec.Code == http.StatusBadRequest && json.Unmarshal(rec.Body.Bytes(), &m) == nil &&
		m["errorCode"] == "ValidationException" && m["message"] != "" && m["message"] == m["error"]
}

func clip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// denyProblems calls every fixed-action route as tok (whose claims are c, a principal no policy allows)
// and returns, by "METHOD path", why a route's answer is not its gate's denial: anything but the exact
// 403 AccessDeniedException the gate writes for the route's action and ARN, or any call behind the gate.
// checked counts the routes called.
func (p routeProbe) denyProblems(tok string, c sessionClaims) (checked int, problems map[string]string) {
	problems = map[string]string{}
	for _, rt := range fixedActionRoutes(p.z.reg) {
		key := rt.Method + " " + rt.Path
		checked++
		want, arn, problem := p.gateDenial(rt, c)
		if problem != "" {
			problems[key] = problem
			continue
		}
		var before int64
		if p.reached != nil {
			before = p.reached()
		}
		got, problem := p.call(rt, tok)
		if problem != "" {
			problems[key] = problem
			continue
		}
		var why []string
		if p.reached != nil {
			if n := p.reached() - before; n > 0 {
				why = append(why, fmt.Sprintf("reached %d call(s) behind the gate", n))
			}
		}
		if action, msg := deniedBy(got); action != rt.Action ||
			!strings.HasPrefix(msg, "You are not authorized to perform: "+rt.Action+" on resource: "+arn) {
			why = append(why, fmt.Sprintf("answered %d %s, want 403 AccessDeniedException naming %s on %s", got.Code, clip(got.Body.Bytes()), rt.Action, arn))
		} else if got.Code != want.Code || got.Body.String() != want.Body.String() ||
			got.Header().Get("Content-Type") != want.Header().Get("Content-Type") {
			why = append(why, fmt.Sprintf("answered %d %s, not the gate's own denial %s", got.Code, clip(got.Body.Bytes()), clip(want.Body.Bytes())))
		}
		if len(why) > 0 {
			problems[key] = strings.Join(why, "; ")
		}
	}
	return checked, problems
}

// allowProblems calls every fixed-action route as tok (a principal policy allows everything) and returns,
// by "METHOD path", why a route did not get past its gate: refused by sign-in, the CSRF check or the gate's
// body check, denied by IAM, or no answer. What the handler then answers (it may fail against an absent
// upstream, or refuse the made-up body) is its own. reachedRoutes counts the routes whose call was seen
// behind the gate.
func (p routeProbe) allowProblems(tok string) (checked, reachedRoutes int, problems map[string]string) {
	problems = map[string]string{}
	for _, rt := range fixedActionRoutes(p.z.reg) {
		key := rt.Method + " " + rt.Path
		checked++
		var before int64
		if p.reached != nil {
			before = p.reached()
		}
		got, problem := p.call(rt, tok)
		if problem != "" {
			problems[key] = problem
			continue
		}
		if p.reached != nil && p.reached() > before {
			reachedRoutes++
		}
		switch action, msg := deniedBy(got); {
		case got.Code == http.StatusUnauthorized:
			problems[key] = "refused by sign-in: " + clip(got.Body.Bytes())
		case got.Code == http.StatusForbidden && strings.Contains(got.Body.String(), "missing "+csrfHeader):
			problems[key] = "refused by the CSRF check"
		case bodyRefused(got):
			problems[key] = "refused by the gate's body check: " + clip(got.Body.Bytes())
		case action != "":
			problems[key] = fmt.Sprintf("denied %s: %s", action, msg)
		}
	}
	return checked, reachedRoutes, problems
}

func reportRouteProblems(t *testing.T, what string, problems map[string]string) {
	t.Helper()
	keys := make([]string, 0, len(problems))
	for k := range problems {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Errorf("%s %s: %s", k, what, problems[k])
	}
}

// ── the console's router ─────────────────────────────────────────────────────────

// refusingTransport is a Kubernetes API that refuses every request at once, counting it.
type refusingTransport struct{ hits *atomic.Int64 }

func (rt refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	rt.hits.Add(1)
	return nil, errors.New("no Kubernetes API in this test")
}

// consoleRouteProbe is the console's real router, its gate in enforce over world, with every upstream
// a handler calls answering at once and counted: the Kubernetes API (the handlers' clientset, the proxy,
// the watch stream, the CRD schemas and the policy loader all go through one refusing transport), the
// HTTP services (Grafana, Prometheus, Loki, NATS monitoring, the Iceberg catalog, the CA issuer, MinIO:
// a server answering 404) and NATS (a listener that hangs up). The gate's own namespace lookups go to a
// fake clientset; anything else asked of it is a handler's.
func consoleRouteProbe(t *testing.T, world iamauthz.World) routeProbe {
	t.Helper()
	var hits atomic.Int64

	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "no upstream in this test", http.StatusNotFound)
	}))
	t.Cleanup(web.Close)
	for _, k := range []string{"GRAFANA_PROXY_TARGET", "PROMETHEUS_URL", "LOKI_URL", "NATS_MONITOR_URL", "ICEBERG_CATALOG_URL", "CA_ISSUER_ENDPOINT"} {
		t.Setenv(k, web.URL)
	}
	t.Setenv("MINIO_ENDPOINT", strings.TrimPrefix(web.URL, "http://"))
	nats, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nats.Close() })
	go func() {
		for {
			c, err := nats.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	t.Setenv("NATS_URL", "nats://"+nats.Addr().String())

	kube := refusingTransport{&hits}
	// No client-side rate limit: a refused request must answer at once, not queue behind the limiter.
	cfg := &rest.Config{Host: "http://127.0.0.1:1", Transport: kube, QPS: -1}
	host, _ := url.Parse(cfg.Host)
	var ci kubernetes.Interface = kubernetes.NewForConfigOrDie(cfg)
	client := &k8s.Client{Config: cfg, Transport: kube, Host: host, Clientset: &ci}
	auth := &authStore{mode: "local", sessionKey: []byte("k"), cs: ci, ns: "open-infra-console", logger: testLogger()}
	prev := consoleIAM
	t.Cleanup(func() { consoleIAM = prev })
	router, z := buildRouter(client, auth, testLogger())

	// The gate's closures hold z, so its evaluator and clientset are swapped in place.
	z.eval = iamauthz.New(func(context.Context) (iamauthz.World, error) { return world, nil }, time.Minute,
		iamauthz.WithMode(iamauthz.ModeEnforce), iamauthz.WithLogger(testLogger()))
	gateCS := fake.NewSimpleClientset()
	gateCS.PrependReactor("*", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetVerb() != "get" || a.GetResource().Resource != "namespaces" {
			hits.Add(1)
		}
		return false, nil, nil
	})
	z.cs = gateCS
	return routeProbe{router: router, z: z, auth: auth, reached: hits.Load}
}

// Every route with a fixed IAM action denies a signed-in principal no policy allows, with the gate's own
// AccessDenied for the route's action and ARN, and nothing behind the gate is reached.
func TestConsoleRoutes_EveryGatedRouteDeniesWithoutPolicy(t *testing.T) {
	p := consoleRouteProbe(t, testWorld(t, nil, nil))
	tok, c := p.session(t, "route-nobody")
	fixed := len(fixedActionRoutes(p.z.reg))

	checked, problems := p.denyProblems(tok, c)
	reportRouteProblems(t, "by a principal with no policy", problems)
	if checked != fixed || fixed < 88 {
		t.Errorf("checked %d routes of %d with a fixed IAM action (the table names at least 88)", checked, fixed)
	}
	if p.reached() != 0 {
		t.Errorf("a denied route reached %d call(s) behind its gate", p.reached())
	}
	t.Logf("%d of %d fixed-action routes denied a principal with no policy at the gate", checked-len(problems), fixed)
}

// …and every one of them lets AdministratorAccess past the gate, to the handler.
func TestConsoleRoutes_EveryGatedRouteAllowsAdministratorAccess(t *testing.T) {
	w := testWorld(t, map[string]string{"AdministratorAccess": adminDoc}, map[string][]string{"User::route-admin": {"AdministratorAccess"}})
	p := consoleRouteProbe(t, w)
	tok, _ := p.session(t, "route-admin")
	fixed := len(fixedActionRoutes(p.z.reg))

	start := time.Now()
	checked, reached, problems := p.allowProblems(tok)
	reportRouteProblems(t, "by AdministratorAccess", problems)
	if checked != fixed || fixed < 88 {
		t.Errorf("checked %d routes of %d with a fixed IAM action (the table names at least 88)", checked, fixed)
	}
	t.Logf("%d of %d fixed-action routes let AdministratorAccess past the gate (%d seen calling an upstream) in %s",
		checked-len(problems), fixed, reached, time.Since(start).Round(time.Millisecond))
}

// The checks catch a route the table names but no gate decides, one decided on another action, one whose
// ARN cannot be built, and one whose gate denies even AdministratorAccess — and pass a route gated right.
func TestConsoleRoutes_CheckCatchesAnUngatedRoute(t *testing.T) {
	w := testWorld(t, map[string]string{"AdministratorAccess": adminDoc}, map[string][]string{"User::route-admin": {"AdministratorAccess"}})
	z := newTestAuthz(t, iamauthz.ModeEnforce, w, true)
	auth := &authStore{mode: "local", sessionKey: []byte("k"), cs: z.cs, ns: "open-infra-console", logger: testLogger()}
	z.auth = auth

	var hits atomic.Int64
	hit := func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write([]byte("ok")) }
	// A gate asking a fixed question whatever the route, and one denying whatever the policy.
	asks := func(action string, deny bool) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ok, reason := z.decide(r, action, "*", allowLegacy); !ok || deny {
					writeAccessDenied(w, action, "*", reason)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}
	router := chi.NewRouter()
	router.Route("/api", func(api chi.Router) {
		api.Use(auth.requireAuth)
		z.handle(api, apiPrefix, http.MethodGet, "/buckets/{bucket}/objects", 0, "s3:ListBucket", bucketARN, hit)
		// In the table, mounted with no gate.
		z.reg.Add(awsaction.Route{Method: http.MethodGet, Path: "/api/buckets", Action: "s3:ListAllMyBuckets"})
		api.Get("/buckets", hit)
		// In the table as s3:DeleteBucket, decided as s3:ListBucket.
		z.reg.Add(awsaction.Route{Method: http.MethodDelete, Path: "/api/buckets/{bucket}", Action: "s3:DeleteBucket", ARN: bucketARN})
		api.With(asks("s3:ListBucket", false)).Delete("/buckets/{bucket}", hit)
		// An ARN that cannot be built.
		z.handle(api, apiPrefix, http.MethodGet, "/buckets/{bucket}/object", 0, "s3:GetObject",
			func(*http.Request) string { panic("no ARN") }, hit)
		// Denied whatever the policy.
		z.reg.Add(awsaction.Route{Method: http.MethodPost, Path: "/api/buckets", Action: "s3:CreateBucket"})
		api.With(asks("s3:CreateBucket", true)).Post("/buckets", hit)
	})
	p := routeProbe{router: router, z: z, auth: auth, reached: hits.Load}

	tok, c := p.session(t, "route-nobody")
	checked, problems := p.denyProblems(tok, c)
	if checked != 5 {
		t.Errorf("checked %d routes, want all 5", checked)
	}
	for _, key := range []string{"GET /api/buckets", "DELETE /api/buckets/{bucket}", "GET /api/buckets/{bucket}/object"} {
		if problems[key] == "" {
			t.Errorf("the deny check passed %s", key)
		}
	}
	if !strings.Contains(problems["GET /api/buckets"], "reached 1 call(s) behind the gate") {
		t.Errorf("an ungated route must be reported as reached: %q", problems["GET /api/buckets"])
	}
	for _, key := range []string{"GET /api/buckets/{bucket}/objects", "POST /api/buckets"} {
		if why, bad := problems[key]; bad {
			t.Errorf("the deny check reported %s, which its gate denies: %s", key, why)
		}
	}

	hits.Store(0)
	tok, _ = p.session(t, "route-admin")
	_, _, problems = p.allowProblems(tok)
	for _, key := range []string{"POST /api/buckets", "GET /api/buckets/{bucket}/object"} {
		if problems[key] == "" {
			t.Errorf("the allow check passed %s", key)
		}
	}
	if why, bad := problems["GET /api/buckets/{bucket}/objects"]; bad {
		t.Errorf("the allow check reported a route gated right: %s", why)
	}
}
