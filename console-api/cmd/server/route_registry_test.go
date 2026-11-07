package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/k8s"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The console's half of the customer-surface registry (probe/registry/console-routes.json): every route
// the console serves, with the IAM action it is and the shape of the resource ARN it is decided on, the
// routes decided per request (the Kubernetes proxy, the watch stream, the dashboards proxy, self-service)
// and the public ones with why they need no authorization. All of it is read from the router itself, so
// a new route reaches the registry, and the inventory rendered from it (docs/customer-surface.md), without
// anyone writing it down. probe/shimgen.py joins it with the kinds table (iam-actions.json), the claim
// kinds' fields, the console's screens and the aws-shim's services, and fails CI when a customer-reachable
// capability has no AWS-shaped entry. A stale file fails go test; UPDATE_REGISTRY=1 rewrites it.
const consoleRoutesPath = "../../../probe/registry/console-routes.json"

type consoleRouteEntry struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Action   string `json:"action,omitempty"`   // the IAM action (fixed routes)
	Resource string `json:"resource,omitempty"` // the ARN it is decided on, {placeholders} for the request's names; "*" for none
	Decided  string `json:"decided,omitempty"`  // how a per-request route's action is chosen
	Reason   string `json:"reason,omitempty"`   // why a public route needs no authorization
}

type consoleRouteRegistry struct {
	GeneratedBy string              `json:"generatedBy"`
	Routes      []consoleRouteEntry `json:"routes"`
	PerRequest  []consoleRouteEntry `json:"perRequest"`
	Public      []consoleRouteEntry `json:"public"`
}

var routeParamRe = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)

// arnShape is the resource ARN a route builds, with each name it reads from the request (URL parameter,
// query or body field) left as a {placeholder} and the caller's account as {account}.
func arnShape(rt string, arn arnFunc) string {
	if arn == nil {
		return "*"
	}
	path := rt
	rctx := chi.NewRouteContext()
	for _, m := range routeParamRe.FindAllStringSubmatch(rt, -1) {
		rctx.URLParams.Add(m[1], "{"+m[1]+"}")
	}
	path = routeParamRe.ReplaceAllStringFunc(path, func(s string) string { return url.PathEscape(s) })
	q := url.Values{}
	for _, k := range []string{"namespace", "name", "id", "key"} {
		q.Set(k, "{"+k+"}")
	}
	body := `{"name":"{name}","namespace":"{namespace}","id":"{id}","subject":"{subject}","deviceName":"{deviceName}","target":"{target}"}`
	r := httptest.NewRequest(http.MethodPost, path+"?"+q.Encode(), strings.NewReader(body))
	r = r.WithContext(context.WithValue(context.WithValue(r.Context(), chi.RouteCtxKey, rctx), ctxUser{}, userClaims("{caller}")))
	return strings.ReplaceAll(arn(r), iam.ManagementAccount, "{account}")
}

func buildConsoleRouteRegistry(t *testing.T) consoleRouteRegistry {
	t.Helper()
	t.Setenv("GRAFANA_PROXY_TARGET", "http://127.0.0.1:1") // the dashboards proxy is part of the surface
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
	z.cs = nil // the ARN shapes name the account as {account}, not a namespace lookup's answer
	reg := consoleRouteRegistry{GeneratedBy: "console-api/cmd/server/route_registry_test.go (go test; UPDATE_REGISTRY=1 rewrites)",
		Routes: []consoleRouteEntry{}, PerRequest: []consoleRouteEntry{}, Public: []consoleRouteEntry{}}
	for _, rt := range z.reg.Routes() {
		if d, ok := strings.CutPrefix(rt.Action, "per-request: "); ok {
			reg.PerRequest = append(reg.PerRequest, consoleRouteEntry{Method: rt.Method, Path: rt.Path, Decided: d})
			continue
		}
		reg.Routes = append(reg.Routes, consoleRouteEntry{Method: rt.Method, Path: rt.Path, Action: rt.Action,
			Resource: arnShape(rt.Path, rt.ARN)})
	}
	for _, p := range z.reg.PublicRoutes() {
		reg.Public = append(reg.Public, consoleRouteEntry{Method: p.Method, Path: p.Path, Reason: p.Reason})
	}
	return reg
}

func TestConsoleRouteRegistryIsCurrent(t *testing.T) {
	reg := buildConsoleRouteRegistry(t)
	if len(reg.Routes) < 88 || len(reg.PerRequest) == 0 || len(reg.Public) == 0 {
		t.Fatalf("the route table read %d fixed, %d per-request, %d public routes: the router was not walked",
			len(reg.Routes), len(reg.PerRequest), len(reg.Public))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", " ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(reg); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_REGISTRY") != "" {
		if err := os.WriteFile(consoleRoutesPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	cur, err := os.ReadFile(consoleRoutesPath)
	if err != nil || !bytes.Equal(cur, buf.Bytes()) {
		t.Fatalf("%s is stale (the console's routes changed): run probe/shimgen.py (or UPDATE_REGISTRY=1 go test "+
			"./cmd/server -run TestConsoleRouteRegistryIsCurrent) and commit the result (read error: %v)", consoleRoutesPath, err)
	}
}

// A route's resource is what its ARN builder makes of the request's own names, so a route decided on
// one bucket, function or snapshot says so in the registry, and one decided on nothing says "*".
func TestConsoleRouteRegistry_ResourceShapes(t *testing.T) {
	reg := buildConsoleRouteRegistry(t)
	got := map[string]string{}
	for _, r := range reg.Routes {
		got[r.Method+" "+r.Path] = r.Action + " " + r.Resource
	}
	for route, want := range map[string]string{
		"GET /api/buckets":                                "s3:ListAllMyBuckets *",
		"DELETE /api/buckets/{bucket}":                    "s3:DeleteBucket arn:aws:s3:::{bucket}",
		"POST /api/functions/{namespace}/{name}/invoke":   "lambda:InvokeFunction arn:aws:lambda:us-east-1:{account}:function:{name}",
		"DELETE /api/snapshots":                           "rds:DeleteDBSnapshot arn:aws:rds:us-east-1:{account}:snapshot:{id}",
		"GET /api/nodes/disk":                             "openinfra-operator:ListNodes *",
		"POST /api/dataflows/{namespace}/{name}/status":   "openinfra:GetDataFlow arn:aws:openinfra:us-east-1:{account}:dataflow/{name}",
		"GET /api/queries/{namespace}/{name}/result":      "athena:GetQueryResults arn:aws:athena:us-east-1:{account}:workgroup/primary",
		"POST /api/models/{namespace}/{name}/chat":        "sagemaker:InvokeEndpoint arn:aws:sagemaker:us-east-1:{account}:endpoint/{name}",
		"GET /api/functions/{namespace}/{name}/code":      "lambda:GetFunction arn:aws:lambda:us-east-1:{account}:function:{name}",
		"GET /api/migrations/{namespace}/{name}/status":   "dms:DescribeReplicationTasks arn:aws:dms:us-east-1:{account}:task:{name}",
		"POST /api/directories/{namespace}/{name}/ldap":   "ds:DescribeDirectories arn:aws:ds:us-east-1:{account}:directory/{name}",
		"GET /api/replications/{namespace}/{name}/status": "dms:DescribeReplicationTasks arn:aws:dms:us-east-1:{account}:task:{name}",
	} {
		if g, ok := got[route]; !ok || g != want {
			t.Errorf("%s: %q, want %q", route, g, want)
		}
	}
}
