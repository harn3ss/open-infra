package awsaction

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// Route is one console (BFF) route as an authorization question: what IAM action it is and the ARN of
// the resource it acts on, built from the request (its URL parameters and the caller's account).
type Route struct {
	Method string                       // GET, POST … as the router registers it
	Path   string                       // the router's full pattern, mount prefixes included (/api/buckets/{bucket}/objects)
	Action string                       // the IAM action, e.g. s3:ListBucket
	ARN    func(r *http.Request) string // the resource; nil means "*"
}

// Authorizer decides one request: whether the signed-in principal may perform action on arn, and why
// not. The console's iamauthz adapter implements it.
type Authorizer func(r *http.Request, action, arn string) (allowed bool, reason string)

// Registry holds every route's action, so a route without one can't exist: MustCover fails on any route
// the router serves that was neither registered nor declared public.
type Registry struct {
	mu     sync.Mutex
	routes map[string]Route
	public map[string]string // key -> why it needs no authorization (sign-in, health, static assets)
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{routes: map[string]Route{}, public: map[string]string{}}
}

func routeKey(method, path string) string { return strings.ToUpper(method) + " " + path }

// Add records a route; adding one twice panics (two answers for one route is a bug).
func (g *Registry) Add(rt Route) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := routeKey(rt.Method, rt.Path)
	if _, dup := g.routes[k]; dup {
		panic("awsaction: route registered twice: " + k)
	}
	if rt.Action == "" {
		panic("awsaction: route with no action: " + k)
	}
	g.routes[k] = rt
}

// Public records a route that needs no authorization, with the reason (sign-in, health, static UI).
func (g *Registry) Public(method, path, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.public[routeKey(method, path)] = reason
}

// Lookup returns a registered route.
func (g *Registry) Lookup(method, path string) (Route, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	rt, ok := g.routes[routeKey(method, path)]
	return rt, ok
}

// PublicRoute is a route that needs no authorization, and why.
type PublicRoute struct {
	Method, Path, Reason string
}

// PublicRoutes returns every route recorded as public, sorted by method and path.
func (g *Registry) PublicRoutes() []PublicRoute {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]PublicRoute, 0, len(g.public))
	for k, why := range g.public {
		m, p, _ := strings.Cut(k, " ")
		out = append(out, PublicRoute{Method: m, Path: p, Reason: why})
	}
	sort.Slice(out, func(i, j int) bool {
		return routeKey(out[i].Method, out[i].Path) < routeKey(out[j].Method, out[j].Path)
	})
	return out
}

// Routes returns every registered route, sorted by method and path.
func (g *Registry) Routes() []Route {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Route, 0, len(g.routes))
	for _, rt := range g.routes {
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool {
		return routeKey(out[i].Method, out[i].Path) < routeKey(out[j].Method, out[j].Path)
	})
	return out
}

// Authorize records rt and returns the middleware that authorizes it: authz is asked for rt.Action on
// rt.ARN(r) before the handler runs, and a denial answers 403 in AWS's shape (AccessDenied) without
// reaching it. Use it on the route itself: router.With(reg.Authorize(rt, authz)).Get(rt.Path, h).
func (g *Registry) Authorize(rt Route, authz Authorizer) func(http.Handler) http.Handler {
	g.Add(rt)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			arn := "*"
			if rt.ARN != nil {
				arn = rt.ARN(r)
			}
			if ok, reason := authz(r, rt.Action, arn); !ok {
				writeAccessDenied(w, rt.Action, arn, reason)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeAccessDenied answers a denial as AWS does: 403, code AccessDenied, and a message naming the
// action and resource.
func writeAccessDenied(w http.ResponseWriter, action, arn, reason string) {
	msg := fmt.Sprintf("not authorized to perform: %s on resource: %s", action, arn)
	if reason != "" {
		msg += " (" + reason + ")"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": "AccessDenied", "error": msg})
}

// Uncovered lists the routes router serves that are neither registered nor public, sorted.
func (g *Registry) Uncovered(router chi.Routes) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var missing []string
	_ = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		k := routeKey(method, route)
		if _, ok := g.routes[k]; ok {
			return nil
		}
		if _, ok := g.public[k]; ok {
			return nil
		}
		missing = append(missing, k)
		return nil
	})
	sort.Strings(missing)
	return missing
}

// MustCover panics, naming them, when router serves a route with no recorded action: a test calls it
// over the console's router so no route can go unauthorized.
func (g *Registry) MustCover(router chi.Routes) {
	if missing := g.Uncovered(router); len(missing) > 0 {
		panic("awsaction: routes with no IAM action: " + strings.Join(missing, ", "))
	}
}
