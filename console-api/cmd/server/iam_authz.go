package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/awsaction"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/proxy"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The console as a client of the one evaluator.
//
// Every route the console serves is an AWS authorization question: an IAM action on a resource ARN
// (awsaction.Registry), asked of the shared evaluator (internal/iamauthz) as the signed-in principal —
// exactly the question the equivalent API call asks at the aws-shim. IAM_AUTHZ picks how far IAM policy
// decides:
//
//   - legacy (the default): nothing changes. Routes pass the gate, and each handler's own check (a
//     SubjectAccessReview as the user, authz.go) and the impersonating proxy decide, as before.
//   - shadow: the IAM decision is computed and logged (iam-shadow) where it differs; legacy still decides.
//   - enforce: IAM policy decides. The route gate is authoritative; handlers' SubjectAccessReviews defer
//     to it; the proxy authorizes each Kubernetes request by its AWS action before forwarding it and then
//     acts as the principal's account identity (generated RBAC is the second check, never the first).
//
// A User or Role labelled openinfra.dev/iam-authz: enforce is in enforce while the platform is in shadow
// (the canary). The Secret-backed root is the account's root user: always allowed, in every mode, and
// the proxy keeps acting as its break-glass identity.

// consoleAuthz is the console's gate over the shared evaluator.
type consoleAuthz struct {
	reg    *awsaction.Registry
	eval   *iamauthz.Evaluator
	auth   *authStore
	cs     kubernetes.Interface
	logger *slog.Logger

	// nsAccount resolves a namespace's account (its openinfra.dev/account-id label; "" = the management
	// account). Cached: namespaces change account rarely, and every proxied request asks.
	nsMu    sync.Mutex
	nsCache map[string]nsAccountEntry
}

type nsAccountEntry struct {
	account string
	at      time.Time
}

// consoleIAM is the router's gate, read by authorize (authz.go) so the handlers' own checks follow the
// same mode. Set once by newRouter.
var consoleIAM *consoleAuthz

func newConsoleAuthz(cs kubernetes.Interface, auth *authStore, checker *dataplaneauthz.Checker, logger *slog.Logger) *consoleAuthz {
	return &consoleAuthz{
		reg:     awsaction.NewRegistry(),
		eval:    checker.IAM(),
		auth:    auth,
		cs:      cs,
		logger:  logger,
		nsCache: map[string]nsAccountEntry{},
	}
}

// ── principals and modes ─────────────────────────────────────────────────────────

// principal is the signed-in caller as the evaluator sees it.
func (z *consoleAuthz) principal(c sessionClaims) iamauthz.Principal {
	return iamauthz.PrincipalFromClaims(c.Claims, c.Account)
}

// modeFor is the mode this request's principal is evaluated in (legacy when there is no evaluator).
func (z *consoleAuthz) modeFor(r *http.Request) iamauthz.Mode {
	if z == nil || z.eval == nil {
		return iamauthz.ModeLegacy
	}
	c, ok := claimsFrom(r)
	if !ok {
		return z.eval.Mode()
	}
	return z.eval.ModeFor(r.Context(), z.principal(c))
}

// enforced reports whether IAM policy decides this request (never with authentication off).
func (z *consoleAuthz) enforced(r *http.Request) bool {
	if z == nil || z.auth == nil || z.auth.mode == "none" {
		return false
	}
	return z.modeFor(r) == iamauthz.ModeEnforce
}

// decide asks the evaluator, in the principal's mode, with legacy as the legacy decision. With
// authentication off (AUTH_MODE=none, a development console) everything is allowed, as before.
func (z *consoleAuthz) decide(r *http.Request, action, arn string, legacy func() (bool, string)) (bool, string) {
	if z == nil || z.auth == nil || z.auth.mode == "none" {
		return true, ""
	}
	c, ok := claimsFrom(r)
	if !ok {
		return false, "not signed in"
	}
	if z.roleSessionOutsideEnforce(r, c) {
		return false, "this role session ended because IAM policy no longer decides it; switch back"
	}
	if z.eval == nil {
		if legacy == nil {
			return false, "no decision"
		}
		return legacy()
	}
	p := z.principal(c)
	reqCtx := s3authz.RequestContext(c.Claims.PrincipalID(), r)
	d := z.eval.Decide(r.Context(), p, action, arn, reqCtx, legacy)
	if !d.Allowed && d.Mode == iamauthz.ModeEnforce {
		z.logger.Warn("iam denied", "principal", p.ARN(), "action", action, "resource", arn, "reason", d.Reason)
	}
	return d.Allowed, d.Reason
}

// allowLegacy is the legacy decision of a route gate that did not exist before: the route is reached and
// the handler's own checks decide, exactly as before the gate.
func allowLegacy() (bool, string) { return true, "" }

// ── the route table ──────────────────────────────────────────────────────────────

// arnFunc builds a route's resource ARN from the request; nil means "*".
type arnFunc func(*http.Request) string

type ctxRouteAuthorized struct{}

// routeAuthorized reports whether this request already passed its route's IAM gate in enforce mode, so
// a handler's SubjectAccessReview (authz.go) need not ask again with a coarser question.
func routeAuthorized(r *http.Request) bool {
	v, _ := r.Context().Value(ctxRouteAuthorized{}).(bool)
	return v
}

func withRouteAuthorized(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxRouteAuthorized{}, true)
}

// gate records {method, path} → (action, ARN) and returns its middleware: the evaluator is asked before
// the handler runs, and a denial answers AWS's AccessDenied without reaching it.
func (z *consoleAuthz) gate(method, path, action string, arn arnFunc) func(http.Handler) http.Handler {
	z.reg.Add(awsaction.Route{Method: method, Path: path, Action: action, ARN: arn})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res := "*"
			if arn != nil {
				res = arn(r)
			}
			ok, reason := z.decide(r, action, res, allowLegacy)
			if !ok {
				writeAccessDenied(w, action, res, reason)
				return
			}
			if z.enforced(r) {
				r = r.WithContext(withRouteAuthorized(r.Context()))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// handle registers one route on rt (mounted at prefix) with its timeout (0 = none), IAM action and ARN.
func (z *consoleAuthz) handle(rt chi.Router, prefix, method, path string, timeout time.Duration, action string,
	arn arnFunc, h http.HandlerFunc) {
	mws := []func(http.Handler) http.Handler{}
	if timeout > 0 {
		mws = append(mws, middleware.Timeout(timeout))
	}
	mws = append(mws, z.gate(method, prefix+path, action, arn))
	rt.With(mws...).MethodFunc(method, path, h)
}

// public records a route that needs no authorization, with the reason.
func (z *consoleAuthz) public(method, path, reason string) { z.reg.Public(method, path, reason) }

// allMethods are the methods chi registers for a Handle (every one), each of which the registry must
// cover.
var allMethods = []string{http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions,
	http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace, "QUERY"}

// perRequest records a route whose action depends on the request and is decided inside its handler
// (the Kubernetes proxy, the watch stream, the Grafana proxy, a password change on self or another).
func (z *consoleAuthz) perRequest(methods []string, path, describe string) {
	for _, m := range methods {
		z.reg.Add(awsaction.Route{Method: m, Path: path, Action: "per-request: " + describe})
	}
}

// writeAccessDenied answers a denial as AWS does, in the console's AWS error shape (awserr): 403,
// errorCode AccessDeniedException, and a message naming the action and resource (AWS's wording), plus
// the action and resource as fields so the UI can render an access-denied page.
func writeAccessDenied(w http.ResponseWriter, action, arn, reason string) {
	msg := fmt.Sprintf("You are not authorized to perform: %s on resource: %s", action, arn)
	if reason != "" {
		msg += " (" + reason + ")"
	}
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error": msg, "errorCode": "AccessDeniedException", "action": action, "resource": arn,
	})
}

// require asks for one more action a handler's operation needs beyond its route's (creating a user
// with a password is also iam:CreateLoginProfile; attaching a policy is iam:AttachUserPolicy). Legacy
// passes (the handler's own checks decide, as before); shadow logs; enforce decides, writing the denial.
func (z *consoleAuthz) require(w http.ResponseWriter, r *http.Request, action, arn string) bool {
	if z == nil {
		return true
	}
	ok, reason := z.decide(r, action, arn, allowLegacy)
	if !ok {
		writeAccessDenied(w, action, arn, reason)
	}
	return ok
}

// ── accounts and ARNs ────────────────────────────────────────────────────────────

// callerAccount is the signed-in principal's account (the management account when it names none).
func callerAccount(r *http.Request) string {
	if c, ok := claimsFrom(r); ok && c.Account != "" {
		return c.Account
	}
	return iam.ManagementAccount
}

// namespaceAccount is the account a namespace belongs to: its openinfra.dev/account-id label, else the
// management account. Cached for 30s; a lookup failure answers the management account (the resource
// then carries the caller-independent default, never a guessed foreign account).
func (z *consoleAuthz) namespaceAccount(ctx context.Context, ns string) string {
	if z == nil || ns == "" || z.cs == nil {
		return iam.ManagementAccount
	}
	z.nsMu.Lock()
	if e, ok := z.nsCache[ns]; ok && time.Since(e.at) < 30*time.Second {
		z.nsMu.Unlock()
		return e.account
	}
	z.nsMu.Unlock()
	acct := iam.ManagementAccount
	// A platform namespace is never an account's, whatever its labels say (as the accounts directory).
	if obj, err := z.cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err == nil && !accounts.IsPlatformNamespace(ns) {
		if v := strings.TrimSpace(obj.Labels[accounts.LabelAccountID]); v != "" {
			acct = v
		}
	}
	z.nsMu.Lock()
	z.nsCache[ns] = nsAccountEntry{account: acct, at: time.Now()}
	z.nsMu.Unlock()
	return acct
}

// kindARN is the ARN of the {namespace}/{name} claim of kind a route acts on, in that namespace's
// account (awsaction's ARN shape for the kind; "*" when the kind is unknown).
func (z *consoleAuthz) kindARN(kind string) arnFunc {
	return func(r *http.Request) string {
		e, ok := awsaction.Lookup(kind)
		if !ok {
			return "*"
		}
		acct := z.namespaceAccount(r.Context(), chi.URLParam(r, "namespace"))
		return e.ARNFor(awsaction.Scope{Account: acct}, chi.URLParam(r, "name"), nil)
	}
}

// iamARN is the ARN of the IAM entity (user, group, policy, role) named by the route's {name}, in the
// caller's account.
func iamARN(kind string) arnFunc {
	return func(r *http.Request) string { return iamEntityARN(kind, callerAccount(r), chi.URLParam(r, "name")) }
}

// iamEntityARN is arn:aws:iam::<account>:<user|group|policy|role>/<name>.
func iamEntityARN(kind, account, name string) string {
	if name == "" {
		return "*"
	}
	return "arn:aws:iam::" + account + ":" + kind + "/" + name
}

// bucketARN is arn:aws:s3:::<bucket> for the route's {bucket}.
func bucketARN(r *http.Request) string { return "arn:aws:s3:::" + chi.URLParam(r, "bucket") }

// objectARN is arn:aws:s3:::<bucket>/<key> for the route's {bucket} and ?key=.
func objectARN(r *http.Request) string {
	return "arn:aws:s3:::" + chi.URLParam(r, "bucket") + "/" + r.URL.Query().Get("key")
}

// queueARN is the SQS queue ARN of the route's {stream} (a queue is a JetStream stream here), in the
// caller's account.
func queueARN(r *http.Request) string {
	return "arn:aws:sqs:" + awsaction.DefaultRegion + ":" + callerAccount(r) + ":" + chi.URLParam(r, "stream")
}

// ── the Kubernetes proxy and the watch stream ────────────────────────────────────

// kubernetesQuestion is the AWS question a Kubernetes request is: discovery is openinfra:DescribeAPIs
// (read-only metadata, which ReadOnlyAccess covers by its Describe* wildcard); anything else is
// awsaction's mapping, in the account of the namespace it names. ok=false for a request the table
// cannot map (refused in enforce).
func (z *consoleAuthz) kubernetesQuestion(ctx context.Context, k proxy.Request) (action, arn string, ok bool) {
	if k.Discovery {
		return "openinfra:DescribeAPIs", "*", true
	}
	acct := z.namespaceAccount(ctx, k.Namespace)
	return awsaction.ForKubernetes(k.Verb, k.Group, k.ResourcePath(), k.Namespace, k.Name, acct)
}

// authorizeKubernetes decides one Kubernetes request: legacy is legacyDecision (the impersonated proxy's
// own RBAC check happens upstream, so nil means "forward and let RBAC decide"); enforce is IAM policy.
func (z *consoleAuthz) authorizeKubernetes(r *http.Request, k proxy.Request, legacy func() (bool, string)) (bool, string, string, string) {
	action, arn, ok := z.kubernetesQuestion(r.Context(), k)
	if !ok {
		action, arn = "openinfra:Unmapped", "*"
		if z.enforced(r) && z.auth != nil && z.auth.mode != "none" {
			if c, signed := claimsFrom(r); signed && z.principal(c).Type == iamauthz.Root {
				return true, "", action, arn // root reaches the whole API, as break-glass must
			}
			return false, fmt.Sprintf("%s %s/%s has no IAM action", k.Verb, k.Group, k.ResourcePath()), action, arn
		}
	}
	if legacy == nil {
		legacy = allowLegacy
	}
	allowed, reason := z.decide(r, action, arn, legacy)
	return allowed, reason, action, arn
}

// proxyHandler wraps the Kubernetes reverse proxy with the gate: each request is parsed into the
// Kubernetes question it is, authorized by its AWS action, and forwarded as identity().
func (z *consoleAuthz) proxyHandler(prefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k, ok := proxy.ParseRequest(r.Method, strings.TrimPrefix(r.URL.Path, prefix), r.URL.Query())
		if !ok {
			if z.enforced(r) {
				writeAccessDenied(w, "openinfra:Unmapped", "*", "not a Kubernetes API request the console serves")
				return
			}
			next.ServeHTTP(w, r) // legacy: forwarded as before, the API server answers
			return
		}
		if proxiedRootUser(r, k) {
			writeReservedRoot(w) // in every mode: only the Secret-backed root is root
			return
		}
		allowed, reason, action, arn := z.authorizeKubernetes(r, k, nil)
		if !allowed {
			writeAccessDenied(w, action, arn, reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// proxyIdentity is who a proxied request acts as to the API server: in legacy and shadow the user with
// its group tiers (iam.Identity); in enforce the principal's account identity with no groups, so the
// generated RBAC is a second check of the same principal. Root keeps its break-glass identity in every
// mode, so no compiler, corpus or ceiling change can take the console from it.
func (z *consoleAuthz) proxyIdentity(r *http.Request) (proxy.Identity, bool) {
	c, ok := claimsFrom(r)
	if !ok {
		return proxy.Identity{}, false
	}
	enforce := z.enforced(r) && z.principal(c).Type != iamauthz.Root && proxyAccountIdentity()
	u, g, ok := iam.IdentityFor(c.Claims, enforce)
	return proxy.Identity{User: u, Groups: g}, ok
}

// proxyAccountIdentity reports whether, in enforce, the proxy acts as the account identity (the default)
// or keeps the legacy identity (IAM_PROXY_IDENTITY=legacy: for a canary before the generated RBAC
// exists, IAM policy still decides first).
func proxyAccountIdentity() bool { return getenv("IAM_PROXY_IDENTITY", "account") != "legacy" }

// watchHandler wraps the watch stream with the gate. The stream reads with the console's
// ServiceAccount, so without a check any signed-in user could watch any resource: the legacy decision is
// a SubjectAccessReview of watch AS the user (what the impersonated proxy would allow), and enforce is
// IAM policy on the list action.
func (z *consoleAuthz) watchHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		q := r.URL.Query()
		q.Set("watch", "true")
		k, ok := proxy.ParseRequest(http.MethodGet, path, q)
		if !ok || k.Discovery {
			if z.enforced(r) {
				writeAccessDenied(w, "openinfra:Unmapped", "*", "the watch stream serves Kubernetes resources only")
				return
			}
			next.ServeHTTP(w, r) // legacy: the stream answers a bad path itself, as before
			return
		}
		legacy := func() (bool, string) {
			c, signed := claimsFrom(r)
			if !signed {
				return false, "not signed in"
			}
			return iam.CanDo(r.Context(), z.cs, c.Claims, "watch", k.Group, k.ResourcePath(), k.Namespace, "")
		}
		allowed, reason, action, arn := z.authorizeKubernetes(r, k, legacy)
		if !allowed {
			writeAccessDenied(w, action, arn, reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// grafanaGate gates the same-origin Grafana proxy: Grafana shows every dashboard, metric and log, the
// CloudWatch read surface, so enforce needs cloudwatch:GetDashboard. Legacy keeps the signed-in check.
func (z *consoleAuthz) grafanaGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || z.auth == nil {
			next.ServeHTTP(w, r)
			return
		}
		claims, ok := z.auth.parse(c.Value)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxUser{}, claims))
		if ok, reason := z.decide(r, "cloudwatch:GetDashboard", "*", allowLegacy); !ok {
			writeAccessDenied(w, "cloudwatch:GetDashboard", "*", reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── the handlers' own checks ─────────────────────────────────────────────────────

// authorizeKubernetesVerb is authorize's decision in the principal's mode: legacy is the
// SubjectAccessReview as the user (iam.CanDo, unchanged); shadow logs the IAM decision for the same
// question; enforce defers to the route gate when it already decided this request, else asks IAM
// policy for the Kubernetes verb's AWS action (an unmapped one is refused).
func (z *consoleAuthz) authorizeKubernetesVerb(r *http.Request, cs kubernetes.Interface, c sessionClaims,
	verb, group, resource, namespace, name string) (bool, string) {
	legacy := func() (bool, string) {
		return iam.CanDo(r.Context(), cs, c.Claims, verb, group, resource, namespace, name)
	}
	if z.roleSessionOutsideEnforce(r, c) {
		return false, "this role session ended because IAM policy no longer decides it; switch back"
	}
	if z == nil || z.eval == nil {
		return legacy()
	}
	mode := z.modeFor(r)
	if mode == iamauthz.ModeLegacy {
		return legacy()
	}
	if mode == iamauthz.ModeEnforce && routeAuthorized(r) {
		return true, ""
	}
	acct := z.namespaceAccount(r.Context(), namespace)
	action, arn, ok := awsaction.ForKubernetes(verb, group, resource, namespace, name, acct)
	if !ok {
		if mode == iamauthz.ModeEnforce && z.principal(c).Type != iamauthz.Root {
			return false, verb + " " + group + "/" + resource + " has no IAM action"
		}
		return legacy()
	}
	return z.decide(r, action, arn, legacy)
}
