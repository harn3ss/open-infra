package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// fnNameRE is exactly the RFC-1123 label a kind: Function / Knative Service name can be. Validating the
// function name at the parse choke point (which feeds BOTH the sync target URL and the async subject +
// header) stops a crafted name — "evil.com#", "host:port?", anything with a URL-authority-breaking
// character — from escaping the constructed cluster-local URL and redirecting the POST off-cluster.
// iam.CanDo cannot be relied on for this: a namespace-wide `get`/`create functions` grant authorizes
// any name.
var fnNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// lambdaHandler fronts AWS Lambda's Invoke over open-infra's kind: Function (Knative Serving). This
// is the design's designated second service: "one Knative compute path — the backend
// already speaks the protocol." A Function is a scale-to-zero HTTP workload; Lambda Invoke is, at
// heart, an HTTP POST of a payload to a named function and a response body back — so the
// translation is a genuine, thin mapping, not a protocol reimplementation.
//
// Protocol: the Lambda REST invoke path `POST /2015-03-31/functions/{name}/invocations`, body =
// the invocation payload. The shim resolves {name} to the Function's cluster-local Knative address
// and forwards the payload; the function's response body is returned verbatim. Errors use Lambda's
// JSON dialect (x-amzn-errortype header + a JSON message body).
//
// Invocation types: RequestResponse (synchronous), Event (asynchronous — durably queued via
// asyncInvoker), and DryRun (authorize-only) are all supported. Functions are resolved in a single
// configured namespace; a downstream HTTP error is surfaced as Lambda's X-Amz-Function-Error.
// Qualifiers are supported for the synchronous path: an alias (or $LATEST) routes to the Knative
// traffic tag the Function composition publishes at <alias>-<name>. Cross-namespace resolution and
// qualified async delivery are the flagged next steps.
type lambdaHandler struct {
	cs        kubernetes.Interface
	client    *http.Client
	fnNS      string                  // namespace kind: Function / Knative Services live in
	svcSuffix string                  // cluster DNS suffix; endpoint = http://<name>.<fnNS>.<svcSuffix>
	async     *asyncInvoker           // durable async (Event) delivery; nil = async unavailable (no NATS)
	authz     *dataplaneauthz.Checker // fine-grained kind: Policy data-plane check (additive; may be nil)
	logger    *slog.Logger
}

func newLambdaHandler(cs kubernetes.Interface, fnNS, svcSuffix string, async *asyncInvoker, logger *slog.Logger) *lambdaHandler {
	return &lambdaHandler{
		cs:        cs,
		client:    &http.Client{Timeout: 60 * time.Second},
		fnNS:      fnNS,
		svcSuffix: svcSuffix,
		async:     async,
		logger:    logger,
	}
}

func (h *lambdaHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeLambdaError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func (h *lambdaHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	name, qualifier, ok := parseInvokePath(r)
	if !ok {
		writeLambdaError(w, http.StatusNotImplemented, "InvalidAction", requestID,
			"only POST /2015-03-31/functions/{name}[:{qualifier}]/invocations is implemented")
		return
	}
	// A non-default qualifier (a Lambda alias) routes to the Knative traffic tag the Function
	// composition publishes at <alias>-<name>; $LATEST / unset is the default (100%) route.
	qualified := qualifier != "" && qualifier != "$LATEST"

	// Authorize through the shared impersonated SubjectAccessReview — one policy world. Invoking EXECUTES
	// the function's code (with side effects — pointedly for async Event invokes), so it maps to `create`
	// on functions, NOT `get`: read-only principals (openinfra:readers hold only get/list/watch) must not
	// be able to run a function; powerusers/admins hold create. Applies to all invocation types.
	if denied, reason := deniedByDataPlane(r.Context(), h.authz, claims, "lambda:InvokeFunction", "Function", name, r); denied {
		h.logger.Warn("lambda denied by data-plane policy", "user", claims.Sub, "function", name, "reason", reason)
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, "create", "openinfra.dev", "functions", h.fnNS, name); !allowed {
		h.logger.Warn("lambda denied", "user", claims.Sub, "function", name, "reason", reason)
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID,
			"not authorized to invoke function '"+name+"'")
		return
	}

	// Invocation type (X-Amz-Invocation-Type): RequestResponse (default) runs synchronously below;
	// DryRun validates permissions only; Event queues the payload for durable async delivery and returns
	// 202 immediately. The authorization check above already ran, so DryRun is complete right here.
	switch r.Header.Get("X-Amz-Invocation-Type") {
	case "DryRun":
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(http.StatusNoContent) // 204 — authorized, not executed
		return
	case "Event":
		if h.async == nil {
			writeLambdaError(w, http.StatusServiceUnavailable, "ServiceException", requestID,
				"asynchronous (Event) invocation requires the event bus (set NATS_URL on the shim)")
			return
		}
		if qualified {
			// Async delivery resolves the function by name at the pump; alias/qualifier routing is a
			// sync-only capability today. Refuse rather than silently invoke the default route.
			writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID,
				"asynchronous (Event) invocation with a qualifier/alias is not supported; invoke the alias synchronously, or invoke the unqualified function asynchronously")
			return
		}
		// Async payloads are read into a durable queue message; cap at AWS's 256 KB async limit.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256*1024))
		if err != nil {
			writeLambdaError(w, http.StatusRequestEntityTooLarge, "RequestTooLargeException", requestID,
				"async invocation payload exceeds the 256 KB limit")
			return
		}
		if err := h.async.publish(name, r.Header.Get("Content-Type"), body, requestID); err != nil {
			h.logger.Warn("lambda async enqueue failed", "function", name, "error", err.Error())
			writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID,
				"could not enqueue the asynchronous invocation")
			return
		}
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(http.StatusAccepted) // 202, empty body — AWS's async invoke response
		return
	}

	// AWS throttles a SYNCHRONOUS invoke with 429 TooManyRequestsException when concurrent executions
	// are at the account limit. Our analog is the per-tenant function-concurrency ResourceQuota
	// (count/pods, scoped to the openinfra-function priority — one running burstable pod == one in-flight
	// request). Check it at the front door: at the cap, reject with 429 rather than forwarding into
	// Knative's activator, which would queue the request until it times out into a 503 (the documented
	// 503-not-429 gap). Async (Event) invokes were durably queued above and DryRun already returned, so
	// only the sync path reaches here. Inert when the tenant has not opted into the quota.
	if throttled, retryAfter := h.concurrencyThrottled(r.Context()); throttled {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		h.logger.Info("lambda throttled at tenant concurrency cap", "function", name, "namespace", h.fnNS)
		writeLambdaError(w, http.StatusTooManyRequests, "TooManyRequestsException", requestID,
			"Rate Exceeded: the tenant function-concurrency limit has been reached")
		return
	}

	// Resolve to the Function's cluster-local Knative address and forward the payload. Hitting the
	// cluster-local URL is what drives Knative scale-from-zero. A qualifier routes to the alias's
	// Knative traffic tag (<alias>-<name>); $LATEST / unset hits the default route.
	host := name
	if qualified {
		host = qualifier + "-" + name
	}
	target := "http://" + host + "." + h.fnNS + "." + h.svcSuffix + "/"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, r.Body)
	if err != nil {
		writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not build upstream request")
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	// Direct-invoke: the runtime returns the handler's RAW value as the payload and signals a thrown
	// error via X-Amz-Function-Error (HTTP stays 200) — AWS Invoke semantics — instead of mapping the
	// return to an API-Gateway proxy response (which is only for the apigateway doorway).
	req.Header.Set("X-Openinfra-Invoke", "direct")

	resp, err := h.client.Do(req)
	if err != nil {
		// Unreachable / no such function → Lambda's ResourceNotFoundException.
		h.logger.Warn("lambda upstream unreachable", "function", name, "target", target, "error", err.Error())
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID,
			"function '"+name+"' could not be reached")
		return
	}
	defer resp.Body.Close()

	// Lambda returns 200 for a completed RequestResponse invocation, with the function's payload as
	// the body; a function-side error is signalled by the X-Amz-Function-Error header, not the HTTP
	// status. In direct-invoke mode the runtime sets that header itself on a thrown handler error, so
	// propagate it; a non-2xx WITHOUT it is a genuine infra/invocation error, mapped onto the same header.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if fe := resp.Header.Get("X-Amz-Function-Error"); fe != "" {
		w.Header().Set("X-Amz-Function-Error", fe)
	} else if resp.StatusCode >= http.StatusBadRequest {
		w.Header().Set("X-Amz-Function-Error", "Unhandled")
	}
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

// concurrencyThrottled reports whether the function namespace's function-concurrency-quota has reached
// its count/pods limit — i.e. Knative could not create another function pod right now, so a sync invoke
// needing one would otherwise queue in the activator and time out into a 503. It is the AWS-correct
// surfacing of the native ResourceQuota (which stays the hard backstop); best-effort by design — a
// missing or unreadable quota means "no cap enforced here" (not throttled), so a tenant that has not
// opted into the quota behaves exactly as before. retryAfter is a conservative seconds hint for the
// caller's back-off (AWS sends one on a throttle).
func (h *lambdaHandler) concurrencyThrottled(ctx context.Context) (throttled bool, retryAfter string) {
	rq, err := h.cs.CoreV1().ResourceQuotas(h.fnNS).Get(ctx, "function-concurrency-quota", metav1.GetOptions{})
	if err != nil {
		return false, "" // no quota (not opted in) or unreadable — the native quota remains the backstop
	}
	const podsKey = corev1.ResourceName("count/pods")
	hard, hok := rq.Status.Hard[podsKey]
	used, uok := rq.Status.Used[podsKey]
	if hok && uok && used.Cmp(hard) >= 0 {
		return true, "1"
	}
	return false, ""
}

// parseInvokePath matches POST /2015-03-31/functions/{name}/invocations (optionally
// /2015-03-31/functions/{name}:{qualifier}/invocations) and returns {name} + {qualifier}. The
// qualifier is a Lambda alias (or $LATEST); it may also come from ?Qualifier=. Both name and a
// non-$LATEST qualifier are validated as RFC-1123 labels because BOTH feed the constructed
// cluster-local URL authority (<qualifier>-<name>.<ns>.<suffix>) — the same off-cluster-redirect
// guard the bare name already has — and their combined DNS label must fit in 63 bytes.
func parseInvokePath(r *http.Request) (name, qualifier string, ok bool) {
	if r.Method != http.MethodPost {
		return "", "", false
	}
	p := strings.TrimPrefix(r.URL.Path, "/2015-03-31/functions/")
	if p == r.URL.Path { // prefix wasn't present
		return "", "", false
	}
	fn, rest, found := strings.Cut(p, "/")
	if !found || rest != "invocations" {
		return "", "", false
	}
	name, qualifier, _ = strings.Cut(fn, ":") // "name" or "name:qualifier"
	if q := r.URL.Query().Get("Qualifier"); q != "" {
		if qualifier != "" && qualifier != q { // conflicting path vs query qualifier
			return "", "", false
		}
		qualifier = q
	}
	if !fnNameRE.MatchString(name) {
		return "", "", false
	}
	if qualifier != "" && qualifier != "$LATEST" {
		if !fnNameRE.MatchString(qualifier) || len(qualifier)+1+len(name) > 63 {
			return "", "", false
		}
	}
	return name, qualifier, true
}

// writeLambdaError writes Lambda's JSON error dialect: the error class in the x-amzn-errortype
// header (which the SDKs key off) and a JSON message body.
func writeLambdaError(w http.ResponseWriter, status int, errorType, requestID, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-errortype", errorType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}
