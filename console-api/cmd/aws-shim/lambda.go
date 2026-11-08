package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// maxSyncInvokePayload is AWS Lambda's synchronous invocation payload limit (6 MB).
const maxSyncInvokePayload = 6 * 1024 * 1024

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
// asyncInvoker), and DryRun (authorize-only) are all supported. A function is found by name in the
// Lambda API's namespace or a CloudFormation stack's (fn_locate.go) — the caller's account's: a member
// account's functions are in its own namespaces, and another account's ARN is refused as AWS refuses a
// cross-account call no resource-based policy allows; a downstream HTTP error is surfaced
// as Lambda's X-Amz-Function-Error. Qualifiers are supported for the synchronous path: an alias (or
// $LATEST) routes to the Knative traffic tag the Function composition publishes at <alias>-<name>.
// Qualified async delivery is the flagged next step.
type lambdaHandler struct {
	cs        kubernetes.Interface
	client    *http.Client
	fnNS      string                  // namespace kind: Function / Knative Services live in
	svcSuffix string                  // cluster DNS suffix; endpoint = http://<name>.<fnNS>.<svcSuffix>
	async     *asyncInvoker           // durable async (Event) delivery; nil = async unavailable (no NATS)
	authz     *dataplaneauthz.Checker // fine-grained kind: Policy data-plane check (additive; may be nil)
	logger    *slog.Logger
	// account and region make a function's ARN in the read operations' answers (lambda_read.go).
	account, region string
	// fns finds which namespace a function lives in (the Lambda API's or a CloudFormation stack's,
	// fn_locate.go); nil = always fnNS.
	fns *fnLocator
	// timeouts reads a function's timeout, which a synchronous invoke waits for (lambda_timeout.go); nil =
	// the default timeout. coldStart is added to it (invokeColdStartAllowance; tests shorten it).
	timeouts  *fnTimeouts
	coldStart time.Duration
}

func newLambdaHandler(cs kubernetes.Interface, fnNS, svcSuffix string, async *asyncInvoker, logger *slog.Logger) *lambdaHandler {
	return &lambdaHandler{
		cs: cs,
		// No client-wide timeout: each invoke waits for its function's own (lambda_timeout.go).
		client:    &http.Client{},
		coldStart: invokeColdStartAllowance,
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
	// The read operations (GetFunction, GetFunctionConfiguration, ListFunctions, GetPolicy): lambda_read.go.
	if op, fn, q, read, bad := parseLambdaReadPath(r); read {
		if bad {
			writeLambdaError(w, http.StatusBadRequest, "InvalidParameterValueException", requestID,
				"FunctionName is not a valid function name or ARN")
			return
		}
		if h.refusedCrossAccount(w, r, claims, requestID, lambdaReadAction(op), fn) {
			return
		}
		h.serveRead(w, r, claims, requestID, op, fn, q)
		return
	}
	name, qualifier, ok := parseInvokePath(r)
	if !ok {
		writeLambdaError(w, http.StatusNotImplemented, "InvalidAction", requestID,
			"only Invoke (POST /2015-03-31/functions/{name}[:{qualifier}]/invocations), GetFunction, GetFunctionConfiguration, ListFunctions and GetPolicy are implemented")
		return
	}
	if h.refusedCrossAccount(w, r, claims, requestID, "lambda:InvokeFunction", name) {
		return
	}
	// A non-default qualifier (a Lambda alias) routes to the Knative traffic tag the Function
	// composition publishes at <alias>-<name>; $LATEST / unset is the default (100%) route.
	qualified := qualifier != "" && qualifier != "$LATEST"

	// Authorize through the shared impersonated SubjectAccessReview — one policy world. Invoking EXECUTES
	// the function's code (with side effects — pointedly for async Event invokes), so it maps to `create`
	// on functions, NOT `get`: read-only principals (openinfra:readers hold only get/list/watch) must not
	// be able to run a function; powerusers/admins hold create. Applies to all invocation types.
	// lambda:InvokeFunction on the function (decide). In legacy the data-plane refinement, then the
	// coarse check where the function lives (the Lambda API's namespace or a stack's); in enforce IAM
	// policy alone.
	ns := h.fns.namespaceFor(r.Context(), name, h.fnNS) // the caller's account's function (fn_locate.go)
	if ok, reason := decide(r.Context(), r, h.authz, claims, "lambda:InvokeFunction", "Function", name, func() (bool, string) {
		if denied, reason := deniedByDataPlane(r.Context(), h.authz, claims, "lambda:InvokeFunction", "Function", name, r); denied {
			return false, reason
		}
		if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, "create", "openinfra.dev", "functions", ns, name); !allowed {
			h.logger.Warn("lambda denied", "user", claims.Sub, "function", name, "reason", reason)
			return false, "not authorized to invoke function '" + name + "'"
		}
		return true, ""
	}); !ok {
		h.logger.Warn("lambda invoke denied", "user", claims.Sub, "function", name, "reason", reason)
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if ns == noFnNamespace {
		// A member account with no namespace has no functions.
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID,
			"Function not found: "+h.functionARNIn(r.Context(), name))
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
		if err := h.async.publishFor(callerAccount(r.Context()), name, ns, r.Header.Get("Content-Type"), body, requestID); err != nil {
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
	if throttled, retryAfter := h.concurrencyThrottled(r.Context(), ns); throttled {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		h.logger.Info("lambda throttled at tenant concurrency cap", "function", name, "namespace", ns)
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
	target := "http://" + host + "." + ns + "." + h.svcSuffix + "/"
	// The payload goes to the function whole, with its length: a streamed (chunked) body reaches a runtime
	// that reads Content-Length as an empty event. A synchronous invocation's payload is at most 6 MB, as on
	// AWS, which refuses a larger one with RequestEntityTooLargeException.
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSyncInvokePayload))
	if err != nil {
		writeLambdaError(w, http.StatusRequestEntityTooLarge, "RequestEntityTooLargeException", requestID,
			"Request must be smaller than 6291456 bytes for the InvokeFunction operation")
		return
	}
	// The invoke waits for the function's own timeout (plus its cold start), as Lambda runs it (#372).
	fnTimeout := h.timeouts.of(r.Context(), ns, name)
	ictx, cancel := context.WithTimeout(r.Context(), fnTimeout+h.coldStart)
	defer cancel()
	req, err := http.NewRequestWithContext(ictx, http.MethodPost, target, bytes.NewReader(payload))
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
	if err != nil && ictx.Err() == context.DeadlineExceeded && r.Context().Err() == nil {
		h.logger.Info("lambda invoke timed out", "function", name, "timeout", fnTimeout.String())
		writeTaskTimedOut(w, requestID, fnTimeout)
		return
	}
	if err != nil {
		// Unreachable / no such function → Lambda's ResourceNotFoundException.
		h.logger.Warn("lambda upstream unreachable", "function", name, "target", target, "error", err.Error())
		writeLambdaError(w, http.StatusNotFound, "ResourceNotFoundException", requestID,
			"function '"+name+"' could not be reached")
		return
	}
	defer resp.Body.Close()
	// Knative ends a request at the revision's timeout (spec.timeout) with a 504 the function never
	// answered: the function ran out of time.
	if resp.StatusCode == http.StatusGatewayTimeout && resp.Header.Get("X-Amz-Function-Error") == "" {
		writeTaskTimedOut(w, requestID, fnTimeout)
		return
	}

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
func (h *lambdaHandler) concurrencyThrottled(ctx context.Context, ns string) (throttled bool, retryAfter string) {
	rq, err := h.cs.CoreV1().ResourceQuotas(ns).Get(ctx, "function-concurrency-quota", metav1.GetOptions{})
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
	// A function ARN or partial ARN (arn:aws:lambda:<region>:<acct>:function:<name>[:<qualifier>],
	// <acct>:function:<name>) names the function as its name does — the form a stack's Arn output gives.
	return parseFunctionRef(fn, r.URL.Query().Get("Qualifier"))
}

// Lambda keeps each account's functions apart (fn_locate.go: a member account's are in its own
// namespaces), so it is an account-scoped front door.
func init() { accountScopedServices["lambda"] = true }

// refusedCrossAccount refuses, as AWS does, a request whose FunctionName is an ARN (or partial ARN) of a
// function in another account: reaching another account's function needs that function's resource-based
// policy to allow it (AddPermission), and a Function here has none (GetPolicy). The function of the same
// name in the caller's own account is never taken for it. A bare name is the caller's account's. The
// management account's requests are refused only for an ARN naming a member account the directory knows:
// an ARN carrying any other account (one kept from before accounts, or from the estate a stack came from)
// names the management account's function, as it always has.
func (h *lambdaHandler) refusedCrossAccount(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID, action, name string) bool {
	ctx := r.Context()
	acct := functionRefAccount(lambdaPathRef(r))
	if acct == "" || acct == callerAccount(ctx) {
		return false
	}
	if !isMemberRequest(ctx) && !h.fns.memberAccount(acct) {
		return false
	}
	arn := "arn:aws:lambda:" + h.regionIn(ctx) + ":" + acct + ":function:" + name
	h.logger.Warn("lambda cross-account request refused", "user", claims.Sub, "account", callerAccount(ctx), "function", arn)
	writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID,
		notAuthorized(principalOf(ctx, claims), action, arn, "")+" because no resource-based policy allows the "+action+" action")
	return true
}

// lambdaPathRef is the FunctionName segment of a /2015-03-31/functions/{FunctionName}[/…] path, as sent
// ("" for none).
func lambdaPathRef(r *http.Request) string {
	p := strings.TrimPrefix(r.URL.Path, "/2015-03-31/functions/")
	if p == r.URL.Path {
		return ""
	}
	ref, _, _ := strings.Cut(p, "/")
	return ref
}

// functionRefAccount is the account a FunctionName names: an ARN's (arn:aws:lambda:<region>:<account>:
// function:<name>) or a partial ARN's (<account>:function:<name>); "" for a bare name or an ARN carrying no
// 12-digit account.
func functionRefAccount(ref string) string {
	if strings.HasPrefix(ref, "arn:") {
		return awsidentity.AccountOfARN(ref)
	}
	if acct, _, ok := strings.Cut(ref, ":function:"); ok && len(acct) == 12 && strings.Trim(acct, "0123456789") == "" {
		return acct
	}
	return ""
}

// writeLambdaError writes Lambda's JSON error dialect: the error class in the x-amzn-errortype
// header (which the SDKs key off) and a JSON message body.
func writeLambdaError(w http.ResponseWriter, status int, errorType, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-errortype", errorType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}
