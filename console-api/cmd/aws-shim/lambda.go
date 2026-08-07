package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

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
// v1 scope: RequestResponse only (synchronous); functions are resolved in a single configured
// namespace; a downstream HTTP error is surfaced as Lambda's X-Amz-Function-Error. Async (Event)
// invocation, qualifiers/versions, and cross-namespace resolution are the flagged next steps.
type lambdaHandler struct {
	cs        kubernetes.Interface
	client    *http.Client
	fnNS      string // namespace kind: Function / Knative Services live in
	svcSuffix string // cluster DNS suffix; endpoint = http://<name>.<fnNS>.<svcSuffix>
	logger    *slog.Logger
}

func newLambdaHandler(cs kubernetes.Interface, fnNS, svcSuffix string, logger *slog.Logger) *lambdaHandler {
	return &lambdaHandler{
		cs:        cs,
		client:    &http.Client{Timeout: 60 * time.Second},
		fnNS:      fnNS,
		svcSuffix: svcSuffix,
		logger:    logger,
	}
}

func (h *lambdaHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeLambdaError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func (h *lambdaHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	name, ok := parseInvokePath(r)
	if !ok {
		writeLambdaError(w, http.StatusNotImplemented, "InvalidAction", requestID,
			"only POST /2015-03-31/functions/{name}/invocations is implemented")
		return
	}

	// Authorize through the shared impersonated SubjectAccessReview — one policy world. Invoking is
	// a read-level use of the function (it does not mutate the Function resource), so it maps to
	// `get` on functions; a principal who cannot see the function cannot invoke it.
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, "get", "openinfra.dev", "functions", h.fnNS, name); !allowed {
		h.logger.Warn("lambda denied", "user", claims.Sub, "function", name, "reason", reason)
		writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", requestID,
			"not authorized to invoke function '"+name+"'")
		return
	}

	// Resolve to the Function's cluster-local Knative address and forward the payload. Hitting the
	// cluster-local URL is what drives Knative scale-from-zero.
	target := "http://" + name + "." + h.fnNS + "." + h.svcSuffix + "/"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, r.Body)
	if err != nil {
		writeLambdaError(w, http.StatusInternalServerError, "ServiceException", requestID, "could not build upstream request")
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}

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
	// status. We map a downstream HTTP error onto that convention.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		w.Header().Set("X-Amz-Function-Error", "Unhandled")
	}
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

// parseInvokePath matches POST /2015-03-31/functions/{name}/invocations and returns {name}.
func parseInvokePath(r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		return "", false
	}
	p := strings.TrimPrefix(r.URL.Path, "/2015-03-31/functions/")
	if p == r.URL.Path { // prefix wasn't present
		return "", false
	}
	name, rest, found := strings.Cut(p, "/")
	if !found || rest != "invocations" || name == "" {
		return "", false
	}
	return name, true
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
