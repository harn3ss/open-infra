package main

import (
	"log/slog"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/awssig"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// The shim is a router with pluggable per-service handlers (design handoff §2): one front door,
// many domain experts. Each AWS service (S3, STS, Lambda, …) is a small handler carrying its own
// decoder, its own authorization mapping, and its own error DIALECT — S3 speaks XML <Error>, the
// query-protocol services speak <ErrorResponse>, the JSON-RPC services speak JSON. Adding a
// service is registering one more awsService; the shared SigV4 authentication and identity
// resolution below are done ONCE, for every service, so no handler grows its own weaker auth.
type awsService interface {
	// serve handles an already-AUTHENTICATED request; the handler does its own per-operation
	// authorization (iam.CanDo) against claims.
	serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string)
	// authFailure writes THIS service's dialect of a 403 authentication failure, so an SDK sees
	// the byte-shape it expects even when the request is rejected before any operation runs.
	authFailure(w http.ResponseWriter, r *http.Request, requestID string)
}

// serviceRouter authenticates once, then dispatches to the handler for the AWS service the client
// signed for. The target service is read from the SigV4 credential scope (…/<service>/aws4_request)
// — the client always names it there — so routing needs no fragile host/path sniffing.
type serviceRouter struct {
	auth     *authenticator
	services map[string]awsService // keyed by AWS service name: "s3", "sts", "lambda"
	logger   *slog.Logger
}

func (rt *serviceRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r)

	cred, err := awssig.ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		// No parseable SigV4 — we can't know the intended service or its error dialect. Default to
		// an S3-shaped 403 (the overwhelming majority of unauthenticated probing is S3-shaped).
		writeS3Error(w, "AccessDenied", requestID, r.URL.Path)
		return
	}

	svc, ok := rt.services[cred.Service]
	if !ok {
		// The client signed for a service this shim does not front. Be honest and specific rather
		// than pretending: a 501 with the service name, so the caller knows it isn't implemented.
		rt.logger.Warn("unsupported AWS service", "service", cred.Service, "path", r.URL.Path)
		writeUnsupportedService(w, cred.Service, requestID)
		return
	}

	// Shared authentication for EVERY service: verify SigV4, resolve the principal. On failure the
	// SERVICE writes its own dialect of the rejection.
	claims, err := rt.auth.authenticate(r.Context(), r)
	if err != nil {
		svc.authFailure(w, r, requestID)
		return
	}
	svc.serve(w, r, claims, requestID)
}

// writeUnsupportedService reports a not-fronted service. It uses an S3-style error body as a
// lowest-common-denominator (valid XML, a clear NotImplemented code); the HTTP 501 is what SDKs key
// their "operation unsupported" handling off regardless of dialect.
func writeUnsupportedService(w http.ResponseWriter, service, requestID string) {
	writeS3ErrorMsg(w, "NotImplemented", http.StatusNotImplemented, requestID,
		"AWS service '"+service+"' is not fronted by this open-infra shim")
}
