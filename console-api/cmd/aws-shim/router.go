package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/awssig"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// fwdModeKey carries the auth mode the shim will forward to open-appsync (X-OpenInfra-Auth-Mode). The
// SigV4 path leaves it unset (defaults to aws_iam); the JWT path sets aws_oidc / aws_cognito_user_pools.
type fwdModeKey struct{}

func withForwardedMode(ctx context.Context, mode string) context.Context {
	return context.WithValue(ctx, fwdModeKey{}, mode)
}

// forwardedMode returns the auth mode to forward, defaulting to aws_iam (a SigV4-authenticated request).
func forwardedMode(ctx context.Context) string {
	if m, ok := ctx.Value(fwdModeKey{}).(string); ok && m != "" {
		return m
	}
	return "aws_iam"
}

// The shim is a router with pluggable per-service handlers: one front door,
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
	auth       *authenticator
	jwt        *jwtAuthenticator     // OIDC/Cognito verifier for the appsync data plane; nil = JWT auth off
	lambdaAuth *lambdaAuthorizer     // @aws_lambda authorizer Function for the appsync data plane; nil = off
	services   map[string]awsService // keyed by AWS service name: "s3", "sts", "lambda", "appsync"
	logger     *slog.Logger
}

func (rt *serviceRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r)

	authHdr := r.Header.Get("Authorization")
	cred, err := awssig.ParseAuthorization(authHdr)
	if err != nil {
		// sts:AssumeRoleWithWebIdentity (workload identity) carries NO SigV4 — the projected
		// ServiceAccount token in the form IS the credential. Route it to STS before any other
		// non-SigV4 handling; the handler verifies the token and fails closed.
		if isWebIdentityAssume(r) {
			if sts, ok := rt.services["sts"].(*stsHandler); ok {
				sts.assumeRoleWithWebIdentity(w, r, requestID)
				return
			}
		}
		// Not SigV4. The AppSync data plane accepts ONE non-SigV4 mode, whichever is configured on this
		// shim: a Lambda authorizer (an opaque custom token) OR an OIDC/Cognito bearer JWT — never both
		// (main refuses to start with both). So every appsync request is valid SigV4 OR valid via the one
		// configured token mode, never neither: a token that fails is rejected as hard as a bad signature.
		if rt.lambdaAuth != nil {
			if strings.TrimSpace(authHdr) != "" {
				rt.serveAppsyncLambda(w, r, strings.TrimSpace(authHdr), requestID)
				return
			}
		} else if tok, ok := bearerToken(authHdr); ok {
			rt.serveAppsyncJWT(w, r, tok, requestID)
			return
		}
		// No parseable SigV4 and no usable token — we can't know the intended service or its error
		// dialect. Default to an S3-shaped 403 (most unauthenticated probing is S3-shaped).
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

// isWebIdentityAssume reports whether this is an unauthenticated sts:AssumeRoleWithWebIdentity POST
// (the one STS call that carries no SigV4 — the ServiceAccount token in the form is the credential).
func isWebIdentityAssume(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	_ = r.ParseForm()
	return r.PostFormValue("Action") == "AssumeRoleWithWebIdentity"
}

// serveAppsyncJWT handles the OIDC/Cognito bearer-JWT path for the appsync data plane. It fails CLOSED:
// if appsync isn't fronted, or JWT auth isn't configured, or the token doesn't verify, it rejects with
// appsync's dialect exactly as a bad SigV4 signature would. On success it dispatches to the appsync
// handler with the verified principal and the auth mode to forward.
func (rt *serviceRouter) serveAppsyncJWT(w http.ResponseWriter, r *http.Request, token, requestID string) {
	appsvc, ok := rt.services["appsync"]
	if !ok {
		writeUnsupportedService(w, "appsync", requestID)
		return
	}
	// The AppSync MANAGEMENT plane (/v1/...) is control-plane — IAM/console only, never a data-plane
	// OIDC/Cognito user token. A JWT reaches only the GraphQL data plane; reject management outright.
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		appsvc.authFailure(w, r, requestID)
		return
	}
	if rt.jwt == nil {
		// A JWT was presented but OIDC/Cognito auth is not configured on this shim → reject hard.
		appsvc.authFailure(w, r, requestID)
		return
	}
	claims, mode, err := rt.jwt.verify(r.Context(), token)
	if err != nil {
		rt.logger.Warn("appsync jwt rejected", "error", err.Error())
		appsvc.authFailure(w, r, requestID)
		return
	}
	appsvc.serve(w, r.WithContext(withForwardedMode(r.Context(), mode)), claims, requestID)
}

// serveAppsyncLambda handles the @aws_lambda authorizer path for the appsync data plane. It mirrors
// serveAppsyncJWT's fail-closed discipline exactly: if appsync isn't fronted, or the request targets the
// management plane, or no authorizer is configured, or the authorizer denies/errors, it rejects with
// appsync's dialect as hard as a bad SigV4 signature. On authorize it dispatches with the authorizer's
// principal and forwarded mode aws_lambda; the engine then gates @aws_lambda fields and runs the field SAR.
func (rt *serviceRouter) serveAppsyncLambda(w http.ResponseWriter, r *http.Request, token, requestID string) {
	appsvc, ok := rt.services["appsync"]
	if !ok {
		writeUnsupportedService(w, "appsync", requestID)
		return
	}
	// The management plane (/v1/...) is control-plane — IAM/console only, never a data-plane token.
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		appsvc.authFailure(w, r, requestID)
		return
	}
	if rt.lambdaAuth == nil {
		appsvc.authFailure(w, r, requestID)
		return
	}
	claims, err := rt.lambdaAuth.verify(r.Context(), token)
	if err != nil {
		rt.logger.Warn("appsync lambda authorizer rejected", "error", err.Error())
		appsvc.authFailure(w, r, requestID)
		return
	}
	appsvc.serve(w, r.WithContext(withForwardedMode(r.Context(), "aws_lambda")), claims, requestID)
}

// writeUnsupportedService reports a not-fronted service. It uses an S3-style error body as a
// lowest-common-denominator (valid XML, a clear NotImplemented code); the HTTP 501 is what SDKs key
// their "operation unsupported" handling off regardless of dialect.
func writeUnsupportedService(w http.ResponseWriter, service, requestID string) {
	writeS3ErrorMsg(w, "NotImplemented", http.StatusNotImplemented, requestID,
		"AWS service '"+service+"' is not fronted by this open-infra shim")
}
