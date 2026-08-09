package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// capturingAppsync records how the router dispatched, including the forwarded auth mode + principal.
type capturingAppsync struct {
	served bool
	failed bool
	mode   string
	claims iam.Claims
}

func (f *capturingAppsync) serve(_ http.ResponseWriter, r *http.Request, c iam.Claims, _ string) {
	f.served = true
	f.claims = c
	f.mode = forwardedMode(r.Context())
}
func (f *capturingAppsync) authFailure(http.ResponseWriter, *http.Request, string) { f.failed = true }

// authorizerRouter wires a serviceRouter whose Lambda authorizer points at a fake authorizer Function.
func authorizerRouter(t *testing.T, isAuthorized bool, appsvc awsService) *serviceRouter {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if isAuthorized {
			_, _ = io.WriteString(w, `{"isAuthorized":true,"resolverContext":{"sub":"ada","groups":["Ops"]}}`)
		} else {
			_, _ = io.WriteString(w, `{"isAuthorized":false}`)
		}
	}))
	t.Cleanup(ts.Close)
	return &serviceRouter{
		lambdaAuth: &lambdaAuthorizer{client: ts.Client(), fnURL: ts.URL + "/", fnName: "authz", userClaim: "sub", groupsClaim: "groups"},
		services:   map[string]awsService{"appsync": appsvc},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// The management plane (/v1/...) must be UNREACHABLE via a data-plane authorizer token.
func TestLambda_ManagementPlaneRejected(t *testing.T) {
	fake := &capturingAppsync{}
	rt := authorizerRouter(t, true, fake)
	r := httptest.NewRequest(http.MethodPost, "/v1/apis/abc/resolvers", nil)
	rt.serveAppsyncLambda(httptest.NewRecorder(), r, "tok", "req-1")
	if fake.served || !fake.failed {
		t.Fatalf("management-plane (/v1/) must be rejected, not served (served=%v failed=%v)", fake.served, fake.failed)
	}
}

// No authorizer configured → fail closed.
func TestLambda_NoAuthorizerRejects(t *testing.T) {
	fake := &capturingAppsync{}
	rt := &serviceRouter{services: map[string]awsService{"appsync": fake}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rt.serveAppsyncLambda(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/graphql", nil), "tok", "req-2")
	if fake.served || !fake.failed {
		t.Fatalf("an authorizer token with no authorizer configured must be rejected (served=%v failed=%v)", fake.served, fake.failed)
	}
}

// The authorizer denying → fail closed.
func TestLambda_DeniedRejects(t *testing.T) {
	fake := &capturingAppsync{}
	rt := authorizerRouter(t, false, fake)
	rt.serveAppsyncLambda(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/graphql", nil), "tok", "req-3")
	if fake.served || !fake.failed {
		t.Fatalf("a denied request must be rejected (served=%v failed=%v)", fake.served, fake.failed)
	}
}

// The authorizer authorizing → served, with mode aws_lambda and the mapped principal.
func TestLambda_AuthorizedServesWithMode(t *testing.T) {
	fake := &capturingAppsync{}
	rt := authorizerRouter(t, true, fake)
	rt.serveAppsyncLambda(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/graphql", nil), "tok", "req-4")
	if !fake.served || fake.failed {
		t.Fatalf("an authorized request must be served (served=%v failed=%v)", fake.served, fake.failed)
	}
	if fake.mode != "aws_lambda" {
		t.Errorf("forwarded mode = %q, want aws_lambda", fake.mode)
	}
	if fake.claims.Sub != "ada" {
		t.Errorf("forwarded subject = %q, want ada", fake.claims.Sub)
	}
}

// ServeHTTP routing: when a Lambda authorizer is configured, a non-SigV4 opaque Authorization token is
// routed to the authorizer path (not 403'd, not treated as a JWT).
func TestServeHTTP_RoutesOpaqueTokenToAuthorizer(t *testing.T) {
	fake := &capturingAppsync{}
	rt := authorizerRouter(t, true, fake)
	r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	r.Header.Set("Authorization", "opaque-custom-token-not-a-jwt")
	rt.ServeHTTP(httptest.NewRecorder(), r)
	if !fake.served || fake.mode != "aws_lambda" {
		t.Fatalf("an opaque token with an authorizer configured must route to the authorizer (served=%v mode=%q)", fake.served, fake.mode)
	}
}
