package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// fakeAppsync records which lifecycle method the router invoked.
type fakeAppsync struct {
	served bool
	failed bool
}

func (f *fakeAppsync) serve(http.ResponseWriter, *http.Request, iam.Claims, string) { f.served = true }
func (f *fakeAppsync) authFailure(http.ResponseWriter, *http.Request, string)       { f.failed = true }

func discardRouter(appsvc awsService) *serviceRouter {
	return &serviceRouter{
		jwt:      nil, // not reached: the /v1 reject fires before the verifier
		services: map[string]awsService{"appsync": appsvc},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// The AppSync management plane (/v1/...) must be UNREACHABLE via a data-plane bearer JWT — control-plane
// is IAM/console only. A bearer token to /v1/ must be rejected (authFailure), never served.
func TestJWT_ManagementPlaneRejected(t *testing.T) {
	fake := &fakeAppsync{}
	rt := discardRouter(fake)
	r := httptest.NewRequest(http.MethodPost, "/v1/apis/abc/resolvers", nil)
	rt.serveAppsyncJWT(httptest.NewRecorder(), r, "aaa.bbb.ccc", "req-1")
	if fake.served {
		t.Fatal("management-plane (/v1/) request must NOT be served via a JWT")
	}
	if !fake.failed {
		t.Fatal("management-plane (/v1/) JWT request must be rejected")
	}
}

// A data-plane JWT with no verifier configured must reject (fail-closed), never serve.
func TestJWT_NoVerifierRejects(t *testing.T) {
	fake := &fakeAppsync{}
	rt := discardRouter(fake) // jwt == nil
	r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	rt.serveAppsyncJWT(httptest.NewRecorder(), r, "aaa.bbb.ccc", "req-2")
	if fake.served || !fake.failed {
		t.Fatalf("a JWT with no verifier configured must be rejected (served=%v failed=%v)", fake.served, fake.failed)
	}
}
