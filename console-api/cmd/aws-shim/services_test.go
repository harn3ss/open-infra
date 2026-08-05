package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/awssig"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// recordingService is a stub awsService that records whether it was reached, so router tests can
// assert dispatch without any backend.
type recordingService struct{ served, authFailed bool }

func (s *recordingService) serve(w http.ResponseWriter, _ *http.Request, _ iam.Claims, _ string) {
	s.served = true
	w.WriteHeader(http.StatusOK)
}
func (s *recordingService) authFailure(w http.ResponseWriter, _ *http.Request, _ string) {
	s.authFailed = true
	w.WriteHeader(http.StatusForbidden)
}

// signedFor builds a request signed with SigV4 for a given service scope, so router dispatch (which
// reads the service out of the credential scope) can be exercised end-to-end.
func signedFor(t *testing.T, service, accessKeyID, secretKey, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	cred := awssig.Credential{AccessKeyID: accessKeyID, Date: "20150830", Region: "us-east-1",
		Service: service, SignedHeaders: []string{"host", "x-amz-content-sha256", "x-amz-date"}}
	sig, err := awssig.Sign(req, cred, secretKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKeyID+
		"/20150830/us-east-1/"+service+"/aws4_request, "+
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+sig)
	return req
}

func newTestRouter(services map[string]awsService) *serviceRouter {
	const id, secret, owner = "OIAKROUTER0000000000", "router-secret", "carol"
	keys := fakeKeys{id: {AccessKeyID: id, SecretKey: secret, Owner: owner}}
	return &serviceRouter{
		auth: &authenticator{keys: keys, resolve: func(_ context.Context, o string) ([]string, bool) {
			return []string{"openinfra:users"}, o == owner
		}},
		services: services,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestRouter_DispatchByService(t *testing.T) {
	const id, secret = "OIAKROUTER0000000000", "router-secret"
	s3svc, stssvc := &recordingService{}, &recordingService{}
	rt := newTestRouter(map[string]awsService{"s3": s3svc, "sts": stssvc})

	// A request signed for "sts" must reach the sts handler, not s3.
	rt.ServeHTTP(httptest.NewRecorder(), signedFor(t, "sts", id, secret, "POST", "http://shim/"))
	if !stssvc.served || s3svc.served {
		t.Fatalf("sts request dispatched wrong: sts.served=%v s3.served=%v", stssvc.served, s3svc.served)
	}

	// A request signed for "s3" must reach s3.
	s3svc.served, stssvc.served = false, false
	rt.ServeHTTP(httptest.NewRecorder(), signedFor(t, "s3", id, secret, "GET", "http://shim/bucket/key"))
	if !s3svc.served || stssvc.served {
		t.Fatalf("s3 request dispatched wrong: s3.served=%v sts.served=%v", s3svc.served, stssvc.served)
	}
}

func TestRouter_UnsupportedService(t *testing.T) {
	const id, secret = "OIAKROUTER0000000000", "router-secret"
	rt := newTestRouter(map[string]awsService{"s3": &recordingService{}})
	w := httptest.NewRecorder()
	// Signed for dynamodb, which is not fronted → 501 NotImplemented, and no handler reached.
	rt.ServeHTTP(w, signedFor(t, "dynamodb", id, secret, "POST", "http://shim/"))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("unsupported service: status=%d want 501", w.Code)
	}
}

func TestRouter_AuthFailureUsesServiceDialect(t *testing.T) {
	const id = "OIAKROUTER0000000000"
	svc := &recordingService{}
	rt := newTestRouter(map[string]awsService{"s3": svc})
	// Correct service, but signed with the WRONG secret → the service's authFailure runs.
	rt.ServeHTTP(httptest.NewRecorder(), signedFor(t, "s3", id, "wrong-secret", "GET", "http://shim/b/k"))
	if !svc.authFailed || svc.served {
		t.Fatalf("expected s3.authFailure on bad signature: authFailed=%v served=%v", svc.authFailed, svc.served)
	}
}

func TestSTS_GetCallerIdentity(t *testing.T) {
	h := &stsHandler{account: "open-infra", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest("POST", "http://sts/", strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "dave", Groups: []string{"openinfra:users"}}, "req-9")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp getCallerIdentityResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("STS response is not SDK-parseable XML: %v", err)
	}
	if resp.Result.UserId != "dave" || resp.Result.Account != "open-infra" {
		t.Fatalf("bad identity: %+v", resp.Result)
	}
	if !strings.Contains(resp.Result.Arn, "user/dave") {
		t.Fatalf("ARN missing user: %q", resp.Result.Arn)
	}
}

func TestSTS_UnknownActionIsQueryError(t *testing.T) {
	h := &stsHandler{account: "open-infra", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest("POST", "http://sts/", strings.NewReader("Action=AssumeRole"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "dave"}, "r")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", w.Code)
	}
	var e errorResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("not a query <ErrorResponse>: %v", err)
	}
	if e.Error.Code != "InvalidAction" {
		t.Fatalf("want InvalidAction, got %q", e.Error.Code)
	}
}

func TestLambda_ParseInvokePath(t *testing.T) {
	cases := []struct {
		method, path, want string
		ok                 bool
	}{
		{"POST", "/2015-03-31/functions/hello/invocations", "hello", true},
		{"POST", "/2015-03-31/functions/my-fn/invocations", "my-fn", true},
		{"GET", "/2015-03-31/functions/hello/invocations", "", false}, // wrong method
		{"POST", "/2015-03-31/functions/hello", "", false},            // missing /invocations
		{"POST", "/hello/invocations", "", false},                     // wrong prefix
		{"POST", "/2015-03-31/functions//invocations", "", false},     // empty name
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "http://lambda"+c.path, nil)
		got, ok := parseInvokePath(req)
		if ok != c.ok || got != c.want {
			t.Errorf("%s %s: got (%q,%v) want (%q,%v)", c.method, c.path, got, ok, c.want, c.ok)
		}
	}
}

func TestLambda_ErrorDialectIsJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", "r-1", "nope")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
	if got := w.Header().Get("x-amzn-errortype"); got != "AccessDeniedException" {
		t.Fatalf("errortype header=%q", got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Lambda error body is not JSON: %v", err)
	}
	if body["message"] != "nope" {
		t.Fatalf("bad message: %v", body)
	}
}
