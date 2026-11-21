package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
)

// unreadableKeys is a key store the cluster API cannot be reached for: every lookup fails.
type unreadableKeys struct{}

func (unreadableKeys) Lookup(context.Context, string) (awskeys.Key, bool) {
	return awskeys.Key{}, false
}

func (unreadableKeys) LookupErr(context.Context, string) (awskeys.Key, bool, error) {
	return awskeys.Key{}, false, errors.New(`Get "https://10.43.0.1:443/api/v1/namespaces/x/secrets/y": dial tcp: connect: connection refused`)
}

// checkedKeys is fakeKeys with LookupErr: a key it does not hold is absent, not unreadable.
type checkedKeys struct{ fakeKeys }

func (c checkedKeys) LookupErr(ctx context.Context, id string) (awskeys.Key, bool, error) {
	k, ok := c.Lookup(ctx, id)
	return k, ok, nil
}

// A request the shim cannot verify just now (the cluster API briefly unreachable, as while the control plane
// restarts) is answered ServiceUnavailable, which an SDK retries, as AWS answers such a moment: never
// SignatureDoesNotMatch, which tells the caller its request was wrong. A key that does not exist, a wrong
// signature and an owner that is gone stay the one indistinguishable failure.
func TestAuthenticate_UnreadableKeyIsServiceUnavailable(t *testing.T) {
	const id, secret, owner = "OIAKEXAMPLE000000000", "the-real-secret", "alice"
	resolveOK := func(_ context.Context, o string) ([]string, bool) { return []string{"openinfra:users"}, o == owner }

	a := &authenticator{keys: unreadableKeys{}, resolve: resolveOK}
	if _, err := a.authenticate(context.Background(), signedRequest(t, id, secret)); !errors.Is(err, errAuthUnavailable) {
		t.Fatalf("a key that could not be read: %v, want errAuthUnavailable", err)
	}
	// The owner could not be read just now (the resolver notes it, as newOwnerResolver does).
	unreadableOwner := func(ctx context.Context, _ string) ([]string, bool) { noteLookupTrouble(ctx); return nil, false }
	keys := checkedKeys{fakeKeys{id: {AccessKeyID: id, SecretKey: secret, Owner: owner}}}
	a = &authenticator{keys: keys, resolve: unreadableOwner}
	if _, err := a.authenticate(context.Background(), signedRequest(t, id, secret)); !errors.Is(err, errAuthUnavailable) {
		t.Fatalf("an owner that could not be read: %v, want errAuthUnavailable", err)
	}
	a = &authenticator{keys: keys, resolve: resolveOK}
	for name, req := range map[string]*http.Request{
		"a key that does not exist": signedRequest(t, "OIAKNOSUCHKEY0000000", secret),
		"a wrong signature":         signedRequest(t, id, "not-the-secret"),
	} {
		if _, err := a.authenticate(context.Background(), req); !errors.Is(err, errAuth) {
			t.Errorf("%s: %v, want the one failure", name, err)
		}
	}
	if _, err := (&authenticator{keys: keys, resolve: func(context.Context, string) ([]string, bool) { return nil, false }}).
		authenticate(context.Background(), signedRequest(t, id, secret)); !errors.Is(err, errAuth) {
		t.Errorf("an owner that is gone: %v, want the one failure", err)
	}
	// A note made outside an authentication changes nothing.
	noteLookupTrouble(context.Background())

	// Each dialect answers it as ServiceUnavailable, HTTP 503.
	r := withAuthUnavailable(httptest.NewRequest(http.MethodPost, "/", nil))
	for name, c := range map[string]struct {
		svc  awsService
		code string
	}{
		"query (STS)":            {&stsHandler{}, "<Code>ServiceUnavailable</Code>"},
		"query (CloudFormation)": {&cfnDoorway{}, "<Code>ServiceUnavailable</Code>"},
		"JSON (Dynamo)":          {&dynamoHandler{}, "ServiceUnavailableException"},
		"S3":                     {&s3Handler{}, "<Code>ServiceUnavailable</Code>"},
		"EC2":                    {&ec2Handler{}, "<Code>ServiceUnavailable</Code>"},
	} {
		w := httptest.NewRecorder()
		c.svc.authFailure(w, r, "req")
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), c.code) || strings.Contains(w.Body.String(), "signature") {
			t.Errorf("%s: %d %s, want 503 %s", name, w.Code, w.Body.String(), c.code)
		}
	}
	w := httptest.NewRecorder()
	(&stsHandler{}).authFailure(w, httptest.NewRequest(http.MethodPost, "/", nil), "req")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "SignatureDoesNotMatch") {
		t.Errorf("a request refused for its signature keeps the service's own failure: %d %s", w.Code, w.Body.String())
	}
}

// Through the router: the moment's failure reaches the caller as 503, not 403.
func TestRouter_UnreadableKeyIsServiceUnavailable(t *testing.T) {
	const id, secret = "OIAKROUTER0000000000", "router-secret"
	rt := newTestRouter(map[string]awsService{"sts": &stsHandler{}})
	rt.auth.keys = unreadableKeys{}
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, signedFor(t, "sts", id, secret, "POST", "http://shim/"))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "ServiceUnavailable") {
		t.Fatalf("%d %s, want 503 ServiceUnavailable", w.Code, w.Body.String())
	}
}
