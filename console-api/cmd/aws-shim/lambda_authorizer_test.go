package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// verify maps the authorizer's verdict into the shim principal and fails CLOSED on every error path.
func TestLambdaAuthorizer_Verify(t *testing.T) {
	var status int
	var respBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The event carries the caller's token so the authorizer can decide.
		var ev authorizerEvent
		_ = json.NewDecoder(r.Body).Decode(&ev)
		if ev.AuthorizationToken == "" {
			t.Error("authorizer received an empty authorizationToken")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	defer ts.Close()
	la := &lambdaAuthorizer{client: ts.Client(), fnURL: ts.URL + "/", fnName: "authz", userClaim: "sub", groupsClaim: "groups"}

	// Authorized → subject + namespaced groups (openinfra:<g> + openinfra:users), never raw.
	status, respBody = http.StatusOK, `{"isAuthorized":true,"resolverContext":{"sub":"ada","groups":["Admin","Ops"]}}`
	claims, err := la.verify(context.Background(), "opaque-token")
	if err != nil {
		t.Fatalf("authorized request errored: %v", err)
	}
	if claims.Sub != "ada" {
		t.Errorf("sub = %q, want ada", claims.Sub)
	}
	got := map[string]bool{}
	for _, g := range claims.Groups {
		got[g] = true
	}
	for _, want := range []string{"openinfra:Admin", "openinfra:Ops", "openinfra:users"} {
		if !got[want] {
			t.Errorf("groups %v missing namespaced %q", claims.Groups, want)
		}
	}
	if got["Admin"] || got["system:masters"] {
		t.Errorf("groups must never be forwarded un-namespaced: %v", claims.Groups)
	}

	// Authorized but no identity in resolverContext → empty subject + the base authenticated group only.
	status, respBody = http.StatusOK, `{"isAuthorized":true}`
	claims, err = la.verify(context.Background(), "tok")
	if err != nil {
		t.Fatalf("authorized-no-context errored: %v", err)
	}
	if claims.Sub != "" || len(claims.Groups) != 1 || claims.Groups[0] != "openinfra:users" {
		t.Errorf("no-context claims = %+v, want empty sub + [openinfra:users]", claims)
	}

	// Every failure path is fail-closed (an error, never silent allow).
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"denied":       {http.StatusOK, `{"isAuthorized":false}`},
		"server error": {http.StatusInternalServerError, `boom`},
		"unparseable":  {http.StatusOK, `not json`},
		"empty body":   {http.StatusOK, ``},
	} {
		status, respBody = tc.status, tc.body
		if _, err := la.verify(context.Background(), "tok"); err == nil {
			t.Errorf("%s: verify must fail closed (return an error), got nil", name)
		}
	}
}

// An unreachable authorizer Function fails closed rather than allowing the request.
func TestLambdaAuthorizer_Unreachable(t *testing.T) {
	la := newLambdaAuthorizer("nope", "default", "svc.invalid", "sub", "groups")
	la.client = &http.Client{Timeout: 500 * time.Millisecond}
	if _, err := la.verify(context.Background(), "tok"); err == nil {
		t.Error("an unreachable authorizer must fail closed")
	}
}
