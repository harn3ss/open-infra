package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A Task must carry the state-machine role's STS session so it runs under the ROLE's authority,
// not the controller's ambient position (the confused-deputy fix, polyhedron#172/#168). This asserts
// the httpInvoker injects the minted session as X-Openinfra-Task-* headers on the Task POST.
func TestHTTPInvoker_InjectsRoleCredentials(t *testing.T) {
	var got http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	inv := newHTTPInvoker("default", &taskCreds{
		AccessKeyID:  "ASIAEXAMPLESESSION",
		SecretKey:    "secretpart",
		SessionToken: "sealed.session.token",
	})
	res, terr := inv.Invoke(context.Background(), srv.URL, map[string]any{"hello": "world"}, 5)
	if terr != nil {
		t.Fatalf("Invoke: %v", terr)
	}
	if m, ok := res.(map[string]any); !ok || m["ok"] != true {
		t.Fatalf("unexpected result: %#v", res)
	}
	if got.Get("X-Openinfra-Task-Access-Key-Id") != "ASIAEXAMPLESESSION" {
		t.Errorf("access key not injected: %q", got.Get("X-Openinfra-Task-Access-Key-Id"))
	}
	if got.Get("X-Openinfra-Task-Secret-Access-Key") != "secretpart" {
		t.Errorf("secret key not injected: %q", got.Get("X-Openinfra-Task-Secret-Access-Key"))
	}
	if got.Get("X-Openinfra-Task-Session-Token") != "sealed.session.token" {
		t.Errorf("session token not injected: %q", got.Get("X-Openinfra-Task-Session-Token"))
	}
	// The task input is still delivered as the JSON body.
	var body map[string]any
	if err := json.Unmarshal(gotBody, &body); err != nil || body["hello"] != "world" {
		t.Errorf("task input body wrong: %s", gotBody)
	}
}

// With no role (creds == nil), no identity headers are attached — a Task simply runs unauthenticated,
// preserving the legacy behaviour for state machines created without a roleArn.
func TestHTTPInvoker_NoCredentialsWhenRoleAbsent(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	inv := newHTTPInvoker("default", nil)
	if _, terr := inv.Invoke(context.Background(), srv.URL, map[string]any{}, 5); terr != nil {
		t.Fatalf("Invoke: %v", terr)
	}
	for k := range got {
		if strings.HasPrefix(strings.ToLower(k), "x-openinfra-task-") {
			t.Errorf("unexpected identity header on roleless task: %s", k)
		}
	}
}
