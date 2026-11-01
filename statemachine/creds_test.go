package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// credsServer serves Secrets in ns "open-infra-aws-shim" keyed by name.
func credsServer(t *testing.T, secrets map[string]map[string]any) *k8sClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const pfx = "/api/v1/namespaces/open-infra-aws-shim/secrets/"
		if len(r.URL.Path) <= len(pfx) || r.URL.Path[:len(pfx)] != pfx {
			http.NotFound(w, r)
			return
		}
		s, ok := secrets[r.URL.Path[len(pfx):]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(s)
	}))
	t.Cleanup(srv.Close)
	return &k8sClient{host: srv.URL, http: srv.Client()}
}

func credSecret(ownerUID string, controller bool) map[string]any {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	meta := map[string]any{}
	if ownerUID != "" {
		meta["ownerReferences"] = []any{map[string]any{"kind": "Execution", "name": "x", "uid": ownerUID, "controller": controller}}
	}
	return map[string]any{"metadata": meta, "data": map[string]any{
		"accessKeyId": enc("ASIAEXAMPLE"), "secretAccessKey": enc("sk"), "sessionToken": enc("tok")}}
}

// An Execution gets only the credentials Secret its own UID controls: naming another execution's
// Secret (spec.credentialsSecret is a plain name) yields nothing.
func TestGetCredentials_OnlyTheExecutionsOwnSecret(t *testing.T) {
	c := credsServer(t, map[string]map[string]any{
		"mine-creds":       credSecret("uid-mine", true),
		"theirs-creds":     credSecret("uid-theirs", true),
		"unowned-creds":    credSecret("", false),
		"noncontrol-creds": credSecret("uid-mine", false),
	})
	ctx := context.Background()
	got, err := c.getCredentials(ctx, "open-infra-aws-shim", "mine-creds", "uid-mine")
	if err != nil || got == nil || got.AccessKeyID != "ASIAEXAMPLE" {
		t.Fatalf("own Secret: creds=%+v err=%v", got, err)
	}
	for _, name := range []string{"theirs-creds", "unowned-creds", "noncontrol-creds", "missing-creds"} {
		got, err := c.getCredentials(ctx, "open-infra-aws-shim", name, "uid-mine")
		if got != nil || !errors.Is(err, errCredsPending) {
			t.Errorf("%s: must be refused as not this execution's own, got creds=%+v err=%v", name, got, err)
		}
	}
	// An empty execution UID never matches.
	if got, err := c.getCredentials(ctx, "open-infra-aws-shim", "mine-creds", ""); got != nil || err == nil {
		t.Errorf("empty UID must not match: creds=%+v err=%v", got, err)
	}
	// No credentialsSecret: no identity, no error (a state machine without a role).
	if got, err := c.getCredentials(ctx, "open-infra-aws-shim", "", "uid-mine"); got != nil || err != nil {
		t.Errorf("no secret name: creds=%+v err=%v", got, err)
	}
}

func TestYoung(t *testing.T) {
	now := time.Now().UTC()
	if !young(now.Add(-5*time.Second).Format(time.RFC3339), credsGrace) {
		t.Error("5s old must be young")
	}
	if young(now.Add(-2*time.Minute).Format(time.RFC3339), credsGrace) {
		t.Error("2m old must not be young")
	}
	if young("", credsGrace) || young("garbage", credsGrace) {
		t.Error("unparseable must not be young")
	}
}
