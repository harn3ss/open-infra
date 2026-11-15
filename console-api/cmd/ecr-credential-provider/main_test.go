package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shimAnswering(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ecr/pod-credential" {
			t.Errorf("asked %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotAuth
}

const req = `{"apiVersion":"credentialprovider.kubelet.k8s.io/v1","kind":"CredentialProviderRequest",
"image":"registry.example:5000/111122223333/example/app:1","serviceAccountToken":"pod-token","serviceAccountAnnotations":{}}`

func TestExecutionRoleCredential(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	srv, auth := shimAnswering(t, 200, `{"username":"AWS","password":"cred","expiresAt":"`+exp+`"}`)
	out, err := run(strings.NewReader(req), srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if *auth != "Bearer pod-token" {
		t.Fatalf("the shim was sent %q", *auth)
	}
	a, ok := out.Auth["registry.example:5000"]
	if !ok || a.Username != "AWS" || a.Password != "cred" || out.CacheKeyType != "Registry" || out.Kind != "CredentialProviderResponse" {
		t.Fatalf("response %+v", out)
	}
	if d, err := time.ParseDuration(out.CacheDuration); err != nil || d > 30*time.Minute || d < 29*time.Minute {
		t.Fatalf("cached for %q; want half the credential's hour, at most 30m", out.CacheDuration)
	}
}

func TestNoExecutionRoleIsTheNodes(t *testing.T) {
	srv, _ := shimAnswering(t, 204, "")
	out, err := run(strings.NewReader(req), srv.URL, srv.Client())
	if err != nil || len(out.Auth) != 0 {
		t.Fatalf("%+v %v; want no credential", out, err)
	}
	// No pod identity at all: no call, no credential.
	out, err = run(strings.NewReader(`{"image":"registry.example/app:1"}`), "http://unused.invalid", http.DefaultClient)
	if err != nil || len(out.Auth) != 0 {
		t.Fatalf("%+v %v; want no credential", out, err)
	}
}

func TestRefusedRoleFailsThePull(t *testing.T) {
	srv, _ := shimAnswering(t, 403, `{"errors":[{"code":"DENIED"}]}`)
	out, err := run(strings.NewReader(req), srv.URL, srv.Client())
	a, ok := out.Auth["registry.example:5000"]
	if err != nil || !ok || a.Password != "refused" {
		t.Fatalf("%+v %v; want a credential the registry refuses", out, err)
	}
}

func TestShimFailureIsAnError(t *testing.T) {
	srv, _ := shimAnswering(t, 500, "boom")
	if _, err := run(strings.NewReader(req), srv.URL, srv.Client()); err == nil {
		t.Fatal("a failing shim must be an error")
	}
	if _, err := run(strings.NewReader(`{"apiVersion":"credentialprovider.kubelet.k8s.io/v1alpha1","image":"x/y"}`), srv.URL, srv.Client()); err == nil {
		t.Fatal("another apiVersion must be an error")
	}
}

func TestInstallCopiesItself(t *testing.T) {
	dir := t.TempDir()
	if err := installTo(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "ecr-credential-provider"))
	if err != nil || fi.Mode().Perm() != 0o755 || fi.Size() == 0 {
		t.Fatalf("installed %v %v", fi, err)
	}
}
