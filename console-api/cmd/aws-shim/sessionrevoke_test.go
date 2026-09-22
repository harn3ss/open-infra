package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// fakeRevoker is a stub sessionRevoker: it returns a fixed cutoff for every role.
type fakeRevoker struct {
	cutoff time.Time
	on     bool
}

func (f fakeRevoker) RevokedBefore(context.Context, string) (time.Time, bool) { return f.cutoff, f.on }

// assumeAndSign mints a real session for roleName and returns a request signed with its temp creds +
// session token, plus the minter that must verify it — the same round-trip as the end-to-end tests.
func assumeAndSign(t *testing.T, roleName string) (*http.Request, *authenticator) {
	t.Helper()
	h, minter := newSTS(t, fakeRoles{roleName: {trust: []string{"*"}, groups: []string{"openinfra:users"}}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest(roleName, "s1"), iam.Claims{Sub: "alice"}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("assume should be 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp assumeRoleResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c := resp.Result.Credentials
	req := signedSessionRequest(t, c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	return req, &authenticator{keys: fakeKeys{}, resolve: func(context.Context, string) ([]string, bool) { return nil, false }, sts: minter}
}

// A session minted BEFORE the role's cutoff is revoked — denied even though its token is valid and
// its SigV4 signature is correct. The cutoff is set in the future, so the just-minted session (issued
// now) precedes it.
func TestRevoke_SessionBeforeCutoffDenied(t *testing.T) {
	req, auth := assumeAndSign(t, "deploy-role")
	auth.revoke = fakeRevoker{cutoff: time.Now().UTC().Add(time.Hour), on: true}
	if _, err := auth.authenticate(context.Background(), req); err != errAuth {
		t.Fatalf("a session issued before the role cutoff must be errAuth, got %v", err)
	}
}

// A session minted AT/AFTER the cutoff survives — a new assume after a revoke still works. The cutoff
// is in the past, so the just-minted session was issued after it.
func TestRevoke_SessionAfterCutoffAllowed(t *testing.T) {
	req, auth := assumeAndSign(t, "deploy-role")
	auth.revoke = fakeRevoker{cutoff: time.Now().UTC().Add(-time.Hour), on: true}
	claims, err := auth.authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("a session issued after the cutoff must authenticate, got %v", err)
	}
	if claims.AssumedRole != "deploy-role" {
		t.Fatalf("session should act as the role, got %q", claims.AssumedRole)
	}
}

// A role with no cutoff (revoker returns on=false) revokes nothing.
func TestRevoke_NoCutoffAllows(t *testing.T) {
	req, auth := assumeAndSign(t, "deploy-role")
	auth.revoke = fakeRevoker{cutoff: time.Now().UTC().Add(time.Hour), on: false} // future cutoff but not "on"
	if _, err := auth.authenticate(context.Background(), req); err != nil {
		t.Fatalf("no cutoff set must authenticate, got %v", err)
	}
}

// A nil revoker (feature not wired) leaves the assumed-role path exactly as before.
func TestRevoke_NilRevokerAllows(t *testing.T) {
	req, auth := assumeAndSign(t, "deploy-role")
	auth.revoke = nil
	if _, err := auth.authenticate(context.Background(), req); err != nil {
		t.Fatalf("nil revoker must authenticate, got %v", err)
	}
}

// --- roleCutoffCache: parse, absence, and failure posture ---

func roleObj(name, cutoff string) *unstructured.Unstructured {
	spec := map[string]any{"policies": []any{}}
	if cutoff != "" {
		spec["revokeSessionsBefore"] = cutoff
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "Role",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
		"spec":       spec,
	}}
}

func newFakeDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "roles"}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{gvr: "RoleList"}, objs...)
}

func TestRoleCutoffCache_ParsesAndCaches(t *testing.T) {
	want := time.Now().UTC().Truncate(time.Second)
	dyn := newFakeDyn(roleObj("deploy-role", want.Format(time.RFC3339)))
	c := newRoleCutoffCache(dyn, "default", time.Minute)

	cutoff, on := c.RevokedBefore(context.Background(), "deploy-role")
	if !on {
		t.Fatal("a role with revokeSessionsBefore must report a cutoff")
	}
	if !cutoff.Equal(want) {
		t.Fatalf("cutoff = %v, want %v", cutoff, want)
	}
	// Second call within TTL is a cache hit: it must not re-read (delete the object; still answered).
	_ = dyn.Resource(roleGVR).Namespace("default").Delete(context.Background(), "deploy-role", metav1.DeleteOptions{})
	if cutoff2, on2 := c.RevokedBefore(context.Background(), "deploy-role"); !on2 || !cutoff2.Equal(want) {
		t.Fatalf("cached read should still return %v/true, got %v/%v", want, cutoff2, on2)
	}
}

func TestRoleCutoffCache_NoField(t *testing.T) {
	dyn := newFakeDyn(roleObj("plain-role", ""))
	c := newRoleCutoffCache(dyn, "default", time.Minute)
	if _, on := c.RevokedBefore(context.Background(), "plain-role"); on {
		t.Fatal("a role without revokeSessionsBefore must report no cutoff")
	}
}

func TestRoleCutoffCache_UnknownRoleNoCutoff(t *testing.T) {
	dyn := newFakeDyn()
	c := newRoleCutoffCache(dyn, "default", time.Minute)
	// Never loaded + read fails (not found) => no cutoff (allow); crypto + expiry still gate the request.
	if _, on := c.RevokedBefore(context.Background(), "ghost"); on {
		t.Fatal("an unreadable, never-loaded role must report no cutoff (fail-open for this check only)")
	}
}

// Once a cutoff is loaded, a later read error SERVES THE LAST-KNOWN cutoff — a control-plane blip
// must not silently un-revoke every session. ttl=0 forces a re-read on each call.
func TestRoleCutoffCache_ReadErrorServesLastKnown(t *testing.T) {
	want := time.Now().UTC().Truncate(time.Second)
	dyn := newFakeDyn(roleObj("deploy-role", want.Format(time.RFC3339)))
	c := newRoleCutoffCache(dyn, "default", 0) // ttl=0 => always re-read

	if cutoff, on := c.RevokedBefore(context.Background(), "deploy-role"); !on || !cutoff.Equal(want) {
		t.Fatalf("initial load should return %v/true, got %v/%v", want, cutoff, on)
	}
	dyn.PrependReactor("get", "roles", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("apiserver unavailable")
	})
	if cutoff, on := c.RevokedBefore(context.Background(), "deploy-role"); !on || !cutoff.Equal(want) {
		t.Fatalf("on a read error the last-known cutoff must be served (%v/true), got %v/%v", want, cutoff, on)
	}
}
