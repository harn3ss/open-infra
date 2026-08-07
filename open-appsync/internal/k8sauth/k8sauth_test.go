package k8sauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
)

// The SAR authorizer must (a) POST a well-formed SubjectAccessReview carrying the caller's identity and
// the field's requirement to the real k8s endpoint, and (b) honor the allowed verdict — proving field
// auth resolves through the shared RBAC boundary, not a bespoke rule.
func TestSAR_BuildsReviewAndHonorsVerdict(t *testing.T) {
	var seen sarReview
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authorization.k8s.io/v1/subjectaccessreviews" || r.Method != http.MethodPost {
			t.Errorf("unexpected SAR call: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("SAR must carry the service-account bearer token, got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&seen)
		// Allow only alice getting graphqlapis.
		allowed := seen.Spec.User == "alice" &&
			seen.Spec.ResourceAttributes != nil &&
			seen.Spec.ResourceAttributes.Resource == "graphqlapis" &&
			seen.Spec.ResourceAttributes.Verb == "get"
		seen.Status = &sarStat{Allowed: allowed, Reason: "test"}
		_ = json.NewEncoder(w).Encode(seen)
	}))
	defer ts.Close()

	a := New(ts.URL, "tok", ts.Client())
	need := authz.Requirement{Group: "openinfra.dev", Resource: "graphqlapis", Verb: "get", Namespace: "team-a"}

	// Allowed caller.
	if err := a.Authorize(context.Background(), authz.Identity{Username: "alice", Groups: []string{"admins"}}, need); err != nil {
		t.Fatalf("alice should be allowed: %v", err)
	}
	// The SAR carried the identity + requirement faithfully.
	if seen.Spec.User != "alice" || len(seen.Spec.Groups) != 1 || seen.Spec.Groups[0] != "admins" {
		t.Fatalf("SAR did not carry the identity: %+v", seen.Spec)
	}
	if ra := seen.Spec.ResourceAttributes; ra == nil || ra.Group != "openinfra.dev" || ra.Namespace != "team-a" {
		t.Fatalf("SAR did not carry the requirement: %+v", seen.Spec.ResourceAttributes)
	}

	// Denied caller → authz.ErrDenied.
	err := a.Authorize(context.Background(), authz.Identity{Username: "mallory"}, need)
	if !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("mallory should be denied with ErrDenied, got %v", err)
	}
}

// A zero Requirement is allowed without any SAR call (public field).
func TestSAR_ZeroRequirementSkipsCall(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer ts.Close()
	a := New(ts.URL, "tok", ts.Client())
	if err := a.Authorize(context.Background(), authz.Identity{Username: "x"}, authz.Requirement{}); err != nil {
		t.Fatalf("zero requirement should allow: %v", err)
	}
	if called {
		t.Fatal("a public field must not trigger a SAR call")
	}
}
