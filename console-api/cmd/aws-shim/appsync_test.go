package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// csWithSAR returns a fake clientset whose SubjectAccessReviews all return `allowed`.
func csWithSAR(allowed bool) *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allowed}}, nil
	})
	return cs
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestAppsync_ForwardsToEngine_NeverClientHeaders proves the two invariants that survive the
// engine swap: the GraphQL body reaches open-appsync's /graphql with the verified principal as its
// auth context, and NO client-supplied header is ever forwarded (a fresh upstream request) — so an
// attacker can't smuggle an identity/role/secret header through to the engine.
func TestAppsync_ForwardsToEngine_NeverClientHeaders(t *testing.T) {
	var gotBody, gotUser, gotPath string
	var forwardedSmuggled bool
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotPath = r.URL.Path
		gotUser = r.Header.Get("X-OpenInfra-User")
		// The client tried to smuggle these; the fresh request must NOT carry them.
		if r.Header.Get("X-Smuggled-Secret") != "" || r.Header.Get("X-Smuggled-Impersonate") != "" {
			forwardedSmuggled = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"users":[{"id":"1"}]}}`)
	}))
	defer engine.Close()

	h := newAppsyncHandler(csWithSAR(true), engine.URL, "default", discardLogger())
	body := `{"query":"{ users { id } }"}`
	req := httptest.NewRequest("POST", "http://appsync/graphql", strings.NewReader(body))
	req.Header.Set("X-Smuggled-Secret", "attacker-tries-secret") // must be dropped
	req.Header.Set("X-Smuggled-Impersonate", "root")             // must be dropped
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "erin", Groups: []string{"openinfra:admins", "openinfra:users"}}, "req-1")

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("GraphQL response not passed through: %s", w.Body.String())
	}
	if gotBody != body {
		t.Errorf("engine got body %q, want %q", gotBody, body)
	}
	if gotPath != "/graphql" {
		t.Errorf("engine ingress path = %q, want /graphql", gotPath)
	}
	// The forwarded user is NAMESPACED (openinfra:<sub>) — the exact identity iam.Identity authorizes at
	// the coarse gate and the engine's field SAR will impersonate — never the raw subject.
	if gotUser != "openinfra:erin" {
		t.Errorf("X-OpenInfra-User=%q want openinfra:erin (namespaced principal, matching iam.Identity)", gotUser)
	}
	if forwardedSmuggled {
		t.Error("a client-supplied header was forwarded to the engine — fresh-request discipline broken")
	}
}

// A comma inside a group value must NOT cross the shim→engine hop as a second group: the header the
// engine re-splits on commas would otherwise let an authorizer/token-supplied "x,system:masters"
// re-materialize system:masters (cluster-admin). GroupsFromSpec drops any comma-bearing entry, so the
// forwarded X-OpenInfra-Groups value never contains an un-namespaced smuggled group.
func TestAppsync_GroupCommaInjectionBlocked(t *testing.T) {
	var gotGroups string
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = r.Header.Get("X-OpenInfra-Groups")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{}}`)
	}))
	defer engine.Close()

	h := newAppsyncHandler(csWithSAR(true), engine.URL, "default", discardLogger())
	req := httptest.NewRequest("POST", "http://appsync/graphql", strings.NewReader(`{"query":"{ x }"}`))
	// Simulate what an authorizer/token supplied: GroupsFromSpec is the choke point every front door uses.
	claims := iam.Claims{Sub: "mallory", Groups: iam.GroupsFromSpec([]string{"x,system:masters", "openinfra:admins,cluster-admin"})}
	h.serve(httptest.NewRecorder(), req, claims, "req-inj")

	// Re-split exactly as the engine (open-appsync identityFromHeaders) does, and assert no smuggled group.
	for _, g := range strings.Split(gotGroups, ",") {
		g = strings.TrimSpace(g)
		if g == "system:masters" || g == "cluster-admin" {
			t.Fatalf("smuggled group %q crossed the hop; forwarded header was %q", g, gotGroups)
		}
	}
	if !strings.Contains(gotGroups, "openinfra:users") {
		t.Errorf("legitimate base group missing; forwarded header was %q", gotGroups)
	}
}

func TestAppsync_CoarseGateDenies(t *testing.T) {
	// Engine that must NOT be reached when the platform-membership gate denies.
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("engine must not be called when the gate denies")
		w.WriteHeader(500)
	}))
	defer engine.Close()

	h := newAppsyncHandler(csWithSAR(false), engine.URL, "default", discardLogger())
	req := httptest.NewRequest("POST", "http://appsync/graphql", strings.NewReader(`{"query":"{x}"}`))
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "nobody"}, "r")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", w.Code)
	}
	assertAppsyncErrorJSON(t, w, "UnauthorizedException")
}

func TestAppsync_NonPOST(t *testing.T) {
	h := newAppsyncHandler(csWithSAR(true), "http://unused", "default", discardLogger())
	req := httptest.NewRequest("GET", "http://appsync/graphql", nil)
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "erin"}, "r")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", w.Code)
	}
}

func TestAppsync_AuthFailureDialect(t *testing.T) {
	h := newAppsyncHandler(csWithSAR(true), "http://unused", "default", discardLogger())
	w := httptest.NewRecorder()
	h.authFailure(w, httptest.NewRequest("POST", "http://appsync/", nil), "r")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", w.Code)
	}
	assertAppsyncErrorJSON(t, w, "UnauthorizedException")
}

// assertAppsyncErrorJSON verifies the body is a GraphQL-style {errors:[{errorType,...}]} an SDK
// (and a GraphQL client) can parse, carrying the expected errorType.
func assertAppsyncErrorJSON(t *testing.T, w *httptest.ResponseRecorder, wantType string) {
	t.Helper()
	var body struct {
		Errors []struct {
			ErrorType string `json:"errorType"`
			Message   string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("appsync error body is not valid JSON: %v (%s)", err, w.Body.String())
	}
	if len(body.Errors) == 0 || body.Errors[0].ErrorType != wantType {
		t.Fatalf("want errorType %q, got %+v", wantType, body.Errors)
	}
	if got := w.Header().Get("x-amzn-ErrorType"); got != wantType {
		t.Fatalf("x-amzn-ErrorType=%q want %q", got, wantType)
	}
}
