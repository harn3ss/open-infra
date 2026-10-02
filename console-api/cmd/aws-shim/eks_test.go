package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// --- fixtures ---

// newEKSTestHandler builds a doorway fronting one cluster "open-infra" with a fixed, test-controlled
// endpoint / CA / version — the three fields `aws eks update-kubeconfig` actually consumes.
func newEKSTestHandler(allowed bool) *eksHandler {
	caData := base64.StdEncoding.EncodeToString(
		[]byte("-----BEGIN CERTIFICATE-----\nMIIDummyCAdata\n-----END CERTIFICATE-----\n"))
	return newEKSHandler(csWithSAR(allowed), "default", "open-infra", "us-east-1",
		"open-infra", "https://10.0.0.1:6443", caData, "1.31", discardLogger())
}

func eksClaims() iam.Claims {
	return iam.Claims{Sub: "ellen", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
}

func eksReq(method, path string) *http.Request {
	return httptest.NewRequest(method, path, nil)
}

func eksErrorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not valid JSON: %v (%s)", err, w.Body.String())
	}
	return body.Message
}

// assertEKSErrorType checks the restJson1 error dialect: the exception name is in the x-amzn-errortype
// header (NOT a JSON __type), with the given HTTP status.
func assertEKSErrorType(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantType string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status=%d want %d; body=%s", w.Code, wantStatus, w.Body.String())
	}
	if got := w.Header().Get("x-amzn-errortype"); got != wantType {
		t.Fatalf("x-amzn-errortype=%q want %q (body=%s)", got, wantType, w.Body.String())
	}
}

// --- DescribeCluster: the load-bearing op ---

func TestEKS_DescribeCluster(t *testing.T) {
	h := newEKSTestHandler(true)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("GET", "/clusters/open-infra"), eksClaims(), "req-desc")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Cluster struct {
			Name                 string `json:"name"`
			Arn                  string `json:"arn"`
			Status               string `json:"status"`
			Version              string `json:"version"`
			Endpoint             string `json:"endpoint"`
			CertificateAuthority struct {
				Data string `json:"data"`
			} `json:"certificateAuthority"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	c := resp.Cluster
	if c.Name != "open-infra" {
		t.Fatalf("name=%q want open-infra", c.Name)
	}
	if c.Arn != "arn:aws:eks:us-east-1:open-infra:cluster/open-infra" {
		t.Fatalf("arn=%q unexpected", c.Arn)
	}
	if c.Status != "ACTIVE" {
		t.Fatalf("status=%q want ACTIVE", c.Status)
	}
	if c.Version != "1.31" {
		t.Fatalf("version=%q want 1.31 (echoed)", c.Version)
	}
	// The two fields that make the kubeconfig actually work.
	if c.Endpoint != "https://10.0.0.1:6443" {
		t.Fatalf("endpoint=%q unexpected; kubeconfig would point nowhere", c.Endpoint)
	}
	if c.CertificateAuthority.Data == "" {
		t.Fatalf("certificateAuthority.data is empty; kubeconfig would be unusable")
	}
}

func TestEKS_DescribeCluster_WrongName(t *testing.T) {
	h := newEKSTestHandler(true)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("GET", "/clusters/does-not-exist"), eksClaims(), "req-404")
	assertEKSErrorType(t, w, http.StatusNotFound, "ResourceNotFoundException")
	if msg := eksErrorMessage(t, w); !strings.Contains(msg, "does-not-exist") {
		t.Fatalf("not-found message %q should name the requested cluster", msg)
	}
}

// --- ListClusters ---

func TestEKS_ListClusters(t *testing.T) {
	h := newEKSTestHandler(true)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("GET", "/clusters"), eksClaims(), "req-list")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Clusters []string `json:"clusters"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.Clusters) != 1 || resp.Clusters[0] != "open-infra" {
		t.Fatalf("clusters=%+v want [open-infra]", resp.Clusters)
	}
}

// --- authz gate ---

// The coarse authorization gate denies before any work — the same impersonated SubjectAccessReview every
// front door funnels through (mirrors TestGlue_AuthzGateDenies / TestECS_AuthzGateDenies).
func TestEKS_AuthzGateDenies(t *testing.T) {
	h := newEKSTestHandler(false)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("GET", "/clusters/open-infra"),
		iam.Claims{Sub: "nobody", Groups: []string{"openinfra:users"}}, "req-deny")
	assertEKSErrorType(t, w, http.StatusForbidden, "AccessDeniedException")
}

func TestEKS_AuthzGateDenies_ListClusters(t *testing.T) {
	h := newEKSTestHandler(false)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("GET", "/clusters"),
		iam.Claims{Sub: "nobody", Groups: []string{"openinfra:users"}}, "req-deny-list")
	assertEKSErrorType(t, w, http.StatusForbidden, "AccessDeniedException")
}

// --- honest refusals ---

func TestEKS_CreateClusterRefused(t *testing.T) {
	h := newEKSTestHandler(true)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("POST", "/clusters"), eksClaims(), "req-create")
	assertEKSErrorType(t, w, http.StatusBadRequest, "InvalidRequestException")
	if msg := eksErrorMessage(t, w); !strings.Contains(msg, "CreateCluster") {
		t.Fatalf("refusal message %q must name the op CreateCluster", msg)
	}
}

func TestEKS_CreateNodegroupRefused(t *testing.T) {
	h := newEKSTestHandler(true)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("POST", "/clusters/open-infra/node-groups"), eksClaims(), "req-ng")
	assertEKSErrorType(t, w, http.StatusBadRequest, "InvalidRequestException")
	if msg := eksErrorMessage(t, w); !strings.Contains(msg, "CreateNodegroup") {
		t.Fatalf("refusal message %q must name the op CreateNodegroup", msg)
	}
}

// A refusal is a flat capability statement — it happens BEFORE the authz gate, so an unauthorized caller
// still gets the honest "not supported", never a misleading AccessDenied.
func TestEKS_RefusalPrecedesAuthz(t *testing.T) {
	h := newEKSTestHandler(false) // SAR denies
	w := httptest.NewRecorder()
	h.serve(w, eksReq("POST", "/clusters"),
		iam.Claims{Sub: "nobody", Groups: []string{"openinfra:users"}}, "req-ref-authz")
	assertEKSErrorType(t, w, http.StatusBadRequest, "InvalidRequestException")
}

func TestEKS_RefusedSubresources(t *testing.T) {
	cases := []struct {
		method, path, wantOp string
	}{
		{"DELETE", "/clusters/open-infra", "DeleteCluster"},
		{"POST", "/clusters/open-infra/updates", "UpdateClusterVersion"},
		{"POST", "/clusters/open-infra/update-config", "UpdateClusterConfig"},
		{"DELETE", "/clusters/open-infra/node-groups/ng-1", "DeleteNodegroup"},
		{"POST", "/clusters/open-infra/fargate-profiles", "CreateFargateProfile"},
		{"GET", "/clusters/open-infra/fargate-profiles", "ListFargateProfiles"},
		{"POST", "/clusters/open-infra/addons", "CreateAddon"},
		{"GET", "/clusters/open-infra/access-entries", "ListAccessEntries"},
		{"POST", "/clusters/open-infra/identity-provider-configs/associate", "AssociateIdentityProviderConfig"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			h := newEKSTestHandler(true)
			w := httptest.NewRecorder()
			h.serve(w, eksReq(c.method, c.path), eksClaims(), "req-ref")
			assertEKSErrorType(t, w, http.StatusBadRequest, "InvalidRequestException")
			if msg := eksErrorMessage(t, w); !strings.Contains(msg, c.wantOp) {
				t.Fatalf("refusal message %q must name the op %q", msg, c.wantOp)
			}
		})
	}
}

// --- honest node-group answers (empty / not-found, not refusals) ---

func TestEKS_ListNodegroupsEmpty(t *testing.T) {
	h := newEKSTestHandler(true)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("GET", "/clusters/open-infra/node-groups"), eksClaims(), "req-lng")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Nodegroups []string `json:"nodegroups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.Nodegroups) != 0 {
		t.Fatalf("nodegroups=%+v want empty", resp.Nodegroups)
	}
	// Must be an empty ARRAY, not null — tooling that iterates it would NPE on null.
	if !strings.Contains(w.Body.String(), `"nodegroups":[]`) {
		t.Fatalf("body %s should carry an empty array, not null", w.Body.String())
	}
}

func TestEKS_DescribeNodegroupNotFound(t *testing.T) {
	h := newEKSTestHandler(true)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("GET", "/clusters/open-infra/node-groups/ng-1"), eksClaims(), "req-dng")
	assertEKSErrorType(t, w, http.StatusNotFound, "ResourceNotFoundException")
}

// --- unknown path ---

func TestEKS_UnknownPath(t *testing.T) {
	h := newEKSTestHandler(true)
	w := httptest.NewRecorder()
	h.serve(w, eksReq("GET", "/clusters/open-infra/widgets"), eksClaims(), "req-unk")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404; body=%s", w.Code, w.Body.String())
	}
	if msg := eksErrorMessage(t, w); !strings.Contains(msg, "not implemented") {
		t.Fatalf("unknown-path message %q must say not implemented", msg)
	}
}

// --- resolver table (method+path -> op, category) ---

func TestEKS_ResolveTable(t *testing.T) {
	cases := []struct {
		method, path string
		wantOp       string
		wantCat      eksCategory
	}{
		{"GET", "/clusters", "ListClusters", eksRead},
		{"POST", "/clusters", "CreateCluster", eksRefused},
		{"GET", "/clusters/open-infra", "DescribeCluster", eksRead},
		{"DELETE", "/clusters/open-infra", "DeleteCluster", eksRefused},
		{"GET", "/clusters/open-infra/node-groups", "ListNodegroups", eksRead},
		{"POST", "/clusters/open-infra/node-groups", "CreateNodegroup", eksRefused},
		{"GET", "/clusters/open-infra/node-groups/ng-1", "DescribeNodegroup", eksRead},
		{"POST", "/clusters/open-infra/node-groups/ng-1/update-version", "UpdateNodegroupVersion", eksRefused},
		{"POST", "/clusters/open-infra/addons/vpc-cni/update", "UpdateAddon", eksRefused},
		{"GET", "/widgets", "", eksUnknown},
		{"PUT", "/clusters/open-infra", "", eksUnknown},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			got := resolveEKS(eksReq(c.method, c.path))
			if got.op != c.wantOp || got.cat != c.wantCat {
				t.Fatalf("resolveEKS(%s %s) = (op=%q cat=%d) want (op=%q cat=%d)",
					c.method, c.path, got.op, got.cat, c.wantOp, c.wantCat)
			}
		})
	}
}
