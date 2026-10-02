package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// --- fixtures ---

// ecrCS is csWithSAR plus any seeded objects (e.g. the registry-auth Secret).
func ecrCS(allowed bool, objs ...runtime.Object) *fake.Clientset {
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allowed}}, nil
	})
	return cs
}

func ecrSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ecr-registry-auth", Namespace: "default"},
		Data:       map[string][]byte{"username": []byte("user"), "password": []byte("pass")},
	}
}

func newECRTestHandler(cs kubernetes.Interface, registryURL string) *ecrHandler {
	return newECRHandler(cs, "default", "open-infra", "us-east-1", "default", registryURL,
		"http://ecr-registry.open-infra-ecr:5000", "ecr-registry-auth", discardLogger())
}

func ecrClaims() iam.Claims {
	return iam.Claims{Sub: "erin", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
}

func ecrRequest(target, body string) *http.Request {
	req := httptest.NewRequest("POST", "http://ecr/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", ecrTargetPrefix+"."+target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	return req
}

func ecrErrorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not valid JSON: %v (%s)", err, w.Body.String())
	}
	return body.Message
}

// fakeRegistry serves a minimal Distribution /v2 surface for one repo: tags/list, manifest GET (by tag or
// digest, with a Docker-Content-Digest header and a small image manifest body), and a 202 manifest DELETE.
func fakeRegistry(repo string, tagDigest map[string]string) *httptest.Server {
	const manifest = `{"config":{"size":10},"layers":[{"size":20}]}` // config+layers sum = 30
	digests := map[string]bool{}
	for _, d := range tagDigest {
		digests[d] = true
	}
	base := "/v2/" + repo
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base+"/tags/list":
			tags := []string{}
			for tg := range tagDigest {
				tags = append(tags, tg)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": tags})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"/manifests/"):
			ref := strings.TrimPrefix(r.URL.Path, base+"/manifests/")
			d, ok := tagDigest[ref]
			if !ok && digests[ref] {
				d, ok = ref, true
			}
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Docker-Content-Digest", d)
			_, _ = w.Write([]byte(manifest))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"/manifests/"):
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
}

// --- doorway tests ---

// GetAuthorizationToken returns a base64 token that decodes to "<user>:<pass>" (the credential read from
// the Secret) plus the configured proxyEndpoint — exactly what `docker login -u AWS` consumes.
func TestECR_GetAuthorizationToken(t *testing.T) {
	h := newECRTestHandler(ecrCS(true, ecrSecret()), "")
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("GetAuthorizationToken", `{}`), ecrClaims(), "req-tok")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		AuthorizationData []struct {
			AuthorizationToken string  `json:"authorizationToken"`
			ExpiresAt          float64 `json:"expiresAt"`
			ProxyEndpoint      string  `json:"proxyEndpoint"`
		} `json:"authorizationData"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.AuthorizationData) != 1 {
		t.Fatalf("authorizationData len=%d want 1", len(resp.AuthorizationData))
	}
	raw, err := base64.StdEncoding.DecodeString(resp.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		t.Fatalf("token is not base64: %v", err)
	}
	if string(raw) != "user:pass" {
		t.Fatalf("decoded token = %q want %q", string(raw), "user:pass")
	}
	if resp.AuthorizationData[0].ProxyEndpoint != "http://ecr-registry.open-infra-ecr:5000" {
		t.Fatalf("proxyEndpoint = %q", resp.AuthorizationData[0].ProxyEndpoint)
	}
	if resp.AuthorizationData[0].ExpiresAt <= 0 {
		t.Fatalf("expiresAt = %v want a positive epoch", resp.AuthorizationData[0].ExpiresAt)
	}
}

// The coarse authorization gate denies before any work when the caller cannot act — the same impersonated
// SubjectAccessReview every front door funnels through (mirrors TestECS_AuthzGateDenies).
func TestECR_AuthzGateDenies(t *testing.T) {
	h := newECRTestHandler(ecrCS(false), "")
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("CreateRepository", `{"repositoryName":"team/app"}`),
		iam.Claims{Sub: "nobody", Groups: []string{"openinfra:users"}}, "req-deny")
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
}

func TestECR_CreateRepositoryRejectsInvalidName(t *testing.T) {
	h := newECRTestHandler(ecrCS(true), "")
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("CreateRepository", `{"repositoryName":"Invalid Name"}`), ecrClaims(), "req-bad")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidParameterException")
}

func TestECR_CreateRepositoryAcceptsValidName(t *testing.T) {
	h := newECRTestHandler(ecrCS(true), "")
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("CreateRepository", `{"repositoryName":"team/app"}`), ecrClaims(), "req-ok")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Repository struct {
			RepositoryName     string  `json:"repositoryName"`
			RepositoryArn      string  `json:"repositoryArn"`
			RepositoryURI      string  `json:"repositoryUri"`
			RegistryID         string  `json:"registryId"`
			ImageTagMutability string  `json:"imageTagMutability"`
			CreatedAt          float64 `json:"createdAt"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.Repository.RepositoryName != "team/app" {
		t.Fatalf("repositoryName = %q", resp.Repository.RepositoryName)
	}
	if resp.Repository.RepositoryArn != "arn:aws:ecr:us-east-1:open-infra:repository/team/app" {
		t.Fatalf("repositoryArn = %q", resp.Repository.RepositoryArn)
	}
	if resp.Repository.RepositoryURI != "ecr-registry.open-infra-ecr:5000/team/app" {
		t.Fatalf("repositoryUri = %q", resp.Repository.RepositoryURI)
	}
	if resp.Repository.ImageTagMutability != "MUTABLE" {
		t.Fatalf("imageTagMutability = %q want MUTABLE (default)", resp.Repository.ImageTagMutability)
	}
	if resp.Repository.RegistryID != "open-infra" {
		t.Fatalf("registryId = %q", resp.Repository.RegistryID)
	}
}

func TestECR_CreateRepositoryAlreadyExists(t *testing.T) {
	h := newECRTestHandler(ecrCS(true), "")
	first := httptest.NewRecorder()
	h.serve(first, ecrRequest("CreateRepository", `{"repositoryName":"team/app"}`), ecrClaims(), "req-1")
	if first.Code != http.StatusOK {
		t.Fatalf("first create status=%d want 200; body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	h.serve(second, ecrRequest("CreateRepository", `{"repositoryName":"team/app"}`), ecrClaims(), "req-2")
	assertECSErrorType(t, second, http.StatusBadRequest, "RepositoryAlreadyExistsException")
}

// A deliberately-refused op returns InvalidParameterException naming the op (honest, never faked).
func TestECR_RefusedOp(t *testing.T) {
	h := newECRTestHandler(ecrCS(true), "")
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("PutLifecyclePolicy", `{"repositoryName":"team/app"}`), ecrClaims(), "req-ref")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidParameterException")
	if msg := ecrErrorMessage(t, w); !strings.Contains(msg, "PutLifecyclePolicy") {
		t.Fatalf("refusal message should name the op; got %q", msg)
	}
}

// An unknown op is refused as not-implemented, never faked.
func TestECR_UnknownOp(t *testing.T) {
	h := newECRTestHandler(ecrCS(true), "")
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("FloobRepository", `{}`), ecrClaims(), "req-unk")
	assertECSErrorType(t, w, http.StatusBadRequest, "InvalidParameterException")
	if msg := ecrErrorMessage(t, w); !strings.Contains(msg, "not implemented") {
		t.Fatalf("unknown-op message should say not implemented; got %q", msg)
	}
}

func TestECR_RepoURIAndArnFormatting(t *testing.T) {
	h := newECRTestHandler(ecrCS(true), "")
	if got := h.repoArn("team/app"); got != "arn:aws:ecr:us-east-1:open-infra:repository/team/app" {
		t.Fatalf("repoArn = %q", got)
	}
	if got := h.repoURI("team/app"); got != "ecr-registry.open-infra-ecr:5000/team/app" {
		t.Fatalf("repoURI = %q", got)
	}
}

// Two distinct repo names that sanitize to the same fragment must not alias: each resolves to its own
// record, and a third unseen name that also sanitizes alike is simply not found.
func TestECR_SanitizeCollisionGuard(t *testing.T) {
	h := newECRTestHandler(ecrCS(true), "")
	ctx := context.Background()
	if err := h.putRepo(ctx, ecrRepoRecord{RepositoryName: "my/repo", ImageTagMutability: "MUTABLE", CreatedAt: 1}); err != nil {
		t.Fatalf("putRepo my/repo: %v", err)
	}
	if err := h.putRepo(ctx, ecrRepoRecord{RepositoryName: "my-repo", ImageTagMutability: "IMMUTABLE", CreatedAt: 2}); err != nil {
		t.Fatalf("putRepo my-repo: %v", err)
	}
	if ecrSanitize("my/repo") != ecrSanitize("my-repo") {
		t.Fatalf("precondition: the two names should sanitize alike (got %q vs %q)", ecrSanitize("my/repo"), ecrSanitize("my-repo"))
	}
	if h.repoCMName("my/repo") == h.repoCMName("my-repo") {
		t.Fatalf("distinct names must map to distinct ConfigMap names (both %q)", h.repoCMName("my/repo"))
	}
	r1, ok1, err := h.getRepo(ctx, "my/repo")
	if err != nil || !ok1 || r1.ImageTagMutability != "MUTABLE" {
		t.Fatalf("getRepo my/repo = (%+v, %v, %v)", r1, ok1, err)
	}
	r2, ok2, err := h.getRepo(ctx, "my-repo")
	if err != nil || !ok2 || r2.ImageTagMutability != "IMMUTABLE" {
		t.Fatalf("getRepo my-repo = (%+v, %v, %v)", r2, ok2, err)
	}
	if _, ok3, _ := h.getRepo(ctx, "my.repo"); ok3 {
		t.Fatalf("getRepo my.repo must be not-found (never created)")
	}
}

// --- registry /v2 client tests ---

func TestECR_RegistryClientListTags(t *testing.T) {
	srv := fakeRegistry("foo", map[string]string{"v1": "sha256:aaa"})
	defer srv.Close()
	rc := newRegistryClient(srv.URL, "u", "p")
	tags, err := rc.listTags(context.Background(), "foo")
	if err != nil {
		t.Fatalf("listTags: %v", err)
	}
	if len(tags) != 1 || tags[0] != "v1" {
		t.Fatalf("tags = %v want [v1]", tags)
	}
	// an unknown repo (404 from the registry) is an EMPTY set, not an error.
	empty, err := rc.listTags(context.Background(), "nope")
	if err != nil || len(empty) != 0 {
		t.Fatalf("listTags(nope) = (%v, %v) want ([], nil)", empty, err)
	}
}

func TestECR_RegistryClientResolveDigest(t *testing.T) {
	srv := fakeRegistry("foo", map[string]string{"v1": "sha256:deadbeef"})
	defer srv.Close()
	rc := newRegistryClient(srv.URL, "u", "p")
	digest, size, err := rc.resolveDigest(context.Background(), "foo", "v1")
	if err != nil {
		t.Fatalf("resolveDigest: %v", err)
	}
	if digest != "sha256:deadbeef" {
		t.Fatalf("digest = %q", digest)
	}
	if size != 30 { // config(10) + layers(20)
		t.Fatalf("size = %d want 30 (config+layers)", size)
	}
	// a missing ref is the sentinel (digest=="", err==nil), not an error.
	d2, s2, err := rc.resolveDigest(context.Background(), "foo", "missing")
	if err != nil || d2 != "" || s2 != 0 {
		t.Fatalf("resolveDigest(missing) = (%q, %d, %v) want (\"\", 0, nil)", d2, s2, err)
	}
}

// --- image ops over the registry ---

func TestECR_ListImages(t *testing.T) {
	srv := fakeRegistry("team/app", map[string]string{"v1": "sha256:deadbeef"})
	defer srv.Close()
	h := newECRTestHandler(ecrCS(true, ecrSecret()), srv.URL)
	if err := h.putRepo(context.Background(), ecrRepoRecord{RepositoryName: "team/app", ImageTagMutability: "MUTABLE", CreatedAt: 1}); err != nil {
		t.Fatalf("putRepo: %v", err)
	}
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("ListImages", `{"repositoryName":"team/app"}`), ecrClaims(), "req-li")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ImageIds []struct {
			ImageDigest string `json:"imageDigest"`
			ImageTag    string `json:"imageTag"`
		} `json:"imageIds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.ImageIds) != 1 || resp.ImageIds[0].ImageDigest != "sha256:deadbeef" || resp.ImageIds[0].ImageTag != "v1" {
		t.Fatalf("imageIds = %+v", resp.ImageIds)
	}
}

func TestECR_ListImagesOnUnknownRepo(t *testing.T) {
	h := newECRTestHandler(ecrCS(true, ecrSecret()), "http://unused")
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("ListImages", `{"repositoryName":"team/nope"}`), ecrClaims(), "req-li404")
	assertECSErrorType(t, w, http.StatusBadRequest, "RepositoryNotFoundException")
}

func TestECR_DeleteRepositoryNotEmptyThenForce(t *testing.T) {
	srv := fakeRegistry("team/app", map[string]string{"v1": "sha256:deadbeef"})
	defer srv.Close()
	cs := ecrCS(true, ecrSecret())
	h := newECRTestHandler(cs, srv.URL)
	if err := h.putRepo(context.Background(), ecrRepoRecord{RepositoryName: "team/app", ImageTagMutability: "MUTABLE", CreatedAt: 1}); err != nil {
		t.Fatalf("putRepo: %v", err)
	}
	// force=false against a non-empty repo → RepositoryNotEmptyException.
	w := httptest.NewRecorder()
	h.serve(w, ecrRequest("DeleteRepository", `{"repositoryName":"team/app"}`), ecrClaims(), "req-del1")
	assertECSErrorType(t, w, http.StatusBadRequest, "RepositoryNotEmptyException")

	// force=true deletes the images and the record.
	w2 := httptest.NewRecorder()
	h.serve(w2, ecrRequest("DeleteRepository", `{"repositoryName":"team/app","force":true}`), ecrClaims(), "req-del2")
	if w2.Code != http.StatusOK {
		t.Fatalf("force delete status=%d want 200; body=%s", w2.Code, w2.Body.String())
	}
	if _, found, _ := h.getRepo(context.Background(), "team/app"); found {
		t.Fatalf("record should be gone after a forced delete")
	}
}
