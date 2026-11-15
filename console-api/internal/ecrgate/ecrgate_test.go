package ecrgate

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

const (
	repo    = "111122223333/example/app"
	repoARN = "arn:aws:ecr:us-east-1:111122223333:repository/example/app"
	who     = "arn:aws:sts::111122223333:assumed-role/pusher/session"
	dig     = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// pushPolicy is the ECR actions of AWS's documented push policy
// (https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push-iam.html): no GetDownloadUrlForLayer.
var pushPolicy = []string{"pull", "push", BatchCheckLayerAvailability, InitiateLayerUpload, UploadLayerPart,
	CompleteLayerUpload, PutImage, BatchGetImage}

func token(t *testing.T, access ...Access) string {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{"sub": who, "access": access})
	enc := base64.RawURLEncoding.EncodeToString
	return "Bearer " + enc([]byte(`{"alg":"RS256"}`)) + "." + enc(claims) + ".c2ln"
}

func TestClassify(t *testing.T) {
	cases := []struct {
		method, path, query string
		length              int64
		repo, scope         string
		actions             []string
		mountFrom           string
	}{
		{"HEAD", "/v2/" + repo + "/blobs/" + dig, "", 0, repo, "pull", []string{BatchCheckLayerAvailability}, ""},
		{"GET", "/v2/" + repo + "/blobs/" + dig, "", 0, repo, "pull", []string{GetDownloadURLForLayer}, ""},
		{"POST", "/v2/" + repo + "/blobs/uploads/", "", 0, repo, "push", []string{InitiateLayerUpload}, ""},
		{"POST", "/v2/" + repo + "/blobs/uploads/", "digest=" + dig, 10, repo, "push",
			[]string{InitiateLayerUpload, UploadLayerPart, CompleteLayerUpload}, ""},
		{"POST", "/v2/" + repo + "/blobs/uploads/", "mount=" + dig + "&from=111122223333/other", 0, repo, "push",
			[]string{InitiateLayerUpload}, "111122223333/other"},
		{"PATCH", "/v2/" + repo + "/blobs/uploads/0f3c-a1_b.c=", "", 100, repo, "push", []string{UploadLayerPart}, ""},
		{"PUT", "/v2/" + repo + "/blobs/uploads/0f3c", "digest=" + dig, 0, repo, "push", []string{CompleteLayerUpload}, ""},
		{"PUT", "/v2/" + repo + "/blobs/uploads/0f3c", "digest=" + dig, 5, repo, "push",
			[]string{UploadLayerPart, CompleteLayerUpload}, ""},
		{"GET", "/v2/" + repo + "/blobs/uploads/0f3c", "", 0, repo, "pull", []string{UploadLayerPart}, ""},
		{"PUT", "/v2/" + repo + "/manifests/v1.2", "", 0, repo, "push", []string{PutImage}, ""},
		{"GET", "/v2/" + repo + "/manifests/latest", "", 0, repo, "pull", []string{BatchGetImage}, ""},
		{"HEAD", "/v2/" + repo + "/manifests/" + dig, "", 0, repo, "pull", []string{BatchGetImage}, ""},
		{"DELETE", "/v2/" + repo + "/manifests/" + dig, "", 0, repo, "delete", []string{BatchDeleteImage}, ""},
		{"GET", "/v2/" + repo + "/tags/list", "", 0, repo, "pull", []string{ListImages}, ""},
		{"GET", "/v2/" + repo + "/referrers/" + dig, "", 0, repo, "pull", []string{BatchGetImage}, ""},
		// a repository may have a component named like a route word; the route still decides the name
		{"GET", "/v2/a/blobs/b/manifests/latest", "", 0, "a/blobs/b", "pull", []string{BatchGetImage}, ""},
		{"HEAD", "/v2/a/manifests/b/blobs/" + dig, "", 0, "a/manifests/b", "pull", []string{BatchCheckLayerAvailability}, ""},
	}
	for _, c := range cases {
		q, _ := url.ParseQuery(c.query)
		got, ok := Classify(c.method, c.path, q, c.length)
		if !ok || got.Repo != c.repo || got.Scope != c.scope || !slices.Equal(got.Actions, c.actions) || got.MountFrom != c.mountFrom {
			t.Errorf("%s %s?%s = %+v, %v; want repo %s scope %s actions %v mount %q",
				c.method, c.path, c.query, got, ok, c.repo, c.scope, c.actions, c.mountFrom)
		}
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/v2/_catalog"},                        // ECR has no catalog
		{"DELETE", "/v2/" + repo + "/blobs/" + dig},    // nor deleting a layer
		{"GET", "/v2/Upper/manifests/latest"},          // not a repository name
		{"GET", "/v2/a/../b/manifests/latest"},         // nor this
		{"POST", "/v2/" + repo + "/manifests/latest"},  // no such method
		{"GET", "/v2/" + repo + "/blobs/not-a-digest"}, // no such route
	} {
		if got, ok := Classify(c.method, c.path, nil, 0); ok {
			t.Errorf("%s %s classified as %+v; want refused", c.method, c.path, got)
		}
	}
}

// upstream records what reached the registry.
type upstream struct {
	srv  *httptest.Server
	hits []*http.Request
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits = append(u.hits, r.Clone(r.Context()))
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func serve(t *testing.T, g *Gate, method, target, auth string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

// A principal with exactly ECR's push policy pushes, and cannot download a layer: the refusal is ECR's
// DENIED, naming the action and the repository.
func TestPushPolicyPushesButCannotDownload(t *testing.T) {
	up := newUpstream(t)
	u, _ := url.Parse(up.srv.URL)
	g := New(u)
	tok := token(t, Access{Type: "repository", Name: repo, Actions: pushPolicy, Requested: []string{"pull", "push"}, Resource: repoARN})

	for _, step := range []struct{ method, target string }{
		{"HEAD", "/v2/" + repo + "/blobs/" + dig},
		{"POST", "/v2/" + repo + "/blobs/uploads/"},
		{"PATCH", "/v2/" + repo + "/blobs/uploads/0f3c"},
		{"PUT", "/v2/" + repo + "/blobs/uploads/0f3c?digest=" + dig},
		{"PUT", "/v2/" + repo + "/manifests/latest"},
		{"GET", "/v2/" + repo + "/manifests/latest"},
	} {
		if w := serve(t, g, step.method, step.target, tok); w.Code != http.StatusAccepted {
			t.Fatalf("%s %s = %d %s; want forwarded", step.method, step.target, w.Code, w.Body)
		}
	}
	w := serve(t, g, "GET", "/v2/"+repo+"/blobs/"+dig, tok)
	if w.Code != http.StatusForbidden {
		t.Fatalf("layer download = %d; want 403", w.Code)
	}
	var body struct {
		Errors []struct{ Code, Message string }
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	want := "User: " + who + " is not authorized to perform: ecr:GetDownloadUrlForLayer on resource: " + repoARN
	if len(body.Errors) != 1 || body.Errors[0].Code != "DENIED" || body.Errors[0].Message != want {
		t.Fatalf("refusal = %s; want DENIED %q", w.Body, want)
	}
	if len(up.hits) != 6 {
		t.Fatalf("%d requests reached the registry; want the 6 allowed", len(up.hits))
	}
}

// A role allowed everything but PutImage uploads layers and is refused the manifest.
func TestManifestWriteNeedsPutImage(t *testing.T) {
	up := newUpstream(t)
	u, _ := url.Parse(up.srv.URL)
	g := New(u)
	acts := slices.DeleteFunc(slices.Clone(pushPolicy), func(a string) bool { return a == PutImage })
	tok := token(t, Access{Type: "repository", Name: repo, Actions: acts, Requested: []string{"pull", "push"}, Resource: repoARN})
	if w := serve(t, g, "POST", "/v2/"+repo+"/blobs/uploads/", tok); w.Code != http.StatusAccepted {
		t.Fatalf("upload = %d; want forwarded", w.Code)
	}
	w := serve(t, g, "PUT", "/v2/"+repo+"/manifests/latest", tok)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "ecr:PutImage") {
		t.Fatalf("manifest write = %d %s; want 403 naming ecr:PutImage", w.Code, w.Body)
	}
}

// What the token service has not decided goes to the registry, which challenges or decides it as before.
func TestUndecidedRequestsAreForwarded(t *testing.T) {
	up := newUpstream(t)
	u, _ := url.Parse(up.srv.URL)
	g := New(u)
	blob := "/v2/" + repo + "/blobs/" + dig
	for name, auth := range map[string]string{
		"no token":           "",
		"not a token":        "Bearer nope",
		"basic":              "Basic QVdTOng=",
		"another repository": token(t, Access{Type: "repository", Name: "111122223333/other", Actions: []string{"pull"}, Requested: []string{"pull"}}),
		"no decision":        token(t, Access{Type: "repository", Name: repo, Actions: []string{"pull"}}),
		"push not asked":     token(t, Access{Type: "repository", Name: repo, Actions: []string{"push", InitiateLayerUpload}, Requested: []string{"push"}}),
	} {
		up.hits = nil
		if w := serve(t, g, "GET", blob, auth); w.Code != http.StatusAccepted || len(up.hits) != 1 {
			t.Errorf("%s: %d, %d forwarded; want forwarded", name, w.Code, len(up.hits))
		}
	}
	// decided, with nothing granted: ECR's refusal, not the registry's challenge
	tok := token(t, Access{Type: "repository", Name: repo, Actions: nil, Requested: []string{"pull", "push"}, Resource: repoARN})
	if w := serve(t, g, "HEAD", blob, tok); w.Code != http.StatusForbidden {
		t.Errorf("nothing granted: %d; want 403", w.Code)
	}
}

func TestUnsupportedIsRefusedWithoutForwarding(t *testing.T) {
	up := newUpstream(t)
	u, _ := url.Parse(up.srv.URL)
	g := New(u)
	tok := token(t, Access{Type: "repository", Name: repo, Actions: []string{"pull", "push", "delete"}})
	for _, c := range []struct{ method, target string }{
		{"GET", "/v2/_catalog"},
		{"DELETE", "/v2/" + repo + "/blobs/" + dig},
	} {
		if w := serve(t, g, c.method, c.target, tok); w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d; want 404", c.method, c.target, w.Code)
		}
	}
	if len(up.hits) != 0 {
		t.Fatalf("%d unsupported requests reached the registry", len(up.hits))
	}
	for _, p := range []string{"/", "/v2/"} {
		if w := serve(t, g, "GET", p, ""); w.Code != http.StatusAccepted {
			t.Errorf("GET %s = %d; want forwarded", p, w.Code)
		}
	}
}

// A blob mount is honoured only for a caller that may download the layer from the source repository.
func TestMountNeedsDownloadOnTheSource(t *testing.T) {
	up := newUpstream(t)
	u, _ := url.Parse(up.srv.URL)
	g := New(u)
	target := "/v2/" + repo + "/blobs/uploads/?mount=" + dig + "&from=111122223333/other"
	dest := Access{Type: "repository", Name: repo, Actions: pushPolicy, Requested: []string{"pull", "push"}}

	serve(t, g, "POST", target, token(t, dest, Access{Type: "repository", Name: "111122223333/other",
		Actions: []string{"pull", BatchGetImage}, Requested: []string{"pull"}}))
	if q := up.hits[0].URL.Query(); q.Has("mount") || q.Has("from") {
		t.Fatalf("mount without download on the source kept: %s", up.hits[0].URL.RawQuery)
	}
	serve(t, g, "POST", target, token(t, dest, Access{Type: "repository", Name: "111122223333/other",
		Actions: []string{"pull", GetDownloadURLForLayer}, Requested: []string{"pull"}}))
	if q := up.hits[1].URL.Query(); q.Get("mount") != dig || q.Get("from") != "111122223333/other" {
		t.Fatalf("mount with download on the source dropped: %s", up.hits[1].URL.RawQuery)
	}
}

// The registry builds upload URLs from the client's Host and scheme, so both reach it unchanged.
func TestHostAndSchemeReachTheRegistry(t *testing.T) {
	up := newUpstream(t)
	u, _ := url.Parse(up.srv.URL)
	g := New(u)
	r := httptest.NewRequest("POST", "/v2/"+repo+"/blobs/uploads/", nil)
	r.Host = "registry.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	g.ServeHTTP(httptest.NewRecorder(), r)
	if len(up.hits) != 1 || up.hits[0].Host != "registry.example.com" || up.hits[0].Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("registry saw host %q proto %q", up.hits[0].Host, up.hits[0].Header.Get("X-Forwarded-Proto"))
	}
}
