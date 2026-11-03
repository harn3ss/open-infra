package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// The console's bucket browser acts to MinIO with its ServiceAccount identity, so each call must be
// authorized as the signed-in user, with the aws-shim's own check. These send the mismatched pair — a
// user allowed one bucket or key asking for another, a reader writing, a non-admin on a platform bucket —
// and check the disallowed half is refused before MinIO is touched (an allowed call reaches MinIO, which
// these tests do not run: it answers 503, never 403).

// sarByVerb answers SubjectAccessReviews: allowed when allow(verb).
func sarByVerb(allow func(verb string) bool) *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(a ktesting.Action) (bool, runtime.Object, error) {
		sar := a.(ktesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{
			Allowed: allow(sar.Spec.ResourceAttributes.Verb)}}, nil
	})
	return cs
}

// browser routes the bucket endpoints, authorized by a gate over cs and (optionally) a data-plane policy
// for User::alice.
func browser(cs *fake.Clientset, stmts ...policyengine.Statement) http.Handler {
	var checker *dataplaneauthz.Checker
	if len(stmts) > 0 {
		checker = dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
			return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::alice"}, Statements: stmts}}}, nil
		}, time.Minute)
	}
	az := &bucketAuthz{gate: s3authz.Gate{CS: cs, Authz: checker, NS: "default"}, auth: &authStore{mode: "local"}, logger: testLogger()}
	r := chi.NewRouter()
	r.Get("/buckets", handleBuckets(cs, az, testLogger()))
	r.Get("/buckets/{bucket}/objects", handleBucketObjects(cs, az, testLogger()))
	r.Post("/buckets", handleCreateBucket(cs, az, testLogger()))
	r.Delete("/buckets/{bucket}", handleDeleteBucket(cs, az, testLogger()))
	r.Put("/buckets/{bucket}/object", handleUploadObject(cs, az, testLogger()))
	r.Get("/buckets/{bucket}/object", handleDownloadObject(cs, az, testLogger()))
	r.Delete("/buckets/{bucket}/object", handleDeleteObject(cs, az, testLogger()))
	return r
}

func browse(h http.Handler, who iam.Claims, method, path, body string) int {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), ctxUser{}, sessionClaims{Claims: who}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

var (
	alice   = iam.Claims{Sub: "alice", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
	opsUser = iam.Claims{Sub: "ops", Groups: []string{"openinfra:admins", "openinfra:users"}}
	viewer  = iam.Claims{Sub: "alice", Groups: []string{"openinfra:readers", "openinfra:users"}}
)

func allVerbs(string) bool { return true }

// A user whose S3 policy grants one bucket's objects (or one prefix) is refused another bucket's, or
// another key's — the browser no longer reaches every bucket with the console's identity.
func TestBucketBrowser_AUserReachesOnlyTheirGrant(t *testing.T) {
	h := browser(sarByVerb(allVerbs),
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"}, Resources: []string{"Bucket::mine"}},
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::shared/public/*"}})
	for _, c := range []struct {
		method, path string
		denied       bool
	}{
		{"GET", "/buckets/mine/object?key=a.txt", false},
		{"GET", "/buckets/mine/objects", false},
		{"PUT", "/buckets/mine/object?key=a.txt", false},
		{"GET", "/buckets/theirs/object?key=a.txt", true},
		{"GET", "/buckets/theirs/objects", true},
		{"PUT", "/buckets/theirs/object?key=a.txt", true},
		{"DELETE", "/buckets/theirs/object?key=a.txt", true},
		{"DELETE", "/buckets/theirs", true},
		{"POST", "/buckets", true}, // s3:CreateBucket is not granted
		{"GET", "/buckets/shared/object?key=public/a.png", false},
		{"GET", "/buckets/shared/object?key=private/a.png", true},
		{"GET", "/buckets/shared/objects", true}, // the grant is on objects, not on listing the bucket
	} {
		body := ""
		if c.method == "POST" {
			body = `{"name":"newbucket"}`
		}
		code := browse(h, alice, c.method, c.path, body)
		if c.denied && code != http.StatusForbidden {
			t.Errorf("%s %s: %d, want 403", c.method, c.path, code)
		}
		if !c.denied && code == http.StatusForbidden {
			t.Errorf("%s %s: refused, want allowed", c.method, c.path)
		}
	}
}

// A reader may browse but not change anything: the coarse review is the same one the S3 API makes.
func TestBucketBrowser_AReaderCannotWrite(t *testing.T) {
	h := browser(sarByVerb(func(v string) bool { return v == "get" || v == "list" }))
	if code := browse(h, viewer, "GET", "/buckets/mine/object?key=a", ""); code == http.StatusForbidden {
		t.Error("a reader must be able to download")
	}
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/buckets/mine/object?key=a", "x"},
		{"DELETE", "/buckets/mine/object?key=a", ""},
		{"DELETE", "/buckets/mine", ""},
		{"POST", "/buckets", `{"name":"b"}`},
	} {
		if code := browse(h, viewer, c.method, c.path, c.body); code != http.StatusForbidden {
			t.Errorf("reader %s %s: %d, want 403", c.method, c.path, code)
		}
	}
}

// Platform buckets are an administrator's only, whatever a policy grants; and nobody deletes one here.
func TestBucketBrowser_PlatformBucketsAreAdminOnly(t *testing.T) {
	h := browser(sarByVerb(allVerbs), policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}})
	for _, b := range s3authz.PlatformBuckets {
		for _, p := range []string{"/buckets/" + b + "/objects", "/buckets/" + b + "/object?key=k"} {
			if code := browse(h, alice, "GET", p, ""); code != http.StatusForbidden {
				t.Errorf("non-admin GET %s: %d, want 403", p, code)
			}
			if code := browse(h, opsUser, "GET", p, ""); code == http.StatusForbidden {
				t.Errorf("admin GET %s was refused", p)
			}
		}
		if code := browse(h, alice, "PUT", "/buckets/"+b+"/object?key=k", "x"); code != http.StatusForbidden {
			t.Errorf("non-admin upload into %s: %d, want 403", b, code)
		}
		if code := browse(h, opsUser, "DELETE", "/buckets/"+b, ""); code != http.StatusForbidden {
			t.Errorf("admin DELETE platform bucket %s: %d, want 403", b, code)
		}
	}
}
