package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
)

// The S3 front door authorizes an object operation on the object it acts on (Bucket::<bucket>/<key>) and a
// bucket operation on the bucket, as AWS does; platform buckets are admin-only. Each test sends the
// mismatched pair — an allowed bucket or object with a disallowed key, copy source, or caller — and checks
// the disallowed half is refused.

var assumedApp = iam.Claims{Sub: "assumed-role/" + ecrTestRole + "/s", AssumedRole: ecrTestRole}

// allowAllSAR is an S3 front door whose coarse reviews all allow (a poweruser's), so the data-plane
// policy and the fence decide.
func allowAllSAR() *s3Handler {
	return &s3Handler{cs: csWithSARFunc(func(*authzv1.ResourceAttributes) bool { return true }), authzNS: "default", logger: discardLogger()}
}

func s3Allowed(h *s3Handler, c iam.Claims, op s3op) bool {
	return h.allowed(httptest.NewRequest(http.MethodGet, "/", nil), c, op)
}

// An object-prefix grant reaches only the keys under it: another key in the same bucket, and the bucket
// itself (ListBucket), are refused — for an assumed role (its policies are its whole authority) and for a
// User (whose S3 policy tightens the coarse grant).
func TestS3Authz_ObjectPrefixGrantReachesOnlyItsKeys(t *testing.T) {
	grant := dpAllow([]string{"s3:GetObject", "s3:PutObject", "s3:ListBucket"}, "Bucket::b/public/*")
	for _, tc := range []struct {
		name   string
		claims iam.Claims
		h      func() *s3Handler
	}{
		{"assumed role", assumedApp, func() *s3Handler { h := allowAllSAR(); h.authz = roleChecker(grant); return h }},
		{"user", testUser, func() *s3Handler { h := allowAllSAR(); h.authz = userPolicy(grant); return h }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.h()
			for _, c := range []struct {
				op   s3op
				want bool
			}{
				{s3op{kind: "get", bucket: "b", key: "public/a.png"}, true},
				{s3op{kind: "put", bucket: "b", key: "public/new.png", write: true}, true},
				{s3op{kind: "get", bucket: "b", key: "private/a.png"}, false},
				{s3op{kind: "put", bucket: "b", key: "private/a.png", write: true}, false},
				{s3op{kind: "get", bucket: "b", key: "publicity.png"}, false},
				{s3op{kind: "get", bucket: "other", key: "public/a.png"}, false},
				{s3op{kind: "list-objects", bucket: "b"}, false}, // ListBucket is on the bucket, not its objects
			} {
				if got := s3Allowed(h, tc.claims, c.op); got != c.want {
					t.Errorf("%s %s/%s: allowed=%v, want %v", c.op.kind, c.op.bucket, c.op.key, got, c.want)
				}
			}
		})
	}
}

// A whole-bucket grant keeps covering the bucket's objects, so existing policies keep their meaning.
func TestS3Authz_BucketGrantCoversItsObjects(t *testing.T) {
	h := allowAllSAR()
	h.authz = roleChecker(dpAllow([]string{"s3:GetObject", "s3:ListBucket"}, "Bucket::b"))
	for _, c := range []struct {
		op   s3op
		want bool
	}{
		{s3op{kind: "get", bucket: "b", key: "any/key"}, true},
		{s3op{kind: "list-objects", bucket: "b"}, true},
		{s3op{kind: "get", bucket: "b2", key: "any/key"}, false},
	} {
		if got := s3Allowed(h, assumedApp, c.op); got != c.want {
			t.Errorf("%s %s/%s: allowed=%v, want %v", c.op.kind, c.op.bucket, c.op.key, got, c.want)
		}
	}
}

// A copy reads its source as the source object: a caller who may write the destination but not read the
// source key is refused, and so is one who may read the source but not write that destination.
func TestS3Authz_CopySourceIsCheckedAsItsObject(t *testing.T) {
	h := allowAllSAR()
	h.authz = roleChecker(
		dpAllow([]string{"s3:PutObject"}, "Bucket::b/out/*"),
		dpAllow([]string{"s3:GetObject"}, "Bucket::b/public/*"))
	copyReq := func(dest, src string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/b/"+dest, nil)
		r.Header.Set("x-amz-copy-source", "/b/"+src)
		w := httptest.NewRecorder()
		h.serve(w, r, assumedApp, "req-1")
		return w
	}
	if w := copyReq("out/x", "private/secret"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Errorf("copy from a source key outside the grant: %d %s, want 403 AccessDenied", w.Code, w.Body)
	}
	if w := copyReq("elsewhere/x", "public/src"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Errorf("copy to a destination outside the grant: %d %s, want 403 AccessDenied", w.Code, w.Body)
	}
	// The allowed pair passes both checks (the copy itself is MinIO's).
	if !s3Allowed(h, assumedApp, s3op{kind: "get", bucket: "b", key: "public/src"}) ||
		!s3Allowed(h, assumedApp, s3op{kind: "copy-object", bucket: "b", key: "out/x", write: true}) {
		t.Error("copy public/src -> out/x must be allowed")
	}
}

// DeleteObjects authorizes each key on its own object: a grant on a prefix deletes the keys under it, and
// a key outside it is that key's AccessDenied, never sent to MinIO.
func TestS3DeleteObjects_EachKeyIsItsOwnObject(t *testing.T) {
	f := newFakeMultiDeleteS3()
	f.buckets["data"] = map[string]bool{"tmp/a": true, "keep/b": true}
	h := multiDeleteMinio(t, f)
	h.authz = roleChecker(dpAllow([]string{"s3:DeleteObject"}, "Bucket::data/tmp/*"))
	w, res := serveDelete(h, "role", "data", deleteDoc(false, delObj{"tmp/a", ""}, delObj{"keep/b", ""}), nil)
	if w.Code != 200 {
		t.Fatalf("DeleteObjects = %d %s", w.Code, w.Body)
	}
	if len(res.Deleted) != 1 || res.Deleted[0].Key != "tmp/a" {
		t.Errorf("Deleted = %+v, want tmp/a", res.Deleted)
	}
	if len(res.Errors) != 1 || res.Errors[0].Key != "keep/b" || res.Errors[0].Code != "AccessDenied" {
		t.Errorf("Errors = %+v, want keep/b AccessDenied", res.Errors)
	}
	if fmt.Sprint(f.asked) != "[tmp/a]" {
		t.Errorf("MinIO was asked to delete %v, want only tmp/a", f.asked)
	}
}

// Platform buckets (backups, the audit trail, snapshots, the registry, the warehouse) are reachable by an
// administrator only, whatever a policy grants: a User allowed s3:* on every resource, and an assumed role
// with the same grant, are refused there and keep their access elsewhere.
func TestS3Authz_PlatformBucketsAreAdminOnly(t *testing.T) {
	everything := dpAllow([]string{"s3:*"}, "*")
	admin := iam.Claims{Sub: "ops", Groups: []string{"openinfra:admins", "openinfra:users"}}
	user := allowAllSAR()
	user.authz = userPolicy(everything)
	role := allowAllSAR()
	role.authz = roleChecker(everything)
	for _, b := range platformBuckets {
		get := s3op{kind: "get", bucket: b, key: "k"}
		if s3Allowed(user, testUser, get) {
			t.Errorf("a non-admin User read %s/k", b)
		}
		if s3Allowed(role, assumedApp, get) {
			t.Errorf("an assumed role read %s/k", b)
		}
		if s3Allowed(user, testUser, s3op{kind: "list-objects", bucket: b}) {
			t.Errorf("a non-admin User listed %s", b)
		}
		if !s3Allowed(user, admin, get) {
			t.Errorf("an admin was refused %s/k", b)
		}
	}
	// The copy source is fenced too: a copy out of a platform bucket into the caller's own.
	r := httptest.NewRequest(http.MethodPut, "/mine/stolen", nil)
	r.Header.Set("x-amz-copy-source", "/db-snapshots/dump.sql")
	w := httptest.NewRecorder()
	user.serve(w, r, testUser, "req-1")
	if w.Code != http.StatusForbidden {
		t.Errorf("copy out of a platform bucket: %d %s, want 403", w.Code, w.Body)
	}
	if !s3Allowed(user, testUser, s3op{kind: "get", bucket: "mine", key: "k"}) {
		t.Error("the User's own bucket must stay reachable")
	}
}

// Changing an object's tags is a write: a reader (get/list only) may read tags but not set or remove them.
func TestS3Authz_ObjectTaggingIsAWrite(t *testing.T) {
	h := &s3Handler{cs: readerSAR(), authzNS: "default", logger: discardLogger()}
	reader := iam.Claims{Sub: "viewer", Role: "readonly"}
	if !s3Allowed(h, reader, s3op{kind: "get-object-tagging", bucket: "b", key: "k"}) {
		t.Error("a reader must be able to read tags")
	}
	for _, kind := range []string{"put-object-tagging", "delete-object-tagging"} {
		if s3Allowed(h, reader, s3op{kind: kind, bucket: "b", key: "k", write: true}) {
			t.Errorf("a reader was allowed %s", kind)
		}
	}
}

// A TemplateURL is read with the same check: a non-admin cannot read a template out of a platform bucket,
// and an object-prefix grant reaches only its keys.
func TestCFN_TemplateURLReadIsTheS3Check(t *testing.T) {
	s3h := allowAllSAR()
	h := &cfnDoorway{s3: s3h, authz: roleChecker(dpAllow([]string{"s3:GetObject"}, "Bucket::deploy/templates/*"))}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if denied, _ := h.s3ReadDenied(r, assumedApp, "deploy", "templates/app.yaml"); denied {
		t.Error("a template under the granted prefix must be readable")
	}
	if denied, _ := h.s3ReadDenied(r, assumedApp, "deploy", "secrets/app.yaml"); !denied {
		t.Error("a template outside the granted prefix was readable")
	}
	h.authz = userPolicy(dpAllow([]string{"s3:*"}, "*"))
	if denied, _ := h.s3ReadDenied(r, testUser, "db-snapshots", "t.yaml"); !denied {
		t.Error("a non-admin read a template out of a platform bucket")
	}
}
