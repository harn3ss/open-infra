package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/awssig"
)

// emptyPayloadSHA256 is sha256("") — what an S3 client sends in x-amz-content-sha256 for a
// bodyless request (GET/HEAD/DELETE).
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type fakeKeys map[string]awskeys.Key

func (f fakeKeys) Lookup(_ context.Context, id string) (awskeys.Key, bool) {
	k, ok := f[id]
	return k, ok
}

// signedRequest builds a request signed with SigV4 exactly as a real client would, using the
// package's own Sign (vector-anchored), so authenticate exercises the true verification path.
func signedRequest(t *testing.T, accessKeyID, secretKey string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "http://s3.local/my-bucket/obj.txt", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	cred := awssig.Credential{
		AccessKeyID:   accessKeyID,
		Date:          "20150830",
		Region:        "us-east-1",
		Service:       "s3",
		SignedHeaders: []string{"host", "x-amz-content-sha256", "x-amz-date"},
	}
	sig, err := awssig.Sign(req, cred, secretKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKeyID+
		"/20150830/us-east-1/s3/aws4_request, "+
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+sig)
	return req
}

func TestAuthenticate(t *testing.T) {
	const id, secret, owner = "OIAKEXAMPLE000000000", "the-real-secret", "alice"
	keys := fakeKeys{id: {AccessKeyID: id, SecretKey: secret, Owner: owner}}
	resolveOK := func(_ context.Context, o string) ([]string, bool) {
		return []string{"openinfra:powerusers", "openinfra:users"}, o == owner
	}

	t.Run("valid key + valid signature + resolvable owner", func(t *testing.T) {
		a := &authenticator{keys: keys, resolve: resolveOK}
		claims, err := a.authenticate(context.Background(), signedRequest(t, id, secret))
		if err != nil {
			t.Fatalf("expected auth success, got %v", err)
		}
		if claims.Sub != owner || len(claims.Groups) != 2 {
			t.Fatalf("wrong claims: %+v", claims)
		}
	})

	// The "prove the no" battery — every failure must collapse to errAuth, indistinguishably.
	t.Run("unknown access key", func(t *testing.T) {
		a := &authenticator{keys: fakeKeys{}, resolve: resolveOK}
		if _, err := a.authenticate(context.Background(), signedRequest(t, id, secret)); err != errAuth {
			t.Fatalf("unknown key must be errAuth, got %v", err)
		}
	})
	t.Run("valid key but wrong signature (attacker names a key)", func(t *testing.T) {
		// The request is signed with the WRONG secret; the store holds the real one.
		a := &authenticator{keys: keys, resolve: resolveOK}
		bad := signedRequest(t, id, "attacker-guessed-secret")
		if _, err := a.authenticate(context.Background(), bad); err != errAuth {
			t.Fatalf("wrong signature must be errAuth, got %v", err)
		}
	})
	t.Run("owner no longer resolvable (user deleted/disabled)", func(t *testing.T) {
		resolveNone := func(context.Context, string) ([]string, bool) { return nil, false }
		a := &authenticator{keys: keys, resolve: resolveNone}
		if _, err := a.authenticate(context.Background(), signedRequest(t, id, secret)); err != errAuth {
			t.Fatalf("unresolvable owner must be errAuth, got %v", err)
		}
	})
	t.Run("no Authorization header", func(t *testing.T) {
		a := &authenticator{keys: keys, resolve: resolveOK}
		req, _ := http.NewRequest("GET", "http://s3.local/b/k", nil)
		if _, err := a.authenticate(context.Background(), req); err != errAuth {
			t.Fatalf("missing header must be errAuth, got %v", err)
		}
	})
}

func TestDecodeS3(t *testing.T) {
	cases := []struct {
		method, path string
		wantKind     string
		wantWrite    bool
		wantOK       bool
	}{
		{"GET", "/", "list-buckets", false, true},
		{"GET", "/my-bucket", "list-objects", false, true},
		{"HEAD", "/my-bucket", "head-bucket", false, true},
		{"GET", "/my-bucket/path/to/obj.txt", "get", false, true},
		{"HEAD", "/my-bucket/obj", "head", false, true},
		{"PUT", "/my-bucket/obj", "put", true, true},
		{"DELETE", "/my-bucket/obj", "delete", true, true},
		{"POST", "/my-bucket/obj", "", false, false}, // multipart/POST not implemented in v1
		{"PATCH", "/my-bucket", "", false, false},    // not an S3 verb
		{"DELETE", "/", "", false, false},            // delete-all-buckets is nonsense
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, "http://s3.local"+c.path, nil)
		op, ok := decodeS3(req)
		if ok != c.wantOK {
			t.Errorf("%s %s: ok=%v want %v", c.method, c.path, ok, c.wantOK)
			continue
		}
		if ok && (op.kind != c.wantKind || op.write != c.wantWrite) {
			t.Errorf("%s %s: got kind=%q write=%v want kind=%q write=%v",
				c.method, c.path, op.kind, op.write, c.wantKind, c.wantWrite)
		}
	}
}

func TestDecodeS3_ObjectKeyWithSlashes(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://s3.local/bucket/a/b/c.txt", nil)
	op, ok := decodeS3(req)
	if !ok || op.bucket != "bucket" || op.key != "a/b/c.txt" {
		t.Fatalf("nested key mis-decoded: %+v ok=%v", op, ok)
	}
}

func TestWriteS3Error(t *testing.T) {
	t.Run("known code carries S3 status + Code", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeS3Error(w, "NoSuchKey", "req-123", "/bucket/missing")
		if w.Code != http.StatusNotFound {
			t.Fatalf("status=%d want 404", w.Code)
		}
		if got := w.Header().Get("x-amz-request-id"); got != "req-123" {
			t.Fatalf("request id header=%q", got)
		}
		var body s3ErrorBody
		if err := xml.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("error body is not valid XML an SDK could parse: %v", err)
		}
		if body.Code != "NoSuchKey" || body.RequestID != "req-123" {
			t.Fatalf("bad error body: %+v", body)
		}
	})
	t.Run("unknown code degrades to InternalError 500", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeS3Error(w, "SomethingWeird", "r", "/x")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d want 500", w.Code)
		}
		var body s3ErrorBody
		_ = xml.Unmarshal(w.Body.Bytes(), &body)
		if body.Code != "InternalError" {
			t.Fatalf("want InternalError, got %q", body.Code)
		}
	})
}

func TestQuoteETag(t *testing.T) {
	for _, in := range []string{"abc123", `"abc123"`} {
		if got := quoteETag(in); got != `"abc123"` {
			t.Fatalf("quoteETag(%q)=%q want %q", in, got, `"abc123"`)
		}
	}
}
