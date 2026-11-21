package main

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

const allBlocked = `<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls>` +
	`<IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`

func pabBody(acls, ignore, policy, restrict string) io.Reader {
	return strings.NewReader(`<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>` + acls +
		`</BlockPublicAcls><IgnorePublicAcls>` + ignore + `</IgnorePublicAcls><BlockPublicPolicy>` + policy +
		`</BlockPublicPolicy><RestrictPublicBuckets>` + restrict + `</RestrictPublicBuckets></PublicAccessBlockConfiguration>`)
}

// GetPublicAccessBlock answers the configuration in force: a bucket without a public policy has all public
// access blocked (AWS's default for a new bucket); one whose policy allows anyone has its policy public.
func TestS3GetPublicAccessBlock(t *testing.T) {
	f := newFakeS3()
	f.buckets["data"], f.buckets["site"], f.buckets["shared"] = true, true, true
	f.policies["site"] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::site/*"}]}`
	f.policies["shared"] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"}]}`
	h := &s3Handler{mc: fakeMinio(t, f), logger: discardLogger()}
	get := func(bucket string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.getPublicAccessBlock(w, httptest.NewRequest("GET", "/"+bucket+"?publicAccessBlock", nil), s3op{bucket: bucket}, "r")
		return w
	}
	for _, b := range []string{"data", "shared"} {
		if w := get(b); w.Code != 200 || !strings.Contains(w.Body.String(), allBlocked) {
			t.Errorf("%s: GetPublicAccessBlock = %d %s, want all four true", b, w.Code, w.Body)
		}
	}
	w := get("site")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls>"+
		"<BlockPublicPolicy>false</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets>") {
		t.Errorf("a bucket with a public policy: %d %s", w.Code, w.Body)
	}
	if w := get("nope"); w.Code != 404 || !strings.Contains(w.Body.String(), "NoSuchBucket") {
		t.Errorf("a missing bucket: %d %s", w.Code, w.Body)
	}
}

// PutPublicAccessBlock accepts the configuration in force and refuses any other with the reason, never
// accepting a setting it would then ignore; DeletePublicAccessBlock is refused. Both are authorized as
// s3:PutBucketPublicAccessBlock on the bucket, a write; Get as s3:GetBucketPublicAccessBlock.
func TestS3PutDeletePublicAccessBlock(t *testing.T) {
	f := newFakeS3()
	f.buckets["data"], f.buckets["site"] = true, true
	f.policies["site"] = `{"Statement":{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::site/*"}}`
	h := &s3Handler{mc: fakeMinio(t, f), logger: discardLogger()}
	put := func(bucket string, body io.Reader) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.putPublicAccessBlock(w, httptest.NewRequest("PUT", "/"+bucket+"?publicAccessBlock", body), s3op{bucket: bucket}, "r")
		return w
	}
	if w := put("data", pabBody("true", "true", "true", "true")); w.Code != 200 {
		t.Fatalf("blocking everything on a private bucket = %d %s", w.Code, w.Body)
	}
	if w := put("data", pabBody("true", "true", "false", "true")); w.Code != 501 || !strings.Contains(w.Body.String(), "spec.policy") {
		t.Errorf("loosening a private bucket's policy setting = %d %s, want 501 with the reason", w.Code, w.Body)
	}
	if w := put("data", pabBody("false", "true", "true", "true")); w.Code != 501 || !strings.Contains(w.Body.String(), "ACLs") {
		t.Errorf("allowing public ACLs = %d %s, want 501 naming ACLs", w.Code, w.Body)
	}
	if w := put("data", strings.NewReader(`<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>`)); w.Code != 501 {
		t.Errorf("a setting left out is false, as on AWS: %d %s", w.Code, w.Body)
	}
	if w := put("site", pabBody("true", "true", "true", "true")); w.Code != 501 || !strings.Contains(w.Body.String(), "grants public access") {
		t.Errorf("blocking a public policy the platform set = %d %s, want 501 with the reason", w.Code, w.Body)
	}
	if w := put("site", pabBody("true", "true", "false", "false")); w.Code != 200 {
		t.Errorf("the public bucket's configuration in force = %d %s", w.Code, w.Body)
	}
	if w := put("data", strings.NewReader("not xml")); w.Code != 400 || !strings.Contains(w.Body.String(), "MalformedXML") {
		t.Errorf("a malformed body = %d %s", w.Code, w.Body)
	}
	if w := put("nope", pabBody("true", "true", "true", "true")); w.Code != 404 {
		t.Errorf("a missing bucket = %d %s", w.Code, w.Body)
	}
	w := httptest.NewRecorder()
	h.deletePublicAccessBlock(w, httptest.NewRequest("DELETE", "/data?publicAccessBlock", nil), s3op{bucket: "data"}, "r")
	if w.Code != 501 || !strings.Contains(w.Body.String(), "public ACLs and policies") {
		t.Errorf("DeletePublicAccessBlock = %d %s", w.Code, w.Body)
	}
	for method, want := range map[string]struct {
		kind, action string
		write        bool
	}{
		"GET":    {"get-public-access-block", "s3:GetBucketPublicAccessBlock", false},
		"PUT":    {"put-public-access-block", "s3:PutBucketPublicAccessBlock", true},
		"DELETE": {"delete-public-access-block", "s3:PutBucketPublicAccessBlock", true},
	} {
		op, ok := (&s3Handler{}).decode(httptest.NewRequest(method, "/data?publicAccessBlock", nil))
		if !ok || op.kind != want.kind || op.write != want.write || op.action() != want.action || op.onObject() {
			t.Errorf("%s ?publicAccessBlock = %+v ok=%v action %s, want %s as %s on the bucket", method, op, ok, op.action(), want.kind, want.action)
		}
	}
}

func TestPolicyIsPublic(t *testing.T) {
	for doc, want := range map[string]bool{
		``: false,
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`:                                             true,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}`:                                     true,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","*"]}}]}`:                          true,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"}}]}`:                                false,
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`: false,
		`not json`: true,
	} {
		if got := policyIsPublic(doc); got != want {
			t.Errorf("policyIsPublic(%s) = %v, want %v", doc, got, want)
		}
	}
}
