package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

// buildImportResp is the report logic; test it directly across the shapes ImportAWS produces.
func TestBuildImportResp(t *testing.T) {
	// Clean translate: concrete action on a concrete resource — 1 translated, nothing refused/broad.
	stmts, refused, err := policyengine.ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::assets/*"}]}`)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}
	r := buildImportResp(stmts, refused)
	if !r.Faithful || r.Summary.Translated != 1 || r.Summary.Refused != 0 || r.Summary.NeedsReview != 0 {
		t.Fatalf("clean import: got %+v", r.Summary)
	}
	if len(r.Translated) != 1 || r.Translated[0].Effect != "Allow" ||
		len(r.Translated[0].Resources) != 1 || r.Translated[0].Resources[0] != "Bucket::assets" {
		t.Fatalf("clean import translated wrong: %+v", r.Translated)
	}
	if r.Translated[0].Broad {
		t.Error("concrete grant must not be flagged broad")
	}

	// Refusal: an action with no open-infra data plane is refused, not silently dropped, and faithful=false.
	stmts, refused, _ = policyengine.ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"ec2:StartInstances","Resource":"*"}]}`)
	r = buildImportResp(stmts, refused)
	if r.Faithful {
		t.Error("a refusal must make faithful=false")
	}
	if r.Summary.Translated != 0 || r.Summary.Refused == 0 {
		t.Fatalf("refusal summary wrong: %+v", r.Summary)
	}

	// Wildcard grant: honored faithfully but flagged broad + needs-review.
	stmts, refused, _ = policyengine.ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	r = buildImportResp(stmts, refused)
	if !r.Faithful || r.Summary.Translated != 1 || r.Summary.NeedsReview != 1 {
		t.Fatalf("wildcard summary wrong: %+v", r.Summary)
	}
	if !r.Translated[0].Broad {
		t.Error("wildcard grant must be flagged broad")
	}

	// An aws:SourceIp condition must translate and marshal with the LOWERCASE keys the XRD requires
	// (key/cidr/negate), or a copied/merged statement would fail CR validation.
	stmts, refused, err = policyengine.ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::assets/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
	if err != nil || len(stmts) != 1 {
		t.Fatalf("sourceIp import: err=%v stmts=%d", err, len(stmts))
	}
	r = buildImportResp(stmts, refused)
	b, _ := json.Marshal(r)
	for _, want := range []string{`"key":"sourceIp"`, `"cidr":"10.0.0.0/8"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("ipConditions must marshal lowercase; missing %s in %s", want, b)
		}
	}

	// Empty inputs must marshal as [] not null, so the UI never sees a null column.
	r = buildImportResp(nil, nil)
	b, _ = json.Marshal(r)
	for _, field := range []string{`"translated":[]`, `"refused":[]`, `"needsReview":[]`} {
		if !bytes.Contains(b, []byte(field)) {
			t.Errorf("empty report should contain %s; got %s", field, b)
		}
	}
}

func doImport(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	auth := &authStore{mode: "none"}
	h := handleIAMImport(nil, auth, testLogger())
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/iam/import", &buf)
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec
}

func TestHandleIAMImport(t *testing.T) {
	// A valid document with a refusal returns 200 (refusals are the point, not an error).
	rec := doImport(t, importReq{PolicyDocument: `{"Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::assets/*"},
		{"Effect":"Allow","Action":"ec2:StartInstances","Resource":"*"}]}`})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid doc: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var resp importResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Faithful {
		t.Error("doc with an ec2 action must not be faithful")
	}
	if resp.Summary.Translated != 1 || resp.Summary.Refused == 0 {
		t.Fatalf("summary wrong: %+v", resp.Summary)
	}

	// A document-level parse failure is a 400, distinct from a refusal.
	if rec := doImport(t, importReq{PolicyDocument: "{not valid json"}); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed policy doc: want 400, got %d", rec.Code)
	}
	// A bad Effect is a document error → 400.
	if rec := doImport(t, importReq{PolicyDocument: `{"Statement":[{"Effect":"Maybe","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad Effect: want 400, got %d", rec.Code)
	}
	// An empty policyDocument is a 400 with guidance.
	if rec := doImport(t, importReq{PolicyDocument: "   "}); rec.Code != http.StatusBadRequest {
		t.Errorf("empty policyDocument: want 400, got %d", rec.Code)
	}
}
