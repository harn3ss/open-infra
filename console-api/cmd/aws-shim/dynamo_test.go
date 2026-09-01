package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

func dynamoReq(target, body string) *http.Request {
	r := httptest.NewRequest("POST", "http://shim/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")
	if target != "" {
		r.Header.Set("X-Amz-Target", target)
	}
	return r
}

func decodeDynamoErr(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/x-amz-json-1.0" {
		t.Errorf("Content-Type = %q, want application/x-amz-json-1.0", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, w.Body.String())
	}
	return body
}

// A recognized, authorized operation returns an honest 501 in DynamoDB's own dialect — never a fake.
func TestDynamo_RecognizedOpIsHonest501(t *testing.T) {
	h := newDynamoHandler(csWithSAR(true), "default", discardLogger())
	w := httptest.NewRecorder()
	h.serve(w, dynamoReq("DynamoDB_20120810.GetItem", `{"TableName":"t","Key":{"id":{"S":"1"}}}`),
		iam.Claims{Sub: "tester"}, "req-1")

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
	body := decodeDynamoErr(t, w)
	if !strings.HasSuffix(body["__type"], "#NotImplementedException") {
		t.Errorf("__type = %q, want a #NotImplementedException", body["__type"])
	}
}

func TestDynamo_MissingTarget(t *testing.T) {
	h := newDynamoHandler(csWithSAR(true), "default", discardLogger())
	w := httptest.NewRecorder()
	h.serve(w, dynamoReq("", `{}`), iam.Claims{Sub: "tester"}, "r")
	if w.Code != http.StatusBadRequest || !strings.Contains(decodeDynamoErr(t, w)["__type"], "MissingAction") {
		t.Fatalf("missing X-Amz-Target should be a 400 MissingAction; got %d %s", w.Code, w.Body.String())
	}
}

func TestDynamo_UnknownOp(t *testing.T) {
	h := newDynamoHandler(csWithSAR(true), "default", discardLogger())
	w := httptest.NewRecorder()
	h.serve(w, dynamoReq("DynamoDB_20120810.Frobnicate", `{}`), iam.Claims{Sub: "tester"}, "r")
	if w.Code != http.StatusBadRequest || !strings.Contains(decodeDynamoErr(t, w)["__type"], "UnknownOperation") {
		t.Fatalf("unknown op should be a 400 UnknownOperation; got %d %s", w.Code, w.Body.String())
	}
}

// Authorization is fail-closed and precedes the not-implemented answer: a denied caller gets 403,
// not 501 (you learn you lack permission before you learn the op isn't built).
func TestDynamo_DeniedBeforeNotImplemented(t *testing.T) {
	h := newDynamoHandler(csWithSAR(false), "default", discardLogger())
	w := httptest.NewRecorder()
	h.serve(w, dynamoReq("DynamoDB_20120810.PutItem", `{"TableName":"t","Item":{}}`),
		iam.Claims{Sub: "nobody"}, "r")
	if w.Code != http.StatusForbidden || !strings.Contains(decodeDynamoErr(t, w)["__type"], "AccessDenied") {
		t.Fatalf("a denied caller should get 403 AccessDenied; got %d %s", w.Code, w.Body.String())
	}
}

func TestDynamo_VerbForOp(t *testing.T) {
	cases := map[string]string{
		"GetItem": "get", "Query": "get", "Scan": "get", "BatchGetItem": "get",
		"PutItem": "create", "UpdateItem": "create", "CreateTable": "create",
		"DeleteItem": "delete", "DeleteTable": "delete",
	}
	for op, want := range cases {
		if v, known := verbForOp(op); !known || v != want {
			t.Errorf("verbForOp(%s) = %q,%v; want %q,true", op, v, known, want)
		}
	}
	if _, known := verbForOp("Frobnicate"); known {
		t.Error("an unknown op must not map to a verb")
	}
}
