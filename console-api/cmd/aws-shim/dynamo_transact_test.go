package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Without the documentdb Postgres backend both transaction operations answer an honest 501 (a
// snapshot / atomic multi-item write can't be faked over the plain mongo wire), never a silent fake.
func TestTransact_RequirePostgres(t *testing.T) {
	h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "", discardLogger())
	cases := map[string]func(w *httptest.ResponseRecorder){
		"TransactWriteItems": func(w *httptest.ResponseRecorder) {
			h.transactWriteItems(context.Background(), w, "r", map[string]any{"TransactItems": []any{}})
		},
		"TransactGetItems": func(w *httptest.ResponseRecorder) {
			h.transactGetItems(context.Background(), w, "r", map[string]any{"TransactItems": []any{}})
		},
	}
	for op, run := range cases {
		w := httptest.NewRecorder()
		run(w)
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("%s without pg should be 501, got %d: %s", op, w.Code, w.Body.String())
		}
		if !strings.Contains(decodeDynamoErr(t, w)["__type"], "NotImplemented") {
			t.Errorf("%s should be NotImplementedException, got %s", op, w.Body.String())
		}
	}
}

// A cancelled transaction renders TransactionCanceledException with per-item CancellationReasons in
// order — the shape a DynamoDB SDK parses to learn exactly which item's condition failed.
func TestWriteTransactionCanceled_WireShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeTransactionCanceled(w, "req-9", []map[string]any{{"Code": "None"}, conditionalFailedReason()})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if w.Header().Get("x-amzn-RequestId") != "req-9" {
		t.Errorf("request id not echoed: %v", w.Header())
	}
	var body struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
		Reasons []struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"CancellationReasons"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, w.Body.String())
	}
	if !strings.HasSuffix(body.Type, "#TransactionCanceledException") {
		t.Errorf("__type = %q, want a #TransactionCanceledException", body.Type)
	}
	if len(body.Reasons) != 2 || body.Reasons[0].Code != "None" || body.Reasons[1].Code != "ConditionalCheckFailed" {
		t.Errorf("CancellationReasons = %+v, want [None, ConditionalCheckFailed]", body.Reasons)
	}
	if body.Reasons[1].Message == "" || !strings.Contains(body.Message, "ConditionalCheckFailed") {
		t.Errorf("message/reason should name the failed condition: msg=%q reasons=%+v", body.Message, body.Reasons)
	}
}
