package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An error answer passes a Kubernetes error through in AWS's terms: the message names the AWS resource
// and an AWS error code is added. A success, and an error the console wrote itself, are left as they are.
func TestWriteJSON_ErrorsInAWSTerms(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusInternalServerError, map[string]string{
		"error": `create VM snapshot: virtualmachines.openinfra.dev "web" is forbidden: User "alice" cannot get resource "virtualmachines" in API group "openinfra.dev" in the namespace "prod"`,
	})
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if want := "create VM snapshot: User: alice is not authorized to perform: get on resource: EC2 instance web"; got["error"] != want {
		t.Errorf("error = %q, want %q", got["error"], want)
	}
	if got["errorCode"] != "InternalFailure" {
		t.Errorf("errorCode = %q, want InternalFailure (the status the handler chose)", got["errorCode"])
	}

	rec = httptest.NewRecorder()
	writeJSON(rec, http.StatusBadRequest, map[string]string{"error": "name is required"})
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["error"] != "name is required" || got["errorCode"] != "ValidationException" {
		t.Errorf("the console's own message changed: %v", got)
	}

	rec = httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]string{"error": "not an error answer"})
	if rec.Body.String() != "{\"error\":\"not an error answer\"}\n" {
		t.Errorf("a success was modified: %s", rec.Body.String())
	}
}
