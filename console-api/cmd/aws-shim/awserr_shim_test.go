package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
)

// A Kubernetes error a front door passes through reaches the caller in AWS's terms: the error writers
// rewrite it, whatever the service's protocol.
func TestShimErrorWriters_SayKubernetesErrorsInAWSTerms(t *testing.T) {
	k8s := `tables.openinfra.dev "orders" is forbidden: User "alice" cannot get resource "tables" in API group "openinfra.dev" in the namespace "prod"`
	want := "User: alice is not authorized to perform: get on resource: DynamoDB table orders"
	for name, write := range map[string]func(w http.ResponseWriter){
		"query (XML)": func(w http.ResponseWriter) {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", "r1", k8s, cfnXMLNamespace)
		},
		"dynamodb (JSON)": func(w http.ResponseWriter) {
			writeDynamoError(w, http.StatusBadRequest, "AccessDeniedException", "r1", k8s)
		},
		"s3 (XML)": func(w http.ResponseWriter) {
			writeS3ErrorFull(w, "AccessDenied", http.StatusForbidden, "r1", k8s, "/b")
		},
		"lambda (JSON)": func(w http.ResponseWriter) {
			writeLambdaError(w, http.StatusForbidden, "AccessDeniedException", "r1", k8s)
		},
	} {
		rec := httptest.NewRecorder()
		write(rec)
		body := rec.Body.String()
		if !strings.Contains(body, want) {
			t.Errorf("%s: body %s lacks %q", name, body, want)
		}
		for _, leak := range []string{"API group", "in the namespace", "openinfra.dev"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: body still says %q: %s", name, leak, body)
			}
		}
	}
}

// A stack's events and resources state a failure in AWS's terms: a composition's render failure is its
// own reason, an admission denial its validation message.
func TestCFNReasons_SayKubernetesErrorsInAWSTerms(t *testing.T) {
	compose := `cannot compose resources: pipeline step "render-resources" returned a fatal result: cannot execute template: template: manifests:278:6: executing "manifests" at <fail "x">: error calling fail: the instance's root disk needs firmware.mode (bios or uefi)`
	admission := `admission webhook "vfunction.openinfra.dev" denied the request: memory must be at least 128Mi`
	rec := &cfn.StackRecord{Name: "s", DeletedAt: "2026-11-03T00:00:00Z",
		Events: []cfn.StackEvent{
			{LogicalID: "Instance", Status: "CREATE_FAILED", Reason: compose},
			{LogicalID: "Fn", Status: "CREATE_FAILED", Reason: admission},
		},
		Resources: []cfn.StackResource{{LogicalID: "Instance", Type: "AWS::EC2::Instance", Status: "CREATE_FAILED", StatusReason: compose}},
	}
	h := &cfnDoorway{}
	evs := h.stackEvents(context.Background(), rec)
	got := map[string]string{}
	for _, e := range evs {
		got[e.LogicalID] = e.Reason
	}
	if got["Instance"] != "the instance's root disk needs firmware.mode (bios or uefi)" {
		t.Errorf("Instance event reason = %q", got["Instance"])
	}
	if got["Fn"] != "memory must be at least 128Mi" {
		t.Errorf("Fn event reason = %q", got["Fn"])
	}
	if rec.Events[0].Reason != compose {
		t.Error("the stored record's event was rewritten; only what the caller is shown may change")
	}
	rowReason := map[string]string{}
	for _, r := range h.provisionedResourceRows(context.Background(), rec) {
		rowReason[r.logicalID] = r.reason
	}
	if rowReason["Instance"] != "the instance's root disk needs firmware.mode (bios or uefi)" || rowReason["Fn"] != "memory must be at least 128Mi" {
		t.Errorf("resource row reasons = %v", rowReason)
	}
}
