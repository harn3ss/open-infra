package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
)

// A stack's queue URLs are recorded on SQS_QUEUE_URL_BASE (the shim's own address inside the cluster), and
// each caller is answered with them at the endpoint it came in by, as the SQS front door answers it: a caller
// outside the cluster gets a URL it can use. Never an amazonaws.com URL to a caller that did not use an AWS
// name (#350 Y): an SDK that sends to the QueueUrl's host — the JavaScript SDK v2 sets the request's endpoint
// from QueueUrl, whatever endpoint it was given — would send that caller's signed request and message to
// AWS. A guest, which comes in by AWS's own CloudFormation name and resolves sqs.<region>.amazonaws.com to
// this shim (and may not reach the shim's own address), is answered with the AWS-form URLs.
func TestCFN_QueueURLOutputsFollowTheCallersName(t *testing.T) {
	h, ap := cfnTestDoorway(t, "")
	h.sqsURLBase = "https://shim.example:4566"
	// The queue's URL is built on SQS_QUEUE_URL_BASE when the stack completes (cfn's sqsQueueURL; its
	// outputs tests prove the base), so the record holds the shim's own URL.
	own := "https://shim.example:4566/" + h.account + "/jobs"
	rec := &cfn.StackRecord{Name: "app", Namespace: "default", Status: "CREATE_COMPLETE", Outputs: []cfn.StackOutput{
		{OutputKey: "QueueUrl", OutputValue: own, ExportName: "app-QueueUrl"}, {OutputKey: "Config", OutputValue: "queue=" + own},
		{OutputKey: "Other", OutputValue: "https://shim.example:4566/elsewhere"}}}
	if err := ap.putRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	describe := func(host string) map[string]string {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"StackName": {"app"}}.Encode()))
		req.Host = host
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()
		rr := httptest.NewRecorder()
		h.describeStacks(rr, req, ap, "req")
		var got describeStacksXML
		if err := xml.Unmarshal(rr.Body.Bytes(), &got); err != nil || len(got.Stacks) != 1 {
			t.Fatalf("%s: %v\n%s", host, err, rr.Body.String())
		}
		out := map[string]string{}
		for _, o := range got.Stacks[0].Outputs {
			out[o.OutputKey] = o.OutputValue
		}
		return out
	}
	for _, host := range []string{"aws-shim.open-infra-aws-shim.svc.cluster.local:4566", "shim.example:4566", "192.0.2.7:4566"} {
		got := describe(host)
		at := "http://" + host + "/" + h.account + "/jobs"
		if got["QueueUrl"] != at || got["Config"] != "queue="+at {
			t.Errorf("%s: a caller gets the queue's URL at its own endpoint, never an amazonaws.com one: %v", host, got)
		}
	}
	awsForm := "https://sqs." + h.region + ".amazonaws.com/" + h.account + "/jobs"
	got := describe("cloudformation." + h.region + ".amazonaws.com")
	if got["QueueUrl"] != awsForm || got["Config"] != "queue="+awsForm {
		t.Errorf("a guest (by AWS's CloudFormation name) gets the AWS-form queue URL: %v", got)
	}
	if got["Other"] != "https://shim.example:4566/elsewhere" {
		t.Errorf("only queue URLs are rewritten: %v", got)
	}

	// ListExports answers the same way; the export itself (what Fn::ImportValue resolves in another
	// stack, server-side) keeps the shim's URL.
	exports := func(host string) string {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
		req.Host = host
		rr := httptest.NewRecorder()
		h.listExports(rr, req, "req")
		return rr.Body.String()
	}
	if b := exports("shim.example:4566"); !strings.Contains(b, "<Value>http://shim.example:4566/"+h.account+"/jobs</Value>") {
		t.Errorf("ListExports outside a guest:\n%s", b)
	}
	if b := exports("cloudformation." + h.region + ".amazonaws.com"); !strings.Contains(b, "<Value>"+awsForm+"</Value>") {
		t.Errorf("ListExports for a guest:\n%s", b)
	}
	if v := h.exportsFor(context.Background(), "").values["app-QueueUrl"]; v != own {
		t.Errorf("the export Fn::ImportValue reads keeps the shim's URL: %q", v)
	}
}
