package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const paramCheckTmpl = `
Parameters:
  Env:
    Type: String
    AllowedValues: [dev, prod]
    Default: dev
  SubnetId:
    Type: AWS::EC2::Subnet::Id
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: !Sub "${Env} in ${SubnetId}" }
`

// #347 item 25 / #350 U: CreateStack, UpdateStack and CreateChangeSet refuse parameter values as AWS
// does, in AWS's words, before anything is created: a key the template does not declare, a parameter
// with no value, a value outside its AllowedValues, a subnet that does not exist (looked up as the
// caller), and a UsePreviousValue key the stack's previous template did not have.
func TestCFN_ParameterValidation(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0101")
	h.mapper.(*meta.DefaultRESTMapper).Add(schema.GroupVersionKind{Group: "openinfra.dev", Version: "v1", Kind: "Subnet"}, meta.RESTScopeNamespace)
	call := func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		w := serveWith(h, formOp(form), testUser)
		h.ops.drain(10 * time.Second)
		return w
	}
	refused := func(form url.Values, want string) {
		t.Helper()
		w := call(form)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<Code>ValidationError</Code>") ||
			!strings.Contains(w.Body.String(), want) {
			t.Fatalf("%v: want a ValidationError %q, got %d %s", form, want, w.Code, w.Body.String())
		}
	}
	create := func(kv ...string) url.Values {
		f := url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {paramCheckTmpl}}
		for i := 0; i+1 < len(kv); i += 2 {
			n := i/2 + 1
			f.Set("Parameters.member."+strconv.Itoa(n)+".ParameterKey", kv[i])
			f.Set("Parameters.member."+strconv.Itoa(n)+".ParameterValue", kv[i+1])
		}
		return f
	}
	refused(create("SubnetId", "app-net", "Bogus", "x"), "Parameters: [Bogus] do not exist in the template")
	refused(create(), "Parameters: [SubnetId] must have values")
	refused(create("SubnetId", "app-net", "Env", "stage"), "Parameter &#39;Env&#39; must be one of AllowedValues")
	refused(create("SubnetId", "app-net"), "Parameter validation failed: parameter value app-net for parameter name SubnetId does not exist")
	if rec, _ := recordIn(t, fa, "app"); rec != nil {
		t.Fatalf("a refused create left a stack record: %+v", rec)
	}

	fa.put("subnets", opsNS, "app-net", map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Subnet", "spec": map[string]any{}})
	if w := call(create("SubnetId", "app-net")); w.Code != http.StatusOK {
		t.Fatalf("create with an existing subnet: %d %s", w.Code, w.Body.String())
	}
	if rec, _ := recordIn(t, fa, "app"); rec == nil || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("want CREATE_COMPLETE: %+v", rec)
	}

	upd := url.Values{"Action": {"UpdateStack"}, "StackName": {"app"}, "UsePreviousTemplate": {"true"},
		"Parameters.member.1.ParameterKey": {"SubnetId"}, "Parameters.member.1.UsePreviousValue": {"true"},
		"Parameters.member.2.ParameterKey": {"Region"}, "Parameters.member.2.UsePreviousValue": {"true"}}
	refused(upd, "Invalid input for parameter key Region. Cannot specify usePreviousValue as true for a parameter key not in the previous template")
	upd = url.Values{"Action": {"UpdateStack"}, "StackName": {"app"}, "UsePreviousTemplate": {"true"},
		"Parameters.member.1.ParameterKey": {"SubnetId"}, "Parameters.member.1.UsePreviousValue": {"true"},
		"Parameters.member.2.ParameterKey": {"Env"}, "Parameters.member.2.ParameterValue": {"qa"}}
	refused(upd, "Parameter &#39;Env&#39; must be one of AllowedValues")

	cs := url.Values{"Action": {"CreateChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}, "UsePreviousTemplate": {"true"},
		"Parameters.member.1.ParameterKey": {"SubnetId"}, "Parameters.member.1.ParameterValue": {"other-net"}}
	refused(cs, "parameter value other-net for parameter name SubnetId does not exist")
	cs.Set("Parameters.member.2.ParameterKey", "Extra")
	cs.Set("Parameters.member.2.ParameterValue", "1")
	refused(cs, "Parameters: [Extra] do not exist in the template")
}

// #350 Y: a change set is found by its ARN alone (what `aws cloudformation deploy` prints); once executed
// its ExecutionStatus is EXECUTE_COMPLETE, and it cannot be executed again; ValidateTemplate returns the
// template's own Description.
func TestCFN_ChangeSetBookkeeping(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0103")
	call := func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		w := serveWith(h, formOp(form), testUser)
		h.ops.drain(10 * time.Second)
		return w
	}
	tmpl := "Description: the app's keys\nResources:\n  Key: { Type: AWS::KMS::Key, Properties: { Description: k } }\n"
	w := call(url.Values{"Action": {"CreateChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}, "ChangeSetType": {"CREATE"}, "TemplateBody": {tmpl}})
	if w.Code != http.StatusOK {
		t.Fatalf("create change set: %d %s", w.Code, w.Body.String())
	}
	arn := h.changeSetID("app", "cs1")
	if !strings.Contains(w.Body.String(), "<Id>"+arn+"</Id>") {
		t.Fatalf("CreateChangeSet must return the change set's ARN %s: %s", arn, w.Body.String())
	}
	describe := func() string {
		t.Helper()
		w := call(url.Values{"Action": {"DescribeChangeSet"}, "ChangeSetName": {arn}})
		if w.Code != http.StatusOK {
			t.Fatalf("DescribeChangeSet by ARN alone: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if b := describe(); !strings.Contains(b, "<ExecutionStatus>AVAILABLE</ExecutionStatus>") || !strings.Contains(b, "<StackName>app</StackName>") ||
		!strings.Contains(b, "<LogicalResourceId>Key</LogicalResourceId><ResourceType>AWS::KMS::Key</ResourceType>") {
		t.Fatalf("before execution: %s", b)
	}
	if w := call(url.Values{"Action": {"ExecuteChangeSet"}, "ChangeSetName": {arn}}); w.Code != http.StatusOK {
		t.Fatalf("ExecuteChangeSet by ARN alone: %d %s", w.Code, w.Body.String())
	}
	if rec, _ := recordIn(t, fa, "app"); rec == nil || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("want CREATE_COMPLETE: %+v", rec)
	}
	if b := describe(); !strings.Contains(b, "<ExecutionStatus>EXECUTE_COMPLETE</ExecutionStatus>") {
		t.Fatalf("after execution: %s", b)
	}
	w = call(url.Values{"Action": {"ExecuteChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "InvalidChangeSetStatus") {
		t.Fatalf("an executed change set must not run again: %d %s", w.Code, w.Body.String())
	}

	w = call(url.Values{"Action": {"ValidateTemplate"}, "TemplateBody": {tmpl}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<Description>the app&#39;s keys</Description>") ||
		!strings.HasPrefix(w.Header().Get("X-Openinfra-Fidelity"), "open-infra: ") {
		t.Fatalf("ValidateTemplate must return the template's Description: %d %s (header %q)", w.Code, w.Body.String(), w.Header().Get("X-Openinfra-Fidelity"))
	}
}

// #350 T: termination protection — set at create (EnableTerminationProtection) or by
// UpdateTerminationProtection, shown by DescribeStacks, and refusing DeleteStack while on, as on AWS.
func TestCFN_TerminationProtection(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0104")
	call := func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		w := serveWith(h, formOp(form), testUser)
		h.ops.drain(10 * time.Second)
		return w
	}
	tmpl := "Resources:\n  Key: { Type: AWS::KMS::Key, Properties: { Description: k } }\n"
	if w := call(url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {tmpl}, "EnableTerminationProtection": {"true"}}); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	if w := call(url.Values{"Action": {"DescribeStacks"}, "StackName": {"app"}}); !strings.Contains(w.Body.String(), "<EnableTerminationProtection>true</EnableTerminationProtection>") {
		t.Fatalf("DescribeStacks: %s", w.Body.String())
	}
	w := call(url.Values{"Action": {"DeleteStack"}, "StackName": {"app"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cannot be deleted while TerminationProtection is enabled") {
		t.Fatalf("a protected stack's delete must be refused: %d %s", w.Code, w.Body.String())
	}
	if w := call(url.Values{"Action": {"UpdateTerminationProtection"}, "StackName": {"app"}, "EnableTerminationProtection": {"false"}}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<StackId>") {
		t.Fatalf("UpdateTerminationProtection: %d %s", w.Code, w.Body.String())
	}
	if rec, _ := recordIn(t, fa, "app"); rec == nil || rec.TerminationProtection || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("protection must be off, the stack otherwise unchanged: %+v", rec)
	}
	if w := call(url.Values{"Action": {"DeleteStack"}, "StackName": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("delete once unprotected: %d %s", w.Code, w.Body.String())
	}
	if rec, _ := recordIn(t, fa, "app"); rec != nil {
		t.Fatalf("the stack must be deleted: %+v", rec)
	}
}

// While a create is under way, ListStackResources lists only the resources whose creation has
// begun — a resource the record plans but has not started is not shown (it used to show CREATE_COMPLETE),
// and DescribeStackResource does not answer for it; the same after a create that failed before reaching it.
func TestCFN_ListStackResourcesOmitsUnstarted(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0102")
	for _, status := range []string{"CREATE_IN_PROGRESS", "CREATE_FAILED", "ROLLBACK_COMPLETE"} {
		rec := cfn.StackRecord{Name: "mid", Status: status, Template: "Resources:\n  Wait: { Type: AWS::CloudFormation::WaitCondition }\n  Web: { Type: AWS::EC2::Instance }\n",
			Resources: []cfn.StackResource{
				{LogicalID: "Wait", APIVersion: "cfn.openinfra.dev/v1", Kind: "SignalWait", Name: "mid-wait", Type: "AWS::CloudFormation::WaitCondition"},
				{LogicalID: "Web", APIVersion: "openinfra.dev/v1", Kind: "VirtualMachine", Name: "mid-web", Type: "AWS::EC2::Instance"},
			},
			Events: []cfn.StackEvent{{EventID: "e1", LogicalID: "Wait", Type: "AWS::CloudFormation::WaitCondition", Status: "CREATE_IN_PROGRESS", Timestamp: "2026-11-03T00:00:00.000Z"}},
		}
		seedStack(fa, rec, nil)
		w := serveWith(h, formOp(url.Values{"Action": {"ListStackResources"}, "StackName": {"mid"}}), testUser)
		b := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(b, "<LogicalResourceId>Wait</LogicalResourceId>") || strings.Contains(b, "<LogicalResourceId>Web</LogicalResourceId>") {
			t.Fatalf("%s: want only the started wait condition listed: %d %s", status, w.Code, b)
		}
		w = serveWith(h, formOp(url.Values{"Action": {"DescribeStackResource"}, "StackName": {"mid"}, "LogicalResourceId": {"Web"}}), testUser)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Resource Web does not exist for stack mid") {
			t.Fatalf("%s: DescribeStackResource of an unstarted resource: %d %s", status, w.Code, w.Body.String())
		}
	}
}
