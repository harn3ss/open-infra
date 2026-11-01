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
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

const apiStackTmpl = `
Description: a test stack
Parameters:
  Env: { Type: String, Default: prod }
  Secret: { Type: String, NoEcho: true, Default: hunter2 }
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: k }
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: web }
  Web:
    Type: AWS::EC2::Instance
    Metadata:
      AWS::CloudFormation::Init: { config: { commands: { hello: { command: "echo hi" } } } }
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref SG ] }
Outputs:
  KeyArn: { Value: !GetAtt Key.Arn, Export: { Name: !Sub "${AWS::StackName}-key" } }
`

func deployAPIStack(t *testing.T) (*cfnDoorway, *impersonatingApplier) {
	t.Helper()
	h, ap := cfnTestDoorway(t, "")
	h.signals = &signalStore{h: h}
	opts := h.optsFor("web", nil, stackExports{})
	opts.Wait = false
	opts.Fidelity = "accepted but not emulated as on AWS (1): Web: example"
	if _, err := cfn.Deploy(context.Background(), []byte(apiStackTmpl), opts, ap); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return h, ap
}

// DescribeStackEvents lists the create newest first, in AWS's shape; the stack's own events carry the
// stack id as their physical id.
func TestCFNAPI_DescribeStackEvents(t *testing.T) {
	h, ap := deployAPIStack(t)
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"web"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStackEvents(w, r, ap, "req") })
	var got struct {
		Events []struct {
			LogicalResourceID  string `xml:"LogicalResourceId"`
			PhysicalResourceID string `xml:"PhysicalResourceId"`
			ResourceType       string `xml:"ResourceType"`
			ResourceStatus     string `xml:"ResourceStatus"`
			Reason             string `xml:"ResourceStatusReason"`
		} `xml:"DescribeStackEventsResult>StackEvents>member"`
	}
	if err := xml.Unmarshal(rr.Body.Bytes(), &got); err != nil || len(got.Events) < 8 {
		t.Fatalf("DescribeStackEvents: %v %d\n%s", err, len(got.Events), rr.Body.String())
	}
	first, last := got.Events[0], got.Events[len(got.Events)-1]
	if first.LogicalResourceID != "web" || first.ResourceStatus != "CREATE_COMPLETE" || first.ResourceType != "AWS::CloudFormation::Stack" ||
		!strings.Contains(first.PhysicalResourceID, ":stack/web/") {
		t.Errorf("newest event is the stack's CREATE_COMPLETE: %+v", first)
	}
	if last.ResourceStatus != "CREATE_IN_PROGRESS" || !strings.Contains(last.Reason, "User Initiated") || !strings.Contains(last.Reason, "open-infra fidelity") {
		t.Errorf("oldest event is the stack's CREATE_IN_PROGRESS, with the fidelity summary: %+v", last)
	}
	seen := map[string]bool{}
	for _, e := range got.Events {
		seen[e.LogicalResourceID+":"+e.ResourceType+":"+e.ResourceStatus] = true
	}
	for _, want := range []string{"Key:AWS::KMS::Key:CREATE_COMPLETE", "Web:AWS::EC2::Instance:CREATE_IN_PROGRESS", "SG:AWS::EC2::SecurityGroup:CREATE_COMPLETE"} {
		if !seen[want] {
			t.Errorf("missing event %s", want)
		}
	}
}

// ListStackResources / DescribeStackResources report each resource's CloudFormation type, physical id and
// own status; DescribeStackResource returns its Metadata (what cfn-init reads).
func TestCFNAPI_Resources(t *testing.T) {
	h, ap := deployAPIStack(t)
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"web"}}, func(w http.ResponseWriter, r *http.Request) { h.listStackResources(w, r, ap, "req") })
	body := rr.Body.String()
	for _, want := range []string{"<LogicalResourceId>Web</LogicalResourceId><PhysicalResourceId>web</PhysicalResourceId><ResourceType>AWS::EC2::Instance</ResourceType>",
		"<ResourceStatus>CREATE_COMPLETE</ResourceStatus>", "<ResourceType>AWS::KMS::Key</ResourceType>"} {
		if !strings.Contains(body, want) {
			t.Errorf("ListStackResources lacks %q:\n%s", want, body)
		}
	}
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"web"}, "LogicalResourceId": {"SG"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStackResources(w, r, ap, "req") })
	if b := rr.Body.String(); strings.Count(b, "<member>") != 1 || !strings.Contains(b, "<ResourceType>AWS::EC2::SecurityGroup</ResourceType>") || !strings.Contains(b, "<PhysicalResourceId>web-sg</PhysicalResourceId>") {
		t.Errorf("DescribeStackResources filtered to SG:\n%s", b)
	}
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"web"}, "LogicalResourceId": {"Web"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStackResource(w, r, ap, "req") })
	var one struct {
		Metadata string `xml:"DescribeStackResourceResult>StackResourceDetail>Metadata"`
		Type     string `xml:"DescribeStackResourceResult>StackResourceDetail>ResourceType"`
	}
	if err := xml.Unmarshal(rr.Body.Bytes(), &one); err != nil || one.Type != "AWS::EC2::Instance" || !strings.Contains(one.Metadata, `"AWS::CloudFormation::Init"`) {
		t.Errorf("DescribeStackResource must return the Metadata: %v %+v\n%s", err, one, rr.Body.String())
	}
}

// DescribeStacks lists every template parameter (a default as such, NoEcho masked), the Description, and
// the fidelity summary as the status reason.
func TestCFNAPI_DescribeStacksParametersDescriptionFidelity(t *testing.T) {
	h, ap := deployAPIStack(t)
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"web"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStacks(w, r, ap, "req") })
	b := rr.Body.String()
	for _, want := range []string{"<ParameterKey>Env</ParameterKey><ParameterValue>prod</ParameterValue>",
		"<ParameterKey>Secret</ParameterKey><ParameterValue>****</ParameterValue>", "<Description>a test stack</Description>",
		"<StackStatusReason>open-infra fidelity: accepted but not emulated"} {
		if !strings.Contains(b, want) {
			t.Errorf("DescribeStacks lacks %q:\n%s", want, b)
		}
	}
	if strings.Contains(b, "hunter2") {
		t.Fatalf("a NoEcho default must never be shown")
	}
}

// ValidateTemplate checks a template without parameter values, as AWS does.
func TestCFNAPI_ValidateTemplateWithoutValues(t *testing.T) {
	h, ap := cfnTestDoorway(t, "")
	tmpl := `
Parameters:
  Ami: { Type: String }
Resources:
  Key: { Type: AWS::KMS::Key, Properties: { Description: !Ref Ami } }
`
	rr := cfnPost(t, h, ap, url.Values{"TemplateBody": {tmpl}}, func(w http.ResponseWriter, r *http.Request) { h.validateTemplate(w, r, "req") })
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<ParameterKey>Ami</ParameterKey>") {
		t.Fatalf("ValidateTemplate must accept a parameter with no default: %d\n%s", rr.Code, rr.Body.String())
	}
	bad := strings.Replace(tmpl, "AWS::KMS::Key", "AWS::Nope::Thing", 1)
	rr = cfnPost(t, h, ap, url.Values{"TemplateBody": {bad}}, func(w http.ResponseWriter, r *http.Request) { h.validateTemplate(w, r, "req") })
	if rr.Code == http.StatusOK {
		t.Fatalf("an unsupported type still refuses")
	}
}

// ListImports names the stacks that import an export.
func TestCFNAPI_ListImports(t *testing.T) {
	h, ap := deployAPIStack(t)
	if err := ap.putRecord(context.Background(), &cfn.StackRecord{Name: "app", Namespace: "default", Status: "CREATE_COMPLETE", Imports: []string{"web-key"}}); err != nil {
		t.Fatal(err)
	}
	rr := cfnPost(t, h, ap, url.Values{"ExportName": {"web-key"}}, func(w http.ResponseWriter, r *http.Request) { h.listImports(w, r, "req") })
	if !strings.Contains(rr.Body.String(), "<Imports><member>app</member></Imports>") {
		t.Fatalf("ListImports:\n%s", rr.Body.String())
	}
	rr = cfnPost(t, h, ap, url.Values{"ExportName": {"nope"}}, func(w http.ResponseWriter, r *http.Request) { h.listImports(w, r, "req") })
	if rr.Code == http.StatusOK {
		t.Fatalf("an unknown export is an error")
	}
}

// SignalResource: an instance of the stack (a session of its instance role) may signal it; a User needs
// update rights; another role may not. A signal is recorded where the engine waits for it.
func TestCFNAPI_SignalResource(t *testing.T) {
	h, ap := cfnTestDoorway(t, "")
	h.signals = &signalStore{h: h}
	ctx := context.Background()
	rec := &cfn.StackRecord{Name: "web", Namespace: "default", Status: "CREATE_IN_PROGRESS",
		Resources: []cfn.StackResource{{LogicalID: "Web", Kind: "VirtualMachine", Name: "web-web", Spec: map[string]any{"instanceRole": "web-role"}}}}
	if err := ap.putRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	signal := func(claims iam.Claims, uid string) int {
		form := url.Values{"Action": {"SignalResource"}, "StackName": {"web"}, "LogicalResourceId": {"Web"}, "UniqueId": {uid}, "Status": {"SUCCESS"}}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()
		rr := httptest.NewRecorder()
		h.signalResource(rr, req, claims, "req")
		return rr.Code
	}
	if code := signal(iam.Claims{Sub: "role/web-role/i-1", AssumedRole: "web-role"}, "i-1"); code != http.StatusOK {
		t.Fatalf("the stack's own instance role may signal it: %d", code)
	}
	if code := signal(iam.Claims{Sub: "role/other/x", AssumedRole: "other"}, "x"); code != http.StatusForbidden {
		t.Fatalf("another role may not: %d", code)
	}
	if code := signal(iam.Claims{Sub: "openinfra:alice", Groups: []string{"openinfra:admins"}}, "u-1"); code != http.StatusOK {
		t.Fatalf("a User with update rights may: %d", code)
	}
	sigs, err := h.signals.Signals(ctx, "web", "Web")
	if err != nil || len(sigs) != 2 || sigs[0].UniqueID != "i-1" {
		t.Fatalf("the signals are recorded for the engine: %+v %v", sigs, err)
	}
	rec.Status = "CREATE_COMPLETE"
	_ = ap.putRecord(ctx, rec)
	if code := signal(iam.Claims{Sub: "role/web-role/i-1", AssumedRole: "web-role"}, "i-9"); code != http.StatusBadRequest {
		t.Fatalf("a stack not in progress cannot be signaled: %d", code)
	}
}

// A WaitConditionHandle URL is signed for its stack and handle; a PUT with the right signature records
// the signal, a wrong one is refused, and the body must be AWS's.
func TestCFNAPI_WaitConditionHandleURL(t *testing.T) {
	h, ap := cfnTestDoorway(t, "")
	h.signals = &signalStore{h: h}
	h.signalBase = "https://shim.example:4567"
	ctx := context.Background()
	if err := ap.putRecord(ctx, &cfn.StackRecord{Name: "web", Namespace: "default", Status: "CREATE_IN_PROGRESS"}); err != nil {
		t.Fatal(err)
	}
	u := h.signalURL("web", "Handle")
	if !strings.HasPrefix(u, "https://shim.example:4567/cfn-signal/web/Handle?sig=") {
		t.Fatalf("handle URL: %s", u)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	srv := h.waitConditionHandler(next)
	put := func(target, body string) int {
		pu, _ := url.Parse(target)
		req := httptest.NewRequest(http.MethodPut, pu.RequestURI(), strings.NewReader(body))
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := put(u, `{"Status":"SUCCESS","UniqueId":"web","Data":"ready","Reason":"ok"}`); code != http.StatusOK {
		t.Fatalf("a signed PUT is accepted: %d", code)
	}
	if code := put(strings.Replace(u, "Handle?", "Other?", 1), `{"Status":"SUCCESS","UniqueId":"web"}`); code != http.StatusForbidden {
		t.Fatalf("the signature is bound to the handle: %d", code)
	}
	if code := put(u, `{"Status":"MAYBE"}`); code != http.StatusBadRequest {
		t.Fatalf("the body must be AWS's: %d", code)
	}
	sigs, _ := h.signals.Signals(ctx, "web", "Handle")
	if len(sigs) != 1 || sigs[0].Data != "ready" {
		t.Fatalf("the signal is recorded with its data: %+v", sigs)
	}
	if code := put("https://shim.example/healthz", ""); code != http.StatusTeapot {
		t.Fatalf("other paths pass through: %d", code)
	}
}

// A TemplateURL names an object in this shim's S3 — virtual-hosted or path-style, on this endpoint or an
// AWS S3 hostname — and is never fetched over the network; anything else is refused.
func TestCFNAPI_TemplateObject(t *testing.T) {
	h := &cfnDoorway{s3: &s3Handler{vhostSuffixes: []string{"s3.example.lan"}}}
	req := httptest.NewRequest(http.MethodPost, "https://shim.example:4566/", nil)
	for raw, want := range map[string]string{
		"https://tmpl.s3.example.lan/stacks/app.yaml":                        "tmpl|stacks/app.yaml",
		"https://s3.example.lan/tmpl/stacks/app.yaml":                        "tmpl|stacks/app.yaml",
		"https://shim.example:4566/tmpl/app.yaml":                            "tmpl|app.yaml",
		"https://tmpl.s3.us-east-1.amazonaws.com/app.yaml?X-Amz-Signature=x": "tmpl|app.yaml",
		"https://s3.amazonaws.com/tmpl/dir/app%20v2.yaml":                    "tmpl|dir/app v2.yaml",
	} {
		b, k, err := h.templateObject(raw, req)
		if err != nil || b+"|"+k != want {
			t.Errorf("%s -> %s|%s (%v), want %s", raw, b, k, err, want)
		}
	}
	for _, raw := range []string{"https://evil.example/tmpl/app.yaml", "file:///etc/passwd", "https://169.254.169.254/latest/meta-data", "https://s3.example.lan/onlybucket"} {
		if _, _, err := h.templateObject(raw, req); err == nil {
			t.Errorf("%s must be refused", raw)
		}
	}
}
