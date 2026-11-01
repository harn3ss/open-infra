package main

import (
	"github.com/harn3ss/open-infra/cfn"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// `aws cloudformation deploy` describes and executes the change set by the Id CreateChangeSet returned
// (an ARN), and clients may pass a StackId; both must reach the handlers as bare names.
func TestNormalizeStackArgs_ARNsBecomeNames(t *testing.T) {
	form := url.Values{
		"Action":        {"DescribeChangeSet"},
		"StackName":     {"arn:aws:cloudformation:us-east-1:000000000000:stack/web/1a2b3c"},
		"ChangeSetName": {"arn:aws:cloudformation:us-east-1:000000000000:changeSet/awscli-cloudformation-package-deploy-1700000000/9f8e7d"},
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	normalizeStackArgs(r)
	if got := r.PostFormValue("StackName"); got != "web" {
		t.Errorf("StackName = %q, want web", got)
	}
	if got := r.PostFormValue("ChangeSetName"); got != "awscli-cloudformation-package-deploy-1700000000" {
		t.Errorf("ChangeSetName = %q", got)
	}
}

func TestNormalizeStackArgs_NamesUntouched(t *testing.T) {
	form := url.Values{"StackName": {"web"}, "ChangeSetName": {"add-logs"}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	normalizeStackArgs(r)
	if r.PostFormValue("StackName") != "web" || r.PostFormValue("ChangeSetName") != "add-logs" {
		t.Errorf("plain names changed: %v", r.PostForm)
	}
	for _, v := range []string{"arn:aws:s3:::bucket", "arn:aws:cloudformation:r:a:other/x/y", "arn:aws:cloudformation:r:a:stack/"} {
		if _, ok := nameFromCFNArn(v, ":stack/"); ok {
			t.Errorf("nameFromCFNArn(%q) accepted a non-stack ARN", v)
		}
	}
}

// `aws cloudformation deploy` sends every parameter it was not told to override as UsePreviousValue on
// an update; those take the value the stack was last deployed with, never the template default.
func TestParams_UsePreviousValue(t *testing.T) {
	form := url.Values{
		"Parameters.member.1.ParameterKey":     {"SiteDomain"},
		"Parameters.member.1.ParameterValue":   {"site.example.test"},
		"Parameters.member.2.ParameterKey":     {"InstanceType"},
		"Parameters.member.2.UsePreviousValue": {"true"},
		"Parameters.member.3.ParameterKey":     {"Brand"},
		"Parameters.member.3.UsePreviousValue": {"true"},
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	params, prev := parseCFNParamsPrev(r)
	if len(prev) != 2 || params["SiteDomain"] != "site.example.test" {
		t.Fatalf("params=%v prev=%v", params, prev)
	}
	if _, set := params["InstanceType"]; set {
		t.Fatalf("a UsePreviousValue parameter must not be sent as an empty value: %v", params)
	}
	cur := &cfn.StackRecord{Parameters: map[string]string{"InstanceType": "t3.large", "SiteDomain": "old.example.test"}}
	params = withPreviousValues(params, prev, cur)
	if params["InstanceType"] != "t3.large" {
		t.Errorf("InstanceType should keep its previous value t3.large, got %q", params["InstanceType"])
	}
	if params["SiteDomain"] != "site.example.test" {
		t.Errorf("an explicit value wins over the previous one, got %q", params["SiteDomain"])
	}
	if _, set := params["Brand"]; set {
		t.Errorf("a parameter the stack never had keeps the template default (left unset), got %q", params["Brand"])
	}
}

func TestTemplateParametersXML(t *testing.T) {
	tmpl := []byte("Parameters:\n  B: { Type: String }\n  A: { Type: Number, Default: 3 }\nResources:\n  X: { Type: AWS::S3::Bucket }\n")
	got := templateParametersXML(tmpl, true)
	want := "<Parameters><member><ParameterKey>A</ParameterKey><DefaultValue>3</DefaultValue><ParameterType>Number</ParameterType><NoEcho>false</NoEcho></member>" +
		"<member><ParameterKey>B</ParameterKey><ParameterType>String</ParameterType><NoEcho>false</NoEcho></member></Parameters>"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if templateParametersXML([]byte("Resources: {X: {Type: AWS::S3::Bucket}}"), false) != "<Parameters/>" {
		t.Errorf("a template without Parameters renders an empty list")
	}
}
