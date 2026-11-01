package main

import (
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
