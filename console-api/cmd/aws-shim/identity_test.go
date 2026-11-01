package main

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// STS reports AWS's ARN forms in the install's 12-digit account: an IAM user is arn:aws:iam::<acct>:
// user/<name>, an assumed-role session arn:aws:sts::<acct>:assumed-role/<role>/<session>.
func TestSTS_CallerIdentityIsAWSShaped(t *testing.T) {
	h := &stsHandler{account: "123456789012", logger: discardLogger()}
	for _, c := range []struct {
		claims iam.Claims
		arn    string
	}{
		{iam.Claims{Sub: "alice"}, "arn:aws:iam::123456789012:user/alice"},
		{iam.Claims{Sub: "assumed-role/deploy/s1", AssumedRole: "deploy"}, "arn:aws:sts::123456789012:assumed-role/deploy/s1"},
	} {
		req := httptest.NewRequest("POST", "http://sts.local/", strings.NewReader("Action=GetCallerIdentity"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.serve(w, req, c.claims, "rid")
		var resp getCallerIdentityResponse
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v (%s)", err, w.Body.String())
		}
		if resp.Result.Arn != c.arn || resp.Result.Account != "123456789012" {
			t.Errorf("caller %+v: Arn=%q Account=%q, want %q in 123456789012", c.claims, resp.Result.Arn, resp.Result.Account, c.arn)
		}
	}
}

// AssumeRole accepts the role ARN in the AWS form a template builds (${AWS::AccountId}), as well as the
// legacy form (TestAssumeRole_TrustedCallerGetsCredentials).
func TestSTS_AssumeRoleAcceptsTheAWSFormARN(t *testing.T) {
	h, _ := newSTS(t, fakeRoles{"deploy-role": {trust: []string{"alice"}}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("arn:aws:iam::000000000000:role/deploy-role", "s1"), iam.Claims{Sub: "alice"}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("assume with the AWS-form ARN: %d %s", w.Code, w.Body.String())
	}
}

// The StackId the front door reports is the value a template resolves AWS::StackId to.
func TestCFN_StackIDIsAWSStackId(t *testing.T) {
	defer awsidentity.Set(awsidentity.Current())
	id := awsidentity.Identity{AccountID: "123456789012", Region: "eu-west-1", StackNamespace: "open-infra-cfn"}
	awsidentity.Set(id)
	h := &cfnDoorway{account: id.AccountID, region: id.Region, ns: id.StackNamespace}
	if got, want := h.stackID("app"), awsidentity.Current().StackID("app"); got != want {
		t.Fatalf("stackID = %s, AWS::StackId = %s", got, want)
	}
	if got := h.stackID("app"); !strings.HasPrefix(got, "arn:aws:cloudformation:eu-west-1:123456789012:stack/app/") {
		t.Fatalf("stackID = %s", got)
	}
}

// API Gateway's proxy event carries the install's account in requestContext.accountId.
func TestAPIGW_ProxyEventAccountIsTheInstall(t *testing.T) {
	defer awsidentity.Set(awsidentity.Current())
	awsidentity.Set(awsidentity.Identity{AccountID: "123456789012", Region: "us-east-1"})
	for _, v := range []string{"1.0", "2.0"} {
		ev := buildProxyEvent(v, httptest.NewRequest("GET", "/x", nil), "api1", "prod", "GET /x", "/x", nil, nil, "rid")
		rc, _ := ev["requestContext"].(map[string]any)
		if rc["accountId"] != "123456789012" {
			t.Errorf("payload %s: requestContext.accountId = %v", v, rc["accountId"])
		}
	}
}

// A request naming a topic or queue by any of the forms it may be stored under finds it: a legacy row by
// the current account's ARN (a template's ${AWS::AccountId}), a current row by the legacy ARN (a client
// that kept one). Nothing else is rewritten.
func TestResolveStored(t *testing.T) {
	id := awsidentity.Identity{AccountID: "000000000000", Region: "us-east-1"}
	in := func(stored ...string) func(context.Context, string) (bool, error) {
		return func(_ context.Context, v string) (bool, error) {
			for _, s := range stored {
				if s == v {
					return true, nil
				}
			}
			return false, nil
		}
	}
	legacyTopic, newTopic := "arn:aws:sns:us-east-1:open-infra:orders", "arn:aws:sns:us-east-1:000000000000:orders"
	legacyURL, newURL := "http://shim:4566/open-infra/jobs", "http://shim:4566/000000000000/jobs"
	cases := []struct {
		name, given string
		exists      func(context.Context, string) (bool, error)
		want        string
	}{
		{"legacy row, current-account ARN", newTopic, in(legacyTopic), legacyTopic},
		{"current row, legacy ARN", legacyTopic, in(newTopic), newTopic},
		{"current row, current ARN", newTopic, in(newTopic), newTopic},
		{"no such topic: the current account's form", legacyTopic, in(), newTopic},
		{"legacy queue, current-account URL", newURL, in(legacyURL), legacyURL},
		{"current queue, legacy URL", legacyURL, in(newURL), newURL},
		{"another account's ARN is left alone", "arn:aws:sns:us-east-1:123456789012:orders", in(newTopic), "arn:aws:sns:us-east-1:123456789012:orders"},
		{"a name is left alone", "orders", in(newTopic), "orders"},
		{"a failed lookup changes nothing", legacyTopic, func(context.Context, string) (bool, error) { return false, errors.New("db down") }, legacyTopic},
	}
	for _, c := range cases {
		if got := resolveStored(context.Background(), id, c.given, c.exists); got != c.want {
			t.Errorf("%s: resolveStored(%q) = %q, want %q", c.name, c.given, got, c.want)
		}
	}
}
