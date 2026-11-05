package cfn

import (
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// A stack acts in the account its StackId names: a member account's stack resolves AWS::AccountId to its
// own account and builds its resources' ARNs in it; the management account's stack (and one whose
// StackId names no account) is exactly the install's identity, as before accounts.
func TestPseudoParams_FollowTheStacksAccount(t *testing.T) {
	defer awsidentity.Set(awsidentity.Current())
	install := awsidentity.Identity{AccountID: "123456789012", Region: "eu-west-1", StackNamespace: "open-infra-cfn"}
	awsidentity.Set(install)
	member := install.ForAccount("912345678901", "team-a")

	for _, tc := range []struct {
		name, stackID, account string
	}{
		{"no StackId (derived)", "", install.AccountID},
		{"the management account's", install.NewStackID("app"), install.AccountID},
		{"a member account's", member.NewStackID("app"), "912345678901"},
		{"a legacy StackId with no account", "arn:aws:cloudformation:eu-west-1:open-infra:stack/app/x", install.AccountID},
	} {
		p := pseudoParamsFor("app", tc.stackID)
		if p["AWS::AccountId"] != tc.account || p["AWS::Region"] != "eu-west-1" {
			t.Errorf("%s: AWS::AccountId=%v AWS::Region=%v, want %s eu-west-1", tc.name, p["AWS::AccountId"], p["AWS::Region"], tc.account)
		}
		if tc.stackID == "" && p["AWS::StackId"] != install.StackID("app") {
			t.Errorf("%s: AWS::StackId = %v", tc.name, p["AWS::StackId"])
		}
	}

	tpl := []byte(`
Resources:
  Topic: { Type: AWS::SNS::Topic, Properties: { TopicName: orders } }
Outputs:
  Arn: { Value: !Ref Topic }
`)
	for _, tc := range []struct{ stackID, want string }{
		{install.NewStackID("app"), install.RegionalARN("sns", "orders")},
		{member.NewStackID("app"), member.RegionalARN("sns", "orders")},
	} {
		tmpl, err := Parse(tpl)
		if err != nil {
			t.Fatal(err)
		}
		r := newResolver(tmpl, nil, nil, pseudoParamsFor("app", tc.stackID))
		ctx := &stackCtx{template: tmpl, resolver: r}
		got, ok := inStackARN("Topic", ctx)
		if !ok || got != tc.want || !strings.Contains(got, ":"+awsidentity.AccountOfARN(tc.stackID)+":") {
			t.Errorf("the topic's ARN in the stack %s = %q, want %q", tc.stackID, got, tc.want)
		}
	}
}
