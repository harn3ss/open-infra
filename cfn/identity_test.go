package cfn

import (
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// The pseudo-parameters are the install's identity — the account, region and partition the aws-shim
// reports — and AWS::StackId is the stack's own StackId, the ARN the front door returns for it.
func TestPseudoParams_AreTheInstallIdentity(t *testing.T) {
	defer awsidentity.Set(awsidentity.Current())
	id := awsidentity.Identity{AccountID: "123456789012", Region: "eu-west-1", StackNamespace: "open-infra-cfn"}
	awsidentity.Set(id)

	p := pseudoParams("app")
	want := map[string]any{
		"AWS::AccountId": "123456789012",
		"AWS::Region":    "eu-west-1",
		"AWS::Partition": "aws",
		"AWS::URLSuffix": "amazonaws.com",
		"AWS::StackName": "app",
		"AWS::StackId":   id.StackID("app"),
	}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, want %v", k, p[k], v)
		}
	}

	// A template that builds an ARN from them gets the ARN the shim reports for the resource.
	tpl := []byte(`
Resources:
  Topic: { Type: AWS::SNS::Topic, Properties: { TopicName: orders } }
Outputs:
  Built:  { Value: !Sub "arn:${AWS::Partition}:sns:${AWS::Region}:${AWS::AccountId}:orders" }
  Domain: { Value: !Sub "orders.s3.${AWS::Region}.${AWS::URLSuffix}" }
  Id:     { Value: !Ref AWS::StackId }
`)
	tmpl, err := Parse(tpl)
	if err != nil {
		t.Fatal(err)
	}
	r := newResolver(tmpl, nil, nil, pseudoParams("app"))
	if got := r.resolve(outVal(tmpl, "Built")); got != id.RegionalARN("sns", "orders") {
		t.Errorf("built topic ARN = %v, want %s", got, id.RegionalARN("sns", "orders"))
	}
	if got := r.resolve(outVal(tmpl, "Domain")); got != "orders.s3.eu-west-1.amazonaws.com" {
		t.Errorf("regional domain = %v", got)
	}
	if got := r.resolve(outVal(tmpl, "Id")); got != id.StackID("app") {
		t.Errorf("AWS::StackId = %v, want %s", got, id.StackID("app"))
	}
}

func outVal(t *Template, name string) any {
	o, _ := t.Outputs[name].(map[string]any)
	return o["Value"]
}
