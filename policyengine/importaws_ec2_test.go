package policyengine

import (
	"strings"
	"testing"
)

// #347 item 22: the ARNs an ssm:SendCommand statement names (the instance and the document) and the EC2
// front door's resources map to the types the aws-shim checks; the SSM agent's ec2messages actions import.
func TestImportAWS_EC2AndRunCommandResources(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0":      "Instance::i-0123456789abcdef0",
		"arn:aws:ec2:us-east-1:123456789012:instance/*":                        "Instance::*",
		"arn:aws:ssm:us-east-1::document/AWS-RunShellScript":                   "Document::AWS-RunShellScript",
		"arn:aws:ec2:us-east-1:123456789012:volume/vol-1":                      "Volume::vol-1",
		"arn:aws:ec2:us-east-1:123456789012:key-pair/ops":                      "KeyPair::ops",
		"arn:aws:ec2:us-east-1:123456789012:security-group/web":                "SecurityGroup::web",
		"arn:aws:ec2:us-east-1:123456789012:elastic-ip/eipalloc-0123456789a":   "ElasticIp::eipalloc-0123456789a",
		"arn:aws:ec2:us-east-1:123456789012:vpc-flow-log/fl-0123456789abcdef0": "VpcFlowLog::fl-0123456789abcdef0",
		"arn:aws:ec2:us-east-1:123456789012:network-interface/eni-0123456789a": "NetworkInterface::eni-0123456789a",
		"arn:aws:ssm:us-east-1:123456789012:parameter/app/db":                  "Parameter::app/db",
	} {
		got, ok := arnToResource(arn)
		if !ok || !strings.HasPrefix(got, strings.SplitN(want, "::", 2)[0]+"::") || strings.TrimSuffix(got, "*") != strings.TrimSuffix(want, "*") {
			t.Errorf("%s -> %q %v, want %q", arn, got, ok, want)
		}
	}
	stmts, unsupported, err := ImportAWS(`{"Statement":[
	  {"Effect":"Allow","Action":["ssm:SendCommand"],"Resource":["arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0","arn:aws:ssm:us-east-1::document/AWS-RunShellScript"]},
	  {"Effect":"Allow","Action":["ssm:UpdateInstanceInformation","ec2messages:GetMessages","ec2messages:SendReply"],"Resource":"*"},
	  {"Effect":"Allow","Action":["ec2:DescribeInstances","ec2:ImportKeyPair","ec2:DescribeNetworkInterfaces","ec2:CreateFlowLogs","ec2:DescribeFlowLogs","ec2:DeleteFlowLogs"],"Resource":"*"}]}`)
	if err != nil || len(unsupported) != 0 || len(stmts) != 3 {
		t.Fatalf("import: %v unsupported=%v stmts=%d", err, unsupported, len(stmts))
	}
	if _, unsupported, _ := ImportAWS(`{"Statement":[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"}]}`); len(unsupported) == 0 {
		t.Errorf("an EC2 action the shim does not serve must still be reported, not imported")
	}
}
