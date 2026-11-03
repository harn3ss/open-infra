package cfn

import (
	"fmt"
	"strings"
	"testing"
)

// #347 item 22: AmazonSSMManagedInstanceCore makes an instance managed — its companion policy carries the
// SSM agent's registration and Run Command channel (what the aws-shim's /v1/vm-commands checks), not only
// the parameter reads.
func TestManagedPolicy_SSMCoreCarriesTheAgentChannel(t *testing.T) {
	out, _, f := managedPolicyCompanions("R", "s-r", []any{"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"})
	if len(f) != 0 || len(out) != 1 {
		t.Fatalf("companions=%d findings=%v", len(out), f)
	}
	got := fmt.Sprint(out[0].Spec["dataPlane"])
	for _, a := range []string{"ssm:UpdateInstanceInformation", "ec2messages:GetMessages", "ec2messages:SendReply", "ssm:GetParameter"} {
		if !strings.Contains(got, a) {
			t.Errorf("AmazonSSMManagedInstanceCore must grant %s: %s", a, got)
		}
	}
}
