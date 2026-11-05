package cfn

import (
	"fmt"
	"strings"
	"testing"
)

// AmazonSSMManagedInstanceCore makes an instance managed: the shipped policy carries the SSM agent's
// registration and Run Command channel (what the aws-shim's /v1/vm-commands checks), not only the
// parameter reads, in the data-plane statements today's front doors evaluate.
func TestManagedPolicy_SSMCoreCarriesTheAgentChannel(t *testing.T) {
	refs, _, f := managedPolicyRefs("R", []any{"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"})
	if len(f) != 0 || len(refs) != 1 || refs[0] != "aws-amazonssmmanagedinstancecore" {
		t.Fatalf("refs=%v findings=%v", refs, f)
	}
	p, _ := ManagedPolicyByName("AmazonSSMManagedInstanceCore")
	stmts, err := p.DataPlaneStatements()
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(stmts)
	for _, a := range []string{"ssm:UpdateInstanceInformation", "ec2messages:GetMessages", "ec2messages:SendReply", "ssm:GetParameter"} {
		if !strings.Contains(got, a) {
			t.Errorf("AmazonSSMManagedInstanceCore must grant %s: %s", a, got)
		}
	}
}
