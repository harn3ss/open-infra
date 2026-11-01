package cfn

import (
	"os"
	"strings"
	"testing"
)

// The generic lift-and-shift fixture plans as provisionable, and the plan's fidelity summary names
// every property the template relies on that open-infra accepts without emulating (#347 Done-when 4).
func TestPlan_LiftAndShiftFixture_FidelitySummary(t *testing.T) {
	data, err := os.ReadFile("testdata/lift-and-shift/template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlan(data, map[string]string{
		"SiteDomain":        "site.example.test",
		"AppRepositoryName": "fixture-app",
	}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if p.Verdict != ProvisionableWithCaveats {
		t.Fatalf("verdict %s, blockers %v", p.Verdict, p.Blockers)
	}
	all := ""
	for _, f := range p.Fidelity {
		all += f.Resource + ": " + f.Detail + "\n"
	}
	for _, want := range []string{
		"InstanceRole: ManagedPolicyArns are NOT attached",
		"AppBucket: PublicAccessBlockConfiguration is a no-op",
		"SiteDistribution: certificate SiteCertificate is not requested from ACM",
		"AppInstance: Elastic IP AppAddress maps onto this VM's LAN IP",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("fidelity summary is missing %q; got:\n%s", want, all)
		}
	}
	// The UserData references the stack's buckets; it must resolve (and so be applied), not be dropped.
	if strings.Contains(all, "UserData could not be statically resolved") {
		t.Errorf("UserData was dropped as unresolvable:\n%s", all)
	}
	for _, r := range p.Resources {
		if r.LogicalID == "AppInstance" && len(r.Caveats) == 0 {
			t.Errorf("AppInstance carries no per-resource caveats")
		}
	}
}

// A Ref to an in-stack bucket resolves before deploy to the bucket's name — explicit, or the name its
// kind: Bucket is created with — so UserData like `aws s3 cp s3://${Bucket}/...` is applied as written.
func TestPlan_StaticRefOfBucketResolvesInUserData(t *testing.T) {
	tmpl := []byte(`
Resources:
  Named:
    Type: AWS::S3::Bucket
    Properties: { BucketName: fixed-name }
  Generated:
    Type: AWS::S3::Bucket
  Box:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          aws s3 cp s3://${Named}/a /tmp/a
          aws s3 cp s3://${Generated}/b /tmp/b
`)
	p, err := BuildPlan(tmpl, nil, "s")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range p.Fidelity {
		if strings.Contains(f.Detail, "UserData could not be statically resolved") {
			t.Fatalf("UserData dropped: %s", f.Detail)
		}
	}
	r := newResolver(mustParse(t, tmpl), nil, nil, pseudoParams("s"))
	ctx := &stackCtx{template: r.t, resolver: r}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, ctx) }
	if got := r.ref("Named"); got != "fixed-name" {
		t.Errorf("Ref Named = %v, want fixed-name", got)
	}
	if got := r.ref("Generated"); got != k8sName("Generated") {
		t.Errorf("Ref Generated = %v, want %s", got, k8sName("Generated"))
	}
}

func mustParse(t *testing.T, data []byte) *Template {
	t.Helper()
	tm, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}
