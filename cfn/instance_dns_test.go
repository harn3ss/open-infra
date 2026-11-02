package cfn

import (
	"context"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

func withPublicDNSSuffix(t *testing.T, suffix string) {
	t.Helper()
	prev := awsidentity.Current()
	id := prev
	id.PublicDNSSuffix = suffix
	awsidentity.Set(id)
	t.Cleanup(func() { awsidentity.Set(prev) })
}

const dnsTmpl = `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
  Db:
    Type: AWS::EC2::Instance
    Properties: { ImageId: debian-12, SecurityGroupIds: [ !Ref TestSG ] }
Outputs:
  WebPublicDns:  { Value: !GetAtt Web.PublicDnsName }
  WebPrivateDns: { Value: !GetAtt Web.PrivateDnsName }
  DbPublicDns:   { Value: !GetAtt Db.PublicDnsName }
  DbPrivateDns:  { Value: !Sub "${Db.PrivateDnsName}" }
`

func dnsStatus(key string) (map[string]any, bool) {
	switch key {
	case "VirtualMachine/s-web":
		return map[string]any{"ip": "10.16.0.21", "lanIp": "192.0.2.50"}, true
	case "VirtualMachine/s-db":
		return map[string]any{"ip": "10.16.0.22"}, true
	}
	return nil, false
}

// PrivateDnsName is AWS's name for the VM's address; PublicDnsName the VM's LAN IP on the install's public
// DNS suffix, and "" for an instance with no public address — as AWS reports them.
func TestInstance_DNSNamesResolve(t *testing.T) {
	withPublicDNSSuffix(t, "lan.example.test")
	rec, err := Deploy(context.Background(), []byte(dnsTmpl), deployOpts(), &fakeApplier{statusFn: dnsStatus})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	out := outputMap(rec)
	for k, want := range map[string]string{
		"WebPublicDns":  "ec2-192-0-2-50.lan.example.test",
		"WebPrivateDns": "ip-10-16-0-21.ec2.internal",
		"DbPublicDns":   "",
		"DbPrivateDns":  "ip-10-16-0-22.ec2.internal",
	} {
		o, ok := out[k]
		if !ok || o.OutputValue != want {
			t.Errorf("Output %s = %q (present %v), want %q", k, o.OutputValue, ok, want)
		}
	}
}

// With no public DNS suffix an exposed instance has no public DNS name either: "", and the plan says why.
func TestInstance_PublicDNSNameEmptyWithoutSuffix(t *testing.T) {
	withPublicDNSSuffix(t, "")
	rec, err := Deploy(context.Background(), []byte(dnsTmpl), deployOpts(), &fakeApplier{statusFn: dnsStatus})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got := outputMap(rec)["WebPublicDns"].OutputValue; got != "" {
		t.Fatalf("PublicDnsName without a suffix = %q, want \"\"", got)
	}
	p, err := BuildPlan([]byte(dnsTmpl), nil, "s")
	if err != nil {
		t.Fatal(err)
	}
	if p.Verdict == Rejected {
		t.Fatalf("the DNS-name attributes must plan: %v", p.Blockers)
	}
	got := fidelityText(p)
	for _, want := range []string{"Web.PublicDnsName is \"\": this install sets no public DNS suffix", "Db.PublicDnsName is \"\": the instance has no public address", "Web.PrivateDnsName is AWS's name for the VM's address (ip-a-b-c-d.ec2.internal)"} {
		if !strings.Contains(got, want) {
			t.Errorf("fidelity summary is missing %q:\n%s", want, got)
		}
	}
}

func TestAWSIdentity_DNSNames(t *testing.T) {
	if got := awsidentity.PrivateDNSName("10.1.2.3", "us-east-1"); got != "ip-10-1-2-3.ec2.internal" {
		t.Errorf("us-east-1 private name = %q", got)
	}
	if got := awsidentity.PrivateDNSName("10.1.2.3", "eu-west-1"); got != "ip-10-1-2-3.eu-west-1.compute.internal" {
		t.Errorf("eu-west-1 private name = %q", got)
	}
	id := awsidentity.Identity{PublicDNSSuffix: "lan.example.test"}
	if got := id.PublicDNSName("192.0.2.9"); got != "ec2-192-0-2-9.lan.example.test" {
		t.Errorf("public name = %q", got)
	}
	if got := id.PublicDNSName("not-an-ip"); got != "" {
		t.Errorf("a non-address must give no name, got %q", got)
	}
	if got := (awsidentity.Identity{}).PublicDNSName("192.0.2.9"); got != "" {
		t.Errorf("no suffix must give no name, got %q", got)
	}
	env := map[string]string{"PUBLIC_DNS_SUFFIX": ".LAN.Example.Test."}
	got, warns := awsidentity.FromEnv(func(k string) string { return env[k] })
	if got.PublicDNSSuffix != "lan.example.test" || len(warns) != 0 {
		t.Errorf("FromEnv suffix = %q warns=%v", got.PublicDNSSuffix, warns)
	}
	env["PUBLIC_DNS_SUFFIX"] = "bad suffix!"
	got, warns = awsidentity.FromEnv(func(k string) string { return env[k] })
	if got.PublicDNSSuffix != "" || len(warns) == 0 {
		t.Errorf("an invalid suffix must be ignored with a warning: %q %v", got.PublicDNSSuffix, warns)
	}
}
