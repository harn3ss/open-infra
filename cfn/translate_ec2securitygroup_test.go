package cfn

import (
	"strings"
	"testing"
)

// A faithful SG: a CidrIp ingress on a single TCP port, and an egress to an in-stack SG reference.
func TestTranslate_EC2SecurityGroup_Faithful(t *testing.T) {
	tmpl := `
Resources:
  DbSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: db }
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 }
      SecurityGroupEgress:
        - { IpProtocol: tcp, FromPort: 5432, ToPort: 5432, DestinationSecurityGroupId: !Ref DbSG }
`
	ctx := ecsCtx(t, tmpl)
	props := ecsResolvedService(t, ctx, "WebSG")
	m, fs := translateEC2SecurityGroup("WebSG", props, ctx)
	if len(fs) != 0 {
		t.Fatalf("a faithful SG must translate cleanly: %s", findingsText(fs))
	}
	if m.Kind != "SecurityGroup" || m.APIVersion != "openinfra.dev/v1" {
		t.Fatalf("bad head: %+v", m)
	}
	ing, _ := m.Spec["ingress"].([]any)
	if len(ing) != 1 {
		t.Fatalf("want 1 ingress rule: %#v", m.Spec["ingress"])
	}
	r0 := ing[0].(map[string]any)
	if r0["protocol"] != "TCP" {
		t.Errorf("ingress protocol: %#v", r0["protocol"])
	}
	if p, _ := r0["ports"].([]any); len(p) != 1 || p[0] != 443 {
		t.Errorf("ingress ports should be [443]: %#v", r0["ports"])
	}
	from := r0["from"].([]any)[0].(map[string]any)
	if from["cidr"] != "0.0.0.0/0" {
		t.Errorf("ingress source cidr: %#v", from)
	}
	eg, _ := m.Spec["egress"].([]any)
	if len(eg) != 1 {
		t.Fatalf("want 1 egress rule: %#v", m.Spec["egress"])
	}
	to := eg[0].(map[string]any)["to"].([]any)[0].(map[string]any)
	if to["securityGroup"] != "dbsg" {
		t.Errorf("egress to an in-stack SG ref should map to securityGroup=dbsg: %#v", to)
	}
}

// All-ports (FromPort 0 / ToPort 65535) -> empty ports (the kind: SecurityGroup "all" convention).
func TestTranslate_EC2SecurityGroup_AllPorts(t *testing.T) {
	tmpl := `
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: all
      SecurityGroupIngress:
        - { IpProtocol: udp, FromPort: 0, ToPort: 65535, CidrIp: 10.0.0.0/8 }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateEC2SecurityGroup("SG", ecsResolvedService(t, ctx, "SG"), ctx)
	if len(fs) != 0 {
		t.Fatalf("all-ports must translate: %s", findingsText(fs))
	}
	r0 := m.Spec["ingress"].([]any)[0].(map[string]any)
	if _, has := r0["ports"]; has {
		t.Errorf("all-ports should emit NO ports key (empty=all): %#v", r0)
	}
	if r0["protocol"] != "UDP" {
		t.Errorf("protocol UDP expected: %#v", r0["protocol"])
	}
}

// FAIL-CLOSED: every rule kind: SecurityGroup cannot express EXACTLY must produce a Finding (which blocks
// the resource), never a looser emitted rule.
func TestTranslate_EC2SecurityGroup_FailClosed(t *testing.T) {
	cases := map[string]struct {
		rule string
		want string
	}{
		"protocol -1 (all)":   {`{ IpProtocol: "-1", CidrIp: 0.0.0.0/0 }`, "only TCP or UDP"},
		"icmp":                {`{ IpProtocol: icmp, FromPort: -1, ToPort: -1, CidrIp: 0.0.0.0/0 }`, "only TCP or UDP"},
		"true port range":     {`{ IpProtocol: tcp, FromPort: 8000, ToPort: 8100, CidrIp: 0.0.0.0/0 }`, "port range"},
		"ipv6 source":         {`{ IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIpv6: "::/0" }`, "CidrIpv6"},
		"no source":           {`{ IpProtocol: tcp, FromPort: 443, ToPort: 443 }`, "needs a CidrIp"},
		"out-of-stack SG ref": {`{ IpProtocol: tcp, FromPort: 443, ToPort: 443, SourceSecurityGroupId: sg-0abc123 }`, "in-stack AWS::EC2::SecurityGroup"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tmpl := "Resources:\n  SG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n      GroupDescription: x\n      SecurityGroupIngress:\n        - " + c.rule + "\n"
			ctx := ecsCtx(t, tmpl)
			_, fs := translateEC2SecurityGroup("SG", ecsResolvedService(t, ctx, "SG"), ctx)
			if !strings.Contains(findingsText(fs), c.want) {
				t.Fatalf("expected a fail-closed refusal containing %q, got: %s", c.want, findingsText(fs))
			}
		})
	}
}

// An unknown property is refused (blockUnknownProps), not silently dropped.
func TestTranslate_EC2SecurityGroup_UnknownProp(t *testing.T) {
	_, fs := translateEC2SecurityGroup("SG", map[string]any{
		"GroupDescription": "x", "SomeBogusProp": true,
	}, nil)
	if !strings.Contains(findingsText(fs), "SomeBogusProp") {
		t.Fatalf("unknown prop must be refused: %s", findingsText(fs))
	}
}
