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
		"protocol -1 (all)":      {`{ IpProtocol: "-1", CidrIp: 0.0.0.0/0 }`, "only TCP or UDP"},
		"icmp":                   {`{ IpProtocol: icmp, FromPort: -1, ToPort: -1, CidrIp: 0.0.0.0/0 }`, "only TCP or UDP"},
		"true port range":        {`{ IpProtocol: tcp, FromPort: 8000, ToPort: 8100, CidrIp: 0.0.0.0/0 }`, "port range"},
		"ipv6 source":            {`{ IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIpv6: "::/0" }`, "CidrIpv6"},
		"no source":              {`{ IpProtocol: tcp, FromPort: 443, ToPort: 443 }`, "needs a CidrIp"},
		"out-of-stack SG ref":    {`{ IpProtocol: tcp, FromPort: 443, ToPort: 443, SourceSecurityGroupId: sg-0abc123 }`, "in-stack AWS::EC2::SecurityGroup"},
		"unresolvable !Ref CIDR": {`{ IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: !Ref NoSuchParam }`, "needs a CidrIp"},
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

// A standalone AWS::EC2::SecurityGroupIngress/Egress whose GroupId !Refs an in-stack SG collates into
// that SG's spec.ingress/egress (the circular-ref-breaking pattern), with the same fail-closed fidelity.
func TestTranslate_EC2SecurityGroup_StandaloneRuleCollation(t *testing.T) {
	tmpl := `
Resources:
  AppSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: app
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 }
  ExtraIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: { GroupId: !Ref AppSG, IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 10.0.0.0/8 }
  ExtraEgress:
    Type: AWS::EC2::SecurityGroupEgress
    Properties: { GroupId: !Ref AppSG, IpProtocol: udp, FromPort: 53, ToPort: 53, CidrIp: 0.0.0.0/0 }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateEC2SecurityGroup("AppSG", ecsResolvedService(t, ctx, "AppSG"), ctx)
	if len(fs) != 0 {
		t.Fatalf("standalone-rule collation must translate cleanly: %s", findingsText(fs))
	}
	ing, _ := m.Spec["ingress"].([]any)
	if len(ing) != 2 { // the inline 443 + the collated standalone 22
		t.Fatalf("want 2 ingress rules (inline + collated), got %d: %#v", len(ing), m.Spec["ingress"])
	}
	eg, _ := m.Spec["egress"].([]any)
	if len(eg) != 1 { // the collated standalone 53
		t.Fatalf("want 1 collated egress rule, got %d: %#v", len(eg), m.Spec["egress"])
	}
	// The standalone child translators are no-ops when in-stack (the group owns the rule).
	if mm, cf := translateEC2SecurityGroupRule("ExtraIngress", ecsResolvedService(t, ctx, "ExtraIngress"), ctx); mm != nil || len(cf) != 0 {
		t.Fatalf("an in-stack standalone rule must be a clean no-op: manifest=%v findings=%s", mm, findingsText(cf))
	}
}

// SECURITY (regression): a standalone AWS::EC2::SecurityGroupIngress the template gates OFF with a false
// Condition must NOT be collated into the SG. Before the fix, sgStandaloneRules ignored res.Condition, so
// a rule the operator turned off (classically SSH-from-anywhere) was deployed anyway — a fail-OPEN.
func TestTranslate_EC2SecurityGroup_ConditionedOffStandaloneRuleAbsent(t *testing.T) {
	tmpl := `
Parameters:
  EnableAdmin: { Type: String, Default: "false" }
  OfficeCidr:  { Type: String, Default: "10.20.0.0/16" }
Conditions:
  AdminOn: !Equals [!Ref EnableAdmin, "true"]
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: !Ref OfficeCidr }
  AdminOpenToWorld:
    Type: AWS::EC2::SecurityGroupIngress
    Condition: AdminOn
    Properties: { GroupId: !Ref WebSG, IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0 }
`
	// Condition OFF (default EnableAdmin=false): the port-22 rule must be absent.
	ctx := ecsCtx(t, tmpl)
	m, fs := translateEC2SecurityGroup("WebSG", ecsResolvedService(t, ctx, "WebSG"), ctx)
	if len(fs) != 0 {
		t.Fatalf("must translate cleanly: %s", findingsText(fs))
	}
	ing, _ := m.Spec["ingress"].([]any)
	if len(ing) != 1 {
		t.Fatalf("a conditioned-OFF standalone rule must not be collated — want the 1 inline rule only, got %d: %#v", len(ing), m.Spec["ingress"])
	}
	r0 := ing[0].(map[string]any)
	if p, _ := r0["ports"].([]any); len(p) != 1 || p[0] != 443 {
		t.Fatalf("the surviving rule must be the inline :443, never the gated-off :22: %#v", r0)
	}

	// Condition ON (EnableAdmin=true): the same rule IS collated — proving the skip is condition-driven,
	// not a blanket drop of standalone rules.
	on := ctxWithParams(t, tmpl, map[string]string{"EnableAdmin": "true"})
	mOn, fsOn := translateEC2SecurityGroup("WebSG", ecsResolvedService(t, on, "WebSG"), on)
	if len(fsOn) != 0 {
		t.Fatalf("condition-ON must translate cleanly: %s", findingsText(fsOn))
	}
	if ingOn, _ := mOn.Spec["ingress"].([]any); len(ingOn) != 2 {
		t.Fatalf("with the condition ON the port-22 rule must be collated — want 2 ingress rules, got %d: %#v", len(ingOn), mOn.Spec["ingress"])
	}
}

// Cross-stack SG reference: an ingress rule's SourceSecurityGroupId given as a parameter (a sibling
// stack's SG name passed in) resolves to that kind: SecurityGroup name — like SecurityGroupIds does —
// instead of refusing. A raw sg- id still refuses (opaque).
func TestTranslate_EC2SecurityGroup_SourceSGFromParameter(t *testing.T) {
	tmpl := `
Parameters:
  AppSgName: { Type: String, Default: "app-sg" }
Resources:
  DbSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: db
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 3306, ToPort: 3306, SourceSecurityGroupId: !Ref AppSgName }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateEC2SecurityGroup("DbSG", ecsResolvedService(t, ctx, "DbSG"), ctx)
	if len(fs) != 0 {
		t.Fatalf("a parameter-valued SourceSecurityGroupId must resolve to a SG name: %s", findingsText(fs))
	}
	peer := m.Spec["ingress"].([]any)[0].(map[string]any)["from"].([]any)[0].(map[string]any)
	if peer["securityGroup"] != "app-sg" {
		t.Fatalf("SourceSecurityGroupId from a parameter should map to securityGroup=app-sg: %#v", peer)
	}

	// A raw sg- id passed through a parameter still refuses (opaque, like an AMI).
	raw := ctxWithParams(t, tmpl, map[string]string{"AppSgName": "sg-0abc123"})
	_, fsRaw := translateEC2SecurityGroup("DbSG", ecsResolvedService(t, raw, "DbSG"), raw)
	if !strings.Contains(findingsText(fsRaw), "sg- id") {
		t.Fatalf("a parameter resolving to a raw sg- id must refuse, got: %s", findingsText(fsRaw))
	}
}

// A CidrIp given as `!Ref Param` resolves to the parameter's value — inline and in a collated standalone
// rule — instead of being emitted as the literal intrinsic. Regression for the map[Ref:X]-as-CIDR bug,
// where the raw {Ref: X} was fmt.Sprint'd to "map[Ref:X]" and treated as a real CIDR.
func TestTranslate_EC2SecurityGroup_RefCidrResolves(t *testing.T) {
	tmpl := `
Parameters:
  OfficeCidr: { Type: String, Default: "10.20.0.0/16" }
  DnsCidr:    { Type: String, Default: "10.30.0.0/16" }
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: !Ref OfficeCidr }
  ExtraIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: { GroupId: !Ref WebSG, IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: !Ref DnsCidr }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateEC2SecurityGroup("WebSG", ecsResolvedService(t, ctx, "WebSG"), ctx)
	if len(fs) != 0 {
		t.Fatalf("a !Ref CIDR must resolve, not refuse: %s", findingsText(fs))
	}
	ing, _ := m.Spec["ingress"].([]any)
	if len(ing) != 2 {
		t.Fatalf("want 2 ingress rules (inline + collated standalone): %#v", m.Spec["ingress"])
	}
	got := map[string]bool{}
	for _, raw := range ing {
		c := raw.(map[string]any)["from"].([]any)[0].(map[string]any)["cidr"]
		got[c.(string)] = true
	}
	for _, want := range []string{"10.20.0.0/16", "10.30.0.0/16"} {
		if !got[want] {
			t.Fatalf("a !Ref CIDR must resolve to the parameter value %q; got %#v", want, got)
		}
	}
}

// A standalone rule targeting an out-of-stack group is refused (can't attach to a group we don't manage).
func TestTranslate_EC2SecurityGroupRule_OutOfStackRefused(t *testing.T) {
	_, fs := translateEC2SecurityGroupRule("R", map[string]any{
		"GroupId": "sg-0abc123", "IpProtocol": "tcp", "FromPort": float64(22), "ToPort": float64(22), "CidrIp": "0.0.0.0/0",
	}, nil)
	if !strings.Contains(findingsText(fs), "in-stack AWS::EC2::SecurityGroup") {
		t.Fatalf("a standalone rule on an out-of-stack group must be refused: %s", findingsText(fs))
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
