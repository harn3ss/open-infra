package cfn

import "testing"

// A standalone AWS::EC2::SecurityGroupIngress/Egress may name its group by !GetAtt <sg>.GroupId as well as
// by !Ref <sg>: for a VPC security group both are its id, and AWS accepts either.
func TestTranslate_EC2SecurityGroup_StandaloneRuleByGetAttGroupId(t *testing.T) {
	tmpl := `
Resources:
  AppSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: app
      VpcId: vpc-0123456789abcdef0
  WebIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: { GroupId: !GetAtt AppSG.GroupId, IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 0.0.0.0/0 }
  DnsEgress:
    Type: AWS::EC2::SecurityGroupEgress
    Properties: { GroupId: !GetAtt [AppSG, GroupId], IpProtocol: udp, FromPort: 53, ToPort: 53, CidrIp: 0.0.0.0/0 }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateEC2SecurityGroup("AppSG", ecsResolvedService(t, ctx, "AppSG"), ctx)
	if len(fs) != 0 {
		t.Fatalf("a rule naming its group by GetAtt GroupId must collate cleanly: %s", findingsText(fs))
	}
	if ing, _ := m.Spec["ingress"].([]any); len(ing) != 1 {
		t.Fatalf("want the GetAtt-named ingress rule collated, got %#v", m.Spec["ingress"])
	}
	if eg, _ := m.Spec["egress"].([]any); len(eg) != 1 {
		t.Fatalf("want the GetAtt-named egress rule collated, got %#v", m.Spec["egress"])
	}
	for _, id := range []string{"WebIngress", "DnsEgress"} {
		if mm, cf := translateEC2SecurityGroupRule(id, ecsResolvedService(t, ctx, id), ctx); mm != nil || len(cf) != 0 {
			t.Fatalf("%s: an in-stack rule named by GetAtt GroupId must be a clean no-op: manifest=%v findings=%s", id, mm, findingsText(cf))
		}
	}
}

// Another attribute of the group (its VpcId) names no group: the rule is refused, never collated.
func TestTranslate_EC2SecurityGroup_StandaloneRuleByOtherAttributeRefused(t *testing.T) {
	tmpl := `
Resources:
  AppSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: app, VpcId: vpc-0123456789abcdef0 }
  OddIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: { GroupId: !GetAtt AppSG.VpcId, IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 0.0.0.0/0 }
`
	ctx := ecsCtx(t, tmpl)
	m, _ := translateEC2SecurityGroup("AppSG", ecsResolvedService(t, ctx, "AppSG"), ctx)
	if ing, _ := m.Spec["ingress"].([]any); len(ing) != 0 {
		t.Fatalf("a rule naming the group's VpcId must not be collated: %#v", m.Spec["ingress"])
	}
	if _, cf := translateEC2SecurityGroupRule("OddIngress", ecsResolvedService(t, ctx, "OddIngress"), ctx); len(cf) == 0 {
		t.Fatal("a rule whose GroupId is the group's VpcId must be refused")
	}
}
