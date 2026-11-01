package cfn

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// A rule whose port is set but does not resolve (another resource's GetAtt) is refused — before, it read
// as an absent port, which means ALL ports.
func TestSG_UnresolvablePortIsRefusedNotAllPorts(t *testing.T) {
	tmpl := `
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties: { Engine: postgres, DBInstanceClass: db.t3.micro, AllocatedStorage: 20 }
  AppSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: app
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: !GetAtt DB.Endpoint.Port, ToPort: !GetAtt DB.Endpoint.Port, CidrIp: 10.0.0.0/8 }
`
	m, fs := translateIn(t, tmpl, "AppSG", nil)
	if !strings.Contains(findingsText(fs), "not a concrete port number") {
		t.Fatalf("want a refusal, got findings %q and manifest %#v", findingsText(fs), m)
	}
	if _, msg := sgPorts(nil, nil); msg != "" {
		t.Errorf("absent ports still mean all ports: %q", msg)
	}
	if _, msg := sgPorts("<DB.Endpoint.Port>", nil); msg == "" {
		t.Error("a placeholder FromPort must be refused")
	}
}

// Security-group lists that are not written as a literal list resolve (a list parameter, Fn::Split, a
// list-level Fn::If) or refuse — they never drop to "no security group".
func TestSG_NonLiteralListsResolveOrRefuse(t *testing.T) {
	tmpl := `
Parameters:
  Groups: { Type: CommaDelimitedList, Default: "web,db" }
  Joined: { Type: String, Default: "web,db" }
  UseA: { Type: String, Default: "true" }
Conditions:
  A: !Equals [ !Ref UseA, "true" ]
Resources:
  SgA:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: a }
  SgB:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: b }
  ByParam:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: !Ref Groups }
  BySplit:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: !Split [ ",", !Ref Joined ] }
  ByIf:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: !If [ A, [ !Ref SgA ], [ !Ref SgB ] ] }
  Unresolvable:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: !GetAtt SgA.Something }
`
	for id, want := range map[string]string{"ByParam": "web,db", "BySplit": "web,db", "ByIf": "sga"} {
		m := vmFor(t, tmpl, id, nil)
		if got := strings.Join(toStrs(m.Spec["securityGroups"]), ","); got != want {
			t.Errorf("%s: securityGroups = %q, want %q", id, got, want)
		}
	}
	if m := vmFor(t, tmpl, "ByIf", map[string]string{"UseA": "false"}); strings.Join(toStrs(m.Spec["securityGroups"]), ",") != "sgb" {
		t.Errorf("ByIf (condition off) = %v, want sgb", m.Spec["securityGroups"])
	}
	if _, fs := translateIn(t, tmpl, "Unresolvable", nil); !strings.Contains(findingsText(fs), "does not resolve to a list of security groups") {
		t.Errorf("an unresolvable list must refuse, got %q", findingsText(fs))
	}
}

// A list-level Fn::If around a group's rules keeps the rules its condition picks.
func TestSG_ConditionalRuleListIsKept(t *testing.T) {
	tmpl := `
Parameters:
  Open: { Type: String, Default: "true" }
Conditions:
  IsOpen: !Equals [ !Ref Open, "true" ]
Resources:
  Web:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress: !If
        - IsOpen
        - [ { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 } ]
        - [ { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 10.0.0.0/8 } ]
`
	m, fs := translateIn(t, tmpl, "Web", nil)
	if len(fs) != 0 {
		t.Fatalf("findings: %s", findingsText(fs))
	}
	in, _ := m.Spec["ingress"].([]any)
	if len(in) != 1 || !strings.Contains(strings.ReplaceAll(fmtAny(in), " ", ""), "0.0.0.0/0") {
		t.Fatalf("the condition's rules must be kept: %#v", m.Spec)
	}
}

// A security group named from outside the stack must exist when the instance is applied.
func TestSG_ExternalGroupMustExist(t *testing.T) {
	tmpl := []byte(`
Parameters:
  Group: { Type: String, Default: shared-web }
Resources:
  Box:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref Group ] }
`)
	f := &fakeApplier{}
	_, err := Deploy(context.Background(), tmpl, deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "SecurityGroup shared-web does not exist") {
		t.Fatalf("want a refusal for a missing external group, got %v", err)
	}
	f = &fakeApplier{liveSpecs: map[string]map[string]any{"SecurityGroup/shared-web": {}}}
	if _, err := Deploy(context.Background(), tmpl, deployOpts(), f); err != nil {
		t.Fatalf("an existing external group must be accepted: %v", err)
	}
}

func toStrs(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, e := range l {
			s, _ := e.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

func fmtAny(v any) string { return fmt.Sprint(v) }
