package cfn

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// #347 item 1.6: an AWS::EC2::EIP associated with an in-stack AWS::EC2::Instance folds onto that VM's
// LAN IP — spec.expose plus spec.ports derived from the instance's SecurityGroup ingress — and the EIP /
// EIPAssociation themselves provision nothing. Addresses are RFC 5737 documentation ranges.

// vmFor translates instance id in tmpl's stack context (params optional) and returns the VM manifest.
func vmFor(t *testing.T, tmpl, id string, params map[string]string) *Manifest {
	t.Helper()
	ctx := ctxWithParams(t, tmpl, params)
	m, fs := translateEC2Instance(id, ecsResolvedService(t, ctx, id), ctx)
	if len(fs) != 0 {
		t.Fatalf("instance %s must translate cleanly: %s", id, findingsText(fs))
	}
	return m
}

// translateIn runs resource id's own translator in tmpl's stack context.
func translateIn(t *testing.T, tmpl, id string, params map[string]string) (*Manifest, []Finding) {
	t.Helper()
	ctx := ctxWithParams(t, tmpl, params)
	return translatorFor(ctx.template.Resources[id].Type)(id, ecsResolvedService(t, ctx, id), ctx)
}

// portsOf renders spec.ports as "port/PROTO" strings, in order.
func portsOf(m *Manifest) []string {
	var out []string
	ps, _ := m.Spec["ports"].([]any)
	for _, p := range ps {
		pm := p.(map[string]any)
		out = append(out, fmt.Sprintf("%v/%v", pm["port"], pm["protocol"]))
	}
	return out
}

const eipWebTmpl = `
Parameters:
  OfficeCidr: { Type: String, Default: 198.51.100.0/24 }
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 }
        - { IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 0.0.0.0/0 }
        - { IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: !Ref OfficeCidr }
        - { IpProtocol: udp, FromPort: 53, ToPort: 53, CidrIp: 0.0.0.0/0 }
  AltHttps:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: { GroupId: !Ref WebSG, IpProtocol: tcp, FromPort: 8443, ToPort: 8443, CidrIp: 0.0.0.0/0 }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      SecurityGroupIds: [ !Ref WebSG ]
  WebEip:
    Type: AWS::EC2::EIP
    Properties:
      Domain: vpc
      InstanceId: !Ref Web
      Tags: [ { Key: Name, Value: web } ]
`

// The EIP's own InstanceId: the VM is exposed and publishes the SG-allowed ports; the access port (TCP 22)
// is not duplicated; the EIP itself is a no-op; the fidelity caveats ride the VM.
func TestTranslate_EIP_InstanceId_ExposesVMWithSGPorts(t *testing.T) {
	m := vmFor(t, eipWebTmpl, "Web", nil)
	if m.Spec["expose"] != true {
		t.Fatalf("an EIP on the instance must set spec.expose: %#v", m.Spec)
	}
	if got, want := strings.Join(portsOf(m), ","), "53/UDP,80/TCP,443/TCP,8443/TCP"; got != want {
		t.Fatalf("ports derived from the SG (inline + standalone rule), access port excluded: got %s, want %s", got, want)
	}
	cav := strings.Join(m.Caveats, "\n")
	for _, want := range []string{"LAN address, NOT a public internet IP", "does not outlive the VM", "WebEip.AllocationId is a stable synthetic", "80/TCP", "Tags dropped"} {
		if !strings.Contains(cav, want) {
			t.Errorf("VM caveats should mention %q:\n%s", want, cav)
		}
	}
	em, fs := translateIn(t, eipWebTmpl, "WebEip", nil)
	if em != nil || len(fs) != 0 {
		t.Fatalf("an associated EIP provisions nothing standalone (folded into the VM): m=%v fs=%s", em, findingsText(fs))
	}
}

// An EIPAssociation (InstanceId + AllocationId, or the EIP address form) maps exactly like the EIP's own
// InstanceId; the instance's SGs may come from its primary NetworkInterface GroupSet.
func TestTranslate_EIPAssociation_SameMapping(t *testing.T) {
	for name, assoc := range map[string]string{
		"AllocationId": `{ AllocationId: !GetAtt WebEip.AllocationId, InstanceId: !Ref Web, PrivateIpAddress: 192.0.2.10 }`,
		"EIP address":  `{ EIP: !Ref WebEip, InstanceId: !Ref Web }`,
	} {
		t.Run(name, func(t *testing.T) {
			tmpl := `
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      NetworkInterfaces:
        - { DeviceIndex: "0", GroupSet: [ !Ref WebSG ] }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  Assoc:
    Type: AWS::EC2::EIPAssociation
    Properties: ` + assoc + "\n"
			m := vmFor(t, tmpl, "Web", nil)
			if m.Spec["expose"] != true || strings.Join(portsOf(m), ",") != "443/TCP" {
				t.Fatalf("the association must expose the VM with the SG's 443: expose=%v ports=%v", m.Spec["expose"], portsOf(m))
			}
			for _, id := range []string{"WebEip", "Assoc"} {
				if rm, fs := translateIn(t, tmpl, id, nil); rm != nil || len(fs) != 0 {
					t.Fatalf("%s must be a clean no-op (folded into the VM): m=%v fs=%s", id, rm, findingsText(fs))
				}
			}
			if name == "AllocationId" && !strings.Contains(strings.Join(m.Caveats, "\n"), "PrivateIpAddress dropped") {
				t.Errorf("an association's PrivateIpAddress should be a caveat on the VM: %v", m.Caveats)
			}
		})
	}
}

// Port derivation: a small range expands, a wide range / all-ports / SG-sourced rule is a caveat, never
// published. (A wide range also makes the SG translator itself refuse — this exercises only what the EIP
// would publish.)
func TestTranslate_EIP_PortRangesAndCaveats(t *testing.T) {
	tmpl := `
Resources:
  AppSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: app }
  DbSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: db
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 8000, ToPort: 8003, CidrIp: 0.0.0.0/0 }
        - { IpProtocol: tcp, FromPort: 9000, ToPort: 9100, CidrIp: 0.0.0.0/0 }
        - { IpProtocol: tcp, FromPort: 0, ToPort: 65535, CidrIp: 203.0.113.0/24 }
        - { IpProtocol: udp, CidrIp: 203.0.113.0/24 }
        - { IpProtocol: tcp, FromPort: 5432, ToPort: 5432, SourceSecurityGroupId: !Ref AppSG }
        - { IpProtocol: icmp, FromPort: -1, ToPort: -1, CidrIp: 0.0.0.0/0 }
  Db:
    Type: AWS::EC2::Instance
    Properties: { ImageId: debian-12, SecurityGroupIds: [ !Ref DbSG ] }
  DbEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Db }
`
	m := vmFor(t, tmpl, "Db", nil)
	if got, want := strings.Join(portsOf(m), ","), "8000/TCP,8001/TCP,8002/TCP,8003/TCP"; got != want {
		t.Fatalf("only the small range should publish (expanded): got %s, want %s", got, want)
	}
	cav := strings.Join(m.Caveats, "\n")
	for _, want := range []string{
		"port range 9000-9100 (101 ports)",          // wide range -> caveat
		"allows every TCP port from 203.0.113.0/24", // 0-65535 -> caveat
		"allows every UDP port from 203.0.113.0/24", // no ports -> all -> caveat
		"sourced from another SecurityGroup",        // SG-sourced 5432 -> not published
		`IpProtocol "icmp" carries no TCP/UDP port`, // portless protocol
	} {
		if !strings.Contains(cav, want) {
			t.Errorf("caveats should contain %q:\n%s", want, cav)
		}
	}
	for _, p := range portsOf(m) {
		if strings.HasPrefix(p, "5432/") || strings.HasPrefix(p, "9000/") {
			t.Fatalf("an SG-sourced or wide-range port must never be published: %v", portsOf(m))
		}
	}
}

// Protocol -1 ("all") is a caveat — the EIP must NOT publish every port. The VM is still exposed.
func TestTranslate_EIP_ProtocolAllCaveat(t *testing.T) {
	tmpl := `
Resources:
  OpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: open
      SecurityGroupIngress:
        - { IpProtocol: "-1", CidrIp: 0.0.0.0/0 }
  Box:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref OpenSG ] }
  BoxEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Box }
`
	m := vmFor(t, tmpl, "Box", nil)
	if m.Spec["expose"] != true {
		t.Fatalf("the VM is still exposed (access port): %#v", m.Spec)
	}
	if _, has := m.Spec["ports"]; has {
		t.Fatalf("protocol -1 must publish NO ports, got %v", portsOf(m))
	}
	if cav := strings.Join(m.Caveats, "\n"); !strings.Contains(cav, "allows ALL protocols and ports") || !strings.Contains(cav, "only the access port (SSH 22)") {
		t.Fatalf("protocol -1 must be a loud caveat, not a publish-everything:\n%s", cav)
	}
}

// A Windows VM's access port is RDP 3389 — not duplicated; SSH 22 from the SG publishes as an extra port.
func TestTranslate_EIP_WindowsAccessPort(t *testing.T) {
	tmpl := `
Resources:
  WinSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: win
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 3389, ToPort: 3389, CidrIp: 198.51.100.0/24 }
        - { IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 198.51.100.0/24 }
  Win:
    Type: AWS::EC2::Instance
    Properties: { ImageId: windows-server-2022, SecurityGroupIds: [ !Ref WinSG ] }
  WinEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Win }
`
	m := vmFor(t, tmpl, "Win", nil)
	if got := strings.Join(portsOf(m), ","); got != "22/TCP" {
		t.Fatalf("RDP 3389 is the access port (not duplicated); SSH 22 is extra: got %s", got)
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "RDP 3389") {
		t.Errorf("the caveat should name the Windows access port: %v", m.Caveats)
	}
}

// An instance with no SecurityGroup that an Elastic IP publishes gets the stack's default group, as on AWS
// it gets the VPC default group: inbound only from the group's own members, all outbound — never no
// firewall at all.
func TestTranslate_EIP_NoSecurityGroupGetsTheDefaultGroup(t *testing.T) {
	tmpl := `
Resources:
  Bare:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  BareEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Bare }
`
	m, fs := translateIn(t, tmpl, "Bare", nil)
	if len(fs) > 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	sgs, _ := m.Spec["securityGroups"].([]string)
	if len(sgs) != 1 || len(m.Extra) == 0 || m.Extra[0].Kind != "SecurityGroup" || m.Extra[0].Name != sgs[0] {
		t.Fatalf("want the default group attached and emitted, got groups %v, extra %v", m.Spec["securityGroups"], m.Extra)
	}
	ing, _ := m.Extra[0].Spec["ingress"].([]any)
	for _, r := range ing {
		from := r.(map[string]any)["from"].([]any)
		if len(from) != 1 || from[0].(map[string]any)["securityGroup"] != sgs[0] {
			t.Fatalf("the default group admits only its own members, got %v", ing)
		}
	}
	if m.Extra[0].Spec["egress"] != nil {
		t.Fatalf("the default group restricts no egress, got %v", m.Extra[0].Spec["egress"])
	}
}

// A SecurityGroup named by a parameter (a sibling stack's kind: SecurityGroup) is attached, but its rules
// aren't visible here — its ports are NOT guessed; a caveat says so. In-stack groups still derive ports.
func TestTranslate_EIP_OutOfStackSGCaveat(t *testing.T) {
	tmpl := `
Parameters:
  SharedSg: { Type: String, Default: shared-web }
Resources:
  LocalSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: local
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 }
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref LocalSG, !Ref SharedSg ] }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
`
	m := vmFor(t, tmpl, "Web", nil)
	if got := strings.Join(portsOf(m), ","); got != "443/TCP" {
		t.Fatalf("only the in-stack group's port publishes: got %s", got)
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "SecurityGroup(s) shared-web are not in this stack") {
		t.Fatalf("an out-of-stack SG's ports must be a caveat, not guessed: %v", m.Caveats)
	}
}

// The single-gateway case is unchanged: an EIP used as a NatGateway's AllocationId is the NAT border
// device's address — the EIP refuses (author kind: NatGateway + ElasticIp natively), the NatGateway stays
// plan-only, and an instance in the same stack is NOT exposed by it.
func TestTranslate_EIP_NatGatewayAddressUnchanged(t *testing.T) {
	tmpl := `
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 192.0.2.0/24 }
  Pub:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Vpc, CidrBlock: 192.0.2.0/25 }
  NatEip:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  Nat:
    Type: AWS::EC2::NatGateway
    Properties: { AllocationId: !GetAtt NatEip.AllocationId, SubnetId: !Ref Pub }
  App:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
`
	_, fs := translateIn(t, tmpl, "NatEip", nil)
	if !strings.Contains(findingsText(fs), "address of AWS::EC2::NatGateway Nat") {
		t.Fatalf("a NAT gateway's EIP must refuse (native NatGateway+ElasticIp): %s", findingsText(fs))
	}
	if m := vmFor(t, tmpl, "App", nil); m.Spec["expose"] != nil {
		t.Fatalf("a NAT EIP must not expose an unrelated instance: %#v", m.Spec)
	}
	p := mustPlan(t, []byte(tmpl), nil, "s")
	b := blockersJoined(p)
	if p.Verdict != Rejected || !strings.Contains(b, "Nat (AWS::EC2::NatGateway): maps to kind: NatGateway at plan but has no create translator") {
		t.Fatalf("NatGateway handling must be unchanged (plan-only, REJECTED):\n%s", b)
	}
}

// One LAN IP per VM: two EIPs on one instance refuse (whichever way they associate), as does one EIP on
// two instances. The conflicted VM is not exposed.
func TestTranslate_EIP_MultipleRefused(t *testing.T) {
	two := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  EipA:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
  EipB:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  AssocB:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !GetAtt EipB.AllocationId, InstanceId: !Ref Web }
`
	for _, id := range []string{"EipA", "AssocB"} {
		if _, fs := translateIn(t, two, id, nil); !strings.Contains(findingsText(fs), "would carry 2 Elastic IPs (EipA, EipB)") {
			t.Fatalf("%s: two EIPs on one instance must refuse: %s", id, findingsText(fs))
		}
	}
	if m := vmFor(t, two, "Web", nil); m.Spec["expose"] != nil {
		t.Fatalf("a conflicted VM must not be half-exposed: %#v", m.Spec)
	}
	if p := mustPlan(t, []byte(two), nil, "s"); p.Verdict != Rejected {
		t.Fatalf("two EIPs on one instance must REJECT the plan, got %s", p.Verdict)
	}

	shared := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  Db:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  Eip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
  AssocDb:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !GetAtt Eip.AllocationId, InstanceId: !Ref Db }
`
	if _, fs := translateIn(t, shared, "Eip", nil); !strings.Contains(findingsText(fs), "associated with more than one instance (Db, Web)") {
		t.Fatalf("one EIP on two instances must refuse: %s", findingsText(fs))
	}
}

// An EIP associated with nothing in the stack refuses (nothing would carry the address), as does one
// whose InstanceId names an out-of-stack instance.
func TestTranslate_EIP_UnassociatedOrExternalRefused(t *testing.T) {
	tmpl := `
Parameters:
  ExistingInstance: { Type: String, Default: i-0123456789abcdef0 }
Resources:
  Loose:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  External:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref ExistingInstance }
`
	if _, fs := translateIn(t, tmpl, "Loose", nil); !strings.Contains(findingsText(fs), "associated with nothing in the stack") {
		t.Fatalf("an unassociated EIP must refuse: %s", findingsText(fs))
	}
	if _, fs := translateIn(t, tmpl, "External", nil); !strings.Contains(findingsText(fs), "in-stack AWS::EC2::Instance") {
		t.Fatalf("an out-of-stack InstanceId must refuse: %s", findingsText(fs))
	}
	// A specific / BYOIP address can't be honored.
	_, fs := translateEC2EIP("Byo", map[string]any{"Address": "198.51.100.7"}, &stackCtx{template: &Template{Resources: map[string]Resource{}}})
	if !strings.Contains(findingsText(fs), "property Address is not translatable") {
		t.Fatalf("a specific Address must refuse: %s", findingsText(fs))
	}
}

// EIPAssociation refusals: an ENI association (no standalone ENI modeled), an out-of-stack instance or
// allocation, and a missing InstanceId.
func TestTranslate_EIPAssociation_Refusals(t *testing.T) {
	tmpl := `
Parameters:
  ExistingAlloc: { Type: String, Default: eipalloc-0123456789abcdef0 }
  ExistingInstance: { Type: String, Default: i-0123456789abcdef0 }
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  Eip:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  ByEni:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !GetAtt Eip.AllocationId, NetworkInterfaceId: eni-0123456789abcdef0 }
  ToExternal:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !GetAtt Eip.AllocationId, InstanceId: !Ref ExistingInstance }
  FromExternal:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !Ref ExistingAlloc, InstanceId: !Ref Web }
  NoInstance:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !GetAtt Eip.AllocationId }
`
	for id, want := range map[string]string{
		"ByEni":        "NetworkInterfaceId does not map",
		"ToExternal":   "InstanceId must !Ref an in-stack AWS::EC2::Instance",
		"FromExternal": "this deploy path keeps no allocations", // offline: no allocations to associate
		"NoInstance":   "needs an InstanceId",
	} {
		if _, fs := translateIn(t, tmpl, id, nil); !strings.Contains(findingsText(fs), want) {
			t.Errorf("%s: want a refusal containing %q, got: %s", id, want, findingsText(fs))
		}
	}
	// None of those is a valid binding, so the instance is not exposed.
	if m := vmFor(t, tmpl, "Web", nil); m.Spec["expose"] != nil {
		t.Fatalf("refused associations must not expose the VM: %#v", m.Spec)
	}
}

// A conditioned association: an InstanceId wrapped in !If follows the condition — ON exposes the VM,
// OFF leaves the EIP unassociated (refused) and the VM unexposed. A conditioned-OFF EIP exposes nothing.
func TestTranslate_EIP_Conditions(t *testing.T) {
	tmpl := `
Parameters:
  WantEip: { Type: String, Default: "true" }
Conditions:
  HasEip: !Equals [ !Ref WantEip, "true" ]
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
  Eip:
    Type: AWS::EC2::EIP
    Properties:
      InstanceId: !If [ HasEip, !Ref Web, !Ref "AWS::NoValue" ]
`
	if m := vmFor(t, tmpl, "Web", nil); m.Spec["expose"] != true {
		t.Fatalf("condition ON: the !If-wrapped InstanceId must expose the VM: %#v", m.Spec)
	}
	if m := vmFor(t, tmpl, "Web", map[string]string{"WantEip": "false"}); m.Spec["expose"] != nil {
		t.Fatalf("condition OFF: the VM must not be exposed: %#v", m.Spec)
	}
	if _, fs := translateIn(t, tmpl, "Eip", map[string]string{"WantEip": "false"}); !strings.Contains(findingsText(fs), "associated with nothing") {
		t.Fatalf("condition OFF: the EIP has no association and must refuse: %s", findingsText(fs))
	}

	gated := `
Parameters:
  WantEip: { Type: String, Default: "false" }
Conditions:
  HasEip: !Equals [ !Ref WantEip, "true" ]
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  Eip:
    Type: AWS::EC2::EIP
    Condition: HasEip
    Properties: { InstanceId: !Ref Web }
`
	if m := vmFor(t, gated, "Web", nil); m.Spec["expose"] != nil {
		t.Fatalf("a conditioned-OFF EIP must not expose the VM: %#v", m.Spec)
	}
}

// Attributes: GetAtt AllocationId is a stable synthetic eipalloc- id (per stack + logical id, in Sub too);
// Ref / GetAtt PublicIp stay unresolved placeholders (a LAN IP assigned at apply) — never a fake address.
func TestResolve_EIPAttributes(t *testing.T) {
	ctx := ecsCtx(t, eipWebTmpl) // stack "s"
	r := ctx.resolver
	alloc := r.resolve(map[string]any{"Fn::GetAtt": []any{"WebEip", "AllocationId"}})
	s, ok := concrete(alloc)
	if !ok || !regexp.MustCompile(`^eipalloc-[0-9a-f]{17}$`).MatchString(s) {
		t.Fatalf("GetAtt AllocationId must be a concrete eipalloc-<17 hex>, got %#v", alloc)
	}
	if s != eipAllocationID("s", "WebEip") || s != r.resolve(map[string]any{"Fn::Sub": "${WebEip.AllocationId}"}) {
		t.Fatalf("AllocationId must be stable (and the same through Fn::Sub): %s", s)
	}
	if s == eipAllocationID("other-stack", "WebEip") || s == eipAllocationID("s", "OtherEip") {
		t.Fatalf("AllocationId must differ per stack and per logical id")
	}
	for name, v := range map[string]any{
		"Ref":      map[string]any{"Ref": "WebEip"},
		"PublicIp": map[string]any{"Fn::GetAtt": []any{"WebEip", "PublicIp"}},
	} {
		if got, ok := concrete(r.resolve(v)); ok {
			t.Errorf("%s on an EIP is a LAN IP assigned at apply — it must stay unresolved, got %q", name, got)
		}
	}
}

// Plan: a stack whose EIP is associated with an in-stack instance is PROVISIONABLE_WITH_CAVEATS — the EIP
// is Deployable, maps to the VM (spec.expose), and no translator refuses.
func TestPlan_EIP_DeployableWithCaveats(t *testing.T) {
	p := mustPlan(t, []byte(eipWebTmpl), nil, "s")
	if p.Verdict != ProvisionableWithCaveats || len(p.Blockers) != 0 {
		t.Fatalf("want PROVISIONABLE_WITH_CAVEATS and no blocker, got %s:\n%s", p.Verdict, blockersJoined(p))
	}
	for _, r := range p.Resources {
		if !r.Deployable || len(r.TranslateRefusals) != 0 {
			t.Fatalf("%s should be Deployable with no refusal: %+v", r.LogicalID, r)
		}
		if r.LogicalID == "WebEip" && r.Kind != "VirtualMachine(spec.expose)" {
			t.Fatalf("the EIP maps to the VM's expose: kind=%q", r.Kind)
		}
	}
}

// Deploy: the EIP applies no object of its own; the VM is applied with spec.expose + the derived ports.
func TestDeploy_EIP_FoldsIntoVM(t *testing.T) {
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), []byte(eipWebTmpl), deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got := strings.Join(f.appliedNonCM(), ","); got != "SecurityGroup/s-websg,VirtualMachine/s-web" {
		t.Fatalf("only the SG and the VM are applied (the EIP folds into the VM), got %s", got)
	}
	spec := f.liveSpecs["VirtualMachine/s-web"]
	if spec["expose"] != true {
		t.Fatalf("the applied VM must carry expose: %#v", spec)
	}
	if got := strings.Join(portsOf(&Manifest{Spec: spec}), ","); got != "53/UDP,80/TCP,443/TCP,8443/TCP" {
		t.Fatalf("the applied VM must carry the SG-derived ports, got %s", got)
	}
}
