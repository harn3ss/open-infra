package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// netStackTemplate is a network stack: a VPC with a public subnet routed to an internet gateway, a
// private subnet, and an S3 gateway endpoint.
const netStackTemplate = `
Resources:
  VPC:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.40.0.0/16 }
  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref VPC, CidrBlock: 10.40.1.0/24 }
  PrivateSubnet:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref VPC, CidrBlock: 10.40.2.0/24 }
  IGW:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags: [{ Key: Name, Value: edge }]
  Attach:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties: { VpcId: !Ref VPC, InternetGatewayId: !Ref IGW }
  PublicRT:
    Type: AWS::EC2::RouteTable
    Properties: { VpcId: !Ref VPC }
  DefaultRoute:
    Type: AWS::EC2::Route
    DependsOn: Attach
    Properties: { RouteTableId: !Ref PublicRT, DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref IGW }
  PublicAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: { SubnetId: !Ref PublicSubnet, RouteTableId: !Ref PublicRT }
  S3Endpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties: { VpcId: !Ref VPC, ServiceName: !Sub "com.amazonaws.${AWS::Region}.s3" }
`

// netStackRecord is the stack as deployed in namespace ns: its record names the kinds it applied.
func netStackRecord(name, ns string) cfn.StackRecord {
	return cfn.StackRecord{Name: name, Namespace: ns, Status: "CREATE_COMPLETE", Template: netStackTemplate,
		CreatedAt: "2026-11-01T10:00:00Z", UpdatedAt: "2026-11-01T10:05:00Z",
		Resources: []cfn.StackResource{
			{LogicalID: "VPC", APIVersion: "openinfra.dev/v1", Kind: "Vpc", Name: "net-vpc", Type: "AWS::EC2::VPC", Status: "CREATE_COMPLETE"},
			{LogicalID: "PublicSubnet", APIVersion: "openinfra.dev/v1", Kind: "Subnet", Name: "net-public", Type: "AWS::EC2::Subnet", Status: "CREATE_COMPLETE"},
			{LogicalID: "PrivateSubnet", APIVersion: "openinfra.dev/v1", Kind: "Subnet", Name: "net-private", Type: "AWS::EC2::Subnet", Status: "CREATE_COMPLETE"},
			{LogicalID: "S3Endpoint", APIVersion: "openinfra.dev/v1", Kind: "VpcEndpoint", Name: "net-s3endpoint", Type: "AWS::EC2::VPCEndpoint", Status: "CREATE_COMPLETE"},
		}}
}

// stackRecordConfigMap is a stack record as a front door with no record namespace keeps one (in its own
// namespace, ec2TestNS). A stack in the member account's home is the member account's, kept under its own
// record name and account label (cfn_accounts.go).
func stackRecordConfigMap(t *testing.T, rec cfn.StackRecord) *unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	name, labels := "cfn-stack-"+rec.Name, map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": rec.Name}
	if rec.Namespace == memberHome {
		name, labels[labelRecordAccount] = physicalRecordName(testMember, name), testMember
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": name, "namespace": ec2TestNS, "labels": labels},
		"data":     map[string]any{"stack.json": string(data)}}}
}

var structuralLists = map[schema.GroupVersionResource]string{
	vmClaimGVR: "VirtualMachineList", vpcGVR: "VpcList", subnetGVR: "SubnetList", natGatewayGVR: "NatGatewayList",
	vpcEndpointGVR: "VpcEndpointList", configMapGVR: "ConfigMapList", secretGVR: "SecretList",
}

// netObjects are what the net stack (named stack, deployed in namespace ns) and the operator (natively: the
// NAT gateway and the VPC's default route to it, the private subnet's ACL rules) left in ns.
func netObjects(t *testing.T, stack, ns string) []runtime.Object {
	in := func(u *unstructured.Unstructured) *unstructured.Unstructured { u.SetNamespace(ns); return u }
	view, _ := cfnViewJSON(cfn.AWSView{CidrBlock: "10.40.0.0/16"})
	vpc := in(ec2Obj("Vpc", "net-vpc", map[string]any{"routes": []any{map[string]any{"cidr": "0.0.0.0/0", "nextHop": "10.40.1.254"}}},
		map[string]any{"ready": true}, map[string]string{cfn.AWSViewAnnotation: view}))
	pub := in(ec2Obj("Subnet", "net-public", map[string]any{"cidr": "10.40.1.0/24", "vpc": "net-vpc"}, map[string]any{"ready": true}, nil))
	priv := in(ec2Obj("Subnet", "net-private", map[string]any{"cidr": "10.40.2.0/24", "vpc": "net-vpc", "acls": []any{
		map[string]any{"direction": "ingress", "action": "allow", "cidr": "10.40.0.0/16"},
		map[string]any{"direction": "ingress", "action": "drop", "protocol": "tcp", "port": int64(22), "priority": int64(2000)},
	}}, map[string]any{"ready": true}, nil))
	nat := in(ec2Obj("NatGateway", "net-nat", map[string]any{"vpc": "net-vpc", "subnet": "net-public", "internalIp": "10.40.1.254"},
		map[string]any{"ready": true}, nil))
	ep := in(ec2Obj("VpcEndpoint", "net-s3endpoint", map[string]any{"service": "s3", "vpcEndpointType": "Gateway", "vpc": "net-vpc"},
		map[string]any{"dnsName": "s3.net-vpc.vpce.internal"}, nil))
	ep.SetLabels(map[string]string{"cfn.openinfra.dev/stack": stack})
	return []runtime.Object{vpc, pub, priv, nat, ep, stackRecordConfigMap(t, netStackRecord(stack, ns))}
}

// structuralFixture is the EC2 front door over the net stack, and the physical ids DescribeStackResources
// lists the stack's resources by (each one's Ref), by logical id.
func structuralFixture(t *testing.T, objs ...runtime.Object) (*ec2Handler, *dynamicfake.FakeDynamicClient, map[string]string) {
	t.Helper()
	objs = append(netObjects(t, "net", ec2TestNS), objs...)
	// The fake guesses a kind's resource from its name (NatGateway -> natgatewaies): a NAT gateway is
	// created under its resource instead.
	var nats, rest []runtime.Object
	for _, o := range objs {
		if u, ok := o.(*unstructured.Unstructured); ok && u.GetKind() == "NatGateway" {
			nats = append(nats, o)
			continue
		}
		rest = append(rest, o)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), structuralLists, rest...)
	for _, o := range nats {
		u := o.(*unstructured.Unstructured)
		if _, err := dyn.Resource(natGatewayGVR).Namespace(u.GetNamespace()).Create(context.Background(), u, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	h, _ := ec2Fixture(t)
	h.door.shimDyn = dyn
	h.door.callerDyn = func(string, []string) (dynamic.Interface, error) { return dyn, nil }
	rec := netStackRecord("net", ec2TestNS)
	refs := map[string]string{}
	for _, f := range h.door.foldedResources(context.Background(), &rec, nil) {
		refs[f.LogicalID] = f.PhysicalID
	}
	for _, id := range []string{"IGW", "Attach", "PublicRT", "DefaultRoute", "PublicAssoc"} {
		if refs[id] == "" {
			t.Fatalf("DescribeStackResources lists no physical id for %s: %v", id, refs)
		}
	}
	return h, dyn, refs
}

func mustContain(t *testing.T, what, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("%s must contain %s; got %.2000s", what, want, body)
		}
	}
}

// A stack's internet gateway is described under the id its Ref gave the stack (the id DescribeStackResources
// lists), attached to the VPC its attachment joins it to, with its tags and CloudFormation's.
func TestEC2_DescribeInternetGateways_TheStacksGateway(t *testing.T) {
	h, _, refs := structuralFixture(t)
	igw := refs["IGW"]
	if !strings.HasPrefix(igw, "igw-") {
		t.Fatalf("the gateway's Ref is %q", igw)
	}
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInternetGateways"}})
	if w.Code != 200 {
		t.Fatalf("DescribeInternetGateways: %d %s", w.Code, w.Body.String())
	}
	mustContain(t, "DescribeInternetGateways", w.Body.String(), "<internetGatewaySet><item><internetGatewayId>"+igw+"</internetGatewayId>",
		"<attachmentSet><item><vpcId>net-vpc</vpcId><state>available</state></item></attachmentSet>",
		"<key>Name</key><value>edge</value>", "<key>aws:cloudformation:logical-id</key><value>IGW</value>",
		"<key>aws:cloudformation:stack-name</key><value>net</value>")
	for _, f := range []url.Values{
		{"InternetGatewayId.1": {igw}},
		{"Filter.1.Name": {"attachment.vpc-id"}, "Filter.1.Value.1": {"net-vpc"}},
		{"Filter.1.Name": {"internet-gateway-id"}, "Filter.1.Value.1": {"igw-*"}},
	} {
		f.Set("Action", "DescribeInternetGateways")
		if w := ec2Call(h, ec2Alice, f); !strings.Contains(w.Body.String(), igw) {
			t.Errorf("%v must select the stack's gateway: %s", f, w.Body.String())
		}
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInternetGateways"}, "Filter.1.Name": {"attachment.vpc-id"}, "Filter.1.Value.1": {"another"}}); strings.Contains(w.Body.String(), igw) {
		t.Errorf("a gateway attached to no such VPC was selected: %s", w.Body.String())
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInternetGateways"}, "InternetGatewayId.1": {"igw-00000000000000000"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>InvalidInternetGatewayID.NotFound</Code>") {
		t.Errorf("an unknown gateway: %d %s", w.Code, w.Body.String())
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInternetGateways"}, "Filter.1.Name": {"bogus"}, "Filter.1.Value.1": {"x"}}); !strings.Contains(w.Body.String(), "InvalidParameterValue") {
		t.Errorf("an unknown filter: %s", w.Body.String())
	}
}

// Once its VPC is gone the gateway is detached; a stack whose record says it was deleted holds none.
func TestEC2_DescribeInternetGateways_FollowsTheVPC(t *testing.T) {
	h, dyn, refs := structuralFixture(t)
	if err := dyn.Resource(vpcGVR).Namespace(ec2TestNS).Delete(context.Background(), "net-vpc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInternetGateways"}})
	mustContain(t, "a gateway whose VPC is gone", w.Body.String(), "<internetGatewayId>"+refs["IGW"]+"</internetGatewayId><attachmentSet/>")
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeRouteTables"}}); strings.Contains(w.Body.String(), refs["PublicRT"]) {
		t.Errorf("a route table of a VPC that is gone was described: %s", w.Body.String())
	}
}

// A stack's route table is described under its Ref, with its route under the route's (the table's id and
// destination) and its subnet association under the association's; the VPC's main route table carries the
// kind: Vpc's own routes, a route to a NAT gateway naming it.
func TestEC2_DescribeRouteTables_TheStacksTablesAndTheVPCsMain(t *testing.T) {
	h, _, refs := structuralFixture(t)
	rt, route, assoc, igw := refs["PublicRT"], refs["DefaultRoute"], refs["PublicAssoc"], refs["IGW"]
	if !strings.HasPrefix(rt, "rtb-") || route != rt+"|0.0.0.0/0" || !strings.HasPrefix(assoc, "rtbassoc-") {
		t.Fatalf("the stack's Refs: table %q route %q association %q", rt, route, assoc)
	}
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeRouteTables"}})
	if w.Code != 200 {
		t.Fatalf("DescribeRouteTables: %d %s", w.Code, w.Body.String())
	}
	main := mainRouteTableID(ec2TestNS, "net-vpc")
	body := w.Body.String()
	mustContain(t, "DescribeRouteTables", body,
		"<routeTableId>"+rt+"</routeTableId><vpcId>net-vpc</vpcId>",
		"<destinationCidrBlock>10.40.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId><state>active</state><origin>CreateRouteTable</origin>",
		"<destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><gatewayId>"+igw+"</gatewayId><state>active</state><origin>CreateRoute</origin>",
		"<routeTableAssociationId>"+assoc+"</routeTableAssociationId><routeTableId>"+rt+"</routeTableId><subnetId>net-public</subnetId><main>false</main>",
		"<key>aws:cloudformation:logical-id</key><value>PublicRT</value>",
		"<routeTableId>"+main+"</routeTableId>",
		"<destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><natGatewayId>net-nat</natGatewayId><state>active</state>",
		"<routeTableId>"+main+"</routeTableId><main>true</main>")
	sel := func(f url.Values) string {
		f.Set("Action", "DescribeRouteTables")
		return ec2Call(h, ec2Alice, f).Body.String()
	}
	if b := sel(url.Values{"Filter.1.Name": {"association.subnet-id"}, "Filter.1.Value.1": {"net-public"}}); !strings.Contains(b, rt) || strings.Contains(b, main) {
		t.Errorf("association.subnet-id must select the subnet's table: %s", b)
	}
	if b := sel(url.Values{"Filter.1.Name": {"association.main"}, "Filter.1.Value.1": {"true"}}); strings.Contains(b, rt) || !strings.Contains(b, main) {
		t.Errorf("association.main=true must select the main table: %s", b)
	}
	if b := sel(url.Values{"RouteTableId.1": {rt}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {"net-vpc"}}); !strings.Contains(b, rt) || strings.Contains(b, main) {
		t.Errorf("a RouteTableId names that table: %s", b)
	}
	if b := sel(url.Values{"Filter.1.Name": {"route.gateway-id"}, "Filter.1.Value.1": {igw}}); !strings.Contains(b, rt) || strings.Contains(b, main) {
		t.Errorf("route.gateway-id must select the table routing to the gateway: %s", b)
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeRouteTables"}, "RouteTableId.1": {"rtb-00000000000000000"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>InvalidRouteTableID.NotFound</Code>") {
		t.Errorf("an unknown table: %d %s", w.Code, w.Body.String())
	}
}

// The VPC's default network ACL is associated with each subnet that has no rules of its own; a subnet's
// spec.acls are its own network ACL, in OVN's order, closing with what OVN does with the rest (pass).
func TestEC2_DescribeNetworkAcls(t *testing.T) {
	h, _, _ := structuralFixture(t)
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkAcls"}})
	if w.Code != 200 {
		t.Fatalf("DescribeNetworkAcls: %d %s", w.Code, w.Body.String())
	}
	def := shortHashID("acl-", "default-network-acl/"+ec2TestNS+"/net-vpc", 17)
	own := shortHashID("acl-", "subnet-network-acl/"+ec2TestNS+"/net-private", 17)
	mustContain(t, "DescribeNetworkAcls", w.Body.String(),
		"<networkAclId>"+def+"</networkAclId><vpcId>net-vpc</vpcId><default>true</default>",
		"<ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock>",
		"<networkAclId>"+def+"</networkAclId><subnetId>net-public</subnetId>",
		"<networkAclId>"+own+"</networkAclId><vpcId>net-vpc</vpcId><default>false</default>",
		"<ruleNumber>100</ruleNumber><protocol>6</protocol><ruleAction>deny</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock><portRange><from>22</from><to>22</to></portRange>",
		"<ruleNumber>200</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>false</egress><cidrBlock>10.40.0.0/16</cidrBlock>",
		"<ruleNumber>32767</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>false</egress>",
		"<networkAclId>"+own+"</networkAclId><subnetId>net-private</subnetId>")
	b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkAcls"}, "Filter.1.Name": {"association.subnet-id"}, "Filter.1.Value.1": {"net-public"}}).Body.String()
	if !strings.Contains(b, def) || strings.Contains(b, own) {
		t.Errorf("association.subnet-id must select the subnet's ACL: %s", b)
	}
	b = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkAcls"}, "Filter.1.Name": {"default"}, "Filter.1.Value.1": {"true"}}).Body.String()
	if !strings.Contains(b, def) || strings.Contains(b, own) {
		t.Errorf("default=true must select the default ACL: %s", b)
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkAcls"}, "NetworkAclId.1": {"acl-00000000000000000"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>InvalidNetworkAclID.NotFound</Code>") {
		t.Errorf("an unknown ACL: %d %s", w.Code, w.Body.String())
	}
}

// A stack's VPC endpoint is described under its Ref (its kind: VpcEndpoint's name), with AWS's service name.
func TestEC2_DescribeVpcEndpoints(t *testing.T) {
	h, _, _ := structuralFixture(t)
	rec := netStackRecord("net", ec2TestNS)
	trs, err := cfn.TemplateResourcesOf(&rec, nil, "AWS::EC2::VPCEndpoint")
	if err != nil || len(trs) != 1 {
		t.Fatalf("the endpoint's Ref: %v %v", trs, err)
	}
	ep := trs[0].Ref
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeVpcEndpoints"}})
	if w.Code != 200 {
		t.Fatalf("DescribeVpcEndpoints: %d %s", w.Code, w.Body.String())
	}
	mustContain(t, "DescribeVpcEndpoints", w.Body.String(), "<vpcEndpointSet><item><vpcEndpointId>"+ep+"</vpcEndpointId>",
		"<vpcEndpointType>Gateway</vpcEndpointType><vpcId>net-vpc</vpcId><serviceName>com.amazonaws.us-east-1.s3</serviceName><state>available</state>",
		"<dnsEntrySet><item><dnsName>s3.net-vpc.vpce.internal</dnsName></item></dnsEntrySet>",
		"<key>aws:cloudformation:logical-id</key><value>S3Endpoint</value>", "<key>aws:cloudformation:stack-name</key><value>net</value>")
	b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeVpcEndpoints"}, "VpcEndpointId.1": {ep}, "Filter.1.Name": {"service-name"}, "Filter.1.Value.1": {"com.amazonaws.*.s3"}}).Body.String()
	if !strings.Contains(b, ep) {
		t.Errorf("the endpoint by id and service name: %s", b)
	}
	if b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeVpcEndpoints"}, "Filter.1.Name": {"vpc-endpoint-type"}, "Filter.1.Value.1": {"Interface"}}).Body.String(); strings.Contains(b, ep) {
		t.Errorf("a Gateway endpoint is not an Interface one: %s", b)
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeVpcEndpoints"}, "VpcEndpointId.1": {"vpce-00000000000000000"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>InvalidVpcEndpointId.NotFound</Code>") {
		t.Errorf("an unknown endpoint: %d %s", w.Code, w.Body.String())
	}
}

var structuralOps = []string{"DescribeInternetGateways", "DescribeRouteTables", "DescribeNetworkAcls", "DescribeVpcEndpoints"}

// Authorized as ec2:<Action> on Resource "*", before anything is read: an assumed role with no policy is
// refused each, and an id that exists or not is refused alike. A caller whose RBAC refuses the VPCs (legacy)
// is refused, and one that may not read the stack (legacy) is not shown the stack's gateway or tables.
func TestEC2_StructuralDescribes_Denied(t *testing.T) {
	h, dyn, refs := structuralFixture(t)
	role := iam.Claims{Sub: "assumed-role/r/s", AssumedRole: "r"}
	h.door.authz = checkerFor()
	for _, op := range structuralOps {
		if w := ec2Call(h, role, url.Values{"Action": {op}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
			t.Errorf("%s by an assumed role with no policy: %d %s", op, w.Code, w.Body.String())
		}
	}
	if w := ec2Call(h, role, url.Values{"Action": {"DescribeInternetGateways"}, "InternetGatewayId.1": {refs["IGW"]}}); w.Code != 403 {
		t.Errorf("an existing gateway's id is refused like any other: %d %s", w.Code, w.Body.String())
	}
	// A User's explicit Deny on one of them refuses it.
	h.door.authz = checkerFor(dpAllow([]string{"ec2:*"}, "*"), dpDeny([]string{"ec2:DescribeRouteTables"}, "*"))
	if w := ec2Call(h, iam.Claims{Sub: "tester"}, url.Values{"Action": {"DescribeRouteTables"}}); w.Code != 403 {
		t.Errorf("a User's Deny on ec2:DescribeRouteTables: %d %s", w.Code, w.Body.String())
	}
	if w := ec2Call(h, iam.Claims{Sub: "tester"}, url.Values{"Action": {"DescribeInternetGateways"}}); w.Code != 200 {
		t.Errorf("the User's other describes stay allowed: %d %s", w.Code, w.Body.String())
	}
	h.door.authz = nil
	// Legacy: the stack's template is read only for a caller that may read the stack.
	h.door.cs = csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return !(a.Resource == "applications" && a.Name == "net") })
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInternetGateways"}})
	if w.Code != 200 || strings.Contains(w.Body.String(), refs["IGW"]) {
		t.Errorf("a caller that may not read the stack was shown its gateway: %d %s", w.Code, w.Body.String())
	}
	if b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeRouteTables"}}).Body.String(); strings.Contains(b, refs["PublicRT"]) ||
		!strings.Contains(b, mainRouteTableID(ec2TestNS, "net-vpc")) {
		t.Errorf("without the stack read only the VPC's own table is shown: %s", b)
	}
	// Legacy: the caller's RBAC is its read permission on the kinds.
	dyn.PrependReactor("list", "vpcs", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(vpcGVR.GroupResource(), "", errors.New("RBAC"))
	})
	for _, op := range []string{"DescribeInternetGateways", "DescribeRouteTables", "DescribeNetworkAcls"} {
		if w := ec2Call(h, ec2Alice, url.Values{"Action": {op}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
			t.Errorf("%s by a caller RBAC refuses the VPCs: %d %s", op, w.Code, w.Body.String())
		}
	}
}

// In enforce IAM policy alone decides, and what it allowed is read with the shim's client: a caller with no
// RBAC of its own reads the account's structure; a describe its policy does not allow is refused.
func TestEC2_StructuralDescribes_Enforce(t *testing.T) {
	h, _, refs := structuralFixture(t)
	forbidden := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), structuralLists)
	forbidden.PrependReactor("*", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: a.GetResource().Group, Resource: a.GetResource().Resource}, "", errors.New("no RBAC"))
	})
	h.door.callerDyn = func(string, []string) (dynamic.Interface, error) { return forbidden, nil }
	h.door.cs = csWithSAR(false) // no SubjectAccessReview counts in enforce
	user := iam.Claims{Sub: "tester"}
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:DescribeInternetGateways", "ec2:DescribeRouteTables",
		"ec2:DescribeNetworkAcls", "ec2:DescribeVpcEndpoints"}, "*")))
	for op, want := range map[string]string{"DescribeInternetGateways": refs["IGW"], "DescribeRouteTables": refs["PublicRT"],
		"DescribeNetworkAcls": "<subnetId>net-public</subnetId>", "DescribeVpcEndpoints": "<vpcEndpointId>net-s3endpoint</vpcEndpointId>"} {
		if w := ec2Call(h, user, url.Values{"Action": {op}}); w.Code != 200 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("enforce: %s IAM policy allows: %d %.600s", op, w.Code, w.Body.String())
		}
	}
	h.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"ec2:DescribeVpcs"}, "*")))
	for _, op := range structuralOps {
		if w := ec2Call(h, user, url.Values{"Action": {op}}); w.Code != 403 || !strings.Contains(w.Body.String(), "not authorized to perform: ec2:"+op) {
			t.Errorf("enforce: %s IAM policy does not allow: %d %.300s", op, w.Code, w.Body.String())
		}
	}
}

// The reads are the caller's account's: a member account's request reads its home namespace and its own
// stacks, never the management account's, and the management account's reads stay where they were.
func TestEC2_StructuralReads_AccountScoped(t *testing.T) {
	h, _, _ := structuralFixture(t, netObjects(t, "team-net", memberHome)...)
	// The member account's VPC is another VPC of the same name, in its home.
	n, _, err := h.network(memberCtx(), ec2Alice, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.vpcs) != 1 || n.vpcs[0].GetNamespace() != memberHome || len(n.parts) == 0 {
		t.Fatalf("a member account's network: %d VPCs, %d stack parts", len(n.vpcs), len(n.parts))
	}
	for _, p := range n.parts {
		if p.rec.Namespace != memberHome {
			t.Errorf("a member account read the management account's stack %s", p.rec.Name)
		}
	}
	if mainRouteTableID(memberHome, "net-vpc") == mainRouteTableID(ec2TestNS, "net-vpc") {
		t.Error("two accounts' VPCs of one name must not share a main route table id")
	}
	mgmt, _, err := h.network(context.Background(), ec2Alice, false, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range mgmt.parts {
		if p.rec.Namespace != ec2TestNS {
			t.Errorf("the management account read a member account's stack in %s", p.rec.Namespace)
		}
	}
	if len(mgmt.vpcs) != 1 || mgmt.vpcs[0].GetNamespace() != ec2TestNS {
		t.Errorf("the management account's VPCs: %v", mgmt.vpcs)
	}
}
