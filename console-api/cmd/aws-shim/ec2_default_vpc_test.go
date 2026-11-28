package main

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// kubeovnSubnet is a kube-ovn Subnet (cluster-scoped), Ready with free addresses.
func kubeovnSubnet(name, cidr string, free int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "kubeovn.io/v1", "kind": "Subnet",
		"metadata": map[string]any{"name": name}, "spec": map[string]any{"cidrBlock": cidr, "vpc": "ovn-cluster", "natOutgoing": true},
		"status": map[string]any{"v4availableIPs": free, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}}
}

// ec2DefaultVPCFixture: the management account's default subnet (172.31.0.0/20) and the member account's
// (172.31.16.0/20), beside each account's own VPC and subnet.
func ec2DefaultVPCFixture(t *testing.T) *ec2Handler {
	t.Helper()
	h, _ := ec2AccountsFixture(t)
	for _, s := range []*unstructured.Unstructured{kubeovnSubnet("default-vpc", "172.31.0.0/20", 4091),
		kubeovnSubnet("default-vpc-"+testMember, "172.31.16.0/20", 4090)} {
		if _, err := h.door.shimDyn.Resource(kubeovnSubnetGVR).Create(context.Background(), s, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// As AWS gives every account one, each account has its default VPC: 172.31.0.0/16 (isDefault), its default
// subnet (defaultForAz, public) a /20 of its own, listed beside the account's other VPCs and subnets and
// filtered as they are; the other account's is never its own.
func TestEC2DefaultVPC_DescribeVpcsAndSubnets(t *testing.T) {
	h := ec2DefaultVPCFixture(t)
	mgmt, member := context.Background(), memberCtx()
	mgmtVPC := (&defaultVPC{account: "123456789012"}).vpcID()
	memberVPC := (&defaultVPC{account: testMember}).vpcID()

	w := ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeVpcs"}})
	mustHave(t, "management DescribeVpcs", w.Body.String(),
		[]string{"<vpcId>" + mgmtVPC + "</vpcId>", "<cidrBlock>172.31.0.0/16</cidrBlock>", "<isDefault>true</isDefault>", "<vpcId>s-vpc</vpcId>"},
		[]string{memberVPC})
	w = ec2CallIn(h, mgmt, ec2Alice, url.Values{"Action": {"DescribeVpcs"}, "Filter.1.Name": {"is-default"}, "Filter.1.Value.1": {"true"}})
	mustHave(t, "is-default=true", w.Body.String(), []string{mgmtVPC}, []string{"<vpcId>s-vpc</vpcId>"})
	if !strings.HasPrefix(mgmtVPC, "vpc-") || len(mgmtVPC) != len("vpc-")+17 {
		t.Errorf("a default VPC id in AWS's shape: %s", mgmtVPC)
	}

	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeSubnets"}, "Filter.1.Name": {"default-for-az"}, "Filter.1.Value.1": {"true"}})
	b := w.Body.String()
	mustHave(t, "member default subnet", b, []string{"<cidrBlock>172.31.16.0/20</cidrBlock>", "<vpcId>" + memberVPC + "</vpcId>",
		"<defaultForAz>true</defaultForAz>", "<mapPublicIpOnLaunch>true</mapPublicIpOnLaunch>", "<availableIpAddressCount>4090</availableIpAddressCount>"},
		[]string{"172.31.0.0/20", "<subnetId>s-a</subnetId>"})
	subnetID := (&defaultVPC{account: testMember}).subnetID()
	if !strings.Contains(b, "<subnetId>"+subnetID+"</subnetId>") {
		t.Errorf("the member's default subnet by its id %s: %s", subnetID, b)
	}
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeVpcs"}, "VpcId.1": {mgmtVPC}}); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "InvalidVpcID.NotFound") {
		t.Errorf("another account's default VPC is not the member's: %d %s", w.Code, w.Body.String())
	}
}

// Its internet gateway is attached to it, its main route table sends 0.0.0.0/0 there, and its default network
// ACL allows everything, its subnet associated, as AWS creates them.
func TestEC2DefaultVPC_StructuralDescribes(t *testing.T) {
	h, dyn, _ := structuralFixture(t)
	if _, err := dyn.Resource(kubeovnSubnetGVR).Create(context.Background(), kubeovnSubnet("default-vpc", "172.31.0.0/20", 4091), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	d := &defaultVPC{account: "123456789012"}
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInternetGateways"}})
	mustHave(t, "internet gateway", w.Body.String(), []string{"<internetGatewayId>" + d.igwID() + "</internetGatewayId>",
		"<vpcId>" + d.vpcID() + "</vpcId><state>available</state>"}, nil)
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeRouteTables"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {d.vpcID()}})
	mustHave(t, "main route table", w.Body.String(), []string{d.rtbID(), "<destinationCidrBlock>172.31.0.0/16</destinationCidrBlock>",
		"<destinationCidrBlock>0.0.0.0/0</destinationCidrBlock>", "<gatewayId>" + d.igwID() + "</gatewayId>", "<main>true</main>"}, nil)
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkAcls"}, "Filter.1.Name": {"default"}, "Filter.1.Value.1": {"true"}})
	mustHave(t, "default network ACL", w.Body.String(), []string{d.aclID(), "<subnetId>" + d.subnetID() + "</subnetId>"}, nil)
}

// DescribeAccountAttributes names the account's default VPC, and CreateDefaultVpc answers that it exists, as
// AWS does; an account without one yet says none, and CreateDefaultVpc says why it cannot make it.
func TestEC2DefaultVPC_AccountAttributesAndCreateDefaultVpc(t *testing.T) {
	h := ec2DefaultVPCFixture(t)
	member := memberCtx()
	d := &defaultVPC{account: testMember}
	w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeAccountAttributes"}, "AttributeName.1": {"default-vpc"}})
	mustHave(t, "default-vpc", w.Body.String(), []string{"<attributeName>default-vpc</attributeName>", "<attributeValue>" + d.vpcID() + "</attributeValue>"},
		[]string{"supported-platforms"})
	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeAccountAttributes"}})
	mustHave(t, "every attribute", w.Body.String(), []string{"<attributeName>supported-platforms</attributeName>", "<attributeValue>VPC</attributeValue>",
		"<attributeName>vpc-max-security-groups-per-interface</attributeName>"}, nil)
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeAccountAttributes"}, "AttributeName.1": {"nonsense"}}); w.Code != 400 {
		t.Errorf("an unknown attribute: %d %s", w.Code, w.Body.String())
	}
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"CreateDefaultVpc"}}); w.Code != 400 || !strings.Contains(w.Body.String(), "DefaultVpcAlreadyExists") {
		t.Errorf("CreateDefaultVpc with one: %d %s", w.Code, w.Body.String())
	}

	if err := h.door.shimDyn.Resource(kubeovnSubnetGVR).Delete(context.Background(), "default-vpc-"+testMember, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeAccountAttributes"}, "AttributeName.1": {"default-vpc"}})
	mustHave(t, "no default VPC", w.Body.String(), []string{"<attributeValue>none</attributeValue>"}, nil)
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"CreateDefaultVpc"}}); w.Code != 400 || !strings.Contains(w.Body.String(), "UnsupportedOperation") {
		t.Errorf("CreateDefaultVpc without one: %d %s", w.Code, w.Body.String())
	}
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeVpcs"}}); strings.Contains(w.Body.String(), "<isDefault>true</isDefault>") {
		t.Errorf("an account without a default VPC lists one: %s", w.Body.String())
	}
}

// A default VPC whose internet gateway was removed (the account's spec.defaultVpc.internetGateway false): EC2
// lists no internet gateway for it and its main route table has only its local route, as AWS shows one.
func TestEC2DefaultVPC_WithoutItsInternetGateway(t *testing.T) {
	h, dyn, _ := structuralFixture(t)
	sub := kubeovnSubnet("default-vpc", "172.31.0.0/20", 4091)
	sub.Object["spec"].(map[string]any)["natOutgoing"] = false
	if _, err := dyn.Resource(kubeovnSubnetGVR).Create(context.Background(), sub, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	d := &defaultVPC{account: "123456789012"}
	if b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInternetGateways"}}).Body.String(); strings.Contains(b, d.igwID()) {
		t.Errorf("a default VPC without its gateway lists one: %s", b)
	}
	b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeRouteTables"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {d.vpcID()}}).Body.String()
	if !strings.Contains(b, "<destinationCidrBlock>172.31.0.0/16</destinationCidrBlock>") || strings.Contains(b, "0.0.0.0/0") {
		t.Errorf("its main route table must have only its local route: %s", b)
	}
	if b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeVpcs"}, "Filter.1.Name": {"is-default"}, "Filter.1.Value.1": {"true"}}).Body.String(); !strings.Contains(b, d.vpcID()) {
		t.Errorf("it is still the default VPC: %s", b)
	}
	// Its network ACL shows what its subnet enforces: DNS only to the VPC resolver, egress to the platform's
	// networks and itself, then deny.
	b = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkAcls"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {d.vpcID()}}).Body.String()
	for _, want := range []string{
		"<ruleNumber>90</ruleNumber><protocol>17</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>10.43.0.2/32</cidrBlock><portRange><from>53</from><to>53</to></portRange>",
		"<ruleNumber>91</ruleNumber><protocol>6</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>10.43.0.2/32</cidrBlock><portRange><from>53</from><to>53</to></portRange>",
		"<ruleNumber>92</ruleNumber><protocol>17</protocol><ruleAction>deny</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock><portRange><from>53</from><to>53</to></portRange>",
		"<ruleNumber>93</ruleNumber><protocol>6</protocol><ruleAction>deny</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock><portRange><from>53</from><to>53</to></portRange>",
		"<ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>10.43.0.0/16</cidrBlock>",
		"<cidrBlock>172.31.0.0/20</cidrBlock>", "<ruleNumber>32767</ruleNumber><protocol>-1</protocol><ruleAction>deny</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock>"} {
		if !strings.Contains(b, want) {
			t.Errorf("its network ACL lacks %s: %s", want, b)
		}
	}
	if strings.Contains(b, "<ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock>") {
		t.Errorf("its network ACL must not allow all egress: %s", b)
	}
}

// An instance in its account's default subnet is reported in its default VPC, by EC2's ids, and its subnet-id
// and vpc-id filters select it.
func TestEC2DefaultVPC_InstanceInItsDefaultSubnet(t *testing.T) {
	h, _ := ec2Fixture(t, ec2Obj("VirtualMachine", "s-build", map[string]any{"os": "windows-server-2022", "subnet": "default-vpc"},
		map[string]any{"powerState": "Running", "instanceId": "i-0aaaaaaaaaaaaaaa1"}, nil))
	d := &defaultVPC{account: "123456789012"}
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}})
	mustHave(t, "an instance in the default subnet", w.Body.String(),
		[]string{"<subnetId>" + d.subnetID() + "</subnetId>", "<vpcId>" + d.vpcID() + "</vpcId>"}, []string{"<subnetId>default-vpc</subnetId>"})
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}, "Filter.1.Name": {"subnet-id"}, "Filter.1.Value.1": {d.subnetID()}})
	mustHave(t, "subnet-id filter", w.Body.String(), []string{"i-0aaaaaaaaaaaaaaa1"}, nil)
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstances"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {d.vpcID()}})
	mustHave(t, "vpc-id filter", w.Body.String(), []string{"i-0aaaaaaaaaaaaaaa1"}, nil)
}

// A member account's default VPC without its internet gateway, with a public subnet (its kind: Account's
// spec.defaultVpc.publicSubnet): EC2 lists the public subnet beside the default one, an internet gateway
// attached to the VPC, the public subnet's route table sending 0.0.0.0/0 to it and the main route table (the
// default subnet's) still without, and the default subnet's network ACL keeping it inside the platform while
// the default ACL, allowing everything, is the public subnet's.
func TestEC2DefaultVPC_PublicSubnetForLoadBalancers(t *testing.T) {
	h, dyn, _ := structuralFixture(t)
	h.door.authz = doorAccountsAuthz(t)
	ctx := context.Background()
	sub := kubeovnSubnet("default-vpc-"+testMember, "172.31.16.0/20", 4090)
	sub.Object["spec"].(map[string]any)["natOutgoing"] = false
	if _, err := dyn.Resource(kubeovnSubnetGVR).Create(ctx, sub, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	acct := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "organizations.openinfra.dev/v1", "kind": "Account",
		"metadata": map[string]any{"name": testMember},
		"spec": map[string]any{"defaultVpc": map[string]any{"subnetCidr": "172.31.16.0/20", "internetGateway": false,
			"publicSubnet": map[string]any{"subnetCidr": "172.31.240.0/24"}}}}}
	if _, err := h.door.shimDyn.Resource(gvrAccounts).Create(ctx, acct, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	member := memberCtx()
	d := &defaultVPC{account: testMember}

	b := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeSubnets"}}).Body.String()
	mustHave(t, "the public subnet", b, []string{"<subnetId>" + d.publicSubnetID() + "</subnetId>", "<cidrBlock>172.31.240.0/24</cidrBlock>",
		"<availableIpAddressCount>251</availableIpAddressCount>", "<subnetId>" + d.subnetID() + "</subnetId>"}, nil)
	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeSubnets"}, "SubnetId.1": {d.publicSubnetID()}}).Body.String()
	mustHave(t, "the public subnet by id", b, []string{"<defaultForAz>false</defaultForAz>", "<mapPublicIpOnLaunch>false</mapPublicIpOnLaunch>"},
		[]string{"<subnetId>" + d.subnetID() + "</subnetId>"})

	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeInternetGateways"}}).Body.String()
	mustHave(t, "the gateway the public subnet attaches", b, []string{d.igwID(), d.vpcID()}, nil)

	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeRouteTables"}, "Filter.1.Name": {"association.subnet-id"},
		"Filter.1.Value.1": {d.publicSubnetID()}}).Body.String()
	mustHave(t, "the public subnet's route table", b, []string{d.publicRtbID(), "<destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><gatewayId>" + d.igwID()}, []string{"<routeTableId>" + d.rtbID() + "</routeTableId>"})
	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeRouteTables"}, "RouteTableId.1": {d.rtbID()}}).Body.String()
	if !strings.Contains(b, "<main>true</main>") || strings.Contains(b, "0.0.0.0/0") {
		t.Errorf("the main route table (the default subnet's) must keep no route to the gateway: %s", b)
	}

	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNetworkAcls"}, "NetworkAclId.1": {d.isolatedACLID()}}).Body.String()
	mustHave(t, "the default subnet's ACL", b, []string{"<subnetId>" + d.subnetID() + "</subnetId>", "<cidrBlock>10.43.0.2/32</cidrBlock>",
		"<default>false</default>"}, []string{d.publicSubnetID()})
	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNetworkAcls"}, "NetworkAclId.1": {d.aclID()}}).Body.String()
	mustHave(t, "the default ACL, the public subnet's", b, []string{"<subnetId>" + d.publicSubnetID() + "</subnetId>", "<default>true</default>"},
		[]string{"<subnetId>" + d.subnetID() + "</subnetId>", "10.43.0.2/32"})

	// A CIDR that cannot be a public subnet of the VPC is none.
	for _, bad := range []string{"10.0.0.0/24", "172.31.16.0/24", "172.31.240.1/24", "172.31.0.0/30", "nonsense"} {
		if got := publicSubnetCIDR(bad, "172.31.16.0/20"); got != "" {
			t.Errorf("publicSubnetCIDR(%q) = %q, want none", bad, got)
		}
	}
}

// natVPCFixture: the member account's default VPC with no internet gateway, its public subnet
// (172.31.240.0/24), a NAT gateway there, and a private subnet (172.31.241.0/24) routing one address to the
// gateway; natAddress is the installation's NAT gateway node's address ("": none).
func natVPCFixture(t *testing.T, natAddress string, natted bool) (*ec2Handler, *defaultVPC) {
	t.Helper()
	h, dyn, _ := structuralFixture(t)
	h.door.authz = doorAccountsAuthz(t)
	h.door.natAddress = natAddress
	ctx := context.Background()
	sub := kubeovnSubnet("default-vpc-"+testMember, "172.31.16.0/20", 4090)
	sub.Object["spec"].(map[string]any)["natOutgoing"] = false
	priv := kubeovnSubnet(privateSubnetName(testMember), "172.31.241.0/24", 250)
	priv.Object["spec"].(map[string]any)["natOutgoing"] = natted
	for _, s := range []*unstructured.Unstructured{sub, priv} {
		if _, err := dyn.Resource(kubeovnSubnetGVR).Create(ctx, s, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	acct := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "organizations.openinfra.dev/v1", "kind": "Account",
		"metadata": map[string]any{"name": testMember},
		"spec": map[string]any{"defaultVpc": map[string]any{"subnetCidr": "172.31.16.0/20", "internetGateway": false, "natGateway": true,
			"publicSubnet":  map[string]any{"subnetCidr": "172.31.240.0/24"},
			"privateSubnet": map[string]any{"subnetCidr": "172.31.241.0/24", "natGatewayRoutes": []any{"198.51.100.7/32"}}}}}}
	if _, err := h.door.shimDyn.Resource(gvrAccounts).Create(ctx, acct, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return h, &defaultVPC{account: testMember}
}

// A default VPC's private subnet routes the destinations it names, and only them, to the VPC's NAT gateway in
// its public subnet, as an AWS private subnet does: EC2 lists the subnet, its route table, its network ACL, the
// gateway and the gateway's Elastic IP, by AWS's ids. A principal with no policy is refused.
func TestEC2DefaultVPC_PrivateSubnetAndNATGateway(t *testing.T) {
	h, d := natVPCFixture(t, "192.0.2.11", true)
	member := memberCtx()

	b := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeSubnets"}, "SubnetId.1": {d.privateSubnetID()}}).Body.String()
	mustHave(t, "the private subnet", b, []string{"<cidrBlock>172.31.241.0/24</cidrBlock>", "<availableIpAddressCount>250</availableIpAddressCount>",
		"<state>available</state>", "<defaultForAz>false</defaultForAz>", "<mapPublicIpOnLaunch>false</mapPublicIpOnLaunch>", "<vpcId>" + d.vpcID()},
		[]string{"<subnetId>" + d.subnetID() + "</subnetId>"})

	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeRouteTables"}, "Filter.1.Name": {"association.subnet-id"},
		"Filter.1.Value.1": {d.privateSubnetID()}}).Body.String()
	mustHave(t, "the private subnet's route table", b, []string{d.privateRtbID(), "<destinationCidrBlock>172.31.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId>",
		"<destinationCidrBlock>198.51.100.7/32</destinationCidrBlock><natGatewayId>" + d.natGatewayID() + "</natGatewayId><state>active</state>"},
		[]string{"0.0.0.0/0", "<routeTableId>" + d.rtbID() + "</routeTableId>"})

	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNatGateways"}}).Body.String()
	mustHave(t, "the NAT gateway", b, []string{"<natGatewayId>" + d.natGatewayID() + "</natGatewayId>", "<state>available</state>",
		"<subnetId>" + d.publicSubnetID() + "</subnetId>", "<vpcId>" + d.vpcID() + "</vpcId>", "<connectivityType>public</connectivityType>",
		"<allocationId>" + d.natAllocationID() + "</allocationId>", "<publicIp>192.0.2.11</publicIp>", "<privateIp>172.31.240.4</privateIp>",
		"<networkInterfaceId>" + d.natInterfaceID() + "</networkInterfaceId>"}, []string{"failureCode"})
	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNatGateways"}, "Filter.1.Name": {"subnet-id"}, "Filter.1.Value.1": {d.privateSubnetID()}}).Body.String()
	if strings.Contains(b, d.natGatewayID()) {
		t.Errorf("the NAT gateway is in the public subnet, not the private one: %s", b)
	}
	w := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNatGateways"}, "NatGatewayId.1": {"nat-0123456789abcdef0"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>NatGatewayNotFound</Code>") {
		t.Errorf("an unknown NAT gateway: %d %s", w.Code, w.Body.String())
	}

	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeAddresses"}}).Body.String()
	mustHave(t, "the NAT gateway's Elastic IP", b, []string{"<publicIp>192.0.2.11</publicIp>", "<allocationId>" + d.natAllocationID() + "</allocationId>",
		"<associationId>" + d.natAssociationID() + "</associationId>", "<networkInterfaceId>" + d.natInterfaceID() + "</networkInterfaceId>",
		"<privateIpAddress>172.31.240.4</privateIpAddress>", "<domain>vpc</domain>"}, nil)

	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNetworkAcls"}, "NetworkAclId.1": {d.privateACLID()}}).Body.String()
	mustHave(t, "the private subnet's ACL", b, []string{"<subnetId>" + d.privateSubnetID() + "</subnetId>", "<cidrBlock>198.51.100.7/32</cidrBlock>",
		"<cidrBlock>172.31.16.0/20</cidrBlock>", "<cidrBlock>172.31.241.0/24</cidrBlock>", "<cidrBlock>10.43.0.2/32</cidrBlock>"}, []string{"<subnetId>" + d.subnetID() + "</subnetId>"})
	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNetworkAcls"}, "NetworkAclId.1": {d.isolatedACLID()}}).Body.String()
	mustHave(t, "the default subnet's ACL reaches the private subnet", b, []string{"<cidrBlock>172.31.241.0/24</cidrBlock>"}, []string{"198.51.100.7/32"})

	// Refused without a policy, as every EC2 action.
	if w := ec2CallIn(h, member, iam.Claims{Sub: "carol", Account: testMember}, url.Values{"Action": {"DescribeNatGateways"}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("DescribeNatGateways with no policy: %d %s", w.Code, w.Body.String())
	}

	// A template names the private subnet by its id; one that names no subnet never lands there.
	if got := h.door.defaultSubnets(member)[d.privateSubnetID()]; got != privateSubnetName(testMember) {
		t.Errorf("the private subnet's id names %q", got)
	}
	if !h.door.defaultSubnetsWithoutInternet(member)[privateSubnetName(testMember)] || !h.door.privateSubnets(member)[privateSubnetName(testMember)] {
		t.Error("the private subnet has no route to an internet gateway, and is joined only by naming it")
	}
}

// Without the installation's NAT gateway node the gateway is failed and its routes are blackholes, and the
// private subnet's ACL lets nothing out to them.
func TestEC2DefaultVPC_NATGatewayWithoutItsNode(t *testing.T) {
	h, d := natVPCFixture(t, "", false)
	member := memberCtx()
	b := ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNatGateways"}}).Body.String()
	mustHave(t, "a NAT gateway with no node", b, []string{"<state>failed</state>", "<failureCode>InternalError</failureCode>"}, nil)
	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeRouteTables"}, "RouteTableId.1": {d.privateRtbID()}}).Body.String()
	mustHave(t, "its routes", b, []string{"<destinationCidrBlock>198.51.100.7/32</destinationCidrBlock><natGatewayId>" + d.natGatewayID() + "</natGatewayId><state>blackhole</state>"}, nil)
	b = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DescribeNetworkAcls"}, "NetworkAclId.1": {d.privateACLID()}}).Body.String()
	if strings.Contains(b, "198.51.100.7/32") {
		t.Errorf("the private subnet's ACL allows a route whose gateway is not in service: %s", b)
	}
}

// The private subnet's CIDR and routes: a /24 of the VPC beside its other subnets, and internet destinations only.
func TestEC2DefaultVPC_PrivateSubnetCIDRAndRoutes(t *testing.T) {
	if got := privateSubnetCIDR("172.31.241.0/24", "172.31.16.0/20", "172.31.240.0/24"); got != "172.31.241.0/24" {
		t.Errorf("privateSubnetCIDR = %q", got)
	}
	for _, bad := range []string{"172.31.240.0/24", "172.31.17.0/24", "172.31.241.0/25", "172.31.241.1/24", "10.0.0.0/24", ""} {
		if got := privateSubnetCIDR(bad, "172.31.16.0/20", "172.31.240.0/24"); got != "" {
			t.Errorf("privateSubnetCIDR(%q) = %q, want none", bad, got)
		}
	}
	got := natRoutes([]string{"198.51.100.7/32", "0.0.0.0/0", "10.20.0.0/24", "192.168.100.1/32", "100.64.0.1/32", "198.51.100.7/24", "nonsense", "203.0.113.0/28"})
	if strings.Join(got, ",") != "198.51.100.7/32,203.0.113.0/28" {
		t.Errorf("natRoutes = %v", got)
	}
}

// The VPC resolver names a sender in the private subnet by that subnet, and as one with no route out.
func TestDefaultVPCSenders_PrivateSubnet(t *testing.T) {
	priv := kubeovnSubnet(privateSubnetName(testMember), "172.31.241.0/24", 250)
	priv.SetLabels(map[string]string{"openinfra.dev/default-vpc": "true", "openinfra.dev/account-id": testMember, "openinfra.dev/internet-gateway": "false"})
	def := kubeovnSubnet("default-vpc-"+testMember, "172.31.16.0/20", 4090)
	def.SetLabels(map[string]string{"openinfra.dev/default-vpc": "true", "openinfra.dev/account-id": testMember})
	nets := defaultNetsOf([]unstructured.Unstructured{*priv, *def}, "000000000000")
	s := &defaultVPCSenders{nets: nets, read: time.Now()}
	in, ok := s.At("172.31.241.9", time.Now())
	d := &defaultVPC{account: testMember}
	if !ok || in.Internet || in.SubnetID != d.privateSubnetID() || in.Account != testMember {
		t.Errorf("a private-subnet sender: %+v %v", in, ok)
	}
	if in, ok := s.At("172.31.16.9", time.Now()); !ok || !in.Internet || in.SubnetID != d.subnetID() {
		t.Errorf("a default-subnet sender: %+v %v", in, ok)
	}
}
