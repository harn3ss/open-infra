package main

import (
	"context"
	"net/url"
	"strings"
	"testing"

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
}
