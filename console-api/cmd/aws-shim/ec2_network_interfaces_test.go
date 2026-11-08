package main

import (
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const eniTestAccount = "123456789012" // the fixture door's account (ec2Fixture's)

// vpcFnClaim is a kind: Function in ns, with spec.vpcConfig when vpc is non-nil.
func vpcFnClaim(ns, name string, vpc map[string]any) *unstructured.Unstructured {
	spec := map[string]any{"runtime": "python3.12", "handler": "app.handler"}
	if vpc != nil {
		spec["vpcConfig"] = vpc
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Function",
		"metadata": map[string]any{"name": name, "namespace": ns, "creationTimestamp": "2026-11-01T10:00:00Z"}, "spec": spec}}
}

// eniFixture is an EC2 handler whose account (eniTestAccount) has: a VPC s-vpc with subnets s-a and s-b, a
// security group s-sg named web-sg, the function orders (in the Lambda API's namespace, VpcConfig s-a and
// s-b, one environment running in s-a), the function reports (in the stack namespace, s-a, no VpcId given,
// scaled to zero) and the function plain (no VpcConfig).
func eniFixture(t *testing.T, objs ...runtime.Object) *ec2Handler {
	t.Helper()
	view, _ := cfnViewJSON(cfn.AWSView{GroupName: "web-sg"})
	objs = append([]runtime.Object{
		ec2Obj("Vpc", "s-vpc", map[string]any{}, map[string]any{"ready": true}, nil),
		ec2Obj("Subnet", "s-a", map[string]any{"cidr": "10.20.0.0/24", "vpc": "s-vpc"}, map[string]any{"ready": true}, nil),
		ec2Obj("Subnet", "s-b", map[string]any{"cidr": "10.20.1.0/24", "vpc": "s-vpc"}, map[string]any{"ready": true}, nil),
		ec2Obj("SecurityGroup", "s-sg", map[string]any{"vpc": "s-vpc"}, nil, map[string]string{cfn.AWSViewAnnotation: view}),
		vpcFnClaim("default", "orders", map[string]any{"subnetIds": []any{"s-a", "s-b"}, "securityGroupIds": []any{"s-sg"}, "vpcId": "s-vpc"}),
		vpcFnClaim(ec2TestNS, "reports", map[string]any{"subnetIds": []any{"s-a"}, "securityGroupIds": []any{"s-sg"}}),
		vpcFnClaim("default", "plain", nil),
	}, objs...)
	lists := map[schema.GroupVersionResource]string{
		vmClaimGVR: "VirtualMachineList", vmXRGVR: "XVirtualMachineList", volumeGVR: "VolumeList", functionClaimGVR: "FunctionList",
		securityGroupGVR: "SecurityGroupList", vpcGVR: "VpcList", subnetGVR: "SubnetList", serviceGVR: "ServiceList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), lists, objs...)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	door := &cfnDoorway{shimDyn: dyn, ns: ec2TestNS, account: eniTestAccount, region: "us-east-1", cs: csWithSAR(true), authzNS: "authz",
		callerDyn: func(string, []string) (dynamic.Interface, error) { return dyn, nil }, logger: logger}
	h := newEC2Handler(door, nil, logger)
	h.fns = newFnLocator(dyn, logger, "default", ec2TestNS)
	h.vpc = newVPCInterfaces(nil, nil, nil, "", nil)
	at := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	h.vpc.testAttach(vpcInterface{IP: "10.17.0.5", Namespace: "default", Pod: "orders-00001-deployment-abc", Account: eniTestAccount,
		Function: "orders", VpcID: "s-vpc", SubnetID: "s-a", SubnetIDs: []string{"s-a", "s-b"}, SecurityGroupIDs: []string{"s-sg"},
		ENI: lambdaENIID(eniTestAccount, "orders", "s-a"), MAC: "0a:58:0a:11:00:05", Attached: at})
	// Another account's function of the same name and subnet: never this account's interface.
	h.vpc.testAttach(vpcInterface{IP: "10.17.0.9", Namespace: memberHome, Pod: "orders-00001-deployment-xyz", Account: testMember,
		Function: "orders", VpcID: "s-vpc", SubnetID: "s-a", ENI: lambdaENIID(testMember, "orders", "s-a"), Attached: at})
	return h
}

// testAttach records an interface as attached (the IP-object watch's attach, without a cluster).
func (v *vpcInterfaces) testAttach(in vpcInterface) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.byIP[in.IP] = append(v.byIP[in.IP], in)
}

// Lambda's network interfaces: one per function and subnet of its VpcConfig, requester-managed, of type
// lambda, with the function's security groups; its address is a running environment's, none while the
// function is scaled to zero. Filters, ids and malformed ids answer as EC2's do.
func TestEC2_DescribeNetworkInterfaces(t *testing.T) {
	h := eniFixture(t)
	ordersA, ordersB := lambdaENIID(eniTestAccount, "orders", "s-a"), lambdaENIID(eniTestAccount, "orders", "s-b")
	reports := lambdaENIID(eniTestAccount, "reports", "s-a")
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkInterfaces"}})
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("DescribeNetworkInterfaces: %d %s", w.Code, body)
	}
	if strings.Count(body, "<networkInterfaceId>") != 3 {
		t.Fatalf("want 3 interfaces (orders in s-a and s-b, reports in s-a; plain has no VpcConfig): %s", body)
	}
	mustContain(t, "DescribeNetworkInterfaces", body,
		"<networkInterfaceId>"+ordersA+"</networkInterfaceId><subnetId>s-a</subnetId><vpcId>s-vpc</vpcId><availabilityZone>us-east-1a</availabilityZone>"+
			"<description>AWS Lambda VPC ENI-orders</description><ownerId>"+eniTestAccount+"</ownerId><requesterId>lambda.amazonaws.com</requesterId>"+
			"<requesterManaged>true</requesterManaged><status>in-use</status><macAddress>0a:58:0a:11:00:05</macAddress>"+
			"<privateIpAddress>10.17.0.5</privateIpAddress><sourceDestCheck>true</sourceDestCheck>"+
			"<groupSet><item><groupId>s-sg</groupId><groupName>web-sg</groupName></item></groupSet><tagSet/>"+
			"<privateIpAddressesSet><item><privateIpAddress>10.17.0.5</privateIpAddress><primary>true</primary></item></privateIpAddressesSet>"+
			"<ipv6AddressesSet/><interfaceType>lambda</interfaceType>",
		// Scaled to zero in s-b: the interface, without an address.
		"<networkInterfaceId>"+ordersB+"</networkInterfaceId><subnetId>s-b</subnetId>",
		// No VpcId in its VpcConfig: the subnet's VPC.
		"<networkInterfaceId>"+reports+"</networkInterfaceId><subnetId>s-a</subnetId><vpcId>s-vpc</vpcId>",
		"<description>AWS Lambda VPC ENI-reports</description>")
	if strings.Contains(body, "10.17.0.9") || strings.Contains(body, lambdaENIID(testMember, "orders", "s-a")) {
		t.Errorf("another account's environment must not be this account's interface: %s", body)
	}
	for _, c := range []struct {
		name, value string
		want        []string
	}{
		{"private-ip-address", "10.17.0.5", []string{ordersA}},
		{"addresses.private-ip-address", "10.17.0.*", []string{ordersA}},
		{"subnet-id", "s-b", []string{ordersB}},
		{"vpc-id", "s-vpc", []string{ordersA, ordersB, reports}},
		{"description", "AWS Lambda VPC ENI-rep*", []string{reports}},
		{"interface-type", "lambda", []string{ordersA, ordersB, reports}},
		{"group-id", "s-sg", []string{ordersA, ordersB, reports}},
		{"requester-managed", "true", []string{ordersA, ordersB, reports}},
		{"status", "available", nil},
		{"owner-id", eniTestAccount, []string{ordersA, ordersB, reports}},
		{"network-interface-id", reports, []string{reports}},
		{"attachment.instance-id", "i-0123456789abcdef0", nil}, // AWS's filter; a Lambda interface has no instance
	} {
		w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkInterfaces"}, "Filter.1.Name": {c.name}, "Filter.1.Value.1": {c.value}})
		got := strings.Count(w.Body.String(), "<networkInterfaceId>")
		if got != len(c.want) {
			t.Errorf("filter %s=%s: %d interfaces, want %d: %s", c.name, c.value, got, len(c.want), w.Body.String())
		}
		for _, id := range c.want {
			if !strings.Contains(w.Body.String(), id) {
				t.Errorf("filter %s=%s must select %s", c.name, c.value, id)
			}
		}
	}
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkInterfaces"}, "NetworkInterfaceId.1": {ordersB}})
	if strings.Count(w.Body.String(), "<networkInterfaceId>") != 1 || !strings.Contains(w.Body.String(), ordersB) {
		t.Errorf("by id: %s", w.Body.String())
	}
	for _, c := range []struct {
		form url.Values
		code string
	}{
		{url.Values{"NetworkInterfaceId.1": {"eni-00000000000000000"}}, "InvalidNetworkInterfaceID.NotFound"},
		{url.Values{"NetworkInterfaceId.1": {"orders"}}, "InvalidNetworkInterfaceID.Malformed"},
		{url.Values{"NetworkInterfaceId.1": {ordersA}, "MaxResults": {"5"}}, "InvalidParameterCombination"},
		{url.Values{"Filter.1.Name": {"bogus"}, "Filter.1.Value.1": {"x"}}, "InvalidParameterValue"},
	} {
		c.form.Set("Action", "DescribeNetworkInterfaces")
		if w := ec2Call(h, ec2Alice, c.form); w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>"+c.code+"</Code>") {
			t.Errorf("%v: want %s, got %d %s", c.form, c.code, w.Code, w.Body.String())
		}
	}
	// Paginated, as the CLI asks.
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeNetworkInterfaces"}, "MaxResults": {"5"}})
	if strings.Count(w.Body.String(), "<networkInterfaceId>") != 3 || strings.Contains(w.Body.String(), "<nextToken>") {
		t.Errorf("MaxResults 5 over 3: %s", w.Body.String())
	}
}
