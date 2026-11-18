package main

// The account's default VPC, as AWS gives every account one in each region: 172.31.0.0/16, a default subnet
// in each Availability Zone (the region has one here), an internet gateway attached to it, a main route table
// sending 0.0.0.0/0 to that gateway, and a default network ACL allowing everything. DescribeVpcs reports it
// with isDefault, DescribeSubnets its subnet with defaultForAz and mapPublicIpOnLaunch, and
// DescribeAccountAttributes names it (default-vpc); CreateDefaultVpc answers that it exists, as AWS does.
//
// Its subnet is a /20 of 172.31.0.0/16 on the cluster network, each account's its own: the management
// account's kube-ovn subnet default-vpc (172.31.0.0/20, platform/networking/kube-ovn/default-vpc.yaml), a
// member account's default-vpc-<account id> (its kind: Account's spec.defaultVpc). A workload joins it by
// naming the subnet's id (an ECS service's NetworkConfiguration): nothing else is placed in it. Its ids are
// derived from the account, so they are stable and AWS-shaped.

import (
	"context"
	"net/http"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const defaultVPCCidr = "172.31.0.0/16"

var kubeovnSubnetGVR = schema.GroupVersionResource{Group: "kubeovn.io", Version: "v1", Resource: "subnets"}

// defaultVPC is an account's default VPC.
type defaultVPC struct {
	account   string
	subnet    string // its default subnet's kube-ovn subnet: the logical switch a workload in it names
	cidr      string // its default subnet's CIDR
	available int64  // the subnet's free addresses
	ready     bool
	// internet: the default VPC has its internet gateway (its subnet is NATed out). false is one whose
	// gateway was removed (the account's spec.defaultVpc.internetGateway): no gateway, no 0.0.0.0/0 route.
	internet bool
}

func (d *defaultVPC) vpcID() string { return shortHashID("vpc-", "default-vpc/"+d.account, 17) }
func (d *defaultVPC) subnetID() string {
	return shortHashID("subnet-", "default-subnet/"+d.account, 17)
}
func (d *defaultVPC) igwID() string { return shortHashID("igw-", "default-igw/"+d.account, 17) }
func (d *defaultVPC) rtbID() string { return shortHashID("rtb-", "default-route-table/"+d.account, 17) }
func (d *defaultVPC) aclID() string { return shortHashID("acl-", "default-network-acl/"+d.account, 17) }

func (d *defaultVPC) state() string {
	if d.ready {
		return "available"
	}
	return "pending"
}

// defaultSubnetName is the kube-ovn subnet of the request's account's default VPC.
func defaultSubnetName(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return "default-vpc-" + callerAccount(ctx)
	}
	return "default-vpc"
}

// defaultVPCOf reads the default VPC of the account a request acts in (nil: it has none yet). It is read with
// the shim's client, after the caller's authorization: an account's default VPC is its own.
func (h *ec2Handler) defaultVPCOf(ctx context.Context) *defaultVPC {
	if h.door == nil {
		return nil
	}
	return h.door.defaultVPC(ctx)
}

// defaultVPC is the default VPC of the account a request acts in (nil: none yet).
func (h *cfnDoorway) defaultVPC(ctx context.Context) *defaultVPC {
	if h == nil || h.shimDyn == nil {
		return nil
	}
	u, err := h.shimDyn.Resource(kubeovnSubnetGVR).Get(ctx, defaultSubnetName(ctx), metav1.GetOptions{})
	if err != nil {
		return nil
	}
	return defaultVPCFrom(h.accountFor(ctx), u)
}

// defaultSubnets are the request's account's default subnets, as a template names them (subnet id) -> the
// cluster subnet a workload in it joins (cfn.Capabilities.DefaultSubnets).
func (h *cfnDoorway) defaultSubnets(ctx context.Context) map[string]string {
	if d := h.defaultVPC(ctx); d != nil {
		return map[string]string{d.subnetID(): d.subnet}
	}
	return nil
}

// defaultSubnetsWithoutInternet are those of them whose VPC has no internet gateway, by cluster subnet
// (cfn.Capabilities.NoInternetSubnets).
func (h *cfnDoorway) defaultSubnetsWithoutInternet(ctx context.Context) map[string]bool {
	if d := h.defaultVPC(ctx); d != nil && !d.internet {
		return map[string]bool{d.subnet: true}
	}
	return nil
}

// defaultVPCFrom is the default VPC whose subnet is u, of account.
func defaultVPCFrom(account string, u *unstructured.Unstructured) *defaultVPC {
	cidr, _, _ := unstructured.NestedString(u.Object, "spec", "cidrBlock")
	if cidr == "" {
		return nil
	}
	d := &defaultVPC{account: account, subnet: u.GetName(), cidr: cidr, available: usableAddresses(cidr)}
	d.internet, _, _ = unstructured.NestedBool(u.Object, "spec", "natOutgoing")
	conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" && m["status"] == "True" {
			d.ready = true
		}
	}
	switch n := u.Object["status"].(type) {
	case map[string]any:
		switch v := n["v4availableIPs"].(type) {
		case int64:
			d.available = v
		case float64:
			d.available = int64(v)
		}
	}
	return d
}

// --- DescribeVpcs / DescribeSubnets items ---

func (h *ec2Handler) defaultVPCItem(d *defaultVPC, acct string, fs []ec2Filter) (string, bool) {
	rec := ec2Record{fields: map[string][]string{"vpc-id": {d.vpcID()}, "cidr": {defaultVPCCidr},
		"cidr-block-association.cidr-block": {defaultVPCCidr}, "state": {d.state()}, "is-default": {"true"},
		"owner-id": {acct}, "dhcp-options-id": {"default"}}}
	if !rec.matches(fs) {
		return "", false
	}
	assoc := xset("cidrBlockAssociationSet", []string{xtag("associationId", shortHashID("vpc-cidr-assoc-", d.vpcID(), 17)) +
		xtag("cidrBlock", defaultVPCCidr) + "<cidrBlockState><state>associated</state></cidrBlockState>"})
	return xtag("vpcId", d.vpcID()) + xtag("ownerId", acct) + xtag("state", d.state()) + xtag("cidrBlock", defaultVPCCidr) +
		assoc + "<dhcpOptionsId>default</dhcpOptionsId><instanceTenancy>default</instanceTenancy><isDefault>true</isDefault>", true
}

func (h *ec2Handler) defaultSubnetItem(d *defaultVPC, acct string, fs []ec2Filter) (string, bool) {
	arn := "arn:aws:ec2:" + h.region() + ":" + acct + ":subnet/" + d.subnetID()
	rec := ec2Record{fields: map[string][]string{"subnet-id": {d.subnetID()}, "vpc-id": {d.vpcID()}, "cidr-block": {d.cidr},
		"cidr": {d.cidr}, "cidrBlock": {d.cidr}, "availability-zone": {h.zone()}, "availabilityZone": {h.zone()},
		"state": {d.state()}, "default-for-az": {"true"}, "defaultForAz": {"true"}, "map-public-ip-on-launch": {"true"},
		"owner-id": {acct}, "subnet-arn": {arn}}}
	if !rec.matches(fs) {
		return "", false
	}
	return xtag("subnetId", d.subnetID()) + xtag("subnetArn", arn) + xtag("state", d.state()) + xtag("ownerId", acct) +
		xtag("vpcId", d.vpcID()) + xtag("cidrBlock", d.cidr) +
		"<availableIpAddressCount>" + strconv.FormatInt(d.available, 10) + "</availableIpAddressCount>" +
		xtag("availabilityZone", h.zone()) + xtag("availabilityZoneId", h.zoneID()) + "<defaultForAz>true</defaultForAz>" +
		"<mapPublicIpOnLaunch>true</mapPublicIpOnLaunch><assignIpv6AddressOnCreation>false</assignIpv6AddressOnCreation>", true
}

// --- the structural describes: its internet gateway, main route table and default network ACL ---

func (d *defaultVPC) gateway() ec2Gateway {
	state := "attaching"
	if d.ready {
		state = "available"
	}
	return ec2Gateway{id: d.igwID(), atts: []ec2GatewayAttachment{{vpc: d.vpcID(), state: state}}}
}

func (d *defaultVPC) routeTable() ec2RouteTable {
	routes := []ec2Route{{dest: defaultVPCCidr, gateway: "local", state: "active", origin: "CreateRouteTable"}}
	if d.internet { // its route to the internet gateway (none once the gateway is removed)
		routes = append(routes, ec2Route{dest: "0.0.0.0/0", gateway: d.igwID(), state: "active", origin: "CreateRoute"})
	}
	return ec2RouteTable{id: d.rtbID(), vpc: d.vpcID(), routes: routes,
		assocs: []ec2RouteTableAssoc{{id: shortHashID("rtbassoc-", "main/"+d.rtbID(), 17), main: true}}}
}

func (d *defaultVPC) networkACL() ec2NetworkACL {
	entries := defaultACLEntries()
	if !d.internet {
		entries = isolatedACLEntries(d.cidr)
	}
	return ec2NetworkACL{id: d.aclID(), vpc: d.vpcID(), isDefault: true, entries: entries, subnets: []string{d.subnetID()}}
}

// platformNetworks are the networks a default VPC without its internet gateway may still reach: the cluster's
// services (its AWS endpoints, DNS), its pods and the nodes' join network (account-composition.yaml's ACL).
var platformNetworks = []string{"10.43.0.0/16", "10.16.0.0/16", "100.64.0.0/16"}

// vpcResolverAddress is the VPC resolver's (Route 53 Resolver's) address, the vpc-resolver Service: the only
// DNS server a default VPC without its internet gateway may ask (account-composition.yaml's DNS ACL).
const vpcResolverAddress = "10.43.0.2"

// isolatedACLEntries are the network ACL rules a default VPC without its internet gateway has, as its subnet
// enforces them: DNS (UDP and TCP 53) only to the VPC resolver, so its DNS Firewall cannot be gone around;
// egress allowed to the platform's networks and the subnet itself, every other destination denied; ingress
// as AWS's default ACL allows it (its subnet takes what its security groups admit).
func isolatedACLEntries(cidr string) []ec2ACLEntry {
	resolver := vpcResolverAddress + "/32"
	out := []ec2ACLEntry{
		{rule: 90, protocol: "17", action: "allow", cidr: resolver, egress: true, port: 53},
		{rule: 91, protocol: "6", action: "allow", cidr: resolver, egress: true, port: 53},
		{rule: 92, protocol: "17", action: "deny", cidr: "0.0.0.0/0", egress: true, port: 53},
		{rule: 93, protocol: "6", action: "deny", cidr: "0.0.0.0/0", egress: true, port: 53},
	}
	for i, c := range append(append([]string{}, platformNetworks...), cidr) {
		out = append(out, ec2ACLEntry{rule: 100 + 10*i, protocol: "-1", action: "allow", cidr: c, egress: true})
	}
	out = append(out, ec2ACLEntry{rule: 32767, protocol: "-1", action: "deny", cidr: "0.0.0.0/0", egress: true},
		ec2ACLEntry{rule: 100, protocol: "-1", action: "allow", cidr: "0.0.0.0/0", egress: false},
		ec2ACLEntry{rule: 32767, protocol: "-1", action: "deny", cidr: "0.0.0.0/0", egress: false})
	return out
}

// --- DescribeAccountAttributes / CreateDefaultVpc ---

// describeAccountAttributes answers DescribeAccountAttributes: the account's platform (VPC only), its default
// VPC, and its instance and address limits, as AWS reports them.
func (h *ec2Handler) describeAccountAttributes(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	defaultVpc := "none"
	if d := h.defaultVPCOf(ctx); d != nil {
		defaultVpc = d.vpcID()
	}
	attrs := []struct {
		name   string
		values []string
	}{
		{"supported-platforms", []string{"VPC"}},
		{"default-vpc", []string{defaultVpc}},
		{"max-instances", []string{"20"}},
		{"vpc-max-security-groups-per-interface", []string{"5"}},
		{"max-elastic-ips", []string{"5"}},
		{"vpc-max-elastic-ips", []string{"5"}},
	}
	want := setOf(ec2List(r.Form, "AttributeName"))
	var items []string
	for _, a := range attrs {
		if len(want) > 0 && !want[a.name] {
			continue
		}
		var vals []string
		for _, v := range a.values {
			vals = append(vals, xtag("attributeValue", v))
		}
		items = append(items, xtag("attributeName", a.name)+xset("attributeValueSet", vals))
	}
	for name := range want {
		known := false
		for _, a := range attrs {
			known = known || a.name == name
		}
		if !known {
			writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "Value ("+name+") for parameter attributeName is invalid.")
			return
		}
	}
	writeEC2(w, requestID, "DescribeAccountAttributes", xset("accountAttributeSet", items))
}

// createDefaultVpc answers CreateDefaultVpc: an account's default VPC is made with it, so it exists, as AWS
// answers when one does. One that is not there yet is the platform's to make (the account's spec.defaultVpc).
func (h *ec2Handler) createDefaultVpc(ctx context.Context, w http.ResponseWriter, requestID string) {
	if h.defaultVPCOf(ctx) != nil {
		writeEC2Error(w, http.StatusBadRequest, "DefaultVpcAlreadyExists", requestID, "A Default VPC already exists for this account in this region.")
		return
	}
	writeEC2Error(w, http.StatusBadRequest, "UnsupportedOperation", requestID,
		"This account's default VPC is made with the account, and it does not have one yet: ask the platform's operator to give it one.")
}
