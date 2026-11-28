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
// naming the subnet's id (an ECS service's NetworkConfiguration, an EC2 instance's SubnetId) and, in a default
// VPC without its internet gateway, every ECS task and every instance that names no subnet runs in it; nothing
// else is placed in it. Its ids are derived from the account, so they are stable and AWS-shaped.
//
// A member account's default VPC may also have a public subnet (its kind: Account's
// spec.defaultVpc.publicSubnet): a second subnet whose route table sends 0.0.0.0/0 to the VPC's internet
// gateway, where the account's internet-facing load balancers are placed (elbv2.go). In a default VPC without
// its internet gateway, the public subnet attaches one for itself alone: the default subnet keeps its route
// table with no route to it, so the instances there still reach nothing outside the platform. The public
// subnet holds no instances (none is launched into it here); its addresses are the load balancers'.
//
// It may also have a NAT gateway (spec.defaultVpc.natGateway), a public one in the public subnet with an
// Elastic IP, and a private subnet (spec.defaultVpc.privateSubnet) whose route table sends the destinations it
// names, and nothing else, to that gateway, as an AWS private subnet routes them. The private subnet is a /24
// of the cluster network of its own (default-vpc-<account>-private), centralized on the installation's NAT
// gateway node: its traffic to those destinations leaves the platform NATed by that node, with the node's
// address (NAT_GATEWAY_ADDRESS, the Elastic IP's address here). Its network ACL drops every other destination
// outside the VPC, as the default subnet's does without its internet gateway, and nothing outside reaches in.
// An instance in it runs on that node.

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
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
	// public is the CIDR of its public subnet ("" when it has none): the account's
	// spec.defaultVpc.publicSubnet, for its internet-facing load balancers.
	public string
	// private is its private subnet (nil: none), the account's spec.defaultVpc.privateSubnet.
	private *privateSubnet
	// nat: the VPC has a NAT gateway in its public subnet (spec.defaultVpc.natGateway). natAddress is the
	// address its traffic leaves the platform with, its Elastic IP's ("": the installation has no NAT gateway
	// node, so the gateway is not in service).
	nat        bool
	natAddress string
	created    string // when the account was made (its NAT gateway's createTime)
}

// privateSubnet is a default VPC's private subnet: its route table sends routes, and only them, to the VPC's
// NAT gateway.
type privateSubnet struct {
	subnet    string // its kube-ovn subnet
	cidr      string
	routes    []string
	available int64
	ready     bool
	natted    bool // the subnet's traffic is NATed out through the gateway node (natOutgoing)
}

// privateSubnetSuffix ends the kube-ovn name of a default VPC's private subnet.
const privateSubnetSuffix = "-private"

// privateSubnetName is the kube-ovn subnet of account's default VPC's private subnet.
func privateSubnetName(account string) string { return "default-vpc-" + account + privateSubnetSuffix }

func (d *defaultVPC) vpcID() string { return shortHashID("vpc-", "default-vpc/"+d.account, 17) }
func (d *defaultVPC) subnetID() string {
	return shortHashID("subnet-", "default-subnet/"+d.account, 17)
}
func (d *defaultVPC) igwID() string { return shortHashID("igw-", "default-igw/"+d.account, 17) }
func (d *defaultVPC) rtbID() string { return shortHashID("rtb-", "default-route-table/"+d.account, 17) }
func (d *defaultVPC) aclID() string { return shortHashID("acl-", "default-network-acl/"+d.account, 17) }

// The public subnet's ids: the subnet, its route table, and (in a VPC without its internet gateway) the
// network ACL the default subnet keeps once the default ACL is the public subnet's.
func (d *defaultVPC) publicSubnetID() string {
	return shortHashID("subnet-", "public-subnet/"+d.account, 17)
}
func (d *defaultVPC) publicRtbID() string {
	return shortHashID("rtb-", "public-route-table/"+d.account, 17)
}
func (d *defaultVPC) isolatedACLID() string {
	return shortHashID("acl-", "isolated-network-acl/"+d.account, 17)
}

// The private subnet's ids, and the NAT gateway's: the gateway, its Elastic IP's allocation and association,
// and its network interface in the public subnet.
func (d *defaultVPC) privateSubnetID() string {
	return shortHashID("subnet-", "private-subnet/"+d.account, 17)
}
func (d *defaultVPC) privateRtbID() string {
	return shortHashID("rtb-", "private-route-table/"+d.account, 17)
}
func (d *defaultVPC) privateACLID() string {
	return shortHashID("acl-", "private-network-acl/"+d.account, 17)
}
func (d *defaultVPC) natGatewayID() string { return shortHashID("nat-", "nat-gateway/"+d.account, 17) }
func (d *defaultVPC) natAllocationID() string {
	return shortHashID("eipalloc-", "nat-gateway-address/"+d.account, 17)
}
func (d *defaultVPC) natAssociationID() string {
	return shortHashID("eipassoc-", "nat-gateway-address/"+d.account, 17)
}
func (d *defaultVPC) natInterfaceID() string {
	return shortHashID("eni-", "nat-gateway-interface/"+d.account, 17)
}

// natPrivateIP is the NAT gateway's address in the public subnet: its first after the four AWS reserves.
func (d *defaultVPC) natPrivateIP() string {
	p, err := netip.ParsePrefix(d.public)
	if err != nil {
		return ""
	}
	a := p.Addr()
	for range 4 {
		a = a.Next()
	}
	return a.String()
}

// natInService reports whether the NAT gateway forwards: it exists and the installation has a node for it.
func (d *defaultVPC) natInService() bool { return d.nat && d.natAddress != "" }

// subnetIDOf is the EC2 id of the default VPC's subnet whose kube-ovn subnet is name: the private subnet's,
// or the default subnet's.
func (d *defaultVPC) subnetIDOf(name string) string {
	if d.private != nil && name == d.private.subnet {
		return d.privateSubnetID()
	}
	return d.subnetID()
}

// ownCIDRs are the default VPC's subnets that are the account's own on the cluster network: the default
// subnet and its private subnet. (The public subnet holds only load balancers, whose addresses are not in it.)
func (d *defaultVPC) ownCIDRs() []string {
	out := []string{d.cidr}
	if d.private != nil {
		out = append(out, d.private.cidr)
	}
	return out
}

// hasGateway reports whether an internet gateway is attached to the default VPC: its own (internet), or
// the one its public subnet routes to.
func (d *defaultVPC) hasGateway() bool { return d.internet || d.public != "" }

// isPublicSubnet reports whether subnet (a subnet id) routes 0.0.0.0/0 to the VPC's internet gateway: the
// default subnet while the VPC has its own gateway, the public subnet always.
func (d *defaultVPC) isPublicSubnet(subnet string) bool {
	return (subnet == d.subnetID() && d.internet) || (d.public != "" && subnet == d.publicSubnetID())
}

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

// defaultVPCOfSubnet is the default VPC whose subnet is the kube-ovn subnet name (nil: name is not one of a
// default VPC's): default-vpc is the management account's (mgmt), default-vpc-<account> a member account's
// default subnet, and default-vpc-<account>-private its private subnet.
func defaultVPCOfSubnet(name, mgmt string) *defaultVPC {
	switch {
	case name == "default-vpc":
		return &defaultVPC{account: mgmt, subnet: name}
	case strings.HasPrefix(name, "default-vpc-"):
		acct := strings.TrimPrefix(name, "default-vpc-")
		if a, ok := strings.CutSuffix(acct, privateSubnetSuffix); ok {
			return &defaultVPC{account: a, subnet: "default-vpc-" + a, private: &privateSubnet{subnet: name}}
		}
		return &defaultVPC{account: acct, subnet: name}
	}
	return nil
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
	d := defaultVPCFrom(h.accountFor(ctx), u)
	if d != nil && isMemberRequest(ctx) {
		// Its public subnet, NAT gateway and private subnet, from the member account's kind: Account
		// (spec.defaultVpc).
		if a, aerr := h.shimDyn.Resource(gvrAccounts).Get(ctx, callerAccount(ctx), metav1.GetOptions{}); aerr == nil {
			cidr, _, _ := unstructured.NestedString(a.Object, "spec", "defaultVpc", "publicSubnet", "subnetCidr")
			d.public = publicSubnetCIDR(cidr, d.cidr)
			nat, _, _ := unstructured.NestedBool(a.Object, "spec", "defaultVpc", "natGateway")
			d.nat, d.natAddress, d.created = nat && d.public != "", h.natAddress, ec2Time(a.GetCreationTimestamp().Time)
			pc, _, _ := unstructured.NestedString(a.Object, "spec", "defaultVpc", "privateSubnet", "subnetCidr")
			if pc = privateSubnetCIDR(pc, d.cidr, d.public); pc != "" {
				routes, _, _ := unstructured.NestedStringSlice(a.Object, "spec", "defaultVpc", "privateSubnet", "natGatewayRoutes")
				d.private = &privateSubnet{subnet: privateSubnetName(d.account), cidr: pc, routes: natRoutes(routes),
					available: usableAddresses(pc)}
				if ps, perr := h.shimDyn.Resource(kubeovnSubnetGVR).Get(ctx, d.private.subnet, metav1.GetOptions{}); perr == nil {
					if p := defaultVPCFrom(d.account, ps); p != nil && p.cidr == pc {
						d.private.ready, d.private.available, d.private.natted = p.ready, p.available, p.internet
					}
				}
			}
		}
	}
	return d
}

// privateSubnetCIDR is cidr as a default VPC's private subnet ("" if it cannot be one): a /24 inside
// 172.31.0.0/16 that overlaps neither the default subnet (def) nor the public subnet (pub).
func privateSubnetCIDR(cidr, def, pub string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() != 24 || !netip.MustParsePrefix(defaultVPCCidr).Contains(p.Addr()) {
		return ""
	}
	for _, o := range []string{def, pub} {
		if q, qerr := netip.ParsePrefix(o); qerr == nil && q.Overlaps(p) {
			return ""
		}
	}
	return p.String()
}

// nonInternetNetworks are the networks a route to a NAT gateway may not name: the private, shared, loopback,
// link-local, multicast and reserved ranges (the site's own networks among them), and so 0.0.0.0/0 too.
var nonInternetNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/3")}

// natRoutes are the destinations of a private subnet's routes to the NAT gateway, those that name only the
// internet (the account's XRD refuses the rest; one that slipped past is left out, as the composition leaves it).
func natRoutes(dests []string) []string {
	var out []string
	for _, c := range dests {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			continue
		}
		ok := true
		for _, n := range nonInternetNetworks {
			ok = ok && !n.Overlaps(p)
		}
		if ok {
			out = append(out, p.String())
		}
	}
	return out
}

// publicSubnetCIDR is cidr as a default VPC's public subnet ("" if it cannot be one): a CIDR inside
// 172.31.0.0/16 that does not overlap the default subnet (def).
func publicSubnetCIDR(cidr, def string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 16 || p.Bits() > 28 {
		return ""
	}
	vpc := netip.MustParsePrefix(defaultVPCCidr)
	if !vpc.Contains(p.Addr()) {
		return ""
	}
	if d, derr := netip.ParsePrefix(def); derr == nil && d.Overlaps(p) {
		return ""
	}
	return p.String()
}

// defaultSubnets are the request's account's default subnets, as a template names them (subnet id) -> the
// cluster subnet a workload in it joins (cfn.Capabilities.DefaultSubnets).
// Its private subnet is one of them: a template names it by its id.
func (h *cfnDoorway) defaultSubnets(ctx context.Context) map[string]string {
	if d := h.defaultVPC(ctx); d != nil {
		out := map[string]string{d.subnetID(): d.subnet}
		if d.private != nil {
			out[d.privateSubnetID()] = d.private.subnet
		}
		return out
	}
	return nil
}

// defaultSubnetsWithoutInternet are those of them with no route to an internet gateway, by cluster subnet
// (cfn.Capabilities.NoInternetSubnets): the default subnet of a VPC without its internet gateway, and the
// private subnet always.
func (h *cfnDoorway) defaultSubnetsWithoutInternet(ctx context.Context) map[string]bool {
	d := h.defaultVPC(ctx)
	if d == nil {
		return nil
	}
	out := map[string]bool{}
	if !d.internet {
		out[d.subnet] = true
	}
	if d.private != nil {
		out[d.private.subnet] = true
	}
	return out
}

// privateSubnets are the default VPC's subnets a workload lands in only by naming it, by cluster subnet
// (cfn.Capabilities.PrivateSubnets): its private subnet.
func (h *cfnDoorway) privateSubnets(ctx context.Context) map[string]bool {
	if d := h.defaultVPC(ctx); d != nil && d.private != nil {
		return map[string]bool{d.private.subnet: true}
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

// publicSubnetItem is the default VPC's public subnet, as DescribeSubnets lists a subnet the account made:
// not the default for its zone, and no public address mapped on launch (a load balancer's address is its own).
func (h *ec2Handler) publicSubnetItem(d *defaultVPC, acct string, fs []ec2Filter) (string, bool) {
	id := d.publicSubnetID()
	arn := "arn:aws:ec2:" + h.region() + ":" + acct + ":subnet/" + id
	rec := ec2Record{fields: map[string][]string{"subnet-id": {id}, "vpc-id": {d.vpcID()}, "cidr-block": {d.public},
		"cidr": {d.public}, "cidrBlock": {d.public}, "availability-zone": {h.zone()}, "availabilityZone": {h.zone()},
		"state": {d.state()}, "default-for-az": {"false"}, "defaultForAz": {"false"}, "map-public-ip-on-launch": {"false"},
		"owner-id": {acct}, "subnet-arn": {arn}}}
	if !rec.matches(fs) {
		return "", false
	}
	return xtag("subnetId", id) + xtag("subnetArn", arn) + xtag("state", d.state()) + xtag("ownerId", acct) +
		xtag("vpcId", d.vpcID()) + xtag("cidrBlock", d.public) +
		"<availableIpAddressCount>" + strconv.FormatInt(usableAddresses(d.public), 10) + "</availableIpAddressCount>" +
		xtag("availabilityZone", h.zone()) + xtag("availabilityZoneId", h.zoneID()) + "<defaultForAz>false</defaultForAz>" +
		"<mapPublicIpOnLaunch>false</mapPublicIpOnLaunch><assignIpv6AddressOnCreation>false</assignIpv6AddressOnCreation>", true
}

// privateSubnetItem is the default VPC's private subnet, as DescribeSubnets lists a subnet the account made: not
// the default for its zone, and no public address mapped on launch.
func (h *ec2Handler) privateSubnetItem(d *defaultVPC, acct string, fs []ec2Filter) (string, bool) {
	id, p := d.privateSubnetID(), d.private
	arn := "arn:aws:ec2:" + h.region() + ":" + acct + ":subnet/" + id
	state := "pending"
	if p.ready {
		state = "available"
	}
	rec := ec2Record{fields: map[string][]string{"subnet-id": {id}, "vpc-id": {d.vpcID()}, "cidr-block": {p.cidr},
		"cidr": {p.cidr}, "cidrBlock": {p.cidr}, "availability-zone": {h.zone()}, "availabilityZone": {h.zone()},
		"state": {state}, "default-for-az": {"false"}, "defaultForAz": {"false"}, "map-public-ip-on-launch": {"false"},
		"owner-id": {acct}, "subnet-arn": {arn}}}
	if !rec.matches(fs) {
		return "", false
	}
	return xtag("subnetId", id) + xtag("subnetArn", arn) + xtag("state", state) + xtag("ownerId", acct) +
		xtag("vpcId", d.vpcID()) + xtag("cidrBlock", p.cidr) +
		"<availableIpAddressCount>" + strconv.FormatInt(p.available, 10) + "</availableIpAddressCount>" +
		xtag("availabilityZone", h.zone()) + xtag("availabilityZoneId", h.zoneID()) + "<defaultForAz>false</defaultForAz>" +
		"<mapPublicIpOnLaunch>false</mapPublicIpOnLaunch><assignIpv6AddressOnCreation>false</assignIpv6AddressOnCreation>", true
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

// publicRouteTable is the route table of the public subnet of a default VPC without its own internet gateway
// (nil otherwise: with its gateway, the main route table already sends 0.0.0.0/0 there, and the public
// subnet keeps it): the local route, and 0.0.0.0/0 to the gateway the subnet attaches.
func (d *defaultVPC) publicRouteTable() *ec2RouteTable {
	if d.public == "" || d.internet {
		return nil
	}
	return &ec2RouteTable{id: d.publicRtbID(), vpc: d.vpcID(), routes: []ec2Route{
		{dest: defaultVPCCidr, gateway: "local", state: "active", origin: "CreateRouteTable"},
		{dest: "0.0.0.0/0", gateway: d.igwID(), state: "active", origin: "CreateRoute"}},
		assocs: []ec2RouteTableAssoc{{id: shortHashID("rtbassoc-", "public/"+d.publicRtbID(), 17), subnet: d.publicSubnetID()}}}
}

// privateRouteTable is the route table of the default VPC's private subnet (nil: it has none): the local
// route, and each destination it names to the NAT gateway (active while the gateway is in service and the
// subnet NATs through it, blackhole otherwise). A VPC without a NAT gateway routes none of them.
func (d *defaultVPC) privateRouteTable() *ec2RouteTable {
	if d.private == nil {
		return nil
	}
	rt := &ec2RouteTable{id: d.privateRtbID(), vpc: d.vpcID(), routes: []ec2Route{
		{dest: defaultVPCCidr, gateway: "local", state: "active", origin: "CreateRouteTable"}},
		assocs: []ec2RouteTableAssoc{{id: shortHashID("rtbassoc-", "private/"+d.privateRtbID(), 17), subnet: d.privateSubnetID()}}}
	if d.nat {
		state := "blackhole"
		if d.natInService() && d.private.natted {
			state = "active"
		}
		for _, r := range d.private.routes {
			rt.routes = append(rt.routes, ec2Route{dest: r, nat: d.natGatewayID(), state: state, origin: "CreateRoute"})
		}
	}
	return rt
}

// networkACLs are the default VPC's network ACLs: its default ACL, its subnets associated. In a default VPC
// without its internet gateway the default subnet's ACL keeps it inside the platform; with a public subnet
// too, that ACL is one of its own and the default ACL (allowing everything, as AWS creates it) is the
// public subnet's. A private subnet has an ACL of its own, which lets it leave the VPC only for the platform's
// networks and the destinations its route table sends to the NAT gateway.
func (d *defaultVPC) networkACLs() []ec2NetworkACL {
	var out []ec2NetworkACL
	switch {
	case d.internet:
		subnets := []string{d.subnetID()}
		if d.public != "" {
			subnets = append(subnets, d.publicSubnetID())
		}
		out = []ec2NetworkACL{{id: d.aclID(), vpc: d.vpcID(), isDefault: true, entries: defaultACLEntries(), subnets: subnets}}
	case d.public == "":
		out = []ec2NetworkACL{{id: d.aclID(), vpc: d.vpcID(), isDefault: true, entries: isolatedACLEntries(d.ownCIDRs()...), subnets: []string{d.subnetID()}}}
	default:
		out = []ec2NetworkACL{
			{id: d.aclID(), vpc: d.vpcID(), isDefault: true, entries: defaultACLEntries(), subnets: []string{d.publicSubnetID()}},
			{id: d.isolatedACLID(), vpc: d.vpcID(), entries: isolatedACLEntries(d.ownCIDRs()...), subnets: []string{d.subnetID()}},
		}
	}
	if d.private != nil {
		allowed := d.ownCIDRs()
		if d.natInService() {
			allowed = append(allowed, d.private.routes...)
		}
		out = append(out, ec2NetworkACL{id: d.privateACLID(), vpc: d.vpcID(), entries: isolatedACLEntries(allowed...),
			subnets: []string{d.privateSubnetID()}})
	}
	return out
}

// platformNetworks are the networks a default VPC without its internet gateway may still reach: the cluster's
// services (its AWS endpoints, DNS), its pods and the nodes' join network (account-composition.yaml's ACL).
var platformNetworks = []string{"10.43.0.0/16", "10.16.0.0/16", "100.64.0.0/16"}

// vpcResolverAddress is the VPC resolver's (Route 53 Resolver's) address, the vpc-resolver Service: the only
// DNS server a default VPC without its internet gateway may ask (account-composition.yaml's DNS ACL).
const vpcResolverAddress = "10.43.0.2"

// isolatedACLEntries are the network ACL rules a default VPC without its internet gateway has, as its subnet
// enforces them: DNS (UDP and TCP 53) only to the VPC resolver, so its DNS Firewall cannot be gone around;
// egress allowed to the platform's networks and the allowed CIDRs (the account's own subnets, and a private
// subnet's routes to the NAT gateway), every other destination denied; ingress as AWS's default ACL allows it
// (its subnet takes what its security groups admit).
func isolatedACLEntries(allowed ...string) []ec2ACLEntry {
	resolver := vpcResolverAddress + "/32"
	out := []ec2ACLEntry{
		{rule: 90, protocol: "17", action: "allow", cidr: resolver, egress: true, port: 53},
		{rule: 91, protocol: "6", action: "allow", cidr: resolver, egress: true, port: 53},
		{rule: 92, protocol: "17", action: "deny", cidr: "0.0.0.0/0", egress: true, port: 53},
		{rule: 93, protocol: "6", action: "deny", cidr: "0.0.0.0/0", egress: true, port: 53},
	}
	for i, c := range append(append([]string{}, platformNetworks...), allowed...) {
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

// --- DescribeNatGateways ---

// ec2NatGateway is a NAT gateway as DescribeNatGateways lists it.
type ec2NatGateway struct {
	id, vpc, subnet, state, created, failureCode, failureMessage string
	alloc, assoc, eni, privateIP, publicIP                       string
}

// natGateway is the default VPC's NAT gateway (nil: it has none). Without the installation's NAT gateway node
// it is failed, as a gateway that cannot forward is.
func (d *defaultVPC) natGateway() *ec2NatGateway {
	if !d.nat {
		return nil
	}
	g := &ec2NatGateway{id: d.natGatewayID(), vpc: d.vpcID(), subnet: d.publicSubnetID(), state: "available", created: d.created,
		alloc: d.natAllocationID(), assoc: d.natAssociationID(), eni: d.natInterfaceID(), privateIP: d.natPrivateIP(), publicIP: d.natAddress}
	if !d.natInService() {
		g.state, g.failureCode = "failed", "InternalError"
		g.failureMessage = "The platform has no NAT gateway node: its operator sets one (networking.natGateway.node)."
	}
	return g
}

// describeNatGateways answers DescribeNatGateways: the default VPC's NAT gateway, and each kind: NatGateway of
// the account's own VPCs (their border devices, ec2_structural.go), by their names.
func (h *ec2Handler) describeNatGateways(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"nat-gateway-id", "state", "subnet-id", "vpc-id"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	n, denied, err := h.network(ctx, claims, true, false)
	if err != nil {
		h.readFailed(w, requestID, "NAT gateways", denied, err)
		return
	}
	var gws []ec2NatGateway
	for i := range n.nats {
		u := &n.nats[i]
		vpc, _, _ := unstructured.NestedString(u.Object, "spec", "vpc")
		subnet, _, _ := unstructured.NestedString(u.Object, "spec", "subnet")
		ip, _, _ := unstructured.NestedString(u.Object, "spec", "internalIp")
		ip, _, _ = strings.Cut(ip, "/")
		state := "pending"
		if readyState(u) == "available" {
			state = "available"
		}
		gws = append(gws, ec2NatGateway{id: u.GetName(), vpc: vpc, subnet: subnet, state: state,
			created: ec2Time(u.GetCreationTimestamp().Time), privateIP: ip})
	}
	if n.def != nil {
		if g := n.def.natGateway(); g != nil {
			gws = append(gws, *g)
		}
	}
	ids := ec2List(r.Form, "NatGatewayId")
	want, found := setOf(ids), map[string]bool{}
	var items []string
	for _, g := range gws {
		if len(ids) > 0 && !want[g.id] {
			continue
		}
		found[g.id] = true
		rec := ec2Record{fields: map[string][]string{"nat-gateway-id": {g.id}, "state": {g.state}, "subnet-id": {g.subnet}, "vpc-id": {g.vpc}}}
		if !rec.matches(fs) {
			continue
		}
		addr := xtag("allocationId", g.alloc) + xtag("networkInterfaceId", g.eni) + xtag("privateIp", g.privateIP) +
			xtag("publicIp", g.publicIP) + xtag("associationId", g.assoc) + "<isPrimary>true</isPrimary>"
		if g.alloc != "" {
			addr += "<status>succeeded</status>"
		}
		items = append(items, xtag("createTime", g.created)+xset("natGatewayAddressSet", []string{addr})+xtag("natGatewayId", g.id)+
			xtag("state", g.state)+xtag("failureCode", g.failureCode)+xtag("failureMessage", g.failureMessage)+
			xtag("subnetId", g.subnet)+xtag("vpcId", g.vpc)+"<connectivityType>public</connectivityType><tagSet/>")
	}
	if id, missing := firstMissing(ids, found); missing {
		writeEC2Error(w, http.StatusBadRequest, "NatGatewayNotFound", requestID, "NAT gateway "+id+" was not found")
		return
	}
	writePage(w, r, requestID, "DescribeNatGateways", "natGatewaySet", items, 5, 1000)
}
