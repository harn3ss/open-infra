// The EC2 front door's describes of a VPC's structure (ec2.go): DescribeInternetGateways,
// DescribeRouteTables, DescribeNetworkAcls and DescribeVpcEndpoints, in EC2's Query/XML shapes.
//
// On open-infra a VPC's border device is its kind: NatGateway, its route table is the kind: Vpc's
// spec.routes, a subnet's network ACL is the kind: Subnet's spec.acls, and an endpoint is a kind:
// VpcEndpoint. A stack's internet gateway, route tables, routes, gateway attachment and route-table
// associations provision nothing of their own (cfn/translate.go: each is part of the VPC it names), so they
// are read from the stack's recorded template (cfn.TemplateResourcesOf) under the ids their Ref gave the
// stack — the ids DescribeStackResources lists them by — and exist while the stack holds them and the
// kind: Vpc they are part of exists:
//   - an internet gateway is a stack's AWS::EC2::InternetGateway, attached to each VPC an
//     AWS::EC2::VPCGatewayAttachment joins it to while that kind: Vpc exists (available once it is ready,
//     attaching before);
//   - a route table is each VPC's main route table (its local route and the kind: Vpc's spec.routes, a
//     route to a NAT gateway's internal address naming that kind: NatGateway), and each stack
//     AWS::EC2::RouteTable of a VPC that exists, with its AWS::EC2::Route entries (active while the gateway
//     they name is attached to the VPC, blackhole otherwise) and its AWS::EC2::SubnetRouteTableAssociation
//     entries (while the subnet exists);
//   - a network ACL is each VPC's default network ACL (AWS's default rules, which allow all traffic),
//     associated with every subnet of the VPC that has no ACL rules of its own, and each kind: Subnet's
//     spec.acls as that subnet's network ACL. OVN evaluates a subnet's rules highest priority first and
//     passes what no rule matches, so they are listed in that order and the closing rule (32767) allows; a
//     rule written as a raw OVN match is listed by its structured fields. A stack's
//     AWS::EC2::SubnetNetworkAclAssociation is refused when the stack is planned (the rules of the ACL it
//     names are not in the template), so no association is a stack's;
//   - a VPC endpoint is a kind: VpcEndpoint, by its name (its Ref), with the service it fronts as AWS's
//     service name and the in-cluster DNS name it resolves to as its DNS entry. Its policy document is the
//     default full-access one: the endpoint restricts nothing — access through it is IAM policy's at the
//     front door.
//
// Authorization is the door's: ec2:<Action> on Resource "*" (ec2.go). The kinds are read for the caller
// (listForCallerIn: its RBAC in legacy, the shim's client in enforce) in the caller's account's namespace,
// and a stack's template, in legacy, only for a caller that may read the stack, as DescribeStackResources
// needs (in enforce IAM policy has decided). The owner of everything is the caller's account.
package main

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	vpcEndpointGVR = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "vpcendpoints"}
	natGatewayGVR  = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "natgateways"}
)

// The CloudFormation types of a VPC's structure a stack's template carries.
const (
	cfnInternetGatewayType = "AWS::EC2::InternetGateway"
	cfnGatewayAttachType   = "AWS::EC2::VPCGatewayAttachment"
	cfnRouteTableType      = "AWS::EC2::RouteTable"
	cfnRouteType           = "AWS::EC2::Route"
	cfnRouteTableAssocType = "AWS::EC2::SubnetRouteTableAssociation"
	cfnVPCEndpointType     = "AWS::EC2::VPCEndpoint"
)

var cfnStructuralTypes = []string{cfnInternetGatewayType, cfnGatewayAttachType, cfnRouteTableType, cfnRouteType, cfnRouteTableAssocType}

// vpcEndpointPolicy is the policy document AWS gives an endpoint created without one: full access.
const vpcEndpointPolicy = `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`

// ec2StackPart is a structural resource of one of the account's stacks, as the stack resolved it.
type ec2StackPart struct {
	rec *cfn.StackRecord
	res cfn.TemplateResource
}

func (p ec2StackPart) prop(k string) string { return fnStr(p.res.Properties[k]) }

// ec2Network is what the structural describes answer from: the account's VPCs, subnets and NAT gateways
// the caller may read, and its stacks' structural resources.
type ec2Network struct {
	ns        string
	vpcs      []unstructured.Unstructured
	vpcByName map[string]*unstructured.Unstructured
	subnets   []unstructured.Unstructured
	nats      []unstructured.Unstructured
	parts     []ec2StackPart
}

// network reads the caller's account's VPCs and subnets, with nats its NAT gateways, and with stacks its
// stacks' structural resources.
func (h *ec2Handler) network(ctx context.Context, claims iam.Claims, nats, stacks bool) (*ec2Network, bool, error) {
	n := &ec2Network{ns: accountNamespace(ctx, h.door.ns), vpcByName: map[string]*unstructured.Unstructured{}}
	var denied bool
	var err error
	if n.vpcs, denied, err = h.listForCallerIn(ctx, claims, vpcGVR, n.ns); err != nil {
		return nil, denied, err
	}
	for i := range n.vpcs {
		n.vpcByName[n.vpcs[i].GetName()] = &n.vpcs[i]
	}
	if n.subnets, denied, err = h.listForCallerIn(ctx, claims, subnetGVR, n.ns); err != nil {
		return nil, denied, err
	}
	if nats {
		// A NAT gateway the caller may not read is not named as a route's target; the route is still listed.
		n.nats, _, _ = h.listForCallerIn(ctx, claims, natGatewayGVR, n.ns)
	}
	if stacks {
		if n.parts, err = h.stackParts(ctx, claims); err != nil {
			return nil, false, err
		}
	}
	return n, false, nil
}

// stackParts are the internet gateways, gateway attachments, route tables, routes and route-table
// associations of the account's stacks that hold them — in legacy only of the stacks the caller may read.
func (h *ec2Handler) stackParts(ctx context.Context, claims iam.Claims) ([]ec2StackPart, error) {
	if h.door.shimDyn == nil {
		return nil, nil
	}
	recs, err := accountStacks(ctx, h.door)
	if err != nil {
		return nil, err
	}
	enforce := enforcing(ctx, h.door.authz, claims)
	var out []ec2StackPart
	for _, rec := range recs {
		if !stackHolds(rec) || !mentionsAny(rec.Template, cfnStructuralTypes) {
			continue
		}
		if !enforce {
			if ok, _ := h.door.canDo(ctx, claims, "get", rec.Name); !ok {
				continue
			}
		}
		for _, tr := range templateResources(rec, recs, cfnStructuralTypes...) {
			if tr.Ref != "" {
				out = append(out, ec2StackPart{rec: rec, res: tr})
			}
		}
	}
	return out, nil
}

func mentionsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// firstMissing is the first of ids not found.
func firstMissing(ids []string, found map[string]bool) (string, bool) {
	for _, id := range ids {
		if !found[id] {
			return id, true
		}
	}
	return "", false
}

// writePage answers a describe's items, paged by MaxResults / NextToken (ec2Page).
func writePage(w http.ResponseWriter, r *http.Request, requestID, op, set string, items []string, min, max int) {
	start, end, next, msg, ok := ec2Page(r.Form, len(items), min, max)
	if !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	writeEC2(w, requestID, op, xset(set, items[start:end])+xtag("nextToken", next))
}

// --- internet gateways ---

type ec2Gateway struct {
	id   string
	tags map[string]string
	atts []ec2GatewayAttachment
}

type ec2GatewayAttachment struct{ vpc, state string }

// internetGateways are the stacks' internet gateways, each with the VPCs an attachment joins it to (in any
// of the account's stacks: an attachment may name a gateway another stack exports).
func (h *ec2Handler) internetGateways(n *ec2Network) []ec2Gateway {
	var out []ec2Gateway
	for _, p := range n.parts {
		if p.res.Type != cfnInternetGatewayType {
			continue
		}
		g := ec2Gateway{id: p.res.Ref, tags: stackResourceTags(h.door, p.rec, p.res)}
		seen := map[string]bool{}
		for _, a := range n.parts {
			if a.res.Type != cfnGatewayAttachType || a.prop("InternetGatewayId") != g.id {
				continue
			}
			v := n.vpcByName[a.prop("VpcId")]
			if v == nil || seen[v.GetName()] {
				continue
			}
			seen[v.GetName()] = true
			state := "attaching"
			if readyState(v) == "available" {
				state = "available"
			}
			g.atts = append(g.atts, ec2GatewayAttachment{vpc: v.GetName(), state: state})
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func (h *ec2Handler) describeInternetGateways(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"internet-gateway-id", "attachment.vpc-id", "attachment.state", "owner-id"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	n, denied, err := h.network(ctx, claims, false, true)
	if err != nil {
		h.readFailed(w, requestID, "internet gateways", denied, err)
		return
	}
	acct := callerAccount(ctx)
	ids := ec2List(r.Form, "InternetGatewayId")
	want, found := setOf(ids), map[string]bool{}
	var items []string
	for _, g := range h.internetGateways(n) {
		if len(ids) > 0 && !want[g.id] {
			continue
		}
		found[g.id] = true
		f := map[string][]string{"internet-gateway-id": {g.id}, "owner-id": {acct}}
		atts := make([]string, 0, len(g.atts))
		for _, a := range g.atts {
			f["attachment.vpc-id"] = append(f["attachment.vpc-id"], a.vpc)
			f["attachment.state"] = append(f["attachment.state"], a.state)
			atts = append(atts, xtag("vpcId", a.vpc)+xtag("state", a.state))
		}
		if !(ec2Record{fields: f, tags: g.tags}).matches(fs) {
			continue
		}
		items = append(items, xtag("internetGatewayId", g.id)+xset("attachmentSet", atts)+xtag("ownerId", acct)+xtags(g.tags))
	}
	if id, missing := firstMissing(ids, found); missing {
		writeEC2Error(w, http.StatusBadRequest, "InvalidInternetGatewayID.NotFound", requestID, "The internetGateway ID '"+id+"' does not exist")
		return
	}
	writePage(w, r, requestID, "DescribeInternetGateways", "internetGatewaySet", items, 5, 1000)
}

// --- route tables ---

type ec2RouteTable struct {
	id, vpc string
	routes  []ec2Route
	assocs  []ec2RouteTableAssoc
	tags    map[string]string
}

type ec2Route struct{ dest, dest6, gateway, nat, state, origin string }

type ec2RouteTableAssoc struct {
	id, subnet string
	main       bool
}

// mainRouteTableID is the id of a VPC's main route table (it provisions nothing: the VPC's routes are its own).
func mainRouteTableID(ns, vpc string) string {
	return shortHashID("rtb-", "main-route-table/"+ns+"/"+vpc, 17)
}

// localRoute is a VPC's local route: its CIDR block, reached within the VPC.
func localRoute(v *unstructured.Unstructured) []ec2Route {
	cidr := cfn.ParseAWSView(v.GetAnnotations()).CidrBlock
	if cidr == "" {
		return nil
	}
	return []ec2Route{{dest: cidr, gateway: "local", state: "active", origin: "CreateRouteTable"}}
}

// natFor is the VPC's NAT gateway whose internal address is ip (a route's next hop), or nil.
func (n *ec2Network) natFor(vpc, ip string) *unstructured.Unstructured {
	ip, _, _ = strings.Cut(ip, "/")
	for i := range n.nats {
		g := &n.nats[i]
		v, _, _ := unstructured.NestedString(g.Object, "spec", "vpc")
		addr, _, _ := unstructured.NestedString(g.Object, "spec", "internalIp")
		if addr, _, _ = strings.Cut(addr, "/"); v == vpc && addr != "" && addr == ip {
			return g
		}
	}
	return nil
}

// routeTables are each VPC's main route table and the stacks' route tables of the VPCs that exist, by id.
func (h *ec2Handler) routeTables(n *ec2Network) []ec2RouteTable {
	attached := map[string]bool{} // "<gateway>|<vpc>"
	for _, g := range h.internetGateways(n) {
		for _, a := range g.atts {
			attached[g.id+"|"+a.vpc] = true
		}
	}
	subnets := map[string]bool{}
	for i := range n.subnets {
		subnets[n.subnets[i].GetName()] = true
	}
	var out []ec2RouteTable
	for i := range n.vpcs {
		v := &n.vpcs[i]
		rt := ec2RouteTable{id: mainRouteTableID(n.ns, v.GetName()), vpc: v.GetName(), routes: localRoute(v)}
		routes, _, _ := unstructured.NestedSlice(v.Object, "spec", "routes")
		for _, raw := range routes {
			m, _ := raw.(map[string]any)
			rr := ec2Route{dest: fnStr(m["cidr"]), state: "active", origin: "CreateRoute"}
			if g := n.natFor(v.GetName(), fnStr(m["nextHop"])); g != nil {
				rr.nat = g.GetName()
				if readyState(g) != "available" {
					rr.state = "blackhole"
				}
			}
			rt.routes = append(rt.routes, rr)
		}
		rt.assocs = []ec2RouteTableAssoc{{id: shortHashID("rtbassoc-", "main/"+rt.id, 17), main: true}}
		out = append(out, rt)
	}
	for _, p := range n.parts {
		if p.res.Type != cfnRouteTableType {
			continue
		}
		v := n.vpcByName[p.prop("VpcId")]
		if v == nil {
			continue
		}
		rt := ec2RouteTable{id: p.res.Ref, vpc: v.GetName(), routes: localRoute(v), tags: stackResourceTags(h.door, p.rec, p.res)}
		for _, q := range n.parts {
			if q.prop("RouteTableId") != rt.id {
				continue
			}
			switch q.res.Type {
			case cfnRouteType:
				rr := ec2Route{dest: q.prop("DestinationCidrBlock"), dest6: q.prop("DestinationIpv6CidrBlock"), gateway: q.prop("GatewayId"),
					state: "blackhole", origin: "CreateRoute"}
				if attached[rr.gateway+"|"+rt.vpc] {
					rr.state = "active"
				}
				rt.routes = append(rt.routes, rr)
			case cfnRouteTableAssocType:
				if s := q.prop("SubnetId"); subnets[s] {
					rt.assocs = append(rt.assocs, ec2RouteTableAssoc{id: q.res.Ref, subnet: s})
				}
			}
		}
		out = append(out, rt)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

var routeTableFilters = []string{"route-table-id", "vpc-id", "owner-id", "association.route-table-association-id",
	"association.route-table-id", "association.subnet-id", "association.main", "route.destination-cidr-block",
	"route.destination-ipv6-cidr-block", "route.gateway-id", "route.nat-gateway-id", "route.state", "route.origin"}

func (h *ec2Handler) describeRouteTables(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, routeTableFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	n, denied, err := h.network(ctx, claims, true, true)
	if err != nil {
		h.readFailed(w, requestID, "route tables", denied, err)
		return
	}
	acct := callerAccount(ctx)
	ids := ec2List(r.Form, "RouteTableId")
	want, found := setOf(ids), map[string]bool{}
	var items []string
	for _, rt := range h.routeTables(n) {
		if len(ids) > 0 && !want[rt.id] {
			continue
		}
		found[rt.id] = true
		f := map[string][]string{"route-table-id": {rt.id}, "vpc-id": {rt.vpc}, "owner-id": {acct}}
		add := func(k, v string) {
			if v != "" {
				f[k] = append(f[k], v)
			}
		}
		routes := make([]string, 0, len(rt.routes))
		for _, rr := range rt.routes {
			add("route.destination-cidr-block", rr.dest)
			add("route.destination-ipv6-cidr-block", rr.dest6)
			add("route.gateway-id", rr.gateway)
			add("route.nat-gateway-id", rr.nat)
			add("route.state", rr.state)
			add("route.origin", rr.origin)
			routes = append(routes, xtag("destinationCidrBlock", rr.dest)+xtag("destinationIpv6CidrBlock", rr.dest6)+
				xtag("gatewayId", rr.gateway)+xtag("natGatewayId", rr.nat)+xtag("state", rr.state)+xtag("origin", rr.origin))
		}
		assocs := make([]string, 0, len(rt.assocs))
		for _, a := range rt.assocs {
			add("association.route-table-association-id", a.id)
			add("association.route-table-id", rt.id)
			add("association.subnet-id", a.subnet)
			add("association.main", strconv.FormatBool(a.main))
			assocs = append(assocs, xtag("routeTableAssociationId", a.id)+xtag("routeTableId", rt.id)+xtag("subnetId", a.subnet)+
				xbool("main", a.main)+"<associationState><state>associated</state></associationState>")
		}
		if !(ec2Record{fields: f, tags: rt.tags}).matches(fs) {
			continue
		}
		items = append(items, xtag("routeTableId", rt.id)+xtag("vpcId", rt.vpc)+xtag("ownerId", acct)+xset("routeSet", routes)+
			xset("associationSet", assocs)+"<propagatingVgwSet/>"+xtags(rt.tags))
	}
	if id, missing := firstMissing(ids, found); missing {
		writeEC2Error(w, http.StatusBadRequest, "InvalidRouteTableID.NotFound", requestID, "The routeTable ID '"+id+"' does not exist")
		return
	}
	writePage(w, r, requestID, "DescribeRouteTables", "routeTableSet", items, 5, 100)
}

// --- network ACLs ---

type ec2NetworkACL struct {
	id, vpc   string
	isDefault bool
	entries   []ec2ACLEntry
	subnets   []string
}

type ec2ACLEntry struct {
	rule                   int
	protocol, action, cidr string
	egress                 bool
	port                   int64 // 0: every port
	icmp                   bool
}

// defaultACLEntries are a VPC's default network ACL's rules, as AWS creates them: allow everything in and
// out (100), and the closing deny (32767) nothing reaches.
func defaultACLEntries() []ec2ACLEntry {
	var out []ec2ACLEntry
	for _, egress := range []bool{true, false} {
		out = append(out, ec2ACLEntry{rule: 100, protocol: "-1", action: "allow", cidr: "0.0.0.0/0", egress: egress},
			ec2ACLEntry{rule: 32767, protocol: "-1", action: "deny", cidr: "0.0.0.0/0", egress: egress})
	}
	return out
}

// subnetACLEntries are a kind: Subnet's spec.acls as network ACL rules: each direction's in OVN's order
// (highest priority first) numbered 100, 200, …, and the closing rule, which allows what none matched.
func subnetACLEntries(acls []any) []ec2ACLEntry {
	var out []ec2ACLEntry
	for _, egress := range []bool{true, false} {
		type rule struct {
			m        map[string]any
			priority int64
		}
		var rules []rule
		for _, raw := range acls {
			m, _ := raw.(map[string]any)
			if (fnStr(m["direction"]) == "egress") != egress {
				continue
			}
			p := int64(1000)
			if v, ok := m["priority"].(int64); ok {
				p = v
			}
			rules = append(rules, rule{m, p})
		}
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].priority > rules[j].priority })
		for i, rl := range rules {
			e := ec2ACLEntry{rule: min((i+1)*100, 32766), action: "allow", cidr: fnStr(rl.m["cidr"]), egress: egress}
			if fnStr(rl.m["action"]) == "drop" {
				e.action = "deny"
			}
			if e.cidr == "" {
				e.cidr = "0.0.0.0/0"
			}
			switch strings.ToLower(fnStr(rl.m["protocol"])) {
			case "tcp":
				e.protocol = "6"
			case "udp":
				e.protocol = "17"
			case "icmp":
				e.protocol, e.icmp = "1", true
			default:
				e.protocol = "-1"
			}
			if port, ok := rl.m["port"].(int64); ok && (e.protocol == "6" || e.protocol == "17") {
				e.port = port
			}
			out = append(out, e)
		}
		out = append(out, ec2ACLEntry{rule: 32767, protocol: "-1", action: "allow", cidr: "0.0.0.0/0", egress: egress})
	}
	return out
}

// networkACLs are each VPC's default network ACL and each subnet's own (its spec.acls), by id.
func (h *ec2Handler) networkACLs(n *ec2Network) []ec2NetworkACL {
	var out []ec2NetworkACL
	defaults := map[string]int{} // VPC -> index of its default ACL in out
	for i := range n.vpcs {
		name := n.vpcs[i].GetName()
		defaults[name] = len(out)
		out = append(out, ec2NetworkACL{id: shortHashID("acl-", "default-network-acl/"+n.ns+"/"+name, 17), vpc: name, isDefault: true,
			entries: defaultACLEntries()})
	}
	for i := range n.subnets {
		s := &n.subnets[i]
		vpc, _, _ := unstructured.NestedString(s.Object, "spec", "vpc")
		d, ok := defaults[vpc]
		if !ok {
			continue // a subnet of a VPC the caller does not see (or of the cluster's default network)
		}
		acls, _, _ := unstructured.NestedSlice(s.Object, "spec", "acls")
		if len(acls) == 0 {
			out[d].subnets = append(out[d].subnets, s.GetName())
			continue
		}
		out = append(out, ec2NetworkACL{id: shortHashID("acl-", "subnet-network-acl/"+n.ns+"/"+s.GetName(), 17), vpc: vpc,
			entries: subnetACLEntries(acls), subnets: []string{s.GetName()}})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

var networkACLFilters = []string{"network-acl-id", "vpc-id", "default", "owner-id", "association.association-id",
	"association.network-acl-id", "association.subnet-id", "entry.cidr", "entry.egress", "entry.protocol",
	"entry.rule-action", "entry.rule-number"}

func (h *ec2Handler) describeNetworkAcls(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, networkACLFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	n, denied, err := h.network(ctx, claims, false, false)
	if err != nil {
		h.readFailed(w, requestID, "network ACLs", denied, err)
		return
	}
	acct := callerAccount(ctx)
	ids := ec2List(r.Form, "NetworkAclId")
	want, found := setOf(ids), map[string]bool{}
	var items []string
	for _, acl := range h.networkACLs(n) {
		if len(ids) > 0 && !want[acl.id] {
			continue
		}
		found[acl.id] = true
		f := map[string][]string{"network-acl-id": {acl.id}, "vpc-id": {acl.vpc}, "default": {strconv.FormatBool(acl.isDefault)}, "owner-id": {acct}}
		entries := make([]string, 0, len(acl.entries))
		for _, e := range acl.entries {
			f["entry.cidr"] = append(f["entry.cidr"], e.cidr)
			f["entry.egress"] = append(f["entry.egress"], strconv.FormatBool(e.egress))
			f["entry.protocol"] = append(f["entry.protocol"], e.protocol)
			f["entry.rule-action"] = append(f["entry.rule-action"], e.action)
			f["entry.rule-number"] = append(f["entry.rule-number"], strconv.Itoa(e.rule))
			item := "<ruleNumber>" + strconv.Itoa(e.rule) + "</ruleNumber>" + xtag("protocol", e.protocol) + xtag("ruleAction", e.action) +
				xbool("egress", e.egress) + xtag("cidrBlock", e.cidr)
			if e.icmp {
				item += "<icmpTypeCode><code>-1</code><type>-1</type></icmpTypeCode>"
			}
			if e.port > 0 {
				p := strconv.FormatInt(e.port, 10)
				item += "<portRange><from>" + p + "</from><to>" + p + "</to></portRange>"
			}
			entries = append(entries, item)
		}
		assocs := make([]string, 0, len(acl.subnets))
		for _, s := range acl.subnets {
			aid := shortHashID("aclassoc-", acl.id+"/"+s, 17)
			f["association.association-id"] = append(f["association.association-id"], aid)
			f["association.network-acl-id"] = append(f["association.network-acl-id"], acl.id)
			f["association.subnet-id"] = append(f["association.subnet-id"], s)
			assocs = append(assocs, xtag("networkAclAssociationId", aid)+xtag("networkAclId", acl.id)+xtag("subnetId", s))
		}
		if !(ec2Record{fields: f}).matches(fs) {
			continue
		}
		items = append(items, xtag("networkAclId", acl.id)+xtag("vpcId", acl.vpc)+xbool("default", acl.isDefault)+
			xset("entrySet", entries)+xset("associationSet", assocs)+"<tagSet/>"+xtag("ownerId", acct))
	}
	if id, missing := firstMissing(ids, found); missing {
		writeEC2Error(w, http.StatusBadRequest, "InvalidNetworkAclID.NotFound", requestID, "The networkAcl ID '"+id+"' does not exist")
		return
	}
	writePage(w, r, requestID, "DescribeNetworkAcls", "networkAclSet", items, 5, 1000)
}

// --- VPC endpoints ---

func (h *ec2Handler) describeVpcEndpoints(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"vpc-endpoint-id", "vpc-id", "service-name", "vpc-endpoint-state", "vpc-endpoint-type", "ip-address-type"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	eps, denied, err := h.listForCallerIn(ctx, claims, vpcEndpointGVR, accountNamespace(ctx, h.door.ns))
	if err != nil {
		h.readFailed(w, requestID, "VPC endpoints", denied, err)
		return
	}
	acct := callerAccount(ctx)
	ids := ec2List(r.Form, "VpcEndpointId")
	want, found := setOf(ids), map[string]bool{}
	tagsOf := h.vpcEndpointTags(ctx)
	var items []string
	for i := range eps {
		u := &eps[i]
		id := u.GetName()
		if len(ids) > 0 && !want[id] {
			continue
		}
		found[id] = true
		spec, _, _ := unstructured.NestedMap(u.Object, "spec")
		typ := fnStr(spec["vpcEndpointType"])
		if typ == "" {
			typ = "Interface" // the kind's default
		}
		vpc, service := fnStr(spec["vpc"]), "com.amazonaws."+h.region()+"."+fnStr(spec["service"])
		dnsName, _, _ := unstructured.NestedString(u.Object, "status", "dnsName")
		state := "pending"
		switch {
		case u.GetDeletionTimestamp() != nil:
			state = "deleting"
		case dnsName != "":
			state = "available"
		}
		tags := tagsOf(u)
		rec := ec2Record{fields: map[string][]string{"vpc-endpoint-id": {id}, "vpc-id": {vpc}, "service-name": {service},
			"vpc-endpoint-state": {state}, "vpc-endpoint-type": {typ}, "ip-address-type": {"ipv4"}}, tags: tags}
		if !rec.matches(fs) {
			continue
		}
		var dns []string
		if dnsName != "" {
			dns = append(dns, xtag("dnsName", dnsName))
		}
		items = append(items, xtag("vpcEndpointId", id)+xtag("vpcEndpointType", typ)+xtag("vpcId", vpc)+xtag("serviceName", service)+
			xtag("state", state)+xtag("policyDocument", vpcEndpointPolicy)+"<routeTableIdSet/><subnetIdSet/><groupSet/>"+
			"<ipAddressType>ipv4</ipAddressType><dnsOptions><dnsRecordIpType>ipv4</dnsRecordIpType></dnsOptions>"+
			"<privateDnsEnabled>false</privateDnsEnabled><requesterManaged>false</requesterManaged><networkInterfaceIdSet/>"+
			xset("dnsEntrySet", dns)+xtag("creationTimestamp", ec2Time(u.GetCreationTimestamp().Time))+xtags(tags)+xtag("ownerId", acct))
	}
	if id, missing := firstMissing(ids, found); missing {
		writeEC2Error(w, http.StatusBadRequest, "InvalidVpcEndpointId.NotFound", requestID, "The Vpc Endpoint Id '"+id+"' does not exist")
		return
	}
	writePage(w, r, requestID, "DescribeVpcEndpoints", "vpcEndpointSet", items, 5, 1000)
}

// vpcEndpointTags reads an endpoint's tags: its AWS view's, and for one a stack made (its stack label) the
// template's Tags and the aws:cloudformation:* tags CloudFormation adds. The stack records are read once,
// and only for an endpoint a stack made.
func (h *ec2Handler) vpcEndpointTags(ctx context.Context) func(u *unstructured.Unstructured) map[string]string {
	var recs []*cfn.StackRecord
	loaded := false
	return func(u *unstructured.Unstructured) map[string]string {
		tags := map[string]string{}
		for k, v := range cfn.ParseAWSView(u.GetAnnotations()).Tags {
			tags[k] = v
		}
		stack := u.GetLabels()["cfn.openinfra.dev/stack"]
		if stack == "" {
			return tags
		}
		tags["aws:cloudformation:stack-name"] = stack
		if !loaded && h.door.shimDyn != nil {
			recs, _ = accountStacks(ctx, h.door)
			loaded = true
		}
		for _, rec := range recs {
			if rec.Name != stack {
				continue
			}
			for _, res := range rec.Resources {
				if res.Kind != "VpcEndpoint" || res.Name != u.GetName() {
					continue
				}
				for _, tr := range templateResources(rec, recs, cfnVPCEndpointType) {
					if tr.LogicalID == res.LogicalID {
						for k, v := range stackResourceTags(h.door, rec, tr) {
							tags[k] = v
						}
					}
				}
			}
		}
		return tags
	}
}
