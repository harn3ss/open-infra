// DescribeNetworkInterfaces over the network interfaces Lambda gives functions in a VPC (vpcnet.go).
//
// As on Lambda, a function with VpcConfig has one network interface in each of its subnets (eni-…,
// lambdaENIID), requester-managed (interface type lambda, description "AWS Lambda VPC ENI-<function>"),
// with the function's security groups. It exists while a function of the account has that subnet in its
// VpcConfig (spec.vpcConfig of the kind: Function), whether or not the function is running; its addresses
// are those of the function's execution environments running in that subnet now (none while it is scaled
// to zero), from the Lambda VPC subnet rather than the subnet's own CIDR (docs/lambda-vpc.md says so).
package main

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// lambdaENIRequester is the requester of a Lambda network interface: the Lambda service.
const lambdaENIRequester = "lambda.amazonaws.com"

// lambdaENI is a Lambda function's network interface in one of its subnets.
type lambdaENI struct {
	ID, Namespace, Function, SubnetID, VpcID string
	Groups                                   []string       // security group ids
	Addrs                                    []vpcInterface // the running environments' interfaces, by address
}

// lambdaENIsForCaller is the network interfaces of the caller's account's functions in a VPC, by id. The
// functions are read as listForCallerIn reads a kind (in legacy with the caller's own authority: a
// namespace whose functions it may not list is left out).
func (h *ec2Handler) lambdaENIsForCaller(ctx context.Context, claims iam.Claims) ([]lambdaENI, bool, error) {
	var namespaces []string
	if h.fns != nil {
		namespaces = h.fns.namespacesFor(ctx)
	}
	if len(namespaces) == 0 {
		namespaces = []string{h.accountNS(ctx)}
	}
	account := h.ownerAccount(ctx)
	// A subnet's VPC, for a function whose VpcConfig does not name it.
	subnetVPC := map[string]string{}
	if subs, _, err := h.listForCaller(ctx, claims, subnetGVR); err == nil {
		for i := range subs {
			v, _, _ := unstructured.NestedString(subs[i].Object, "spec", "vpc")
			subnetVPC[subs[i].GetName()] = v
		}
	}
	current := map[string][]vpcInterface{} // namespace/function/subnet -> running interfaces
	for _, in := range h.vpc.Current() {
		if in.Account == account {
			k := in.Namespace + "/" + in.Function + "/" + in.SubnetID
			current[k] = append(current[k], in)
		}
	}
	var out []lambdaENI
	readable := 0
	var lastErr error
	lastDenied := false
	for _, ns := range namespaces {
		fns, denied, err := h.listForCallerIn(ctx, claims, functionClaimGVR, ns)
		if err != nil {
			lastErr, lastDenied = err, denied
			continue
		}
		readable++
		for i := range fns {
			u := &fns[i]
			subnets, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "vpcConfig", "subnetIds")
			if len(subnets) == 0 {
				continue
			}
			groups, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "vpcConfig", "securityGroupIds")
			vpc, _, _ := unstructured.NestedString(u.Object, "spec", "vpcConfig", "vpcId")
			seen := map[string]bool{}
			for _, sn := range subnets {
				if sn == "" || seen[sn] {
					continue
				}
				seen[sn] = true
				e := lambdaENI{ID: lambdaENIID(account, u.GetName(), sn), Namespace: ns, Function: u.GetName(), SubnetID: sn,
					VpcID: vpc, Groups: groups}
				if e.VpcID == "" {
					e.VpcID = subnetVPC[sn]
				}
				e.Addrs = current[ns+"/"+u.GetName()+"/"+sn]
				sort.Slice(e.Addrs, func(a, b int) bool { return e.Addrs[a].IP < e.Addrs[b].IP })
				out = append(out, e)
			}
		}
	}
	if readable == 0 && lastErr != nil {
		return nil, lastDenied, lastErr
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, false, nil
}

// eniFilters are DescribeNetworkInterfaces' filters, AWS's whole list: one whose field a Lambda interface
// does not have (an attachment's instance, an association's public IP) matches none of them.
var eniFilters = []string{"association.allocation-id", "association.association-id", "addresses.association.owner-id",
	"addresses.association.public-ip", "addresses.primary", "addresses.private-ip-address", "association.ip-owner-id",
	"association.public-ip", "association.public-dns-name", "attachment.attach-time", "attachment.attachment-id",
	"attachment.delete-on-termination", "attachment.device-index", "attachment.instance-id", "attachment.instance-owner-id",
	"attachment.status", "availability-zone", "availability-zone-id", "description", "group-id", "group-name",
	"ipv6-addresses.ipv6-address", "interface-type", "mac-address", "network-interface-id", "operator.managed",
	"operator.principal", "owner-id", "private-dns-name", "private-ip-address", "requester-id", "requester-managed",
	"source-dest-check", "status", "subnet-id", "vpc-id"}

func (e lambdaENI) description() string { return "AWS Lambda VPC ENI-" + e.Function }

func (e lambdaENI) mac() string {
	for _, a := range e.Addrs {
		if a.MAC != "" {
			return a.MAC
		}
	}
	return ""
}

func (h *ec2Handler) eniRecord(e lambdaENI, account string, groupNames map[string]string) ec2Record {
	f := map[string][]string{"network-interface-id": {e.ID}, "subnet-id": {e.SubnetID}, "vpc-id": {e.VpcID},
		"availability-zone": {h.zone()}, "availability-zone-id": {h.zoneID()}, "description": {e.description()},
		"interface-type": {"lambda"}, "owner-id": {account}, "requester-id": {lambdaENIRequester}, "requester-managed": {"true"},
		"status": {"in-use"}, "source-dest-check": {"true"}, "operator.managed": {"false"}}
	if m := e.mac(); m != "" {
		f["mac-address"] = []string{m}
	}
	for i, a := range e.Addrs {
		f["private-ip-address"] = append(f["private-ip-address"], a.IP)
		f["addresses.private-ip-address"] = append(f["addresses.private-ip-address"], a.IP)
		if i == 0 {
			f["addresses.primary"] = []string{"true"}
		}
	}
	if len(e.Addrs) > 1 {
		f["addresses.primary"] = append(f["addresses.primary"], "false")
	}
	for _, g := range e.Groups {
		f["group-id"] = append(f["group-id"], g)
		f["group-name"] = append(f["group-name"], groupName(groupNames, g))
	}
	return ec2Record{fields: f}
}

func groupName(names map[string]string, id string) string {
	if n := names[id]; n != "" {
		return n
	}
	return id
}

func (h *ec2Handler) describeNetworkInterfaces(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, eniFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	ids := ec2List(r.Form, "NetworkInterfaceId")
	for _, id := range ids {
		if !strings.HasPrefix(id, "eni-") {
			writeEC2Error(w, http.StatusBadRequest, "InvalidNetworkInterfaceID.Malformed", requestID, "Invalid id: \""+id+"\" (expecting \"eni-...\")")
			return
		}
	}
	if len(ids) > 0 && r.Form.Get("MaxResults") != "" {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterCombination", requestID, "The parameter NetworkInterfaceIds cannot be used with the parameter MaxResults")
		return
	}
	all, denied, err := h.lambdaENIsForCaller(ctx, claims)
	if err != nil {
		h.readFailed(w, requestID, "network interfaces", denied, err)
		return
	}
	// The security groups' names (a group's GroupName where a stack gave it one).
	names := map[string]string{}
	if sgs, _, err := h.listForCaller(ctx, claims, securityGroupGVR); err == nil {
		for i := range sgs {
			if n := cfn.ParseAWSView(sgs[i].GetAnnotations()).GroupName; n != "" {
				names[sgs[i].GetName()] = n
			}
		}
	}
	acct := h.ownerAccount(ctx)
	want, found := setOf(ids), map[string]bool{}
	var sel []lambdaENI
	for _, e := range all {
		if len(ids) > 0 && !want[e.ID] {
			continue
		}
		found[e.ID] = true
		if h.eniRecord(e, acct, names).matches(fs) {
			sel = append(sel, e)
		}
	}
	for _, id := range ids {
		if !found[id] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidNetworkInterfaceID.NotFound", requestID, "The networkInterface ID '"+id+"' does not exist")
			return
		}
	}
	start, end, next, msg, ok := ec2Page(r.Form, len(sel), 5, 1000)
	if !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	items := make([]string, 0, end-start)
	for _, e := range sel[start:end] {
		items = append(items, h.eniXML(e, acct, names))
	}
	writeEC2(w, requestID, "DescribeNetworkInterfaces", xset("networkInterfaceSet", items)+xtag("nextToken", next))
}

// eniXML is a Lambda interface as DescribeNetworkInterfaces answers it (NetworkInterface).
func (h *ec2Handler) eniXML(e lambdaENI, account string, names map[string]string) string {
	var b strings.Builder
	b.WriteString(xtag("networkInterfaceId", e.ID) + xtag("subnetId", e.SubnetID) + xtag("vpcId", e.VpcID) +
		xtag("availabilityZone", h.zone()) + xtag("description", e.description()) + xtag("ownerId", account) +
		xtag("requesterId", lambdaENIRequester) + "<requesterManaged>true</requesterManaged><status>in-use</status>" +
		xtag("macAddress", e.mac()))
	if len(e.Addrs) > 0 {
		b.WriteString(xtag("privateIpAddress", e.Addrs[0].IP))
	}
	b.WriteString("<sourceDestCheck>true</sourceDestCheck>")
	groups := make([]string, 0, len(e.Groups))
	for _, g := range e.Groups {
		groups = append(groups, xtag("groupId", g)+xtag("groupName", groupName(names, g)))
	}
	b.WriteString(xset("groupSet", groups))
	b.WriteString("<tagSet/>")
	addrs := make([]string, 0, len(e.Addrs))
	for i, a := range e.Addrs {
		addrs = append(addrs, xtag("privateIpAddress", a.IP)+xbool("primary", i == 0))
	}
	b.WriteString(xset("privateIpAddressesSet", addrs))
	b.WriteString("<ipv6AddressesSet/><interfaceType>lambda</interfaceType>")
	return b.String()
}
