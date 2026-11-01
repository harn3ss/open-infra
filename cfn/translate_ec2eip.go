// EC2 Elastic IPs -> the VM's LAN IP (#347 item 1.6).
//
// On AWS an Elastic IP is a static public address associated with an instance — by the EIP's own
// InstanceId, or by an AWS::EC2::EIPAssociation (InstanceId + AllocationId/EIP). The open-infra analog
// on a single-gateway site is the VM's LAN IP: a kind: VirtualMachine with spec.expose gets a MetalLB
// LoadBalancer IP carrying its access port (SSH 22 / RDP 3389), and spec.ports publishes extra ports on
// the same IP. An AWS EIP reaches every port the instance's security groups admit, so the VM's
// spec.ports is DERIVED from the ingress rules of its in-stack AWS::EC2::SecurityGroups.
//
// This is a collation anchored on the instance (the shape of the SNS-subscription and standalone-SG-rule
// collations): translateEC2Instance calls eipExposeVM, which sets spec.expose + spec.ports and carries
// the fidelity caveats; the EIP and EIPAssociation themselves provision nothing (nil manifest) and only
// refuse what can't be honored:
//
//   - an EIP used as a NAT gateway's address (an AWS::EC2::NatGateway AllocationId) — that is the
//     kind: NatGateway + kind: ElasticIp border-device case, still authored natively;
//   - an EIP associated with nothing in the stack (no in-stack instance to carry the address);
//   - an InstanceId / AllocationId naming something out of stack;
//   - an association by NetworkInterfaceId (this engine models no standalone ENI);
//   - more than one EIP on one instance, or one EIP on more than one instance (a VM has ONE LAN IP).
//
// Attributes: GetAtt <EIP>.AllocationId resolves to a stable synthetic eipalloc- id (eipAllocationID, in
// the resolver). Ref <EIP> / GetAtt <EIP>.PublicIp are the LAN IP MetalLB assigns at apply — carried
// only on the VM's <name>-lan Service status, not on any claim status field — so they stay unresolved
// placeholders that a consuming property refuses or caveats, like every other deploy-time attribute.
package cfn

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// eipBinding is one association of an in-stack AWS::EC2::EIP with an in-stack AWS::EC2::Instance.
type eipBinding struct {
	eip, instance string // logical ids
	via           string // the resource declaring the association: the EIP itself, or an EIPAssociation
}

// eipAllocationID is the stable synthetic AllocationId of an in-stack EIP: deterministic per stack +
// logical id, in the AWS shape (eipalloc- + 17 hex). It names the allocation; no open-infra API takes it.
func eipAllocationID(stackName, logicalID string) string {
	sum := sha256.Sum256([]byte(stackName + "/" + logicalID))
	return "eipalloc-" + hex.EncodeToString(sum[:])[:17]
}

// refID returns the logical id resource rid's property prop references: a raw {Ref}/{Fn::GetAtt}, or —
// when the reference is wrapped in another intrinsic — the target of the resolved placeholder.
func (c *stackCtx) refID(rid, prop string) (string, bool) {
	raw, _ := c.rawProps(rid)
	v, present := raw[prop]
	if !present {
		return "", false
	}
	if t, ok := getAttTarget(v); ok {
		return t, true
	}
	if c.resolver == nil {
		return "", false
	}
	prev := c.resolver.where // resolveProps relabels the resolver; restore the caller's location
	rp, _ := c.resolveProps(rid)
	c.resolver.where = prev
	return placeholderTarget(rp[prop])
}

// includedType reports whether rid is an in-stack resource of cfnType that its Condition includes.
func (c *stackCtx) includedType(rid, cfnType string) bool {
	r, in := c.template.Resources[rid]
	return in && r.Type == cfnType && c.included(r)
}

// sortedResourceIDs returns the stack's logical ids in a deterministic order (sort.Strings, not the
// insertion-sort sortStrs: this runs once per instance/EIP and estate templates can be large).
func (c *stackCtx) sortedResourceIDs() []string {
	ids := make([]string, 0, len(c.template.Resources))
	for rid := range c.template.Resources {
		ids = append(ids, rid)
	}
	sort.Strings(ids)
	return ids
}

// assocEIP returns the in-stack EIP an AWS::EC2::EIPAssociation names — via AllocationId
// (!GetAtt <EIP>.AllocationId) or EIP (!Ref <EIP>, the address form).
func (c *stackCtx) assocEIP(assocID string) (string, bool) {
	for _, p := range []string{"AllocationId", "EIP"} {
		if t, ok := c.refID(assocID, p); ok && c.includedType(t, "AWS::EC2::EIP") {
			return t, true
		}
	}
	return "", false
}

// eipBindings returns every VALID in-stack EIP -> Instance association among included resources, in a
// deterministic order. An association that refuses (out-of-stack instance/EIP, an ENI) is not a binding.
func (c *stackCtx) eipBindings() []eipBinding {
	var out []eipBinding
	for _, rid := range c.sortedResourceIDs() {
		res := c.template.Resources[rid]
		if !c.included(res) {
			continue
		}
		switch res.Type {
		case "AWS::EC2::EIP":
			if inst, ok := c.refID(rid, "InstanceId"); ok && c.includedType(inst, "AWS::EC2::Instance") {
				out = append(out, eipBinding{eip: rid, instance: inst, via: rid})
			}
		case "AWS::EC2::EIPAssociation":
			if raw, _ := c.rawProps(rid); raw["NetworkInterfaceId"] != nil {
				continue // refused by its own translator (no standalone ENI)
			}
			inst, ok := c.refID(rid, "InstanceId")
			if !ok || !c.includedType(inst, "AWS::EC2::Instance") {
				continue
			}
			if eip, ok := c.assocEIP(rid); ok {
				out = append(out, eipBinding{eip: eip, instance: inst, via: rid})
			}
		}
	}
	return out
}

// eipConflict returns why binding b can't be honored — the EIP is bound to more than one instance, or
// the instance carries more than one EIP — or "" when it is the instance's one and only address.
func eipConflict(b eipBinding, all []eipBinding) string {
	insts, eips := map[string]bool{}, map[string]bool{}
	for _, o := range all {
		if o.eip == b.eip {
			insts[o.instance] = true
		}
		if o.instance == b.instance {
			eips[o.eip] = true
		}
	}
	if len(insts) > 1 {
		return fmt.Sprintf("Elastic IP %s is associated with more than one instance (%s) — an EIP is one address on one instance, and open-infra maps it onto ONE VM's LAN IP", b.eip, strings.Join(sortedSet(insts), ", "))
	}
	if len(eips) > 1 {
		return fmt.Sprintf("instance %s would carry %d Elastic IPs (%s) — open-infra gives a VM ONE LAN IP (spec.expose); associate a single EIP with it (secondary addresses on additional ENIs are not modeled)", b.instance, len(eips), strings.Join(sortedSet(eips), ", "))
	}
	return ""
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrs(out)
	return out
}

// natGatewaysUsingEIP returns the included AWS::EC2::NatGateways whose AllocationId references eipID.
func (c *stackCtx) natGatewaysUsingEIP(eipID string) []string {
	var out []string
	for _, rid := range c.sortedResourceIDs() {
		if !c.includedType(rid, "AWS::EC2::NatGateway") {
			continue
		}
		if t, ok := c.refID(rid, "AllocationId"); ok && t == eipID {
			out = append(out, rid)
		}
	}
	return out
}

// eipAssociationsNaming returns the included AWS::EC2::EIPAssociations that name eipID (valid or not).
func (c *stackCtx) eipAssociationsNaming(eipID string) []string {
	var out []string
	for _, rid := range c.sortedResourceIDs() {
		if !c.includedType(rid, "AWS::EC2::EIPAssociation") {
			continue
		}
		if t, ok := c.assocEIP(rid); ok && t == eipID {
			out = append(out, rid)
		}
	}
	return out
}

// ---- AWS::EC2::EIP -> folded onto the associated VM's LAN IP ----
//
// Provisions nothing on its own (nil manifest): the associated instance's kind: VirtualMachine carries
// the address (spec.expose) — see eipExposeVM. Domain is inert (every address is the VPC kind);
// Tags/NetworkBorderGroup are caveats on the VM. A specific/BYOIP address (Address, PublicIpv4Pool,
// IpamPoolId, TransferAddress) can't be honored and refuses via blockUnknownProps.
func translateEC2EIP(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"Domain": true, "InstanceId": true, "NetworkBorderGroup": true, "Tags": true}
	f := blockUnknownProps(id, props, known)
	refuse := func(msg string) (*Manifest, []Finding) {
		return nil, append(f, Finding{"Resource " + id, msg})
	}
	if ctx == nil {
		return refuse("an Elastic IP needs stack context to find the instance it is associated with")
	}
	if nat := ctx.natGatewaysUsingEIP(id); len(nat) > 0 {
		return refuse("this Elastic IP is the address of AWS::EC2::NatGateway " + strings.Join(nat, ", ") + " (its AllocationId) — the NAT-gateway border device maps to kind: NatGateway + kind: ElasticIp, which are NOT create-deployable from a template (the gateway's internal IP and VPC binding aren't carried): author them natively. Only an EIP associated with an in-stack AWS::EC2::Instance folds onto that VM's LAN IP")
	}
	if _, hasInst := props["InstanceId"]; hasInst {
		all := ctx.eipBindings()
		for _, b := range all {
			if b.via == id {
				if why := eipConflict(b, all); why != "" {
					return refuse(why)
				}
				return nil, f // folded into the instance's VM (spec.expose + spec.ports; caveats ride the VM)
			}
		}
		return refuse("InstanceId must !Ref an in-stack AWS::EC2::Instance — open-infra maps an Elastic IP onto that VM's LAN IP (spec.expose); an out-of-stack instance (a raw i- id or a parameter) has no VM in this stack to carry the address")
	}
	if len(ctx.eipAssociationsNaming(id)) == 0 {
		return refuse("this Elastic IP is associated with nothing in the stack (no InstanceId, and no AWS::EC2::EIPAssociation names it) — open-infra's Elastic IP analog is a VM's LAN IP, so an unassociated address has nothing to carry it (allocating one with no holder would publish an address that reaches nothing). Associate it with an in-stack AWS::EC2::Instance (InstanceId or an EIPAssociation), or author kind: ElasticIp natively")
	}
	return nil, f // an EIPAssociation carries the binding (and refuses on its own if it can't be honored)
}

// ---- AWS::EC2::EIPAssociation -> folded onto the instance's VM (spec.expose) ----
//
// Provisions nothing on its own: it binds an in-stack EIP (AllocationId / EIP) to an in-stack instance
// (InstanceId), and the instance's VM carries the address. PrivateIpAddress is a caveat on the VM (the
// LAN IP forwards to the VM's single address). NetworkInterfaceId refuses: no standalone ENI is modeled.
func translateEC2EIPAssociation(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"AllocationId": true, "EIP": true, "InstanceId": true, "NetworkInterfaceId": true, "PrivateIpAddress": true}
	f := blockUnknownProps(id, props, known)
	refuse := func(msg string) (*Manifest, []Finding) {
		return nil, append(f, Finding{"Resource " + id, msg})
	}
	if ctx == nil {
		return refuse("an EIPAssociation needs stack context to resolve its instance and address")
	}
	if _, ok := props["NetworkInterfaceId"]; ok {
		return refuse("association by NetworkInterfaceId does not map — this engine models no standalone ENI (AWS::EC2::NetworkInterface has no backing kind; only an instance's primary NetworkInterfaces[0] folds into its VM). Associate the EIP by InstanceId with an in-stack AWS::EC2::Instance instead")
	}
	if _, ok := props["InstanceId"]; !ok {
		return refuse("an EIPAssociation needs an InstanceId naming an in-stack AWS::EC2::Instance (the VM whose LAN IP carries the address)")
	}
	inst, ok := ctx.refID(id, "InstanceId")
	if !ok || !ctx.includedType(inst, "AWS::EC2::Instance") {
		return refuse("InstanceId must !Ref an in-stack AWS::EC2::Instance — an out-of-stack instance (a raw i- id or a parameter) has no VM in this stack to carry the address")
	}
	eip, ok := ctx.assocEIP(id)
	if !ok {
		return refuse("AllocationId (!GetAtt <EIP>.AllocationId) or EIP (!Ref <EIP>) must name an in-stack AWS::EC2::EIP — an out-of-stack allocation/address can't be moved onto the VM, whose LAN IP open-infra allocates per VM")
	}
	if why := eipConflict(eipBinding{eip: eip, instance: inst, via: id}, ctx.eipBindings()); why != "" {
		return refuse(why)
	}
	return nil, f // folded into the instance's VM
}

// eipExposeVM folds the in-stack Elastic IP associated with instance instID (if exactly one, cleanly
// bound) onto its VM: spec.expose = true, and spec.ports derived from the instance's in-stack security
// groups. Returns the fidelity caveats for the VM manifest. A conflicted or NAT-bound EIP is left to the
// EIP/EIPAssociation translators, which refuse it (the stack does not deploy).
func eipExposeVM(instID string, spec map[string]any, ctx *stackCtx) []string {
	if ctx == nil || ctx.template == nil {
		return nil
	}
	all := ctx.eipBindings()
	var mine []eipBinding
	for _, b := range all {
		if b.instance == instID {
			mine = append(mine, b)
		}
	}
	if len(mine) == 0 || eipConflict(mine[0], all) != "" || len(ctx.natGatewaysUsingEIP(mine[0].eip)) > 0 {
		return nil
	}
	eip := mine[0].eip
	spec["expose"] = true

	accessPort, accessName := 22, "SSH 22"
	if os, _ := spec["os"].(string); strings.HasPrefix(os, "windows") {
		accessPort, accessName = 3389, "RDP 3389"
	}
	ports, published, pcav := eipPortsFromSGs(instID, accessPort, ctx)
	if len(ports) > 0 {
		spec["ports"] = mergeVMPorts(spec["ports"], ports)
	}

	cav := []string{
		"Elastic IP " + eip + " maps onto this VM's LAN IP (spec.expose — a MetalLB LoadBalancer carrying the access port, " + accessName + ", plus spec.ports). It is a LAN address, NOT a public internet IP. It is stable for the life of the VM but is held by the VM's LoadBalancer Service, so it does not outlive the VM the way an AWS allocation outlives its instance: a replaced (deleted + recreated) VM may draw a different LAN IP. Ref/GetAtt " + eip + ".PublicIp are assigned at apply and do not resolve at translate time; GetAtt " + eip + ".AllocationId is a stable synthetic eipalloc- id",
	}
	if len(published) > 0 {
		cav = append(cav, "ports published on the LAN IP are those the instance's SecurityGroups allow inbound from a CIDR (TCP/UDP): "+strings.Join(published, ", ")+" — each port's reachability is still enforced by the attached kind: SecurityGroups (the LoadBalancer preserves the client source IP), and the access port is always published by expose")
	} else {
		cav = append(cav, "no SecurityGroup ingress rule yielded a publishable port, so only the access port ("+accessName+") is on the LAN IP; its reachability is governed by the VM's attached kind: SecurityGroups")
	}
	cav = append(cav, pcav...)

	if raw, ok := ctx.rawProps(eip); ok {
		for _, p := range []string{"NetworkBorderGroup", "Tags"} {
			if _, has := raw[p]; has {
				cav = append(cav, "Elastic IP "+eip+": "+p+" dropped — no open-infra equivalent (one site, one LAN address pool)")
			}
		}
	}
	for _, b := range mine {
		if b.via == b.eip {
			continue
		}
		if raw, ok := ctx.rawProps(b.via); ok {
			if _, has := raw["PrivateIpAddress"]; has {
				cav = append(cav, "EIPAssociation "+b.via+": PrivateIpAddress dropped — the LAN IP forwards to the VM's single address (secondary private IPs are not modeled)")
			}
		}
	}
	return cav
}

// vmPort is one TCP/UDP port published on a VM's LAN IP.
type vmPort struct {
	port  int
	proto string
}

// eipPortsFromSGs derives the spec.ports an Elastic IP publishes: the TCP/UDP ports the instance's
// in-stack AWS::EC2::SecurityGroups admit from a CIDR source (inline SecurityGroupIngress and standalone
// AWS::EC2::SecurityGroupIngress rules), using the SG translator's own port parsing (sgPorts): a single
// port maps 1:1, a range of up to maxExpandedPortRange ports expands, all-ports / wider ranges / protocol
// -1 / portless protocols are caveats (never "publish everything"). The access port (TCP accessPort) is
// never duplicated. A rule sourced from another SecurityGroup admits in-cluster members over the private
// network, not LAN clients of the address, so it publishes nothing.
func eipPortsFromSGs(instID string, accessPort int, ctx *stackCtx) (ports []any, published []string, cav []string) {
	raw, _ := ctx.rawProps(instID)
	var sgIDs, external []string
	addList := func(v any) {
		list, _ := v.([]any)
		for _, e := range list {
			if t, ok := getAttTarget(e); ok {
				if _, isRes := ctx.template.Resources[t]; isRes {
					if ctx.includedType(t, "AWS::EC2::SecurityGroup") {
						sgIDs = append(sgIDs, t)
					}
					continue
				}
			}
			// A literal or a parameter naming a kind: SecurityGroup outside the stack (a raw sg- id is
			// refused by the instance translator itself).
			if n, ok := concrete(ctx.resolveVal(e)); ok && n != "" && !strings.HasPrefix(strings.ToLower(n), "sg-") {
				external = append(external, n)
			}
		}
	}
	addList(raw["SecurityGroupIds"])
	addList(raw["SecurityGroups"])
	if nis, ok := raw["NetworkInterfaces"].([]any); ok && len(nis) > 0 {
		if ni0 := primaryNIC(nis); ni0 != nil {
			addList(ni0["GroupSet"])
		}
	}
	sgIDs = dedupStrings(sgIDs)
	sortStrs(sgIDs)

	if len(sgIDs) == 0 && len(external) == 0 {
		cav = append(cav, "the instance attaches no SecurityGroup, so no ports beyond the access port were derived (on AWS it would get the VPC default group, which admits no internet inbound) — add spec.ports natively if the workload serves more")
	}
	if len(external) > 0 {
		cav = append(cav, "SecurityGroup(s) "+strings.Join(dedupStrings(external), ", ")+" are not in this stack — their ingress rules can't be read, so the ports they allow were NOT published on the LAN IP; add them to spec.ports natively")
	}

	seen := map[vmPort]bool{}
	var keys []vmPort
	var sgSourced, noCidr []string
	examine := func(label string, rv any) {
		r, ok := rv.(map[string]any)
		if !ok {
			return
		}
		cidr, _ := concrete(ctx.resolveVal(r["CidrIp"]))
		if cidr == "" {
			if _, ok := r["SourceSecurityGroupId"]; ok {
				sgSourced = append(sgSourced, label)
			} else {
				noCidr = append(noCidr, label)
			}
			return
		}
		proto, _ := concrete(ctx.resolveVal(r["IpProtocol"]))
		var p string
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "tcp":
			p = "TCP"
		case "udp":
			p = "UDP"
		case "-1", "all":
			cav = append(cav, label+" allows ALL protocols and ports from "+cidr+" — NOT published (an AWS EIP would expose everything; publishing every port is not a faithful default) — add the ports the workload serves to spec.ports natively")
			return
		default:
			cav = append(cav, fmt.Sprintf("%s: IpProtocol %q carries no TCP/UDP port to publish on the LAN IP — not published", label, proto))
			return
		}
		list, perr := sgPorts(ctx.resolveVal(r["FromPort"]), ctx.resolveVal(r["ToPort"]))
		switch {
		case perr != "":
			cav = append(cav, label+": "+perr+" — not published on the LAN IP; add the ports you need to spec.ports natively")
			return
		case len(list) == 0:
			cav = append(cav, label+" allows every "+p+" port from "+cidr+" — NOT published (an all-ports rule would publish 65535 ports); add the ports the workload serves to spec.ports natively")
			return
		}
		for _, lp := range list {
			n, _ := lp.(int)
			if n < 1 || n > 65535 || (n == accessPort && p == "TCP") {
				continue // the access port is already on the LAN IP (expose); port 0 isn't publishable
			}
			k := vmPort{n, p}
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	for _, sg := range sgIDs {
		sgRaw, _ := ctx.rawProps(sg)
		rules, _ := sgRaw["SecurityGroupIngress"].([]any)
		for i, r := range rules {
			examine(fmt.Sprintf("SecurityGroup %s ingress rule %d", sg, i), r)
		}
		for _, rid := range ctx.sgStandaloneRules(sg, "AWS::EC2::SecurityGroupIngress") {
			rr, _ := ctx.rawProps(rid)
			examine("SecurityGroupIngress "+rid, rr)
		}
	}
	if len(sgSourced) > 0 {
		cav = append(cav, "ingress rules sourced from another SecurityGroup ("+strings.Join(sgSourced, "; ")+") admit that group's in-cluster members over the private network, not LAN clients of the Elastic IP — their ports were not published on the LAN IP")
	}
	if len(noCidr) > 0 {
		cav = append(cav, "ingress rules with no IPv4 CidrIp source ("+strings.Join(noCidr, "; ")+") were not published on the LAN IP")
	}

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].proto < keys[j].proto
	})
	for _, k := range keys {
		ports = append(ports, map[string]any{"port": k.port, "protocol": k.proto})
		published = append(published, fmt.Sprintf("%d/%s", k.port, k.proto))
	}
	return ports, published, cav
}

// mergeVMPorts appends derived ports to any spec.ports already set, skipping duplicates (port+protocol).
func mergeVMPorts(existing any, derived []any) []any {
	cur, _ := existing.([]any)
	if len(cur) == 0 {
		return derived
	}
	key := func(v any) string {
		m, _ := v.(map[string]any)
		proto, _ := m["protocol"].(string)
		if proto == "" {
			proto = "TCP"
		}
		return fmt.Sprint(m["port"]) + "/" + strings.ToUpper(proto)
	}
	have := map[string]bool{}
	for _, e := range cur {
		have[key(e)] = true
	}
	out := append([]any{}, cur...)
	for _, d := range derived {
		if k := key(d); !have[k] {
			have[k] = true
			out = append(out, d)
		}
	}
	return out
}
