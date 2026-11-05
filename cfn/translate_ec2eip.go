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
//   - an EIP associated with nothing in the stack, where no allocations are kept (the CLI) — through the
//     aws-shim's front door (Capabilities.EC2AddressAPI) it is an allocation of its own instead
//     (KindEC2Address): a LAN address held for its stack, which an EIPAssociation in another stack
//     associates by AllocationId, the VM then carrying that address (spec.elasticIp, #347 item 8);
//   - an InstanceId naming something out of stack, and an AllocationId that is neither an in-stack EIP's
//     nor an allocation open-infra holds;
//   - an association by NetworkInterfaceId (this engine models no standalone ENI);
//   - more than one EIP on one instance, or one EIP on more than one instance (a VM has ONE LAN IP).
//
// Attributes: GetAtt <EIP>.AllocationId resolves to a stable synthetic eipalloc- id (eipAllocationID, in
// the resolver). Ref <EIP> / GetAtt <EIP>.PublicIp are the LAN IP MetalLB assigns at apply — carried
// only on the VM's <name>-lan Service status, not on any claim status field — so they stay unresolved
// placeholders that a consuming property refuses or caveats, like every other deploy-time attribute;
// except where another resource embeds them (eipAddressAtCreate: an instance's UserData), where the EIP is
// an allocation of its own created first and the create fills the address in (resolver.addressOf).
package cfn

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// eipBinding is one association of an Elastic IP with an in-stack AWS::EC2::Instance: an in-stack
// AWS::EC2::EIP (eip), or an allocation another stack holds, named by its AllocationId (alloc).
type eipBinding struct {
	eip, instance string // logical ids (eip "" for an allocation from another stack)
	alloc         string // the AllocationId of an allocation from another stack ("" for an in-stack EIP)
	via           string // the resource declaring the association: the EIP itself, or an EIPAssociation
}

// address names the Elastic IP a binding associates, for conflict checks and messages.
func (b eipBinding) address() string {
	if b.alloc != "" {
		return "allocation " + b.alloc
	}
	return b.eip
}

// eipAllocationID is the stable AllocationId of an in-stack EIP: deterministic per stack + logical id, in
// the AWS shape (eipalloc- + 17 hex). An EIP folded onto its in-stack instance is only named by it; an
// EIP associated with nothing in its stack is an allocation held under that id (KindEC2Address), which an
// EIPAssociation in another stack can name.
func eipAllocationID(stackName, logicalID string) string {
	sum := sha256.Sum256([]byte(stackName + "/" + logicalID))
	return "eipalloc-" + hex.EncodeToString(sum[:])[:17]
}

// allocationIDRe is an AllocationId as eipAllocationID makes them.
var allocationIDRe = regexp.MustCompile(`^eipalloc-[0-9a-f]{17}$`)

// eipHolderPort is the one port an allocation's holder Service declares (a Service needs one). The holder
// and the associated VM's LAN Service share the address, so the VM must not publish this port itself.
const eipHolderPort, eipHolderProto = 9, "UDP"

// externalAllocation is the AllocationId an EIPAssociation names when it is not an in-stack EIP's: a
// parameter or an Fn::ImportValue that resolves to an allocation another stack holds. ok=false when the
// property is absent, refers to an in-stack resource, or does not resolve to a concrete value.
func (c *stackCtx) externalAllocation(assocID string) (string, bool) {
	if _, inStack := c.assocEIP(assocID); inStack {
		return "", false
	}
	return c.externalAllocationValue(assocID)
}

// externalAllocationValue is the concrete value an EIPAssociation's AllocationId resolves to, unless it is
// a bare reference to an in-stack resource.
func (c *stackCtx) externalAllocationValue(assocID string) (string, bool) {
	raw, _ := c.rawProps(assocID)
	v, present := raw["AllocationId"]
	if !present {
		return "", false
	}
	if t, ok := getAttTarget(v); ok {
		if _, inStack := c.template.Resources[t]; inStack {
			return "", false
		}
	}
	if c.resolver == nil {
		return "", false
	}
	prev := c.resolver.where
	rp, _ := c.resolveProps(assocID)
	c.resolver.where = prev
	s, ok := concrete(rp["AllocationId"])
	if !ok || s == "" {
		return "", false
	}
	return strings.TrimSpace(s), true
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
	// An Elastic IP's address stays a placeholder here, so a wrapped !Ref <EIP> is still seen as the EIP.
	addr := c.resolver.addressOf
	c.resolver.addressOf = nil
	rp, _ := c.resolveProps(rid)
	c.resolver.addressOf = addr
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
	// GetAtt <EIP>.AllocationId resolves to a concrete id, so behind another intrinsic (an Fn::If that picks
	// it) the reference shows only as the id: match it against the stack's own EIPs.
	if alloc, ok := c.externalAllocationValue(assocID); ok {
		for _, rid := range c.sortedResourceIDs() {
			if c.includedType(rid, "AWS::EC2::EIP") && eipAllocationID(c.stackName(), rid) == alloc {
				return rid, true
			}
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
				b := eipBinding{eip: eip, instance: inst, via: rid}
				if c.eipAddressAtCreate(eip) {
					b.alloc = eipAllocationID(c.stackName(), eip) // an allocation of its own, created first
				}
				out = append(out, b)
			} else if alloc, ok := c.externalAllocation(rid); ok && c.caps.EC2AddressAPI && allocationIDRe.MatchString(alloc) {
				out = append(out, eipBinding{alloc: alloc, instance: inst, via: rid})
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
		if o.address() == b.address() {
			insts[o.instance] = true
		}
		if o.instance == b.instance {
			eips[o.address()] = true
		}
	}
	if len(insts) > 1 {
		return fmt.Sprintf("Elastic IP %s is associated with more than one instance (%s) — an EIP is one address on one instance, and open-infra maps it onto ONE VM's LAN IP", b.address(), strings.Join(sortedSet(insts), ", "))
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

// eipAddressAtCreate reports whether in-stack Elastic IP eipID's address must be known when the resources
// of the stack are created: another resource's properties embed it — Ref <EIP>, Fn::GetAtt <EIP>.PublicIp,
// or ${EIP} in an Fn::Sub (an instance's UserData, typically) — not counting the EIPAssociations that name
// it. On AWS such an EIP is allocated first and its address is in place when the instance that embeds it
// is created; here it is an allocation of its own (KindEC2Address), created first, and the instance
// associates it (spec.elasticIp). Only where allocations are kept (Capabilities.EC2AddressAPI). An EIP with
// its own InstanceId is never one: an instance embedding the EIP that names it is a circular dependency, on
// AWS as here.
func (c *stackCtx) eipAddressAtCreate(eipID string) bool {
	if c == nil || c.template == nil || !c.caps.EC2AddressAPI || !c.includedType(eipID, "AWS::EC2::EIP") {
		return false
	}
	if raw, _ := c.rawProps(eipID); raw != nil && raw["InstanceId"] != nil {
		return false
	}
	if len(c.natGatewaysUsingEIP(eipID)) > 0 {
		return false
	}
	for _, rid := range c.sortedResourceIDs() {
		res := c.template.Resources[rid]
		if rid == eipID || !c.included(res) || res.Type == "AWS::EC2::EIPAssociation" {
			continue
		}
		if raw, _ := c.rawProps(rid); refsEIPAddress(raw, eipID) {
			return true
		}
	}
	return false
}

// refsEIPAddress reports whether raw property value v embeds Elastic IP id's address: Ref id,
// Fn::GetAtt id.PublicIp, or ${id} / ${id.PublicIp} in an Fn::Sub that does not bind the name itself.
func refsEIPAddress(v any, id string) bool {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 1 {
			if r, ok := x["Ref"].(string); ok && r == id {
				return true
			}
			switch g := x["Fn::GetAtt"].(type) {
			case []any:
				if len(g) == 2 && fmt.Sprint(g[0]) == id && fmt.Sprint(g[1]) == "PublicIp" {
					return true
				}
			case string:
				if g == id+".PublicIp" {
					return true
				}
			}
			if s, ok := x["Fn::Sub"]; ok {
				tmpl, vars := "", map[string]any{}
				switch sv := s.(type) {
				case string:
					tmpl = sv
				case []any:
					if len(sv) > 0 {
						tmpl, _ = sv[0].(string)
					}
					if len(sv) > 1 {
						vars, _ = sv[1].(map[string]any)
					}
				}
				for rest := tmpl; ; {
					i := strings.Index(rest, "${")
					if i < 0 {
						break
					}
					end := strings.IndexByte(rest[i:], '}')
					if end < 0 {
						break
					}
					name := rest[i+2 : i+end]
					rest = rest[i+end:]
					if _, bound := vars[name]; !bound && (name == id || name == id+".PublicIp") {
						return true
					}
				}
			}
		}
		for _, e := range x {
			if refsEIPAddress(e, id) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if refsEIPAddress(e, id) {
				return true
			}
		}
	}
	return false
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
	if assocs := ctx.eipAssociationsNaming(id); len(assocs) > 0 && ctx.eipAddressAtCreate(id) {
		// The stack embeds this EIP's address (an instance's UserData, typically): it is an allocation of
		// its own, created before the resources that embed it, so they get the address at create time, as
		// on AWS. The associated instance's VM shares it (spec.elasticIp, eipExposeVM).
		alloc := eipAllocationID(ctx.stackName(), id)
		m := serviceManifest(KindEC2Address, alloc, map[string]any{"allocationId": alloc})
		m.Caveats = append(m.Caveats, "Elastic IP "+id+" is an allocation of its own ("+alloc+"), created before the resources that embed its address, so a Ref or GetAtt PublicIp in them (UserData) is the address itself, as on AWS — a LAN address, not a public internet IP. "+strings.Join(assocs, ", ")+" associates it with its instance; the stack releases it when it is deleted")
		for _, p := range []string{"NetworkBorderGroup", "Tags"} {
			if _, has := props[p]; has {
				m.Caveats = append(m.Caveats, "Elastic IP "+id+": "+p+" dropped — no open-infra equivalent (one site, one LAN address pool)")
			}
		}
		return m, f
	}
	if len(ctx.eipAssociationsNaming(id)) == 0 {
		if ctx.caps.EC2AddressAPI {
			// An allocation of its own: a LAN address held for this stack until the stack deletes it, which
			// an EIPAssociation in another stack names by this AllocationId (GetAtt <EIP>.AllocationId, passed
			// by parameter or export). The aws-shim holds it (a MetalLB address on a holder Service).
			alloc := eipAllocationID(ctx.stackName(), id)
			m := serviceManifest(KindEC2Address, alloc, map[string]any{"allocationId": alloc})
			m.Caveats = append(m.Caveats, "Elastic IP "+id+" is an allocation of its own ("+alloc+"): a LAN address (not a public internet IP) the platform holds for this stack, which an AWS::EC2::EIPAssociation in another stack can associate with its instance by this AllocationId; the address follows that instance and stays with the allocation when the other stack is deleted. Deleting this stack while the address is associated fails (InvalidIPAddress.InUse), as on AWS")
			for _, p := range []string{"NetworkBorderGroup", "Tags"} {
				if _, has := props[p]; has {
					m.Caveats = append(m.Caveats, "Elastic IP "+id+": "+p+" dropped — no open-infra equivalent (one site, one LAN address pool)")
				}
			}
			return m, f
		}
		return refuse("this Elastic IP is associated with nothing in the stack (no InstanceId, and no AWS::EC2::EIPAssociation names it) — here an Elastic IP is a VM's LAN IP, and this deploy path keeps no allocations of its own (the aws-shim's CloudFormation front door does: deploy there to allocate an address that another stack associates by AllocationId). Associate it with an in-stack AWS::EC2::Instance (InstanceId or an EIPAssociation), or author kind: ElasticIp natively")
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
	if _, eip := props["EIP"]; eip && props["AllocationId"] != nil {
		return refuse("an EIPAssociation names its address once — AllocationId or EIP (the legacy public-address form), not both")
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
	b := eipBinding{instance: inst, via: id}
	if eip, ok := ctx.assocEIP(id); ok {
		b.eip = eip
		if ctx.eipAddressAtCreate(eip) {
			// The EIP is an allocation of its own (its address is embedded at create): the VM shares the
			// holder's address, so it must not publish the holder's port either.
			b.alloc = eipAllocationID(ctx.stackName(), eip)
			if why := eipHolderPortClash(inst, ctx); why != "" {
				return refuse(why)
			}
		}
	} else {
		// An allocation another stack holds, named by its AllocationId (a parameter or an export).
		if _, ok := props["EIP"]; ok {
			return refuse("EIP (an address) must !Ref an in-stack AWS::EC2::EIP — an Elastic IP from another stack is associated by its AllocationId (that stack's GetAtt <EIP>.AllocationId, passed by parameter or Fn::ImportValue)")
		}
		alloc, ok := ctx.externalAllocation(id)
		switch {
		case !ok:
			return refuse("AllocationId must name an Elastic IP: !GetAtt <EIP>.AllocationId of an in-stack AWS::EC2::EIP, or the AllocationId of one another stack allocated (a parameter or Fn::ImportValue that resolves to it)")
		case !allocationIDRe.MatchString(alloc):
			return refuse("AllocationId " + alloc + " is not an Elastic IP allocation open-infra holds (eipalloc- followed by 17 hex digits, the AllocationId another stack's AWS::EC2::EIP reports) — an AWS account's allocation ids do not exist here")
		case !ctx.caps.EC2AddressAPI:
			return refuse("AllocationId " + alloc + " names an Elastic IP from another stack, and this deploy path keeps no allocations (the aws-shim's CloudFormation front door does) — associate an in-stack AWS::EC2::EIP instead")
		}
		b.alloc = alloc
		// The allocation's holder Service and the VM's LAN Service share the address; they must not
		// publish the same port.
		if why := eipHolderPortClash(inst, ctx); why != "" {
			return refuse(why)
		}
	}
	if why := eipConflict(b, ctx.eipBindings()); why != "" {
		return refuse(why)
	}
	return nil, f // folded into the instance's VM
}

// eipHolderPortClash is why instance instID cannot carry an allocation's address: its SecurityGroups
// publish the port the allocation's holder Service reserves on that address ("" when they do not).
func eipHolderPortClash(instID string, ctx *stackCtx) string {
	ports, _, _ := eipPortsFromSGs(instID, 22, ctx) // the access port is TCP; only the UDP holder port matters
	for _, p := range ports {
		if m, _ := p.(map[string]any); m != nil && m["port"] == eipHolderPort && m["protocol"] == eipHolderProto {
			return fmt.Sprintf("the instance's SecurityGroups publish %d/%s, which an Elastic IP allocation reserves on its address — publish the workload on another port", eipHolderPort, eipHolderProto)
		}
	}
	return ""
}

// unknownEIPAddressIn names an in-stack Elastic IP whose address raw property value v embeds and that is
// created as an allocation of its own (eipAddressAtCreate) — "" when there is none.
func (c *stackCtx) unknownEIPAddressIn(v any) string {
	for _, rid := range c.sortedResourceIDs() {
		if c.eipAddressAtCreate(rid) && refsEIPAddress(v, rid) {
			return rid
		}
	}
	return ""
}

// inStackAllocation reports whether alloc is the AllocationId of an in-stack Elastic IP.
func (c *stackCtx) inStackAllocation(alloc string) bool {
	if c == nil || c.template == nil {
		return false
	}
	for _, rid := range c.sortedResourceIDs() {
		if c.includedType(rid, "AWS::EC2::EIP") && eipAllocationID(c.stackName(), rid) == alloc {
			return true
		}
	}
	return false
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
	if len(mine) == 0 || eipConflict(mine[0], all) != "" || (mine[0].eip != "" && len(ctx.natGatewaysUsingEIP(mine[0].eip)) > 0) {
		return nil
	}
	eip := mine[0].address()
	spec["expose"] = true
	if alloc := mine[0].alloc; alloc != "" {
		// The VM's LAN IP is the allocation's address: its LAN Service shares that address with the holder
		// (vm-composition.yaml, spec.elasticIp), so it is the same address whichever VM carries it.
		spec["elasticIp"] = map[string]any{"allocationId": alloc}
	}

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
	if mine[0].alloc != "" && mine[0].eip != "" {
		cav = []string{
			"Elastic IP " + mine[0].eip + " is an allocation of its own, created before this instance because the stack embeds its address (Ref/GetAtt " + mine[0].eip + ".PublicIp), so that address is fixed when the instance is created, as on AWS. The VM's LAN Service shares it (spec.expose + spec.elasticIp — a MetalLB LoadBalancer carrying the access port, " + accessName + ", plus spec.ports). It is a LAN address, NOT a public internet IP; a replaced VM carries the same address, and it is released with the stack",
		}
	} else if mine[0].alloc != "" {
		cav = []string{
			"Elastic IP " + eip + " (from another stack) maps onto this VM's LAN IP: the address that allocation holds, shared by the VM's LAN Service (spec.expose + spec.elasticIp — a MetalLB LoadBalancer carrying the access port, " + accessName + ", plus spec.ports). It is a LAN address, NOT a public internet IP. It follows the instance: a replaced VM carries the same address, and deleting this stack leaves the address with its allocation. The VM's address is known once the allocation's is (the instance's PublicIp)",
		}
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

// publicIPExposeVM gives an instance with no Elastic IP the public address AWS would auto-assign: its
// primary interface's AssociatePublicIpAddress, or, when the interface doesn't say, an in-stack subnet
// with MapPublicIpOnLaunch. That address is the VM's LAN IP (spec.expose) and, as with an Elastic IP,
// publishes the ports the instance's security groups admit from a CIDR, not the access port alone.
func publicIPExposeVM(instID string, spec map[string]any, ctx *stackCtx) []string {
	if ctx == nil || ctx.template == nil {
		return nil
	}
	if exp, _ := spec["expose"].(bool); !exp {
		if !launchesIntoPublicSubnet(instID, ctx) {
			return nil
		}
		spec["expose"] = true
	}
	accessPort, accessName := 22, "SSH 22"
	if os, _ := spec["os"].(string); strings.HasPrefix(os, "windows") {
		accessPort, accessName = 3389, "RDP 3389"
	}
	ports, published, pcav := eipPortsFromSGs(instID, accessPort, ctx)
	if len(ports) > 0 {
		spec["ports"] = mergeVMPorts(spec["ports"], ports)
	}
	cav := []string{"the instance's public IPv4 address maps onto its VM's LAN IP (spec.expose — a MetalLB LoadBalancer carrying the access port, " + accessName + ", plus spec.ports). It is a LAN address, NOT a public internet IP, and like an AWS auto-assigned address it changes if the instance is replaced"}
	if len(published) > 0 {
		cav = append(cav, "ports published on the LAN IP are those the instance's SecurityGroups allow inbound from a CIDR (TCP/UDP): "+strings.Join(published, ", ")+" — each port's reachability is still enforced by the attached kind: SecurityGroups")
	}
	return append(cav, pcav...)
}

// launchesIntoPublicSubnet reports whether an instance gets a public address from its subnet: its primary
// interface (or the instance) names an in-stack AWS::EC2::Subnet with MapPublicIpOnLaunch true, and the
// interface does not set AssociatePublicIpAddress (false there overrides the subnet, as on AWS).
func launchesIntoPublicSubnet(instID string, ctx *stackCtx) bool {
	raw, ok := ctx.rawProps(instID)
	if !ok {
		return false
	}
	subnetRef := raw["SubnetId"]
	if nis, ok := listEntries(raw["NetworkInterfaces"], ctx); ok && len(nis) > 0 {
		nis, _ = nicEntries(instID, nis, ctx)
		if ni0 := primaryNIC(nis); ni0 != nil {
			if _, has := ni0["AssociatePublicIpAddress"]; has {
				return false // the interface decides; true already set expose
			}
			if s, has := ni0["SubnetId"]; has {
				subnetRef = s
			}
		}
	}
	t, ok := getAttTarget(subnetRef)
	if !ok || !ctx.includedType(t, "AWS::EC2::Subnet") {
		return false
	}
	props, ok := ctx.resolveProps(t)
	if !ok {
		return false
	}
	pub, ok := cfnBoolValue(props["MapPublicIpOnLaunch"])
	return ok && pub
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
		list, _ := listEntries(v, ctx) // a list that does not resolve is refused by the instance translator
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
	if nis, _ := listEntries(raw["NetworkInterfaces"], ctx); len(nis) > 0 {
		nis, _ = nicEntries(instID, nis, ctx) // an Fn::If entry is the interface its condition picks
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
		rules, _ := listEntries(sgRaw["SecurityGroupIngress"], ctx) // unresolvable: refused by the SG translator
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
