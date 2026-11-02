package cfn

import (
	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// An instance's DNS names (#347 item 7).
//
// Fn::GetAtt <Instance>.PrivateDnsName is AWS's name for its private address (ip-a-b-c-d.ec2.internal in
// us-east-1, ip-a-b-c-d.<region>.compute.internal elsewhere), built from the VM's address. Nothing serves
// that zone on open-infra, so the name identifies the instance but does not resolve.
//
// Fn::GetAtt <Instance>.PublicDnsName is the name of its public address, the VM's LAN IP, on the
// install's public DNS suffix (PUBLIC_DNS_SUFFIX, cfn/awsidentity): ec2-a-b-c-d.<suffix>, the shape of
// AWS's ec2-a-b-c-d.compute-1.amazonaws.com. A site sets a suffix that resolves on its LAN (a wildcard
// zone that answers a name carrying an address with that address). With no suffix, or for an instance
// with no public address, it is "" — what AWS reports for an instance without a public DNS name.

// instanceDNSNameCaveats are the fidelity notes for an instance whose DNS names the template reads.
func instanceDNSNameCaveats(id string, spec map[string]any, ctx *stackCtx) []string {
	if ctx == nil || ctx.template == nil {
		return nil
	}
	var cav []string
	if ctx.attrReferenced(id, "PrivateDnsName") {
		cav = append(cav, "Fn::GetAtt "+id+".PrivateDnsName is AWS's name for the VM's address (ip-a-b-c-d."+privateDNSZone(ctx)+"); no DNS server answers for that zone here, so the name identifies the instance but does not resolve — use PrivateIp to connect")
	}
	if ctx.attrReferenced(id, "PublicDnsName") {
		exposed, _ := spec["expose"].(bool)
		ports, _ := spec["ports"].([]any)
		switch suffix := awsidentity.Current().PublicDNSSuffix; {
		case !exposed && len(ports) == 0:
			cav = append(cav, "Fn::GetAtt "+id+".PublicDnsName is \"\": the instance has no public address (no Elastic IP or AssociatePublicIpAddress), as on AWS")
		case suffix == "":
			cav = append(cav, "Fn::GetAtt "+id+".PublicDnsName is \"\": this install sets no public DNS suffix (PUBLIC_DNS_SUFFIX), so its instances have no public DNS name — as on AWS in a VPC without DNS hostnames. Set one that resolves on the LAN to get ec2-a-b-c-d.<suffix> for the VM's LAN IP")
		default:
			cav = append(cav, "Fn::GetAtt "+id+".PublicDnsName is ec2-<LAN IP with dashes>."+suffix+", the VM's LAN address on this install's public DNS suffix (not an amazonaws.com name)")
		}
	}
	return cav
}

func privateDNSZone(ctx *stackCtx) string {
	region := awsidentity.Current().Region
	if ctx != nil && ctx.resolver != nil {
		if v, ok := ctx.resolver.pseudo["AWS::Region"].(string); ok && v != "" {
			region = v
		}
	}
	host := awsidentity.PrivateDNSName("0.0.0.0", region) // ip-0-0-0-0.<zone>
	return host[len("ip-0-0-0-0."):]
}

// attrReferenced reports whether the template reads Fn::GetAtt id.attr anywhere it is evaluated: an
// Output, or a property of an included resource (following only the branch an Fn::If takes).
func (c *stackCtx) attrReferenced(id, attr string) bool {
	var conds map[string]bool
	if c.resolver != nil {
		conds = c.resolver.conds
	}
	found := false
	check := func(rid, a string) {
		if rid == id && a == attr {
			found = true
		}
	}
	for _, k := range sortedKeys(c.template.Outputs) {
		o, _ := c.template.Outputs[k].(map[string]any)
		if o == nil {
			continue
		}
		if cond, _ := o["Condition"].(string); cond != "" && !conds[cond] {
			continue
		}
		walkOutputRefs(o["Value"], c.template, conds, nil, check)
	}
	for rid, r := range c.template.Resources {
		if found {
			break
		}
		if !c.included(r) {
			continue
		}
		raw, _ := c.rawProps(rid)
		walkOutputRefs(any(raw), c.template, conds, nil, check)
	}
	return found
}
