package cfn

import (
	"fmt"
	"regexp"
	"sort"
)

// sgVPCNameRe is a kind name: a security group id given as a literal (its kind: SecurityGroup name).
var sgVPCNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// lambdaVpcConfig translates an AWS::Lambda::Function's VpcConfig onto spec.vpcConfig (Lambda's VpcConfig
// on a kind: Function, docs/lambda-vpc.md): SubnetIds and SecurityGroupIds (subnet and group names, a
// !Ref to an in-stack AWS::EC2::Subnet / AWS::EC2::SecurityGroup resolving to its name), and the VPC
// they are in, read from the subnets: each must be one this stack creates, of one VPC (its VpcId). An
// empty VpcConfig is no VPC. Ipv6AllowedForDualStack true refuses (IPv4 only).
func lambdaVpcConfig(id string, props map[string]any, ctx *stackCtx) (map[string]any, []Finding) {
	v, ok := props["VpcConfig"]
	if !ok || v == nil {
		return nil, nil
	}
	where := "Resource " + id
	vc, ok := v.(map[string]any)
	if !ok {
		return nil, []Finding{{where, "VpcConfig must be an object of SubnetIds and SecurityGroupIds"}}
	}
	var f []Finding
	for _, k := range sortedKeys(vc) {
		switch k {
		case "SubnetIds", "SecurityGroupIds":
		case "Ipv6AllowedForDualStack":
			if b, _ := vc[k].(bool); b {
				f = append(f, Finding{where, "VpcConfig.Ipv6AllowedForDualStack is not supported: a function's network interfaces are IPv4 only"})
			}
		default:
			f = append(f, Finding{where, "VpcConfig." + k + " is not a property of a Lambda VPC configuration"})
		}
	}
	// Each entry from the raw template: a !Ref to an in-stack resource of the right type is that resource's
	// name; a literal is an id as given (a group only: the VPC is read from the subnets, which must be this
	// stack's).
	raw := map[string]any{}
	if ctx != nil {
		if rp, ok := ctx.rawProps(id); ok {
			raw, _ = rp["VpcConfig"].(map[string]any)
		}
	}
	vpcs := map[string]bool{}
	entries := func(field, cfnType string, max int) []any {
		l, _ := raw[field].([]any)
		if len(l) > max {
			f = append(f, Finding{where, fmt.Sprintf("VpcConfig.%s has %d entries; Lambda takes at most %d", field, len(l), max)})
			return nil
		}
		out := []any{}
		for _, e := range l {
			if t, isRef := refTarget(e); isRef && ctx.includedType(t, cfnType) {
				out = append(out, ctx.name(t))
				if cfnType == "AWS::EC2::Subnet" {
					sr, _ := ctx.rawProps(t)
					vt, isVRef := refTarget(sr["VpcId"])
					if !isVRef || !ctx.includedType(vt, "AWS::EC2::VPC") {
						f = append(f, Finding{where, "VpcConfig.SubnetIds: subnet " + t + " is in no VPC this stack creates (its VpcId must be a !Ref to an AWS::EC2::VPC)"})
						return nil
					}
					vpcs[ctx.name(vt)] = true
				}
				continue
			}
			if cfnType == "AWS::EC2::Subnet" {
				f = append(f, Finding{where, "VpcConfig.SubnetIds must be subnets this stack creates (a !Ref to an AWS::EC2::Subnet): the function's VPC is read from them"})
				return nil
			}
			s, ok := concrete(e)
			if !ok || !sgVPCNameRe.MatchString(s) {
				f = append(f, Finding{where, "VpcConfig.SecurityGroupIds must be security groups this stack creates (a !Ref to an AWS::EC2::SecurityGroup) or group ids"})
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	if ctx == nil {
		return nil, []Finding{{where, "VpcConfig needs the stack's subnets and security groups"}}
	}
	subnets := entries("SubnetIds", "AWS::EC2::Subnet", 16)
	groups := entries("SecurityGroupIds", "AWS::EC2::SecurityGroup", 5)
	if len(f) > 0 {
		return nil, f
	}
	if len(subnets) == 0 && len(groups) == 0 {
		return nil, nil
	}
	if len(subnets) == 0 || len(groups) == 0 {
		return nil, []Finding{{where, "VpcConfig needs both SubnetIds and SecurityGroupIds"}}
	}
	if len(vpcs) != 1 {
		list := make([]string, 0, len(vpcs))
		for v := range vpcs {
			list = append(list, v)
		}
		sort.Strings(list)
		return nil, []Finding{{where, fmt.Sprintf("VpcConfig.SubnetIds must be subnets of one VPC, not %v", list)}}
	}
	vpc := ""
	for v := range vpcs {
		vpc = v
	}
	return map[string]any{"subnetIds": subnets, "securityGroupIds": groups, "vpcId": vpc}, nil
}
