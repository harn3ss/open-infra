// Lambda's VpcConfig on the Lambda API: CreateFunction and UpdateFunctionConfiguration put a function in
// subnets of one VPC with that VPC's security groups (spec.vpcConfig on the kind: Function), and the
// function's configuration answers it back (VpcConfig with its VpcId), as Lambda does. What being in a VPC
// does to the function's network is the composition's and the VPC resolver's (docs/lambda-vpc.md).
//
// As on Lambda:
//   - SubnetIds (at most 16) and SecurityGroupIds (at most 5) are given together, every subnet and group of
//     the caller's account, all of one VPC; an empty VpcConfig takes the function out of its VPC;
//   - the execution role must be allowed to create, describe and delete network interfaces (the
//     AWSLambdaVPCAccessExecutionRole permissions), or the call is refused before anything changes.
//
// A function in a VPC lives where its account's VPCs, subnets and security groups are (accountNamespace
// of the stack namespace: a member account's home; the management account's stack namespace), because a
// security group governs the pods beside it. A new function with a VpcConfig is created there. A function
// the management account made outside it cannot join a VPC; recreate it with its VpcConfig.
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	lambdaMaxVPCSubnets = 16
	lambdaMaxVPCGroups  = 5
)

// lambdaVPCConfig is a request's VpcConfig.
type lambdaVPCConfig struct {
	subnets, groups []string
	set             bool // the request carries VpcConfig
}

func (c lambdaVPCConfig) empty() bool { return len(c.subnets) == 0 && len(c.groups) == 0 }

// parseVpcConfig reads a request's VpcConfig member, with Lambda's validation of its shape.
func parseVpcConfig(body map[string]any) (lambdaVPCConfig, *lambdaErr) {
	v, ok := body["VpcConfig"]
	if !ok || v == nil {
		return lambdaVPCConfig{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return lambdaVPCConfig{}, invalidParam("VpcConfig must be an object of SubnetIds and SecurityGroupIds")
	}
	for k := range m {
		switch k {
		case "SubnetIds", "SecurityGroupIds":
		case "Ipv6AllowedForDualStack":
			if b, _ := m[k].(bool); b {
				return lambdaVPCConfig{}, invalidParam("Ipv6AllowedForDualStack is not supported by open-infra's Lambda: a function's network interfaces are IPv4 only")
			}
		default:
			return lambdaVPCConfig{}, invalidParam("VpcConfig.%s is not a property of a VPC configuration", k)
		}
	}
	ids := func(field, member string, max int) ([]string, *lambdaErr) {
		raw, present := m[field]
		if !present || raw == nil {
			return nil, nil
		}
		l, ok := raw.([]any)
		if !ok {
			return nil, invalidParam("VpcConfig.%s must be a list of ids", field)
		}
		if len(l) > max {
			return nil, lambdaValidation("vpcConfig."+member, fmt.Sprint(l), fmt.Sprintf("Member must have length less than or equal to %d", max))
		}
		out := make([]string, 0, len(l))
		seen := map[string]bool{}
		for _, e := range l {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, invalidParam("VpcConfig.%s must be a list of ids", field)
			}
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		return out, nil
	}
	subnets, e := ids("SubnetIds", "subnetIds", lambdaMaxVPCSubnets)
	if e != nil {
		return lambdaVPCConfig{}, e
	}
	groups, e := ids("SecurityGroupIds", "securityGroupIds", lambdaMaxVPCGroups)
	if e != nil {
		return lambdaVPCConfig{}, e
	}
	if (len(subnets) == 0) != (len(groups) == 0) {
		return lambdaVPCConfig{}, invalidParam("A function in a VPC needs both SubnetIds and SecurityGroupIds: give both, or neither to take it out of its VPC")
	}
	return lambdaVPCConfig{subnets: subnets, groups: groups, set: true}, nil
}

// vpcNamespace is where the caller's account's VPCs, subnets and security groups are (the EC2 front door
// reads them there): a member account's home, the management account's stack namespace.
func (h *lambdaHandler) vpcNamespace(ctx context.Context) string {
	stack := h.fnNS
	if h.fns != nil && len(h.fns.namespaces) > 1 {
		stack = h.fns.namespaces[1]
	}
	return accountNamespace(ctx, stack)
}

// resolveVPC checks a VPC configuration against the account's subnets and security groups in ns and
// returns the VPC they are all in, refusing as Lambda does when one is missing or they span VPCs.
func (h *lambdaHandler) resolveVPC(ctx context.Context, ns string, cfg lambdaVPCConfig) (string, *lambdaErr) {
	if h.fns == nil || h.fns.dyn == nil {
		return "", &lambdaErr{500, "ServiceException", "the VPC configuration could not be checked: the function store is not configured"}
	}
	vpc := ""
	for _, id := range cfg.subnets {
		u, err := h.fns.dyn.Resource(subnetGVR).Namespace(ns).Get(ctx, id, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return "", invalidParam("Error occurred while DescribeSubnets. EC2 Error Code: InvalidSubnetID.NotFound. EC2 Error Message: The subnet ID '%s' does not exist", id)
		} else if err != nil {
			return "", &lambdaErr{500, "ServiceException", "the function's subnets could not be read"}
		}
		sv, _, _ := unstructured.NestedString(u.Object, "spec", "vpc")
		if sv == "" {
			return "", invalidParam("The subnet ID '%s' is not in a VPC: a function's subnets are subnets of one VPC", id)
		}
		if vpc == "" {
			vpc = sv
		} else if sv != vpc {
			return "", invalidParam("The subnets of a function must be in one VPC: '%s' is in %s, not %s", id, sv, vpc)
		}
	}
	for _, id := range cfg.groups {
		u, err := h.fns.dyn.Resource(securityGroupGVR).Namespace(ns).Get(ctx, id, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return "", invalidParam("Error occurred while DescribeSecurityGroups. EC2 Error Code: InvalidGroup.NotFound. EC2 Error Message: The security group '%s' does not exist", id)
		} else if err != nil {
			return "", &lambdaErr{500, "ServiceException", "the function's security groups could not be read"}
		}
		if gv, _, _ := unstructured.NestedString(u.Object, "spec", "vpc"); gv != vpc {
			return "", invalidParam("Security group '%s' is not in the subnets' VPC %s: a function's security groups are its VPC's", id, vpc)
		}
	}
	return vpc, nil
}

// lambdaVPCRoleActions are what Lambda needs the execution role to allow for a function in a VPC (the
// AWSLambdaVPCAccessExecutionRole managed policy's network-interface permissions).
var lambdaVPCRoleActions = []string{"ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface"}

// checkVPCRole refuses a role that may not manage network interfaces, with Lambda's message. Without the
// data-plane policy engine there is no policy to read, and nothing is refused.
func (h *lambdaHandler) checkVPCRole(ctx context.Context, ns, role string) *lambdaErr {
	if h.authz == nil || role == "" {
		return nil
	}
	name := strings.ToLower(roleNameOf(role))
	id := dataplaneauthz.QualifiedName(h.iamHome(), h.executionRoleNamespace(ctx, ns, name), name)
	for _, action := range lambdaVPCRoleActions {
		d := h.authz.Decide(ctx, "Role", id, nil, action, "NetworkInterface", "*", nil)
		if !d.Governed || !d.Allowed {
			op := strings.TrimPrefix(action, "ec2:")
			return invalidParam("The provided execution role does not have permissions to call %s on EC2", op)
		}
	}
	return nil
}

// iamHome is the namespace the IAM policy world keys principals relative to.
func (h *lambdaHandler) iamHome() string {
	if h.rolesHome != "" {
		return h.rolesHome
	}
	return dataplaneauthz.DefaultHomeNamespace
}

// executionRoleNamespace is the namespace the function's execution role resolves in, as executionRole
// finds it: the function's own, else its account's IAM home.
func (h *lambdaHandler) executionRoleNamespace(ctx context.Context, ns, name string) string {
	if in, ok := h.roles.(roleResolverIn); ok && h.roles != nil {
		if _, found := in.ResolveIn(ctx, ns, name); found {
			return ns
		}
		if isMemberRequest(ctx) {
			if home := accountHomeOf(ctx); home != "" {
				return home
			}
		}
	}
	return h.iamHome()
}

// applyVpcConfig puts a request's VpcConfig on the function's spec (in namespace ns), after Lambda's checks.
// role is the execution role the function will run as.
func (h *lambdaHandler) applyVpcConfig(ctx context.Context, spec map[string]any, cfg lambdaVPCConfig, ns, role string) *lambdaErr {
	if !cfg.set {
		return nil
	}
	if cfg.empty() {
		// Out of its VPC. Written as empty lists, which the composition reads as no VPC (a field the claim
		// sync would copy back cannot be removed).
		spec["vpcConfig"] = map[string]any{"subnetIds": []any{}, "securityGroupIds": []any{}}
		return nil
	}
	if want := h.vpcNamespace(ctx); want != ns {
		return invalidParam("This function cannot be put in a VPC: it was created outside its account's network. Create it again with its VpcConfig")
	}
	vpc, e := h.resolveVPC(ctx, ns, cfg)
	if e != nil {
		return e
	}
	if e := h.checkVPCRole(ctx, ns, role); e != nil {
		return e
	}
	subnets := make([]any, len(cfg.subnets))
	for i, s := range cfg.subnets {
		subnets[i] = s
	}
	groups := make([]any, len(cfg.groups))
	for i, g := range cfg.groups {
		groups[i] = g
	}
	spec["vpcConfig"] = map[string]any{"subnetIds": subnets, "securityGroupIds": groups, "vpcId": vpc}
	return nil
}

// vpcConfigOf is a function's VpcConfig as Lambda answers it; nil for a function never in a VPC.
func vpcConfigOf(spec map[string]any) map[string]any {
	vc, ok := spec["vpcConfig"].(map[string]any)
	if !ok {
		return nil
	}
	list := func(k string) []string {
		out := []string{}
		for _, e := range anySlice(vc[k]) {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	subnets, groups := list("subnetIds"), list("securityGroupIds")
	vpc := fnStr(vc["vpcId"])
	if len(subnets) == 0 {
		vpc = ""
	}
	return map[string]any{"SubnetIds": subnets, "SecurityGroupIds": groups, "VpcId": vpc, "Ipv6AllowedForDualStack": false}
}
