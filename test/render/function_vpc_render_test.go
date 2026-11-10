package render

import (
	"strings"
	"testing"
)

// A Function with Lambda's VpcConfig (spec.vpcConfig, docs/lambda-vpc.md): its execution environments run on
// the Lambda VPC subnet, their DNS goes to the VPC resolver only, they are members of the VPC's security
// groups, and the stored package and the role's credentials come from the Lambda service port. A function
// without vpcConfig renders none of it (the role-less golden pins that every existing function is
// unchanged).

func vpcFnSpec(extra map[string]any) map[string]any {
	spec := map[string]any{
		"code": map[string]any{"runtime": "python3.12", "handler": "app.handler",
			"source": map[string]any{"package": map[string]any{"sha256": strings.Repeat("a", 64)}}},
		"role": "fn-role",
		"vpcConfig": map[string]any{"subnetIds": []any{"app-a", "app-b"}, "securityGroupIds": []any{"egress-allowlist"},
			"vpcId": "isolated"},
	}
	for k, v := range extra {
		spec[k] = v
	}
	return spec
}

func TestFunction_VpcConfig(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/function-composition.yaml")
	out := render(t, tmpl, fnRoleCtx("orders", "acct", vpcFnSpec(nil), nil))
	for _, want := range []string{
		`ovn.kubernetes.io/logical_switch: "openinfra-lambda-vpc"`,
		`openinfra.dev/vpc-id: "isolated"`,
		`openinfra.dev/subnet-ids: "app-a,app-b"`,
		`openinfra.dev/security-group-ids: "egress-allowlist"`,
		`openinfra.dev/lambda-vpc: "true"`,
		`"openinfra.dev/sg-egress-allowlist": ""`,
		"dnsPolicy: None",
		`nameservers: [ "10.43.0.2" ]`,
		`searches: [ "acct.svc.cluster.local", "svc.cluster.local", "cluster.local" ]`,
		`OPENINFRA_CODE_URL, value: "http://10.43.0.3:4568/v1/function-code"`,
		`AWS_ENDPOINT_URL_STS, value: "http://10.43.0.3:4568"`,
		// the handler's own AWS calls stay on the front door, subject to its security groups
		`AWS_ENDPOINT_URL, value: "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566"`,
		"matchName: openinfra-lambda-vpc",
		"matchName: openinfra-aws-identity",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("a VPC function's render is missing %q", want)
		}
	}
	if strings.Contains(out, "-eol-egress") {
		t.Error("a supported runtime in a VPC is its security groups' alone: no egress policy of its own")
	}

	// The openinfra-lambda-vpc EnvironmentConfig's values win once Crossplane hands it over.
	extra := map[string]any{"lambda-vpc": map[string]any{"items": []any{map[string]any{"resource": map[string]any{
		"data": map[string]any{"subnet": "lambda-alt", "resolver": "10.96.0.2", "lambdaService": "http://shim.example:4568"}}}}}}
	out = render(t, tmpl, fnRoleCtx("orders", "acct", vpcFnSpec(nil), extra))
	for _, want := range []string{`logical_switch: "lambda-alt"`, `nameservers: [ "10.96.0.2" ]`,
		`OPENINFRA_CODE_URL, value: "http://shim.example:4568/v1/function-code"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the EnvironmentConfig's %q is not used", want)
		}
	}

	// Not in a VPC: none of it.
	plain := vpcFnSpec(nil)
	delete(plain, "vpcConfig")
	out = render(t, tmpl, fnRoleCtx("orders", "acct", plain, nil))
	for _, unwanted := range []string{"logical_switch", "lambda-vpc", "dnsPolicy", ":4568", "openinfra.dev/vpc-id"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("a function outside a VPC renders %q", unwanted)
		}
	}
	// An emptied VPC configuration (UpdateFunctionConfiguration with no subnets) is no VPC.
	emptied := vpcFnSpec(map[string]any{"vpcConfig": map[string]any{"subnetIds": []any{}, "securityGroupIds": []any{}}})
	if out := render(t, tmpl, fnRoleCtx("orders", "acct", emptied, nil)); strings.Contains(out, "logical_switch") {
		t.Error("a VPC configuration with no subnets puts the function in no VPC")
	}

	// A function in a VPC takes its security groups from the VPC configuration only.
	if err := renderErr(tmpl, fnRoleCtx("orders", "acct", vpcFnSpec(map[string]any{"securityGroups": []any{"other"}}), nil)); err == nil ||
		!strings.Contains(err.Error(), "vpcConfig.securityGroupIds") {
		t.Errorf("securityGroups beside vpcConfig must fail, got %v", err)
	}
}

// An unsupported runtime (runtimeImage) in a VPC is egress-denied by a policy that allows nothing but the
// VPC resolver and the Lambda service, and logs what it refuses: its security groups' rules are then its
// whole egress. allowEgress drops the policy, as outside a VPC.
func TestFunction_VpcConfigUnsupportedRuntime(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/function-composition.yaml")
	byo := func(allow bool) map[string]any {
		return vpcFnSpec(map[string]any{"code": map[string]any{"runtimeImage": "ghcr.io/example/legacy-node:16", "unsupportedRuntime": true,
			"allowEgress": allow, "handler": "index.handler", "source": map[string]any{"package": map[string]any{"sha256": strings.Repeat("b", 64)}}}})
	}
	out := render(t, tmpl, fnRoleCtx("legacy", "acct", byo(false), nil))
	pol := grepCtx(out, "legacy-eol-egress")
	for _, want := range []string{"legacy-eol-egress", `ovn.kubernetes.io/enable_log: "true"`, `ovn.kubernetes.io/log_acl_actions: "drop"`,
		"kubernetes.io/metadata.name: open-infra-aws-shim", "app: aws-shim", "port: 5353", "port: 4568"} {
		if !strings.Contains(out, want) {
			t.Errorf("an unsupported runtime in a VPC: missing %q in\n%s", want, pol)
		}
	}
	if strings.Contains(out, "namespaceSelector: {} }") || strings.Contains(out, "[ { namespaceSelector: {} } ]") {
		t.Error("in a VPC the unsupported runtime's policy must not allow every in-cluster destination")
	}
	if out := render(t, tmpl, fnRoleCtx("legacy", "acct", byo(true), nil)); strings.Contains(out, "-eol-egress") {
		t.Error("allowEgress drops the unsupported runtime's egress policy")
	}
	// Outside a VPC the unsupported runtime keeps its in-cluster-only policy, as before.
	plain := byo(false)
	delete(plain, "vpcConfig")
	if out := render(t, tmpl, fnRoleCtx("legacy", "acct", plain, nil)); !strings.Contains(out, "namespaceSelector: {} } ]") {
		t.Error("outside a VPC the unsupported runtime's policy is unchanged")
	}
}

// A security group in a VPC logs what it admits and refuses (for the VPC's flow logs) and, with egress
// rules, lets its members reach the VPC resolver and the Lambda service. A group of no VPC is unchanged.
func TestSecurityGroup_InAVpc(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/securitygroup-composition.yaml")
	ctx := func(spec map[string]any) map[string]any {
		return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec, "metadata": map[string]any{"labels": map[string]any{
				"crossplane.io/claim-name": "egress-allowlist", "crossplane.io/claim-namespace": "acct"}}}}}}
	}
	egress := []any{map[string]any{"protocol": "TCP", "ports": []any{5432}, "to": []any{map[string]any{"securityGroup": "db"}}}}
	out := render(t, tmpl, ctx(map[string]any{"vpc": "isolated", "egress": egress}))
	for _, want := range []string{`ovn.kubernetes.io/enable_log: "true"`, `ovn.kubernetes.io/log_acl_actions: "drop"`,
		"open-infra-aws-shim", "app: aws-shim", "port: 5353", "port: 4568", "openinfra.dev/sg-db"} {
		if !strings.Contains(out, want) {
			t.Errorf("a VPC group with egress rules: missing %q", want)
		}
	}
	// No egress rules: unrestricted outbound (AWS's default), still logged.
	out = render(t, tmpl, ctx(map[string]any{"vpc": "isolated", "ingress": []any{}}))
	if !strings.Contains(out, "enable_log") || strings.Contains(out, "port: 4568") {
		t.Errorf("a VPC group without egress rules is logged and adds no egress allow:\n%s", out)
	}
	// A group of no VPC: exactly as before.
	out = render(t, tmpl, ctx(map[string]any{"egress": egress}))
	if strings.Contains(out, "enable_log") || strings.Contains(out, "aws-shim") || strings.Contains(out, "5353") {
		t.Errorf("a group of no VPC must render as before:\n%s", out)
	}
}
