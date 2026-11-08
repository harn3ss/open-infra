package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/policyengine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// The account's network, where CloudFormation made it (the stack namespace): VPC isolated with two subnets
// and a security group in it, plus a subnet and a group of another VPC and a subnet in no VPC.
func vpcFixtureObjects() []runtime.Object {
	obj := func(kind, name string, spec map[string]any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "openinfra.dev/v1", "kind": kind,
			"metadata": map[string]any{"name": name, "namespace": testCFNNamespace}, "spec": spec}}
	}
	return []runtime.Object{
		obj("Subnet", "app-a", map[string]any{"vpc": "isolated", "cidr": "10.20.1.0/24"}),
		obj("Subnet", "app-b", map[string]any{"vpc": "isolated", "cidr": "10.20.2.0/24"}),
		obj("Subnet", "other-a", map[string]any{"vpc": "other", "cidr": "10.30.1.0/24"}),
		obj("Subnet", "flat", map[string]any{"cidr": "10.40.1.0/24"}),
		obj("SecurityGroup", "egress-allowlist", map[string]any{"vpc": "isolated", "egress": []any{}}),
		obj("SecurityGroup", "other-sg", map[string]any{"vpc": "other"}),
		obj("SecurityGroup", "no-vpc", map[string]any{}),
	}
}

// vpcRoleChecker: the caller may create functions and pass roles; the role exec may manage network
// interfaces only when eni is true.
func vpcRoleChecker(t *testing.T, eni bool) *dataplaneauthz.Checker {
	docs := []dataplaneauthz.PolicyDoc{userDoc(dpAllow([]string{"lambda:*", "iam:PassRole"}, "*"))}
	roleStmts := []policyengine.Statement{dpAllow([]string{"logs:CreateLogStream", "logs:PutLogEvents"}, "*")}
	if eni {
		roleStmts = append(roleStmts, dpAllow([]string{"ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface"}, "*"))
	}
	docs = append(docs, dataplaneauthz.PolicyDoc{Name: "exec-policy", AppliesTo: []string{"Role::exec"}, Statements: roleStmts})
	return checkerInMode(t, "enforce", docs...)
}

func vpcCfg(subnets, groups []any) map[string]any {
	return map[string]any{"VpcConfig": map[string]any{"SubnetIds": subnets, "SecurityGroupIds": groups}}
}

// CreateFunction with a VpcConfig puts the function in its VPC — beside the account's network — and the
// configuration answers the VpcConfig with its VpcId, as Lambda does.
func TestCreateFunction_VpcConfig(t *testing.T) {
	h, dyn, _ := manageFixture(t, vpcRoleChecker(t, true), vpcFixtureObjects()...)
	w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions",
		lmCreateBody(t, vpcCfg([]any{"app-a", "app-b"}, []any{"egress-allowlist"}))), testUser)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateFunction with VpcConfig: %d %s", w.Code, w.Body)
	}
	obj := getClaim(t, dyn, testCFNNamespace, "orders")
	vc, _, _ := unstructured.NestedMap(obj.Object, "spec", "vpcConfig")
	if vc["vpcId"] != "isolated" || len(vc["subnetIds"].([]any)) != 2 || vc["securityGroupIds"].([]any)[0] != "egress-allowlist" {
		t.Fatalf("spec.vpcConfig = %v", vc)
	}
	for _, want := range []string{`"VpcConfig":{`, `"VpcId":"isolated"`, `"SubnetIds":["app-a","app-b"]`, `"SecurityGroupIds":["egress-allowlist"]`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("the configuration is missing %s: %s", want, w.Body)
		}
	}
	w = serveWith(h, lambdaReq(http.MethodGet, "/2015-03-31/functions/orders/configuration", nil), testUser)
	if !strings.Contains(w.Body.String(), `"VpcId":"isolated"`) {
		t.Fatalf("GetFunctionConfiguration answers the VpcConfig: %s", w.Body)
	}

	// Out of the VPC: an empty VpcConfig leaves empty lists (no VPC), and the configuration says so.
	w = serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/configuration", vpcCfg([]any{}, []any{})), testUser)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"VpcId":""`) {
		t.Fatalf("an empty VpcConfig takes the function out of its VPC: %d %s", w.Code, w.Body)
	}
	vc, _, _ = unstructured.NestedMap(getClaim(t, dyn, testCFNNamespace, "orders").Object, "spec", "vpcConfig")
	if len(vc["subnetIds"].([]any)) != 0 || vc["vpcId"] != nil {
		t.Fatalf("out of its VPC, spec.vpcConfig = %v", vc)
	}
	// And back in.
	w = serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/configuration", vpcCfg([]any{"app-b"}, []any{"egress-allowlist"})), testUser)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"SubnetIds":["app-b"]`) {
		t.Fatalf("UpdateFunctionConfiguration puts it back in its VPC: %d %s", w.Code, w.Body)
	}
}

// Lambda's refusals: missing or foreign subnets and groups, a VPC that is not one, the limits, IPv6, and an
// execution role that may not manage network interfaces. A refused call creates nothing.
func TestCreateFunction_VpcConfigRefusals(t *testing.T) {
	many := func(n int, p string) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = p + strings.Repeat("x", i+1)
		}
		return out
	}
	cases := map[string]struct {
		extra map[string]any
		eni   bool
		want  string
	}{
		"subnets without groups": {vpcCfg([]any{"app-a"}, nil), true, "needs both SubnetIds and SecurityGroupIds"},
		"groups without subnets": {vpcCfg(nil, []any{"egress-allowlist"}), true, "needs both SubnetIds and SecurityGroupIds"},
		"a subnet that does not exist": {vpcCfg([]any{"app-z"}, []any{"egress-allowlist"}), true,
			"EC2 Error Code: InvalidSubnetID.NotFound. EC2 Error Message: The subnet ID 'app-z' does not exist"},
		"a group that does not exist": {vpcCfg([]any{"app-a"}, []any{"sg-z"}), true,
			"EC2 Error Code: InvalidGroup.NotFound. EC2 Error Message: The security group 'sg-z' does not exist"},
		"subnets of two VPCs":       {vpcCfg([]any{"app-a", "other-a"}, []any{"egress-allowlist"}), true, "must be in one VPC"},
		"a subnet in no VPC":        {vpcCfg([]any{"flat"}, []any{"no-vpc"}), true, "is not in a VPC"},
		"a group of another VPC":    {vpcCfg([]any{"app-a"}, []any{"other-sg"}), true, "is not in the subnets' VPC isolated"},
		"a group of no VPC":         {vpcCfg([]any{"app-a"}, []any{"no-vpc"}), true, "is not in the subnets' VPC isolated"},
		"17 subnets":                {vpcCfg(many(17, "s"), []any{"egress-allowlist"}), true, "Member must have length less than or equal to 16"},
		"6 groups":                  {vpcCfg([]any{"app-a"}, many(6, "g")), true, "Member must have length less than or equal to 5"},
		"IPv6":                      {map[string]any{"VpcConfig": map[string]any{"SubnetIds": []any{"app-a"}, "SecurityGroupIds": []any{"egress-allowlist"}, "Ipv6AllowedForDualStack": true}}, true, "IPv4 only"},
		"a role without ENI rights": {vpcCfg([]any{"app-a"}, []any{"egress-allowlist"}), false, "The provided execution role does not have permissions to call CreateNetworkInterface on EC2"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h, dyn, _ := manageFixture(t, vpcRoleChecker(t, c.eni), vpcFixtureObjects()...)
			w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, c.extra)), testUser)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), c.want) {
				t.Fatalf("want 400 %q, got %d %s", c.want, w.Code, w.Body)
			}
			for _, ns := range []string{"default", testCFNNamespace} {
				if _, err := dyn.Resource(functionClaimGVR).Namespace(ns).Get(context.Background(), "orders", metav1GetOptions()); err == nil {
					t.Fatalf("a refused CreateFunction must create nothing (found one in %s)", ns)
				}
			}
		})
	}
}

// A function the management account made outside its network (the Lambda API's own namespace) cannot be put
// in a VPC by an update: it is told to be created again with its VpcConfig.
func TestUpdateFunctionConfiguration_VpcConfigOutsideTheNetwork(t *testing.T) {
	h, _, _ := manageFixture(t, vpcRoleChecker(t, true), vpcFixtureObjects()...)
	if w := serveWith(h, lambdaReq(http.MethodPost, "/2015-03-31/functions", lmCreateBody(t, nil)), testUser); w.Code != http.StatusCreated {
		t.Fatalf("CreateFunction: %d %s", w.Code, w.Body)
	}
	w := serveWith(h, lambdaReq(http.MethodPut, "/2015-03-31/functions/orders/configuration", vpcCfg([]any{"app-a"}, []any{"egress-allowlist"})), testUser)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Create it again with its VpcConfig") {
		t.Fatalf("want the function refused a VPC, got %d %s", w.Code, w.Body)
	}
}

func TestVpcConfigOf(t *testing.T) {
	if vpcConfigOf(map[string]any{}) != nil {
		t.Error("a function never in a VPC has no VpcConfig")
	}
	vc := vpcConfigOf(map[string]any{"vpcConfig": map[string]any{"subnetIds": []any{"a"}, "securityGroupIds": []any{"g"}, "vpcId": "v"}})
	if vc["VpcId"] != "v" || len(vc["SubnetIds"].([]string)) != 1 || vc["Ipv6AllowedForDualStack"] != false {
		t.Errorf("VpcConfig %v", vc)
	}
}

func metav1GetOptions() metav1.GetOptions { return metav1.GetOptions{} }
