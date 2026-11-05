package render

import (
	"os"
	"strings"
	"testing"
)

// The shim finds a function by name in the Lambda API's namespace and the stack namespace (fn_locate.go),
// and lists them a page at a time for Lambda ListFunctions (lambda_read.go). That needs exactly `get` and
// `list` on kind: Function, bound in just those two namespaces: a ClusterRoleBinding, another verb (watch,
// or a write) or another resource widens what the shim's own identity may do.
func TestAWSShim_FunctionLookupGrantIsReadOnlyInTwoNamespaces(t *testing.T) {
	const path = "../../platform/aws-shim/aws-shim.yaml"
	cr := yamlDoc(t, path, "ClusterRole", "open-infra-aws-shim-functions")
	mustContain(t, "open-infra-aws-shim-functions", cr,
		"rules:\n  - apiGroups: [openinfra.dev]\n    resources: [functions]\n    verbs: [get, list]")
	if strings.Count(cr, "verbs:") != 1 || strings.Contains(cr, "verbs: [get, list,") {
		t.Errorf("open-infra-aws-shim-functions must grant get and list only, got:\n%s", cr)
	}
	if strings.Count(cr, "apiGroups:") != 1 {
		t.Errorf("open-infra-aws-shim-functions must hold one rule, got:\n%s", cr)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bound := map[string]bool{}
	for _, d := range strings.Split(string(b), "\n---") {
		if !strings.Contains(d, "name: open-infra-aws-shim-functions }") {
			continue
		}
		if strings.Contains(d, "\nkind: ClusterRoleBinding\n") {
			t.Errorf("the function lookup grant must not be bound cluster-wide:\n%s", d)
		}
		for _, ns := range []string{"default", "open-infra-cfn"} {
			if strings.Contains(d, "\nkind: RoleBinding\n") && strings.Contains(d, "\n  namespace: "+ns+"\n") {
				bound[ns] = true
			}
		}
	}
	for _, ns := range []string{"default", "open-infra-cfn"} {
		if !bound[ns] {
			t.Errorf("the function lookup grant is not bound in %s", ns)
		}
	}
}

// EC2's enforce-mode reads (ec2.go listForCaller) are made with the shim's own client: get and list on the
// five EC2 kinds, in the stack namespace only — no write, no watch, nothing cluster-wide.
func TestAWSShim_EC2ReadGrantIsReadOnlyInTheStackNamespace(t *testing.T) {
	const path = "../../platform/aws-shim/aws-shim.yaml"
	role := yamlDoc(t, path, "Role", "aws-shim-ec2-reads")
	mustContain(t, "aws-shim-ec2-reads", role,
		"  namespace: open-infra-cfn\n",
		"rules:\n  - apiGroups: [openinfra.dev]\n    resources: [virtualmachines, volumes, securitygroups, vpcs, subnets]\n    verbs: [get, list]")
	if strings.Count(role, "verbs:") != 1 || strings.Count(role, "apiGroups:") != 1 {
		t.Errorf("aws-shim-ec2-reads must hold one get/list rule, got:\n%s", role)
	}
	rb := yamlDoc(t, path, "RoleBinding", "aws-shim-ec2-reads")
	mustContain(t, "aws-shim-ec2-reads binding", rb, "  namespace: open-infra-cfn\n", "kind: Role, name: aws-shim-ec2-reads }")
}
