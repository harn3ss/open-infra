package render

import (
	"os"
	"strings"
	"testing"
)

// The shim finds a function by name in the caller's account's namespaces (fn_locate.go) — the management
// account's Lambda API and stack namespaces, a member account's home — and lists them a page at a time for
// Lambda ListFunctions (lambda_read.go); CloudWatch Logs lists the resources whose logs AWS keeps. Accounts'
// namespaces are made as accounts are, so the grants are bound in every namespace: exactly get and list, on
// exactly these kinds — another verb (watch, or a write) or another resource widens what the shim's own
// identity may do.
func TestAWSShim_FunctionLookupGrantIsReadOnly(t *testing.T) {
	const path = "../../platform/aws-shim/aws-shim.yaml"
	for _, c := range []struct{ role, resources, binding string }{
		{"open-infra-aws-shim-functions", "[functions]", "aws-shim-functions"},
		{"open-infra-aws-shim-log-sources", "[applications, trainingjobs, processingjobs]", "aws-shim-log-sources"},
	} {
		cr := yamlDoc(t, path, "ClusterRole", c.role)
		mustContain(t, c.role, cr,
			"rules:\n  - apiGroups: [openinfra.dev]\n    resources: "+c.resources+"\n    verbs: [get, list]")
		if strings.Count(cr, "verbs:") != 1 || strings.Count(cr, "apiGroups:") != 1 {
			t.Errorf("%s must hold one get/list rule, got:\n%s", c.role, cr)
		}
		crb := yamlDoc(t, path, "ClusterRoleBinding", c.binding)
		mustContain(t, c.binding, crb, "kind: ClusterRole, name: "+c.role+" }", "name: aws-shim\n    namespace: open-infra-aws-shim")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), "name: open-infra-aws-shim-functions }") != 1 {
		t.Error("the function lookup grant must be bound exactly once (its ClusterRoleBinding)")
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
