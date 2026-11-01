package render

import (
	"os"
	"strings"
	"testing"
)

// The shim finds a function by name in the Lambda API's namespace and the stack namespace (fn_locate.go).
// That needs exactly `get` on kind: Function, bound in just those two namespaces: a ClusterRoleBinding,
// another verb (list/watch, or a write) or another resource widens what the shim's own identity may do.
func TestAWSShim_FunctionLookupGrantIsGetOnlyInTwoNamespaces(t *testing.T) {
	const path = "../../platform/aws-shim/aws-shim.yaml"
	cr := yamlDoc(t, path, "ClusterRole", "open-infra-aws-shim-functions")
	mustContain(t, "open-infra-aws-shim-functions", cr,
		"rules:\n  - apiGroups: [openinfra.dev]\n    resources: [functions]\n    verbs: [get]")
	if strings.Contains(cr, "verbs: [get,") {
		t.Errorf("open-infra-aws-shim-functions must grant get only, got:\n%s", cr)
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
