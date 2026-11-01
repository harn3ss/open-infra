package render

import (
	"os"
	"strings"
	"testing"
)

// yamlDoc returns the document in a multi-document manifest whose kind and metadata.name match.
func yamlDoc(t *testing.T, path, kind, name string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range strings.Split(string(b), "\n---") {
		if strings.Contains(d, "\nkind: "+kind+"\n") && strings.Contains(d, "\n  name: "+name+"\n") {
			return d
		}
	}
	t.Fatalf("%s: no %s %s", path, kind, name)
	return ""
}

func mustContain(t *testing.T, what, doc string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(doc, n) {
			t.Errorf("%s: missing %q", what, n)
		}
	}
}

const passRoleYAML = "../../platform/security/pass-role.yaml"

// iam:PassRole (item 8a): naming a Role on a VirtualMachine, or binding one to a ServiceAccount through
// the instance-role annotation the VM credentials endpoint trusts, needs the `passrole` verb on that Role
// in the object's own namespace, checked as the requester. A change that drops either check, widens the
// Role's namespace, or checks the wrong verb reopens "create a VM, get any VM-trusted Role's credentials".
func TestPassRole_AdmissionChecksTheRequesterOnTheNamedRole(t *testing.T) {
	vm := yamlDoc(t, passRoleYAML, "ValidatingAdmissionPolicy", "openinfra-pass-role")
	mustContain(t, "VM policy", vm,
		"apiGroups: [openinfra.dev]", "resources: [virtualmachines]", "operations: [CREATE, UPDATE]",
		"failurePolicy: Fail",
		"authorizer.group('iam.openinfra.dev').resource('roles').namespace(request.namespace)",
		".name(object.spec.instanceRole).check('passrole').allowed()",
		// only when the role is set or changed — Crossplane's own claim updates are untouched
		"request.operation == 'CREATE'", "oldObject.spec.instanceRole != object.spec.instanceRole")

	sa := yamlDoc(t, passRoleYAML, "ValidatingAdmissionPolicy", "openinfra-instance-role-binding")
	mustContain(t, "ServiceAccount policy", sa,
		"apiGroups: [\"\"]", "resources: [serviceaccounts]", "operations: [CREATE, UPDATE]",
		"failurePolicy: Fail",
		"authorizer.group('iam.openinfra.dev').resource('roles').namespace(request.namespace)",
		".name(object.metadata.annotations['openinfra.dev/instance-role']).check('passrole').allowed()")

	for _, p := range []string{"openinfra-pass-role", "openinfra-instance-role-binding"} {
		b := yamlDoc(t, passRoleYAML, "ValidatingAdmissionPolicyBinding", p)
		mustContain(t, p+" binding", b, "policyName: "+p, "validationActions: [Deny, Audit]")
	}
}

// The persona decision (AWS parity): admins may pass any Role, power users may not — AWS's
// PowerUserAccess excludes iam:PassRole. The provider holds it to render the per-VM ServiceAccount.
func TestPassRole_AdminsYesPowerUsersNo(t *testing.T) {
	cr := yamlDoc(t, passRoleYAML, "ClusterRole", "openinfra-pass-role")
	mustContain(t, "openinfra-pass-role", cr, "apiGroups: [iam.openinfra.dev]", "resources: [roles]", "verbs: [passrole]")
	mustContain(t, "admins binding", yamlDoc(t, passRoleYAML, "ClusterRoleBinding", "openinfra-pass-role-admins"),
		"name: openinfra-pass-role\n", "name: openinfra:admins")
	mustContain(t, "provider binding", yamlDoc(t, passRoleYAML, "ClusterRoleBinding", "openinfra-pass-role-provider"),
		"name: openinfra-pass-role\n", "name: system:serviceaccounts:crossplane-system")

	b, err := os.ReadFile(passRoleYAML)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "openinfra:powerusers") {
		t.Errorf("pass-role.yaml must not grant passrole to openinfra:powerusers")
	}
	pu := yamlDoc(t, "../../platform/console/manifests/rbac-roles.yaml", "ClusterRole", "open-infra-poweruser")
	if strings.Contains(pu, "passrole") || strings.Contains(pu, "iam.openinfra.dev") {
		t.Errorf("open-infra-poweruser must hold no iam.openinfra.dev rights (passrole included)")
	}
}
