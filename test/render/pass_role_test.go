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

	// A Function's execution role (spec.role): passrole on the role's object name — a name, or a role ARN's
	// last segment, lower-cased — in the function's namespace, as the requester; only when it is set or
	// changed, so a role-less Function (and Crossplane's own claim updates) is never checked.
	fn := yamlDoc(t, passRoleYAML, "ValidatingAdmissionPolicy", "openinfra-pass-role-function")
	mustContain(t, "Function policy", fn,
		"apiGroups: [openinfra.dev]", "resources: [functions]", "operations: [CREATE, UPDATE]",
		"failurePolicy: Fail",
		"has(object.spec) && has(object.spec.role) && object.spec.role != ''",
		"request.operation == 'CREATE'", "oldObject.spec.role != object.spec.role",
		"object.spec.role.substring(object.spec.role.lastIndexOf('/') + 1).lowerAscii()",
		"authorizer.group('iam.openinfra.dev').resource('roles').namespace(request.namespace)",
		".name(variables.role).check('passrole').allowed()")

	for _, p := range []string{"openinfra-pass-role", "openinfra-instance-role-binding", "openinfra-pass-role-function"} {
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
		"name: openinfra-pass-role\n", "kind: ServiceAccount\n    name: provider-kubernetes\n    namespace: crossplane-system")

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

// An Application's workload ServiceAccount is named after the app, and vm-<x> is a VirtualMachine's
// identity: an Application named vm-<x> with assumeRole would run as the VM's ServiceAccount. The
// composition refuses it; any other name renders its ServiceAccount as before.
func TestPassRole_ApplicationCannotTakeAVMServiceAccount(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	ctx := func(name, assume string) map[string]any {
		spec := map[string]any{"image": "ghcr.io/me/app:latest", "port": 8080}
		if assume != "" {
			spec["assumeRole"] = assume
		}
		return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{"uid": "uid-1", "labels": map[string]any{
				"crossplane.io/claim-name": name, "crossplane.io/claim-namespace": "shop"}},
		}}}}
	}
	err := renderErr(tmpl, ctx("vm-web01", "webrole"))
	if err == nil || !strings.Contains(err.Error(), "cannot use assumeRole") {
		t.Fatalf("an app named vm-* with assumeRole must be refused, got err=%v", err)
	}
	// Without assumeRole there is no ServiceAccount, so the name is fine.
	if err := renderErr(tmpl, ctx("vm-web01", "")); err != nil {
		t.Fatalf("vm-* without assumeRole must render: %v", err)
	}
	out := render(t, tmpl, ctx("web01", "webrole"))
	if !strings.Contains(out, "kind: ServiceAccount") || !strings.Contains(out, "name: web01\n") {
		t.Fatalf("a normal app with assumeRole must still render its ServiceAccount")
	}
}

// An Execution's credentials Secret is named by the aws-shim alone and never changes: a hand-made
// Execution naming another's Secret is refused at admission (the controller also checks ownership).
func TestPassRole_ExecutionCredentialsAreTheShims(t *testing.T) {
	const shimYAML = "../../platform/aws-shim/aws-shim.yaml"
	p := yamlDoc(t, shimYAML, "ValidatingAdmissionPolicy", "openinfra-execution-credentials")
	mustContain(t, "execution credentials policy", p,
		"apiGroups: [openinfra.dev]", "operations: [CREATE, UPDATE]", "resources: [executions]",
		"failurePolicy: Fail",
		"request.userInfo.username == 'system:serviceaccount:open-infra-aws-shim:aws-shim'",
		"variables.secret == variables.oldSecret && variables.credNS == variables.oldCredNS")
	b := yamlDoc(t, shimYAML, "ValidatingAdmissionPolicyBinding", "openinfra-execution-credentials")
	mustContain(t, "execution credentials binding", b, "policyName: openinfra-execution-credentials", "validationActions: [")
}

// The shim and the console impersonate only openinfra:<user>. RBAC cannot hold impersonate-users to a
// prefix, so each impersonator ClusterRole carries the annotation rbac-to-cedar uses to narrow the Cedar
// corpus; without it a stolen token could act as a control-plane user (system:kube-controller-manager).
func TestImpersonators_UsersHeldToTheOpeninfraPrefix(t *testing.T) {
	for _, c := range []struct{ path, name string }{
		{"../../platform/aws-shim/aws-shim.yaml", "open-infra-aws-shim-impersonator"},
		{"../../platform/console/manifests/rbac-roles.yaml", "open-infra-console-impersonator"},
	} {
		mustContain(t, c.name, yamlDoc(t, c.path, "ClusterRole", c.name),
			"openinfra.dev/impersonate-users: \"openinfra:*\"",
			"resources: [groups]\n    verbs: [impersonate]",
			"resources: [users]\n    verbs: [impersonate]")
	}
}

// The VM credentials endpoint confirms a token is the VM launcher pod's own, which needs the shim to
// read VirtualMachineInstances (status.activePods, spec.volumes). Read-only.
func TestPassRole_ShimCanReadVMIsForTheLauncherCheck(t *testing.T) {
	cr := yamlDoc(t, "../../platform/aws-shim/aws-shim.yaml", "ClusterRole", "open-infra-aws-shim-policies")
	mustContain(t, "open-infra-aws-shim-policies", cr,
		"apiGroups: [kubevirt.io]\n    resources: [virtualmachineinstances]\n    verbs: [get]")
}

// A Lambda function's execution role is handed only to a pod Knative runs for the function: the shim reads
// the pod the token is bound to, its ReplicaSet and Deployment (the controller chain a Knative Revision
// owns), its ServiceAccount and the kind: Function. Read-only, by name — never list,
// never anything that writes. The control-plane grant mirrors the RBAC, as the VM identity's does.
func TestPassRole_ShimCanReadTheFunctionIdentitysPod(t *testing.T) {
	cr := yamlDoc(t, "../../platform/aws-shim/aws-shim.yaml", "ClusterRole", "open-infra-aws-shim-policies")
	mustContain(t, "open-infra-aws-shim-policies", cr,
		"apiGroups: [\"\"]\n    resources: [pods]\n    verbs: [get]\n",
		"apiGroups: [apps]\n    resources: [replicasets, deployments]\n    verbs: [get]\n",
		"apiGroups: [\"\"]\n    resources: [serviceaccounts]\n    verbs: [get]\n")
	mustContain(t, "open-infra-aws-shim-functions",
		yamlDoc(t, "../../platform/aws-shim/aws-shim.yaml", "ClusterRole", "open-infra-aws-shim-functions"),
		"resources: [functions]\n    verbs: [get, list]")
	p := yamlDoc(t, "../../platform/aws-shim/vmcreds-controlplane-policy.yaml", "Policy", "aws-shim-function-identity")
	mustContain(t, "aws-shim-function-identity", p,
		`appliesTo: ["ServiceAccount::open-infra-aws-shim/aws-shim"]`, `actions: ["get"]`, `resources: ["pods::*", "replicasets.apps::*", "deployments.apps::*"]`)
}
