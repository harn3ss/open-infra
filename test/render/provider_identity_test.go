package render

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const providerSetupYAML = "../../platform/abstraction/provider-setup.yaml"

// provider-kubernetes runs as the fixed ServiceAccount provider-kubernetes (a DeploymentRuntimeConfig
// the Provider references), so its grants can be bound to that one identity instead of to every
// ServiceAccount in crossplane-system. The Provider is also installed by the Crossplane chart, so the
// two package references must stay identical, or the chart's init and ArgoCD would fight over it.
func TestProviderKubernetes_RunsAsAFixedServiceAccount(t *testing.T) {
	drc := yamlDoc(t, providerSetupYAML, "DeploymentRuntimeConfig", "openinfra-provider-kubernetes")
	mustContain(t, "runtime config", drc, "serviceAccountTemplate:\n    metadata:\n      name: provider-kubernetes")
	prov := yamlDoc(t, providerSetupYAML, "Provider", "crossplane-contrib-provider-kubernetes")
	mustContain(t, "Provider", prov, "kind: DeploymentRuntimeConfig\n    name: openinfra-provider-kubernetes")

	pkg := regexp.MustCompile(`package: (\S+)`).FindStringSubmatch(prov)
	if pkg == nil {
		t.Fatal("Provider has no package")
	}
	chart, err := os.ReadFile("../../platform/abstraction/crossplane.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chart), "- "+pkg[1]+"\n") {
		t.Errorf("Provider package %s is not the chart's provider.packages entry in crossplane.yaml", pkg[1])
	}

	// The provider's own system rules are granted to the fixed name too (ahead of rbac-manager).
	mustContain(t, "system binding", yamlDoc(t, providerSetupYAML, "ClusterRoleBinding", "openinfra-provider-kubernetes-system"),
		"name: openinfra-provider-kubernetes-system\n", "kind: ServiceAccount\n    name: provider-kubernetes\n    namespace: crossplane-system")
	mustContain(t, "provider binding", yamlDoc(t, providerSetupYAML, "ClusterRoleBinding", "openinfra-provider-kubernetes"),
		"kind: ServiceAccount\n    name: provider-kubernetes\n    namespace: crossplane-system")
}

// The open-appsync authz reconciler writes ServiceAccounts and a ClusterRoleBinding cluster-wide; its
// get/patch/update are pinned by name and an admission policy holds create to the same names.
func TestOpenAppsyncReconciler_WritesOnlyItsOwnObjects(t *testing.T) {
	const f = "../../platform/open-appsync/authz-rbac.yaml"
	cr := yamlDoc(t, f, "ClusterRole", "open-appsync-authz-reconciler")
	mustContain(t, "reconciler role", cr,
		"resources: [serviceaccounts]\n    verbs: [get, patch]\n    resourceNames: [open-appsync]",
		"resources: [clusterrolebindings]\n    verbs: [get, update, patch]\n    resourceNames: [open-appsync-authorizer]")
	for _, unpinned := range []string{"verbs: [get, create, patch]\n", "verbs: [get, create, update, patch]\n"} {
		if strings.Contains(cr, unpinned) {
			t.Errorf("reconciler role still has an unpinned rule %q", unpinned)
		}
	}
	p := yamlDoc(t, f, "ValidatingAdmissionPolicy", "open-appsync-authz-reconciler-scope")
	mustContain(t, "reconciler scope policy", p,
		"system:serviceaccount:crossplane-system:open-appsync-authz-reconciler",
		"object.metadata.name == 'open-appsync'", "object.roleRef.name == 'open-appsync-authorizer'",
		"s.kind == 'ServiceAccount' && s.name == 'open-appsync'")
	mustContain(t, "reconciler scope binding", yamlDoc(t, f, "ValidatingAdmissionPolicyBinding", "open-appsync-authz-reconciler-scope"),
		"policyName: open-appsync-authz-reconciler-scope")
}

// No grant in the platform is bound to the whole crossplane-system ServiceAccount group: it holds every
// reconciler, every Crossplane function pod and `default`, so a grant there is a grant to all of them
// (the provider's role alone is cluster-admin-equivalent). The OpenShift SCC overlay is the one
// exception — an SCC grant lets those pods start, it authorizes no API call.
func TestNoGrantToTheCrossplaneSystemGroup(t *testing.T) {
	var files []string
	for _, dir := range []string{"../../platform/abstraction", "../../platform/security", "../../platform/aws-shim",
		"../../platform/open-appsync", "../../platform/arch", "../../platform/console/manifests"} {
		m, _ := filepath.Glob(dir + "/*.yaml")
		files = append(files, m...)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range strings.Split(string(b), "\n---") {
			if (strings.Contains(d, "\nkind: ClusterRoleBinding\n") || strings.Contains(d, "\nkind: RoleBinding\n")) &&
				strings.Contains(d, "name: system:serviceaccounts:crossplane-system") {
				t.Errorf("%s binds a role to the crossplane-system ServiceAccount group:\n%s", f, d)
			}
		}
	}
}
