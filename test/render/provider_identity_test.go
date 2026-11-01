package render

import (
	"os"
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
