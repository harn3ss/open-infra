package render

import (
	"strings"
	"testing"
)

const ecrCredProviderYAML = "../../platform/aws-shim/ecr-credential-provider.yaml"

// The kubelet's ECR credential provider is installed node by node, binary before config, restarts the
// runtime only on a config change, and undoes a config the kubelet does not come back healthy with.
func TestECRCredentialProvider_Installer(t *testing.T) {
	ds := yamlDoc(t, ecrCredProviderYAML, "DaemonSet", "ecr-credential-provider")
	mustContain(t, "installer", ds,
		"openinfra.dev/ecr-credential-provider: enabled", "openinfra.dev/ecr-pull: enabled",
		"maxUnavailable: 1", "minReadySeconds: 120",
		"command: [/ecr-credential-provider, --install, /out]",
		"serviceAccountTokenAudience: openinfra-ecr-pull", "cacheType: ServiceAccount", "requireServiceAccount: false",
		"apiVersion: credentialprovider.kubelet.k8s.io/v1",
		"http://127.0.0.1:10248/healthz", "restoring the previous config",
		"path: /var/lib/rancher/credentialprovider")
	if !regexpDigest(ds) {
		t.Error("the provider binary's image must be pinned by digest")
	}
	bin, cfg := strings.Index(ds, "provider binary installed"), strings.Index(ds, `> "$CFG.new"`)
	if bin < 0 || cfg < 0 || bin > cfg {
		t.Error("the binary must be installed before the config names it (the kubelet does not start without it)")
	}
	if strings.Count(ds, "restart\n") < 2 {
		t.Error("the runtime is restarted on a config change and again to undo a failed one")
	}

	cr := yamlDoc(t, ecrCredProviderYAML, "ClusterRole", "openinfra-ecr-pull-audience")
	mustContain(t, "audience grant", cr, "resources: [openinfra-ecr-pull]", "verbs: [request-serviceaccounts-token-audience]")
	mustContain(t, "audience binding", yamlDoc(t, ecrCredProviderYAML, "ClusterRoleBinding", "openinfra-ecr-pull-audience"),
		"name: system:nodes")
}

func regexpDigest(doc string) bool {
	i := strings.Index(doc, "open-infra-aws-shim@sha256:")
	if i < 0 {
		return false
	}
	h := doc[i+len("open-infra-aws-shim@sha256:"):]
	if len(h) < 64 {
		return false
	}
	for _, c := range h[:64] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
