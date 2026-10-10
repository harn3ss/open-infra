package render

import (
	"strings"
	"testing"
)

// kind: VpcEndpoint renders an ExternalName Service (the private endpoint DNS) aliasing the aws-shim
// front door, plus a status.dnsName an app uses as its AWS endpoint URL.
func TestVpcEndpoint_AliasesShim(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/networking/kube-ovn/vpcendpoint-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{"service": "s3", "vpcEndpointType": "Interface"},
		"metadata": map[string]any{"labels": map[string]any{
			"crossplane.io/claim-name": "s3ep", "crossplane.io/claim-namespace": "team-a"}},
	}}}}
	out := render(t, tmpl, ctx)
	for _, want := range []string{
		"type: ExternalName",
		"name: vpce-s3ep",
		"externalName: aws-shim.open-infra-aws-shim.svc.cluster.local",
		"openinfra.dev/vpc-endpoint-service: s3",
		"dnsName: \"vpce-s3ep.team-a.svc.cluster.local:4566\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("VpcEndpoint render missing %q; got:\n%s", want, out)
		}
	}
}
