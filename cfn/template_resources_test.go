package cfn

import (
	"os"
	"strings"
	"testing"
)

// The CloudFront policies, origin access control and ACM certificate of a stack provision nothing, so
// the record keeps no entry for them; TemplateResources resolves them as the stack did: each one's Ref
// (the id or ARN its dependents received) and properties, with the distribution's references to them
// resolved to those same values.
func TestTemplateResources_ResolvesTheStacksRefs(t *testing.T) {
	data, err := os.ReadFile("testdata/lift-and-shift/template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]string{"SiteDomain": "site.example.test", "AppRepositoryName": "fixture-app",
		"SesSenderAddress": "app@example.test"}
	got, err := TemplateResources(data, params, nil, "fixture", cfDistributionType, cfOACType, cfRHPType, acmCertificateType)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]TemplateResource{}
	for _, r := range got {
		by[r.LogicalID] = r
	}
	if len(by) != 4 {
		t.Fatalf("resolved %v, want the distribution, OAC, headers policy and certificate", got)
	}
	oac, rhp, cert, dist := by["SiteOriginAccess"], by["SiteHeaders"], by["SiteCertificate"], by["SiteDistribution"]
	if !strings.HasPrefix(oac.Ref, "E") || len(oac.Ref) != 14 || len(rhp.Ref) != 36 || !strings.Contains(cert.Ref, ":certificate/") || !strings.HasPrefix(dist.Ref, "E") {
		t.Fatalf("refs: oac %q, rhp %q, cert %q, dist %q", oac.Ref, rhp.Ref, cert.Ref, dist.Ref)
	}
	again, _ := TemplateResources(data, params, nil, "fixture", cfOACType)
	if len(again) != 1 || again[0].Ref != oac.Ref {
		t.Errorf("a Ref is not stable across calls: %v", again)
	}
	dc, _ := dist.Properties["DistributionConfig"].(map[string]any)
	dcb, _ := dc["DefaultCacheBehavior"].(map[string]any)
	vc, _ := dc["ViewerCertificate"].(map[string]any)
	origins, _ := dc["Origins"].([]any)
	if dcb["ResponseHeadersPolicyId"] != rhp.Ref || vc["AcmCertificateArn"] != cert.Ref || len(origins) != 1 ||
		origins[0].(map[string]any)["OriginAccessControlId"] != oac.Ref {
		t.Errorf("the distribution's references do not resolve to the resources' Refs: %v", dc)
	}
	if cfg, _ := oac.Properties["OriginAccessControlConfig"].(map[string]any); cfg["Name"] != "fixture-site" {
		t.Errorf("OAC properties = %v", oac.Properties)
	}
	if dist.Attrs["DomainName"] != "site.example.test" || dist.Attrs["Id"] != dist.Ref {
		t.Errorf("distribution attributes = %v", dist.Attrs)
	}
	if cert.Properties["DomainName"] != "site.example.test" {
		t.Errorf("certificate properties = %v", cert.Properties)
	}
}
