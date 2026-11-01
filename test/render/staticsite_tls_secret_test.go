package render

import (
	"strings"
	"testing"
)

// A TLS site composes its Ingress's TLS Secret — empty, created and deleted by the provider but never
// updated — so cert-manager fills it and it is deleted with the site instead of outliving it.
func TestStaticSite_TLSSecretIsComposed(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	out := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com"}))
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	var secret map[string]any
	for _, m := range docs {
		meta, _ := m["metadata"].(map[string]any)
		ann, _ := meta["annotations"].(map[string]any)
		if ann["gotemplating.fn.crossplane.io/composition-resource-name"] == "tls-secret" {
			secret = m
		}
	}
	if secret == nil {
		t.Fatalf("no tls-secret Object rendered:\n%s", grepCtx(out, "tls"))
	}
	spec, _ := secret["spec"].(map[string]any)
	pol, _ := spec["managementPolicies"].([]any)
	got := []string{}
	for _, p := range pol {
		got = append(got, p.(string))
	}
	if strings.Join(got, ",") != "Observe,Create,Delete" {
		t.Errorf("managementPolicies = %v; the provider must create and delete it but never update it (cert-manager owns its data)", got)
	}
	man := spec["forProvider"].(map[string]any)["manifest"].(map[string]any)
	meta := man["metadata"].(map[string]any)
	if man["type"] != "kubernetes.io/tls" || meta["name"] != "staticsite-web-tls" || meta["namespace"] != "default" {
		t.Errorf("TLS Secret manifest = %v", man)
	}
	if !strings.Contains(out, "secretName: staticsite-web-tls") {
		t.Error("the Ingress does not use the composed Secret")
	}

	plain := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com", "tls": false}))
	if strings.Contains(plain, "composition-resource-name: tls-secret") {
		t.Error("a site without TLS must not compose a TLS Secret")
	}
}
