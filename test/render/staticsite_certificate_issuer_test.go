package render

import (
	"strings"
	"testing"
)

// A site's certificate comes from the platform's ACM-style CA (openinfra-acm) only when EVERY hostname
// is under a domain the operator validated (the openinfra-certificates EnvironmentConfig), as ACM issues
// only for validated domains; otherwise, and with no validated domains, the self-signed issuer as before.
func TestStaticSite_CertificateIssuerFollowsValidatedDomains(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	issuer := func(spec map[string]any, validated []any) string {
		ctx := staticsiteCtx(spec)
		if validated != nil {
			ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": map[string]any{"validatedDomains": validated}}
		}
		out := render(t, tmpl, ctx)
		for _, ln := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "cert-manager.io/cluster-issuer: "); ok {
				return v
			}
		}
		t.Fatalf("no cert-manager issuer annotation rendered:\n%s", grepCtx(out, "cluster-issuer"))
		return ""
	}
	site := map[string]any{"domain": "app.sites.example.test", "domains": []any{"www.app.sites.example.test"}}
	for _, c := range []struct {
		name      string
		spec      map[string]any
		validated []any
		want      string
	}{
		{"no validated domains", site, nil, "openinfra-issuer"},
		{"every host under a validated domain", site, []any{"sites.example.test"}, "openinfra-acm"},
		{"the host is the validated domain", map[string]any{"domain": "Sites.Example.test"}, []any{"sites.example.test"}, "openinfra-acm"},
		{"one host outside", map[string]any{"domain": "app.sites.example.test", "domains": []any{"www.example.org"}}, []any{"sites.example.test"}, "openinfra-issuer"},
		{"a look-alike suffix is not under it", map[string]any{"domain": "evilsites.example.test"}, []any{"sites.example.test"}, "openinfra-issuer"},
	} {
		if got := issuer(c.spec, c.validated); got != c.want {
			t.Errorf("%s: issuer = %q, want %q", c.name, got, c.want)
		}
	}
}
