package render

import (
	"strings"
	"testing"
)

// CloudFront's viewer protocol policy on a TLS site: a plain-HTTP router (web entrypoint) to the same
// server, where nginx answers 301 to https (redirect-to-https), 403 (https-only) or the content
// (allow-all). Without a policy there is no plain-HTTP router, exactly as before.
func TestStaticSite_ViewerProtocolPolicy(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	cases := map[string]struct{ nginx string }{
		"redirect-to-https": {`if ($http_x_forwarded_proto = "http") { return 301 https://$host$request_uri; }`},
		"https-only":        {`if ($http_x_forwarded_proto = "http") { return 403; }`},
		"allow-all":         {""},
	}
	for policy, c := range cases {
		out := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com", "viewerProtocolPolicy": policy}))
		if !strings.Contains(out, "name: staticsite-web-http") || !strings.Contains(out, "router.entrypoints: web\n") {
			t.Errorf("%s: want a plain-HTTP Ingress on the web entrypoint; got:\n%s", policy, grepCtx(out, "entrypoints"))
		}
		if c.nginx != "" && !strings.Contains(out, c.nginx) {
			t.Errorf("%s: nginx must answer plain HTTP with %q; got:\n%s", policy, c.nginx, grepCtx(out, "x_forwarded_proto"))
		}
		if c.nginx == "" && strings.Contains(out, "x_forwarded_proto") {
			t.Errorf("%s: plain HTTP must be served, not redirected or refused", policy)
		}
	}
	out := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com"}))
	if strings.Contains(out, "staticsite-web-http") || strings.Contains(out, "x_forwarded_proto") {
		t.Error("without a viewer protocol policy a TLS site must have no plain-HTTP router (unchanged)")
	}
}

// CloudFront's Compress: gzip for compressible types of 1,000 bytes or more; off by default.
func TestStaticSite_Compress(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	on := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com", "compress": true}))
	for _, want := range []string{"gzip on;", "gzip_min_length 1000;", "gzip_vary on;", "application/javascript", "image/svg+xml"} {
		if !strings.Contains(on, want) {
			t.Errorf("compress: want %q in the nginx config; got:\n%s", want, grepCtx(on, "gzip"))
		}
	}
	if off := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com"})); strings.Contains(off, "gzip") {
		t.Error("compress is off by default")
	}
}
