package render

import (
	"strings"
	"testing"
)

const staticsiteCompositionPath = "../../platform/abstraction/staticsite-composition.yaml"

func staticsiteCtx(spec map[string]any) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"labels": map[string]any{
					"crossplane.io/claim-name":      "web",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

// A default SPA site: a bucket-setup job (defaulting the bucket to <name>-site), an
// nginx server with history-fallback, and a TLS Ingress on the domain.
func TestStaticSite_DefaultSpa(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	out := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com"}))

	if !strings.Contains(out, "s3://web-site") {
		t.Errorf("bucket should default to <name>-site; got:\n%s", grepCtx(out, "s3://"))
	}
	if !strings.Contains(out, "try_files $uri $uri/ /index.html;") {
		t.Errorf("a SPA site should fall back to index.html; got:\n%s", grepCtx(out, "try_files"))
	}
	if !strings.Contains(out, "kind: Ingress") || !strings.Contains(out, "host: app.example.com") {
		t.Errorf("should render a TLS Ingress on the domain; got:\n%s", grepCtx(out, "Ingress"))
	}
	if !strings.Contains(out, "secretName: staticsite-web-tls") {
		t.Errorf("tls should default on; got:\n%s", grepCtx(out, "tls"))
	}
}

// A non-SPA site with a custom bucket + error document: no history-fallback, an
// explicit 404 page, and the named bucket flowing to the sync.
func TestStaticSite_PlainWithErrorDoc(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	out := render(t, tmpl, staticsiteCtx(map[string]any{
		"domain": "site.example.com", "bucket": "myassets", "spa": false, "errorDocument": "404.html",
	}))
	if !strings.Contains(out, "s3://myassets") {
		t.Errorf("custom bucket should flow to the sync; got:\n%s", grepCtx(out, "s3://"))
	}
	if strings.Contains(out, "try_files $uri $uri/ /index.html;") {
		t.Errorf("a non-SPA site must not history-fallback; got:\n%s", grepCtx(out, "try_files"))
	}
	if !strings.Contains(out, "error_page 404 /404.html;") {
		t.Errorf("a non-SPA site should serve the error document; got:\n%s", grepCtx(out, "error_page"))
	}
}
