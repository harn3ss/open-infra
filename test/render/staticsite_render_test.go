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

// With a build block, an Amplify-style build CronJob is rendered: poll schedule from pollSeconds,
// a sandboxed build step (no cluster creds), clone/build/publish, and change-detection via a SHA
// marker in the bucket. Without a build block, no CronJob.
func TestStaticSite_Build(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	out := render(t, tmpl, staticsiteCtx(map[string]any{
		"domain": "app.example.com",
		"build": map[string]any{
			"repo":         "https://github.com/me/app.git",
			"branch":       "release",
			"buildCommand": "pnpm i && pnpm build",
			"outputDir":    "build",
			"pollSeconds":  int64(120),
			"env":          []any{map[string]any{"name": "VITE_API", "value": "https://api.example.com"}},
		},
	}))
	for _, want := range []string{
		"name: web-site-build",
		"kind: CronJob",
		`schedule: "*/2 * * * *"`,             // 120s -> 2 minutes
		"automountServiceAccountToken: false", // untrusted build gets no cluster creds
		// The scripts read the tenant's values from env, never interpolate them.
		`git clone --depth 1 -b "$BRANCH" "$URL" /ws/src`,
		`exec /bin/sh -c "$BUILD_COMMAND"`,
		`/ws/src/$OUTPUT_DIR/`,          // publishes the custom output dir via the env value
		`s3://web-site/.build/last-sha`, // change-detection marker
		"VITE_API",                      // build env threaded through
		"concurrencyPolicy: Forbid",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("build render missing %q; got:\n%s", want, grepCtx(out, "build"))
		}
	}
	// The tenant's repo, branch, command and output dir ride env VALUES (so a quote or newline in them
	// can neither break the manifest nor the build wrapper). Parse and check the decoded values.
	env := collectEnv(t, out)
	for k, v := range map[string]string{
		"REPO_URL": "https://github.com/me/app.git", "BRANCH": "release",
		"BUILD_COMMAND": "pnpm i && pnpm build", "OUTPUT_DIR": "build",
	} {
		if env[k] != v {
			t.Errorf("env %s = %q, want %q", k, env[k], v)
		}
	}
}

// collectEnv parses rendered manifests and returns every { name, value } env entry's decoded value.
func collectEnv(t *testing.T, out string) map[string]string {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("parse rendered output: %v\n%s", err, out)
	}
	res := map[string]string{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			n, okn := x["name"].(string)
			val, okv := x["value"].(string)
			if okn && okv && len(x) <= 3 {
				res[n] = val
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	for _, d := range docs {
		walk(d)
	}
	return res
}

// A buildCommand with quotes (amplify.yml commands routinely have them) must not be able to break the
// manifest or the build wrapper. It travels as a BUILD_COMMAND env VALUE (JSON-encoded, so quotes and
// newlines are escaped inside one scalar) and runs as its own `sh -c "$BUILD_COMMAND"` — so neither the
// rendered YAML nor the wrapping script can be escaped. This module is stdlib-only (no YAML parser), so
// we assert the structural fix; the live #296 probe proves the apiserver accepts it.
func TestStaticSite_BuildCommandWithQuotes(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	cmd := `echo '<h1>hi</h1>' > dist/index.html && sed -i "s/a/b/g" dist/index.html`
	out := render(t, tmpl, staticsiteCtx(map[string]any{
		"domain": "app.example.com",
		"build":  map[string]any{"repo": "https://github.com/me/app.git", "buildCommand": cmd},
	}))
	// The command rides the BUILD_COMMAND env value and decodes back verbatim (quotes intact), with the
	// manifest still valid — so a quoted command cannot break the YAML.
	if got := collectEnv(t, out)["BUILD_COMMAND"]; got != cmd {
		t.Fatalf("BUILD_COMMAND env = %q, want %q", got, cmd)
	}
	// The command runs via its own shell reading the env var, never interpolated into the script text.
	if !strings.Contains(out, `exec /bin/sh -c "$BUILD_COMMAND"`) {
		t.Fatalf("build step must exec $BUILD_COMMAND, not the interpolated command; got:\n%s", grepCtx(out, "skip"))
	}
	// NOT the old inline forms that a quote would break.
	if strings.Contains(out, "args: ['if [ -f /ws/.skip") || strings.Contains(out, cmd+"\n") {
		t.Fatalf("buildCommand is still interpolated into the script; a quoted command breaks the manifest")
	}
}

func TestStaticSite_NoBuildByDefault(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	out := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com"}))
	if strings.Contains(out, "web-site-build") || strings.Contains(out, "kind: CronJob") {
		t.Errorf("no build block must render no build CronJob; got:\n%s", grepCtx(out, "CronJob"))
	}
}

// Extra hostnames (spec.domains — e.g. a CloudFront distribution's second Alias) each get an Ingress
// rule and join the TLS certificate's hosts; responseHeaders are added by nginx at server level with
// `always`, so error responses carry them too. A CSP value with quotes/semicolons stays one quoted
// nginx string.
func TestStaticSite_DomainsAndResponseHeaders(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	out := render(t, tmpl, staticsiteCtx(map[string]any{
		"domain":  "app.example.com",
		"domains": []any{"www.example.com"},
		"responseHeaders": []any{
			map[string]any{"name": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains"},
			map[string]any{"name": "Content-Security-Policy", "value": "default-src 'self'; img-src 'self' data:"},
			map[string]any{"name": "X-Frame-Options", "value": "DENY"},
		},
	}))
	for _, want := range []string{
		"- host: app.example.com",
		"- host: www.example.com",
		"- hosts: [ app.example.com, www.example.com ]",
		`add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
		`add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:" always;`,
		`add_header X-Frame-Options "DENY" always;`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q; got:\n%s", want, grepCtx(out, strings.Fields(want)[1]))
		}
	}
	// The headers sit at server level (before `location /`), so they apply to every location and to
	// the error_page / try_files internal redirects.
	if strings.Index(out, "add_header X-Frame-Options") > strings.Index(out, "location / {") {
		t.Errorf("responseHeaders must be rendered at server level, before location /; got:\n%s", grepCtx(out, "add_header"))
	}
}

// nginx reads its config only at start, so with responseHeaders set the pod template carries a hash of
// the config inputs: changing a header rolls the pod (an UpdateStack that changes a headers policy takes
// effect) instead of leaving the old headers served.
func TestStaticSite_ResponseHeadersRollThePod(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	hdr := func(v string) map[string]any {
		return staticsiteCtx(map[string]any{
			"domain":          "app.example.com",
			"responseHeaders": []any{map[string]any{"name": "X-Frame-Options", "value": v}},
		})
	}
	hash := func(out string) string {
		i := strings.Index(out, "openinfra.dev/site-config: \"")
		if i < 0 {
			t.Fatalf("pod template has no site-config hash; got:\n%s", grepCtx(out, "template:"))
		}
		rest := out[i+len("openinfra.dev/site-config: \""):]
		return rest[:strings.Index(rest, "\"")]
	}
	a, b := hash(render(t, tmpl, hdr("DENY"))), hash(render(t, tmpl, hdr("SAMEORIGIN")))
	if a == "" || a == b {
		t.Fatalf("a changed header must change the pod's config hash (got %q vs %q)", a, b)
	}
	if a2 := hash(render(t, tmpl, hdr("DENY"))); a2 != a {
		t.Fatalf("the config hash must be stable for the same headers (%q vs %q)", a, a2)
	}
}

// Without domains/responseHeaders the site renders exactly as before: one Ingress rule, the single
// domain in the TLS hosts, and no add_header lines.
func TestStaticSite_SingleDomainNoHeaders(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	out := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com"}))
	if n := strings.Count(out, "- host: "); n != 1 {
		t.Errorf("a single-domain site must render exactly one Ingress rule, got %d", n)
	}
	if !strings.Contains(out, "- hosts: [ app.example.com ]") {
		t.Errorf("TLS hosts should be the single domain; got:\n%s", grepCtx(out, "hosts:"))
	}
	if strings.Contains(out, "add_header") {
		t.Errorf("no responseHeaders must render no add_header; got:\n%s", grepCtx(out, "add_header"))
	}
	// Existing sites render an unchanged pod template (no config-hash annotation -> no rollout on upgrade).
	if !strings.Contains(out, "metadata: { labels: { app: web-site } }") || strings.Contains(out, "site-config") {
		t.Errorf("a site without responseHeaders must keep its pod template unchanged; got:\n%s", grepCtx(out, "app: web-site"))
	}
}
