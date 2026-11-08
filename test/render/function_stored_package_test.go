package render

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A stored deployment package (spec.code.source.package, what a CloudFormation stack's Code.ZipFile or
// Code.S3Bucket/S3Key becomes, #402): the function's pods run as their own identity, whose projected token
// fetches the package from the aws-shim at cold start, so no keys reach the pod and a role combines with it.
const testPkgSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func pkgSpec(role string) map[string]any {
	spec := map[string]any{"code": map[string]any{
		"runtime": "nodejs22", "handler": "index.handler",
		"source": map[string]any{"package": map[string]any{"sha256": testPkgSHA, "size": 312, "origin": "inline"}},
	}}
	if role != "" {
		spec["role"] = role
	}
	return spec
}

func TestFunction_StoredPackageFetchedWithTheFunctionsIdentity(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	for _, role := range []string{"", "orders-reader"} {
		out := render(t, tmpl, fnRoleCtx("orders", "team-a", pkgSpec(role), fnRoleExtra("123456789012", "us-east-1")))
		ksvc := ksvcOf(t, out, "orders")
		if got := mstr(ksvc, "spec", "template", "spec", "serviceAccountName"); got != "fn-orders" {
			t.Errorf("role %q: a stored package is fetched with the function's own identity, fn-orders; got %q", role, got)
		}
		env := envOf(ksvc)
		for k, v := range map[string]string{
			"OPENINFRA_CODE_URL":        "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566/v1/function-code",
			"OPENINFRA_CODE_SHA256":     testPkgSHA,
			"OPENINFRA_CODE_TOKEN_FILE": "/var/run/secrets/openinfra/token",
			"OPENINFRA_HANDLER":         "index.handler",
		} {
			if env[k] != v {
				t.Errorf("role %q: env %s = %q, want %q", role, k, env[k], v)
			}
		}
		for _, k := range []string{"OPENINFRA_CODE_BUCKET", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
			if _, ok := env[k]; ok {
				t.Errorf("role %q: a stored package needs no bucket or keys, but %s is set", role, k)
			}
		}
		if !strings.Contains(out, "mountPath: /var/run/secrets/openinfra, readOnly: true") || !strings.Contains(out, "audience: sts.openinfra") {
			t.Errorf("role %q: the identity token must be projected and mounted read-only:\n%s", role, grepCtx(out, "openinfra-sts-token"))
		}
		if strings.Contains(out, "mountPath: /var/task") {
			t.Errorf("role %q: /var/task is the runtime's own (it unpacks the package there), not a mounted volume", role)
		}
		docs, _ := parseYAMLDocs(out)
		if objectFor(docs, "ServiceAccount", "fn-orders") == nil {
			t.Errorf("role %q: the identity ServiceAccount fn-orders must be rendered", role)
		}
		if _, ok := env["AWS_ROLE_ARN"]; ok != (role != "") {
			t.Errorf("role %q: AWS_ROLE_ARN is set only with a role (set=%v)", role, ok)
		}
	}
}

func TestFunction_StoredPackageIsTheOnlySource(t *testing.T) {
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	for name, src := range map[string]map[string]any{
		"package and configMap": {"package": map[string]any{"sha256": testPkgSHA}, "configMap": "orders-code"},
		"package and bucket":    {"package": map[string]any{"sha256": testPkgSHA}, "bucket": "b", "key": "k.zip"},
		"package and keys":      {"package": map[string]any{"sha256": testPkgSHA}, "secret": "s3-creds"},
	} {
		spec := map[string]any{"code": map[string]any{"runtime": "nodejs22", "handler": "index.handler", "source": src}}
		if err := renderErr(tmpl, fnRoleCtx("orders", "team-a", spec, nil)); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// The XRD admits a package only by its SHA-256.
func TestFunction_StoredPackageShape(t *testing.T) {
	b, err := os.ReadFile("../../platform/abstraction/function-xrd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ {28}sha256:\n(?: {30}.*\n)*? {30}pattern: "([^"]+)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("function-xrd.yaml: code.source.package.sha256 has no pattern")
	}
	re := regexp.MustCompile(string(m[1]))
	if !re.MatchString(testPkgSHA) {
		t.Errorf("the pattern must accept a lowercase hex SHA-256")
	}
	for _, bad := range []string{"", strings.ToUpper(testPkgSHA), testPkgSHA[:63], testPkgSHA + "0", "../" + testPkgSHA[3:]} {
		if re.MatchString(bad) {
			t.Errorf("the pattern must refuse %q", bad)
		}
	}
}
