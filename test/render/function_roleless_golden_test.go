package render

import (
	"os"
	"strings"
	"testing"
)

// The function composition renders every kind: Function on the platform — thousands of them — and any
// change to what a Function renders makes Knative roll a new revision of it: a new pod per function,
// all at once. So a change to the composition must leave every Function that does not use the change
// rendering byte for byte as before. This test holds that line: it renders a representative set of
// Functions that set no execution role (image and code functions, every managed runtime and the custom
// runtime escape hatch, burstable and reserved concurrency, GPU, aliases, triggers, env, secrets,
// queues, security groups, the shape the Lambda estate mirror applies) and compares the output with a
// golden captured from the composition before execution roles existed. A difference fails with the
// first differing line. A deliberate change to these renders regenerates the golden
// (OPENINFRA_UPDATE_GOLDEN=1 go test -run TestFunction_RolelessRenderIsByteIdentical) — and is then a
// change that restarts every function, to be rolled in paced batches.

const (
	functionCompositionPath = "../../platform/abstraction/function-composition.yaml"
	functionRolelessGolden  = "testdata/function-roleless.golden"
)

// rolelessFunctionCases are the role-less specs whose render must never change. Numbers are float64,
// as a Function's spec reaches the composition (decoded from JSON).
func rolelessFunctionCases() []struct {
	name, ns string
	spec     map[string]any
	extra    map[string]any // .extraResources present on the call (a role-less Function ignores it)
} {
	return []struct {
		name, ns string
		spec     map[string]any
		extra    map[string]any
	}{
		{name: "image-minimal", ns: "team-a", spec: map[string]any{"image": "ghcr.io/me/hello:1"}},
		{name: "image-full", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/infer:2", "port": float64(9000), "gpu": float64(1), "memory": "2Gi",
			"timeout": float64(900), "expose": false,
			"scaling":        map[string]any{"min": float64(1), "max": float64(20), "target": float64(50)},
			"env":            []any{map[string]any{"name": "MODE", "value": "fast"}, map[string]any{"name": "Q", "value": `say "hi"`}},
			"secrets":        []any{"api-db-app", "fn-config"},
			"queues":         []any{"orders", "events"},
			"securityGroups": []any{"web", "db-clients"},
		}},
		{name: "image-reserved", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/hello:1", "reservedConcurrency": float64(5), "scaling": map[string]any{"min": float64(2)},
		}},
		{name: "image-burstable", ns: "team-b", spec: map[string]any{
			"image": "ghcr.io/me/hello:1", "burstable": true, "memory": "1Gi", "memoryRequest": "256Mi",
			"scaling": map[string]any{"max": float64(30)},
		}},
		{name: "code-python312-configmap", ns: "team-a", spec: map[string]any{
			"expose": false,
			"code": map[string]any{"runtime": "python3.12", "handler": "app.handler",
				"source": map[string]any{"configMap": "fn-code"}},
		}},
		{name: "code-python313-bucket-layers", ns: "team-a", spec: map[string]any{
			"memory": "512Mi", "timeout": float64(30),
			"code": map[string]any{"runtime": "python3.13", "handler": "main.handle", "region": "eu-west-1",
				"source": map[string]any{"bucket": "fn-artifacts", "key": "f.zip", "secret": "fn-s3"},
				"layers": []any{map[string]any{"bucket": "fn-artifacts", "key": "layer1.zip"}, map[string]any{"bucket": "shared", "key": "deps.zip"}}},
		}},
		{name: "code-nodejs20-bucket-burstable", ns: "team-b", spec: map[string]any{
			"burstable": true, "memory": "1024Mi",
			"code": map[string]any{"runtime": "nodejs20", "handler": "index.handler",
				"source": map[string]any{"bucket": "fn-artifacts", "key": "n.zip", "secret": "fn-s3"}},
		}},
		{name: "code-nodejs22-configmap", ns: "team-b", spec: map[string]any{
			"env":  []any{map[string]any{"name": "TABLE", "value": "orders"}},
			"code": map[string]any{"runtime": "nodejs22", "handler": "app.handler", "source": map[string]any{"configMap": "n22"}},
		}},
		{name: "code-dotnet8-bucket", ns: "team-c", spec: map[string]any{
			"memory": "256Mi", "reservedConcurrency": float64(3),
			"code": map[string]any{"runtime": "dotnet8", "handler": "App::App.Fn::Handle",
				"source": map[string]any{"bucket": "fn-artifacts", "key": "d.zip", "secret": "fn-s3"}},
		}},
		{name: "code-runtimeimage-eol", ns: "mirror", spec: map[string]any{
			"memory": "1024Mi", "timeout": float64(30), "secrets": []any{"fn-env-orders"},
			"code": map[string]any{"runtimeImage": "ecr-registry.open-infra-ecr.svc:5000/runtime/nodejs18:latest",
				"unsupportedRuntime": true, "handler": "index.handler", "region": "us-west-2",
				"source": map[string]any{"bucket": "mirror-code", "key": "code/0f3a.zip", "secret": "mirror-code-read"}},
		}},
		{name: "code-runtimeimage-allowegress", ns: "mirror", spec: map[string]any{
			"burstable": true, "memory": "512Mi",
			"code": map[string]any{"runtimeImage": "ecr-registry.open-infra-ecr.svc:5000/runtime/python37:latest",
				"unsupportedRuntime": true, "allowEgress": true, "handler": "lambda_function.lambda_handler",
				"source": map[string]any{"bucket": "mirror-code", "key": "code/9b1c.zip", "secret": "mirror-code-read"}},
		}},
		{name: "aliases", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/hello:3",
			"aliases": []any{map[string]any{"name": "prod", "weight": float64(90), "revision": "fn-00001"},
				map[string]any{"name": "canary", "weight": float64(10)}},
		}},
		{name: "trigger-stream", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/cdc:1", "trigger": map[string]any{"stream": "orders"},
		}},
		{name: "trigger-subject", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/cdc:1", "trigger": map[string]any{"stream": "orders", "subject": "cdc.orders.public.items"},
		}},
		{name: "int-typed", ns: "team-a", spec: map[string]any{
			"image": "ghcr.io/me/hello:1", "port": 8081, "gpu": 0, "timeout": 60,
			"scaling": map[string]any{"min": 0, "max": 4, "target": 10},
		}},
		{name: "extra-resources-ignored", ns: "team-a",
			spec: map[string]any{"image": "ghcr.io/me/hello:1"},
			extra: map[string]any{
				"accounts":     map[string]any{"items": []any{}},
				"aws-identity": map[string]any{"items": []any{}},
			}},
	}
}

func renderRolelessFunctions(t *testing.T) string {
	t.Helper()
	tmpl := extractInlineTemplate(t, functionCompositionPath)
	var b strings.Builder
	for _, c := range rolelessFunctionCases() {
		ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": c.spec,
			"metadata": map[string]any{"name": c.name + "-x7k2p", "labels": map[string]any{
				"crossplane.io/claim-name": c.name, "crossplane.io/claim-namespace": c.ns}},
		}}}}
		if c.extra != nil {
			ctx["extraResources"] = c.extra
		}
		b.WriteString("=== " + c.name + "\n")
		b.WriteString(render(t, tmpl, ctx))
		b.WriteString("\n")
	}
	return b.String()
}

func TestFunction_RolelessRenderIsByteIdentical(t *testing.T) {
	got := renderRolelessFunctions(t)
	if os.Getenv("OPENINFRA_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(functionRolelessGolden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", functionRolelessGolden)
		return
	}
	want, err := os.ReadFile(functionRolelessGolden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got == string(want) {
		return
	}
	g, w := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	section := ""
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if strings.HasPrefix(wl, "=== ") {
			section = wl
		}
		if gl != wl {
			t.Fatalf("a role-less Function no longer renders byte-identically (%s, line %d):\n  golden: %q\n  now:    %q\n"+
				"every Function on the platform would roll a new revision; if that is intended, regenerate the golden and roll in paced batches",
				section, i+1, wl, gl)
		}
	}
}
