package render

import (
	"strings"
	"testing"
)

// The escape hatch: spec.code.runtimeImage runs the handler on a BYO base image for a runtime open-infra
// does not vouch for (EOL/other). It is fail-closed (requires unsupportedRuntime) and, when used, the
// Function is rendered into an isolated posture — cluster-local, non-production, min-scale 0, egress-denied.
func TestFunction_UnsupportedRuntime(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/function-composition.yaml")
	ctx := func(code map[string]any) map[string]any {
		return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{"code": code},
			"metadata": map[string]any{"labels": map[string]any{
				"crossplane.io/claim-name": "fn", "crossplane.io/claim-namespace": "team-a"}},
		}}}}
	}
	byo := func(extra map[string]any) map[string]any {
		c := map[string]any{"runtimeImage": "node:8-slim", "handler": "index.handler",
			"source": map[string]any{"bucket": "code", "key": "f.zip", "secret": "code-s3"}}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}

	// Fail-closed: a BYO image without accepting unsupportedRuntime is refused.
	if err := renderErr(tmpl, ctx(byo(nil))); err == nil || !strings.Contains(err.Error(), "requires unsupportedRuntime") {
		t.Errorf("runtimeImage without unsupportedRuntime must fail closed; got %v", err)
	}
	// Mutually exclusive with the managed runtime enum.
	if err := renderErr(tmpl, ctx(byo(map[string]any{"unsupportedRuntime": true, "runtime": "nodejs20"}))); err == nil || !strings.Contains(err.Error(), "runtime OR runtimeImage") {
		t.Errorf("runtime + runtimeImage together must fail; got %v", err)
	}

	// Accepted: the isolated posture.
	out := render(t, tmpl, ctx(byo(map[string]any{"unsupportedRuntime": true})))
	for _, want := range []string{
		"image: node:8-slim",                               // the BYO base image is used verbatim
		`openinfra.dev/non-production: "true"`,             // marked
		"networking.knative.dev/visibility: cluster-local", // expose forced off
		`autoscaling.knative.dev/min-scale: "0"`,           // asleep by default
		"kind: NetworkPolicy",                              // egress-denied
		"name: fn-eol-egress",
		"serving.knative.dev/service: fn",
		"namespaceSelector: {}", // in-cluster only
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unsupported-runtime function missing %q; got:\n%s", want, grepCtx(out, "non-production"))
		}
	}
	// The managed runtime images must not leak in.
	if strings.Contains(out, "open-infra-lambda-") {
		t.Errorf("a BYO runtime must not reference a managed runtime image")
	}

	// allowEgress opts out of the deny-egress policy.
	open := render(t, tmpl, ctx(byo(map[string]any{"unsupportedRuntime": true, "allowEgress": true})))
	if strings.Contains(open, "fn-eol-egress") {
		t.Errorf("allowEgress must suppress the deny-egress NetworkPolicy")
	}
	if !strings.Contains(open, `openinfra.dev/non-production: "true"`) {
		t.Errorf("allowEgress still keeps the non-production marking")
	}
}
