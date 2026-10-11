package render

import (
	"strings"
	"testing"
)

func configRuleCtx(spec map[string]any, name string) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{
			"labels": map[string]any{"crossplane.io/claim-name": name, "crossplane.io/claim-namespace": "team-a"},
		},
	}}}}
}

// kind: ConfigRule renders a Kyverno ClusterPolicy in AUDIT mode (report, never block) whose match +
// validate.pattern come from the rule, with failurePolicy Ignore (a Kyverno hiccup can't affect admission).
func TestConfigRule_RendersAuditClusterPolicy(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/configrule-composition.yaml")
	out := render(t, tmpl, configRuleCtx(map[string]any{
		"description":    "buckets must have versioning enabled",
		"match":          map[string]any{"kinds": []any{"Bucket"}, "namespaces": []any{"team-a"}},
		"requirePattern": map[string]any{"spec": map[string]any{"versioning": true}},
		"message":        "bucket must enable versioning",
	}, "bucket-versioning"))
	for _, want := range []string{
		"kind: ClusterPolicy", "apiVersion: kyverno.io/v1",
		"name: openinfra-configrule-bucket-versioning",
		"validationFailureAction: Audit", // report, never block
		"background: true",               // scan existing resources
		"failurePolicy: Ignore",          // never affect admission
		`- "Bucket"`, `- "team-a"`,       // the match scope
		`message: "bucket must enable versioning"`,
		"versioning: true", // the requirePattern body
		"openinfra.dev/configrule: bucket-versioning",
		"clusterPolicy: openinfra-configrule-bucket-versioning", // status
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ConfigRule render missing %q; got:\n%s", want, grepCtx(out, "ClusterPolicy"))
		}
	}
}

// With no namespaces, the policy matches all namespaces (no namespaces selector) + a default message.
func TestConfigRule_AllNamespacesDefaultMessage(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/configrule-composition.yaml")
	out := render(t, tmpl, configRuleCtx(map[string]any{
		"match":          map[string]any{"kinds": []any{"Application"}},
		"requirePattern": map[string]any{"metadata": map[string]any{"labels": map[string]any{"owner": "?*"}}},
	}, "require-owner"))
	if strings.Contains(out, "namespaces:") {
		t.Errorf("no spec.match.namespaces must render no namespaces selector (all namespaces); got:\n%s", grepCtx(out, "resources"))
	}
	// A default non-compliance message is synthesized when none is given.
	if !strings.Contains(out, "require-owner") || !strings.Contains(out, "message:") {
		t.Errorf("a default message naming the rule must render; got:\n%s", grepCtx(out, "message"))
	}
	if !strings.Contains(out, `- "Application"`) {
		t.Errorf("match kind Application expected; got:\n%s", grepCtx(out, "kinds"))
	}
}
