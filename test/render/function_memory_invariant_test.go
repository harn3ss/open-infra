package render

import (
	"regexp"
	"testing"
)

// A burstable kind: Function renders spec.memoryRequest as the container's memory REQUEST and
// spec.memory as its LIMIT. A container's request may not exceed its limit — a claim that inverts
// them is accepted at the claim, renders, and is then refused one layer down at Deployment creation,
// leaving the Service NotReady with no cause visible on the claim (the claim is where a tenant looks,
// and it looks fine). It is latent until an unrelated re-roll re-validates the claim, at which point
// it presents as that rollout's problem rather than as a bad spec.
//
// The guard is a CEL x-kubernetes-validations rule on the XRD spec, so the apiserver rejects the
// inverted claim at admission and names both values. It is a pure arithmetic invariant on two fields
// of the same claim — no cluster state, no runtime knowledge — so it belongs on the contract, not in
// the composition (clamping there would silently change what the tenant asked for).
//
// This test keeps the rule from being dropped. Verified separately by live server dry-run that the
// rule actually rejects 160Mi>128Mi and accepts 512Mi<1Gi (cross-unit), via Crossplane's propagation
// of x-kubernetes-validations into the generated CRD and the apiserver quantity() CEL library.
func TestFunctionMemoryRequestNotAboveLimit(t *testing.T) {
	xrd := mustRead(t, "../../platform/abstraction/function-xrd.yaml")

	if !regexp.MustCompile(`x-kubernetes-validations:`).MatchString(xrd) {
		t.Fatal("function-xrd.yaml has no x-kubernetes-validations block — the memoryRequest<=memory " +
			"admission guard is missing; an inverted claim would render an invalid Deployment " +
			"and sit NotReady with no cause on the claim.")
	}

	// The invariant itself: a quantity comparison of memoryRequest against memory. quantity() is what
	// makes the comparison unit-correct (1Gi vs 512Mi); a lexical string compare would be wrong.
	rule := regexp.MustCompile(
		`quantity\(self\.memoryRequest\)\.compareTo\(quantity\(self\.memory\)\)\s*<=\s*0`)
	if !rule.MatchString(xrd) {
		t.Error("the memoryRequest<=memory CEL rule is missing or altered: expected " +
			"`quantity(self.memoryRequest).compareTo(quantity(self.memory)) <= 0` (unit-correct via " +
			"quantity()). Without it a burstable claim with memoryRequest > memory is admitted and then " +
			"fails at Deployment creation.")
	}

	// The has() guards: the rule must not fire when a field is absent (memoryRequest is optional and
	// ignored unless burstable; memory is unset for cluster-default sizing).
	if !regexp.MustCompile(`!has\(self\.memoryRequest\)`).MatchString(xrd) ||
		!regexp.MustCompile(`!has\(self\.memory\)`).MatchString(xrd) {
		t.Error("the memoryRequest<=memory rule is missing its has() guards — it must only compare when " +
			"both fields are set, or a function that omits memoryRequest (or memory) is wrongly rejected.")
	}

	// The message must name both values, so a tenant can fix the claim without reading the composition.
	if !regexp.MustCompile(`messageExpression:.*self\.memoryRequest.*self\.memory`).MatchString(xrd) {
		t.Error("the guard should use a messageExpression naming both spec.memoryRequest and spec.memory " +
			"values, so the rejection is actionable from the claim alone.")
	}
}
