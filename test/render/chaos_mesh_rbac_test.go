package render

import (
	"regexp"
	"strings"
	"testing"
)

// platform/resilience/chaos-mesh-rbac.yaml is a copy of the Chaos Mesh chart's controller-manager and
// dashboard RBAC (the chart's own is turned off), minus Secrets on the controller's target role. A copy
// goes stale silently when the chart moves, so the version it was taken from is pinned to the
// Application's targetRevision, and the properties that matter are asserted.
func TestChaosMeshRBACMatchesChartVersion(t *testing.T) {
	app := mustRead(t, "../../platform/resilience/chaos-mesh.yaml")
	rbac := mustRead(t, "../../platform/resilience/chaos-mesh-rbac.yaml")

	rev := regexp.MustCompile(`(?m)^\s*targetRevision:\s*(\S+)`).FindStringSubmatch(app)
	copied := regexp.MustCompile(`(?m)^# chart-version:\s*(\S+)`).FindStringSubmatch(rbac)
	if rev == nil || copied == nil {
		t.Fatalf("need chaos-mesh.yaml's targetRevision and chaos-mesh-rbac.yaml's '# chart-version:' line")
	}
	if rev[1] != copied[1] {
		t.Fatalf("chaos-mesh.yaml installs chart %s but chaos-mesh-rbac.yaml copies the RBAC of %s: re-render the chart's "+
			"controller-manager-rbac.yaml and chaos-dashboard-rbac.yaml, carry their rule changes over, then update the line",
			rev[1], copied[1])
	}

	// The chart's RBAC stays off and both Deployments run as the ServiceAccounts this file creates.
	for _, want := range []string{
		"rbac:\n          create: false",
		"serviceAccount: openinfra-chaos-controller-manager",
		"serviceAccount: openinfra-chaos-dashboard",
	} {
		if !strings.Contains(app, want) {
			t.Errorf("chaos-mesh.yaml values missing %q", want)
		}
	}
	for _, sa := range []string{"openinfra-chaos-controller-manager", "openinfra-chaos-dashboard"} {
		if !strings.Contains(rbac, "kind: ServiceAccount\nmetadata:\n  name: "+sa+"\n") {
			t.Errorf("chaos-mesh-rbac.yaml does not create ServiceAccount %s", sa)
		}
	}

	// No cluster-wide grant in the file reaches Secrets; only the namespaced control-plane Role may.
	for _, doc := range strings.Split(rbac, "\n---\n") {
		if !strings.Contains(doc, "kind: ClusterRole\n") {
			continue
		}
		if regexp.MustCompile(`resources:\s*\[[^\]]*\bsecrets\b`).MatchString(doc) || strings.Contains(doc, "- secrets") {
			t.Errorf("a ClusterRole in chaos-mesh-rbac.yaml grants Secrets cluster-wide:\n%s", doc)
		}
		if regexp.MustCompile(`apiGroups:\s*\[\s*""\s*\]\s*\n\s*resources:\s*\["\*"\]`).MatchString(doc) {
			t.Errorf("a ClusterRole in chaos-mesh-rbac.yaml grants every core resource:\n%s", doc)
		}
	}
}
