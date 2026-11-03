package render

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// probe/rbac-unmanaged.sh is read-only and needs a cluster, so CI runs it against a stub kubectl
// serving fixtures that exercise each classification branch: the probe must report exactly the
// unmanaged objects, never a managed one, and must never call a mutating verb.

const stubProbeKubectl = `#!/bin/sh
echo "$*" >> "$STUB/calls.log"
case "$*" in
  "version --request-timeout=15s") echo "Server Version: v1.35.0" ;;
  "get clusterroles,clusterrolebindings -o json --show-managed-fields") cat "$STUB/cluster.json" ;;
  "get roles,rolebindings -A -o json --show-managed-fields") cat "$STUB/ns.json" ;;
  "api-resources --api-group=kubernetes.crossplane.io -o name") echo objects.kubernetes.crossplane.io ;;
  "get objects.kubernetes.crossplane.io -o json") cat "$STUB/objects.json" ;;
  "-n argocd get configmap argocd-cm -o jsonpath="*) echo annotation ;;
  "get applications.argoproj.io -A -o json") cat "$STUB/apps.json" ;;
  *) echo "stub kubectl: unhandled: $*" >&2; exit 99 ;;
esac
`

func rbacObj(kind, ns, name string, mgrs []string, labels, ann map[string]any, extra map[string]any) map[string]any {
	md := map[string]any{"name": name, "creationTimestamp": "2026-01-01T00:00:00Z"}
	if ns != "" {
		md["namespace"] = ns
	}
	if labels != nil {
		md["labels"] = labels
	}
	if ann != nil {
		md["annotations"] = ann
	}
	var mf []any
	for _, m := range mgrs {
		mf = append(mf, map[string]any{"manager": m, "operation": "Update"})
	}
	md["managedFields"] = mf
	o := map[string]any{"kind": kind, "metadata": md}
	for k, v := range extra {
		o[k] = v
	}
	return o
}

func TestRBACUnmanagedProbe_ClassifiesFixtures(t *testing.T) {
	needJQ(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	hand := []string{"kubectl-client-side-apply"}
	tid := func(app, kind, ns, name string) map[string]any {
		return map[string]any{"argocd.argoproj.io/tracking-id": app + ":rbac.authorization.k8s.io/" + kind + ":" + ns + "/" + name}
	}
	rules := map[string]any{"rules": []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get", "list"}}}}
	bind := func(role string) map[string]any {
		return map[string]any{"roleRef": map[string]any{"kind": "ClusterRole", "name": role},
			"subjects": []any{map[string]any{"kind": "ServiceAccount", "namespace": "app", "name": "sa"}}}
	}
	owned := rbacObj("ClusterRole", "", "owned", hand, nil, nil, rules)
	owned["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"kind": "CompositeResourceDefinition", "name": "x", "uid": "u"}}
	cluster := items(
		// managed
		rbacObj("ClusterRole", "", "tracked", hand, nil, tid("platform", "ClusterRole", "argocd", "tracked"), rules),
		owned,
		rbacObj("ClusterRole", "", "system:basic-user", []string{"kube-apiserver"}, map[string]any{"kubernetes.io/bootstrapping": "rbac-defaults"}, nil, rules),
		rbacObj("ClusterRole", "", "xp-role", []string{"crossplane-kubernetes-provider"}, nil, nil, rules),
		rbacObj("ClusterRole", "", "chart-role", []string{"helm"}, map[string]any{"app.kubernetes.io/managed-by": "Helm"}, nil, rules),
		rbacObj("ClusterRole", "", "op-role", hand, map[string]any{"app.kubernetes.io/managed-by": "some-operator"}, nil, rules),
		rbacObj("ClusterRole", "", "knative-thing", []string{"manifestival"}, nil, nil, rules),
		rbacObj("ClusterRoleBinding", "", "multus", hand, nil, nil, bind("multus")),
		// findings
		rbacObj("ClusterRole", "", "hand-role", hand, nil, nil, rules),
		rbacObj("ClusterRole", "", "system:sneaky", hand, nil, nil, rules),
		rbacObj("ClusterRole", "", "kustomized", hand, map[string]any{"app.kubernetes.io/managed-by": "kustomize"}, nil, rules),
		rbacObj("ClusterRole", "", "orphan-app", hand, nil, tid("gone-app", "ClusterRole", "argocd", "orphan-app"), rules),
		rbacObj("ClusterRole", "", "copied", hand, nil, tid("platform", "ClusterRole", "argocd", "tracked"), rules),
		rbacObj("ClusterRole", "", "pruned", hand, nil, tid("platform", "ClusterRole", "argocd", "pruned"), rules),
		rbacObj("ClusterRoleBinding", "", "dangling-bind", hand, nil, nil, bind("no-such-role")),
		// acknowledged: nothing manages it, on purpose, and the reason is on the object
		rbacObj("ClusterRole", "", "engagement-grant", hand, nil,
			map[string]any{"openinfra.dev/rbac-unmanaged-reason": "  per-site key for one engagement; revoked with its User  "}, rules),
		// an empty reason acknowledges nothing
		rbacObj("ClusterRole", "", "blank-reason", hand, nil, map[string]any{"openinfra.dev/rbac-unmanaged-reason": "   "}, rules),
		// a tracking-id problem stays a finding whatever the annotation says
		rbacObj("ClusterRole", "", "copied-acked", hand, nil, map[string]any{
			"argocd.argoproj.io/tracking-id":      "platform:rbac.authorization.k8s.io/ClusterRole:argocd/tracked",
			"openinfra.dev/rbac-unmanaged-reason": "not a way out of a copied tracking-id"}, rules),
	)
	ns := items(
		rbacObj("Role", "open-infra-console", "ns-hand", hand, nil, nil, rules),
		rbacObj("Role", "tenant", "outside-scope", hand, nil, nil, rules), // namespace not audited by default
	)
	objects := items(
		map[string]any{"spec": map[string]any{"forProvider": map[string]any{"manifest": map[string]any{"kind": "ClusterRole", "metadata": map[string]any{"name": "xp-role"}}}}},
		// Observe-only: does not manage what it observes.
		map[string]any{"spec": map[string]any{"managementPolicies": []any{"Observe"}, "forProvider": map[string]any{"manifest": map[string]any{"kind": "ClusterRole", "metadata": map[string]any{"name": "hand-role"}}}}},
	)
	apps := items(map[string]any{"metadata": map[string]any{"namespace": "argocd", "name": "platform"},
		"status": map[string]any{"resources": []any{map[string]any{"kind": "ClusterRole", "name": "pruned", "requiresPruning": true}}}})

	out, code, calls := runRBACProbe(t, cluster, ns, objects, apps)
	if code != 1 {
		t.Fatalf("with findings the probe must exit 1; exit=%d\n%s", code, out)
	}

	var reported []string
	for _, ln := range strings.Split(out, "\n") {
		if !strings.HasPrefix(ln, "✗ ") || !strings.Contains(ln, " — ") {
			continue
		}
		if id := strings.SplitN(strings.TrimPrefix(ln, "✗ "), " — ", 2)[0]; strings.Contains(id, "/") {
			reported = append(reported, id) // a finding line (the summary line has no Kind/ id)
		}
	}
	want := []string{
		"ClusterRole/blank-reason", "ClusterRole/copied", "ClusterRole/copied-acked", "ClusterRole/hand-role",
		"ClusterRole/kustomized", "ClusterRole/orphan-app", "ClusterRole/pruned", "ClusterRole/system:sneaky",
		"ClusterRoleBinding/dangling-bind", "Role/open-infra-console/ns-hand",
	}
	if strings.Join(reported, "\n") != strings.Join(want, "\n") {
		t.Errorf("reported findings:\n  %s\nwant:\n  %s\noutput:\n%s", strings.Join(reported, "\n  "), strings.Join(want, "\n  "), out)
	}
	for _, want := range []string{
		"names Application \"gone-app\", which no longer exists",
		"names a different object",
		"requiresPruning",
		"⚠ does not exist — dangling",
		"⚠ secrets",
		"subjects: ServiceAccount app/sa",
		// acknowledged objects stay in view, with the trimmed reason
		"ℹ 1 unmanaged RBAC object(s) acknowledged",
		"ℹ ClusterRole/engagement-grant — acknowledged: per-site key for one engagement; revoked with its User\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("probe output missing %q:\n%s", want, out)
		}
	}
	assertReadOnlyCalls(t, calls)
}

// Acknowledged objects alone pass the probe, and are still printed with their reason and rules.
func TestRBACUnmanagedProbe_AcknowledgedOnlyPasses(t *testing.T) {
	needJQ(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	rules := map[string]any{"rules": []any{map[string]any{"apiGroups": []any{"openinfra.dev"}, "resources": []any{"applications"}, "verbs": []any{"create"}}}}
	cluster := items(rbacObj("ClusterRole", "", "engagement-writer", []string{"kubectl-client-side-apply"}, nil,
		map[string]any{"openinfra.dev/rbac-unmanaged-reason": "write-only key for one engagement"}, rules))
	out, code, calls := runRBACProbe(t, cluster, items(), items(), items())
	if code != 0 {
		t.Fatalf("acknowledged-only RBAC must pass; exit=%d\n%s", code, out)
	}
	for _, want := range []string{
		"ℹ ClusterRole/engagement-writer — acknowledged: write-only key for one engagement",
		"rules (1): openinfra.dev/applications: create",
		"✓ PASS — every audited ClusterRole/ClusterRoleBinding/Role/RoleBinding is managed or acknowledged.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("probe output missing %q:\n%s", want, out)
		}
	}
	assertReadOnlyCalls(t, calls)
}

// runRBACProbe runs probe/rbac-unmanaged.sh against the stub kubectl serving the given fixtures and
// returns its output, exit code and the kubectl calls it made.
func runRBACProbe(t *testing.T, cluster, ns, objects, apps any) (string, int, string) {
	t.Helper()
	root := t.TempDir()
	stub, bin := filepath.Join(root, "stub"), filepath.Join(root, "bin")
	for _, d := range []string{stub, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(stubProbeKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"cluster.json": cluster, "ns.json": ns, "objects.json": objects, "apps.json": apps} {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(stub, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "../../probe/rbac-unmanaged.sh")
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "STUB=" + stub,
		"TMPDIR=" + root, "HOME=" + root, "RBAC_REPO_DIR="}
	outb, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("running the probe: %v\n%s", err, outb)
		}
		code = ee.ExitCode()
	}
	calls, _ := os.ReadFile(filepath.Join(stub, "calls.log"))
	return string(outb), code, string(calls)
}

// assertReadOnlyCalls: the probe only ever runs get / version / api-resources.
func assertReadOnlyCalls(t *testing.T, calls string) {
	t.Helper()
	for _, c := range strings.Split(strings.TrimSpace(calls), "\n") {
		verb := strings.Fields(strings.TrimPrefix(strings.TrimPrefix(c, "-n argocd "), " "))[0]
		if verb != "get" && verb != "version" && verb != "api-resources" {
			t.Errorf("the probe must be read-only; it ran: kubectl %s", c)
		}
	}
}
