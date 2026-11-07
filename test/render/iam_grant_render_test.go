package render

import (
	"strings"
	"testing"
)

// IAM policy is the only authority (#360): a Group is a container of policies and a Grant attaches
// policies for a while — neither renders a binding. The CEL that refuses the old ClusterRole fields is
// evaluated case by case in test/admission (xrd_rules_test.go); these pin the compositions and that the
// refused fields stay in the schemas, so a manifest naming one is refused rather than silently pruned.

const (
	groupXRDPath         = "../../platform/abstraction/group-xrd.yaml"
	groupCompositionPath = "../../platform/abstraction/group-composition.yaml"
	grantXRDPath         = "../../platform/abstraction/grant-xrd.yaml"
	grantCompositionPath = "../../platform/abstraction/grant-composition.yaml"
)

// noBinding fails if a rendered composition carries any RBAC binding or role reference.
func noBinding(t *testing.T, what, out string) {
	t.Helper()
	for _, bad := range []string{"ClusterRoleBinding", "RoleBinding", "roleRef", "subjects:", "rbac.authorization.k8s.io"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s renders %q — IAM policy is the only authority, no composition binds a user:\n%s", what, bad, out)
		}
	}
}

// A Group renders the same with or without a clusterRole: no binding, only its spec mirror and status.
func TestGroup_ClusterRoleRendersNoBinding(t *testing.T) {
	tmpl := extractInlineTemplate(t, groupCompositionPath)
	plain := render(t, tmpl, iamCtx("builders", "open-infra-console", map[string]any{"policies": []any{"aws-poweruseraccess"}}))
	for _, role := range []string{"open-infra-console", "open-infra-poweruser", "open-infra-readonly", "cluster-admin"} {
		out := render(t, tmpl, iamCtx("builders", "open-infra-console", map[string]any{
			"policies": []any{"aws-poweruseraccess"}, "clusterRole": role}))
		noBinding(t, "a Group naming clusterRole "+role, out)
		if out != plain {
			t.Errorf("a Group naming clusterRole %s must render exactly what it renders without one:\n--- got\n%s\n--- want\n%s", role, out, plain)
		}
	}
	for _, want := range []string{"kind: ConfigMap", "name: openinfra-group-builders", "ready: true", `boundTo: "openinfra:builders"`} {
		if !strings.Contains(plain, want) {
			t.Errorf("group render lacks %q:\n%s", want, plain)
		}
	}
}

// The Group XRD keeps clusterRole in its schema and refuses it with a CEL rule that names the managed
// policy to attach instead.
func TestGroupXRD_RefusesClusterRole(t *testing.T) {
	xrd := mustRead(t, groupXRDPath)
	mustContain(t, "group XRD", xrd,
		"x-kubernetes-validations:", `- rule: "!has(self.clusterRole)"`,
		"spec.clusterRole is not supported: a Group is a container of policies",
		"aws-poweruseraccess", "                clusterRole:\n                  type: string")
}

func grantCtx(spec map[string]any) map[string]any {
	return iamCtx("jit-alice", "open-infra-console", spec)
}

func grantSpecFor(approvedBy, requestedBy string) map[string]any {
	spec := map[string]any{
		"subject":     map[string]any{"kind": "User", "name": "alice"},
		"policies":    []any{"aws-poweruseraccess"},
		"duration":    "4h",
		"reason":      "incident 1234",
		"requestedBy": requestedBy,
	}
	if approvedBy != "" {
		spec["approval"] = map[string]any{"approvedBy": approvedBy, "approvedAt": "2026-11-07T10:00:00Z"}
	}
	return spec
}

// A Grant renders no binding in any state. Approval decides only its status: awaiting approval, approved
// by its own requester (attaches nothing), or active — the evaluator attaches its policies.
func TestGrant_RendersNoBindingAndReportsApproval(t *testing.T) {
	tmpl := extractInlineTemplate(t, grantCompositionPath)
	cases := []struct {
		name        string
		spec        map[string]any
		phase, says string
		ready       bool
	}{
		{"no approval", grantSpecFor("", "alice"), "AwaitingApproval", "attaches nothing until then", false},
		{"approved by the requester", grantSpecFor("alice", "alice"), "NotGrantable", "approved their own request", false},
		{"approved by a second person", grantSpecFor("carol", "alice"), "Active",
			"approved by carol at 2026-11-07T10:00:00Z: attaches aws-poweruseraccess to User alice for 4h", true},
		{"requested from kubectl, approved", grantSpecFor("carol", ""), "Active", "approved by carol", true},
		{"a group's grant", func() map[string]any {
			s := grantSpecFor("carol", "alice")
			s["subject"] = map[string]any{"kind": "Group", "name": "oncall"}
			s["policies"] = []any{"aws-readonlyaccess", "team-logs"}
			return s
		}(), "Active", "attaches aws-readonlyaccess, team-logs to Group oncall", true},
		{"an old grant naming a clusterRole", func() map[string]any {
			s := grantSpecFor("carol", "alice")
			s["clusterRole"] = "open-infra-console"
			return s
		}(), "Active", "attaches aws-poweruseraccess", true},
	}
	for _, c := range cases {
		out := render(t, tmpl, grantCtx(c.spec))
		noBinding(t, "Grant ("+c.name+")", out)
		if !strings.Contains(out, "phase: "+c.phase) || !strings.Contains(out, c.says) {
			t.Errorf("%s: want phase %s saying %q:\n%s", c.name, c.phase, c.says, out)
		}
		if want := "ready: false"; c.ready {
			if !strings.Contains(out, "ready: true") {
				t.Errorf("%s: want ready: true:\n%s", c.name, out)
			}
		} else if !strings.Contains(out, want) {
			t.Errorf("%s: want %s:\n%s", c.name, want, out)
		}
		for _, want := range []string{"kind: ConfigMap", "name: openinfra-grant-jit-alice", "namespace: open-infra-console"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: the grant's spec mirror lacks %q:\n%s", c.name, want, out)
			}
		}
	}
}

// The Grant XRD names policies (required, AWS-named managed or customer policies) and keeps clusterRole
// only to refuse it; its duration is refused at admission beyond 24h.
func TestGrantXRD_PoliciesNotClusterRole(t *testing.T) {
	xrd := mustRead(t, grantXRDPath)
	mustContain(t, "grant XRD", xrd,
		`- rule: "!has(self.clusterRole)"`,
		"spec.clusterRole is not supported: a Grant attaches IAM policies",
		"required: [subject, policies, duration]",
		"                policies:\n                  type: array\n                  minItems: 1",
		"                clusterRole:\n                  type: string",
		"duration(self.duration) <= duration('24h')",
		"jsonPath: .spec.policies")
	if strings.Contains(xrd, "boundTo") {
		t.Error("a Grant binds nothing: its status has no boundTo")
	}
}
