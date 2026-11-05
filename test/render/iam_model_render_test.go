package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The IAM model (#360's policy model): kind: Policy gains spec.document (an AWS policy document), Groups
// become policy containers, and Users and Roles take policies. Shipping it changes nothing for the objects
// that exist: a Policy without a document, a Group with its clusterRole, and every User and Role render
// byte for byte as before — the goldens under testdata/iam-legacy were rendered by the compositions as
// they stood before the change (regenerate only on purpose: UPDATE_IAM_GOLDEN=1).

func iamCtx(name, ns string, spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{
			"name": name + "-x7k2p",
			"labels": map[string]any{
				"crossplane.io/claim-name":      name,
				"crossplane.io/claim-namespace": ns,
			},
		},
	}}}}
}

type iamFixture struct {
	name, file string
	ctx        map[string]any
}

func iamLegacyFixtures() []iamFixture {
	return []iamFixture{
		{"policy-statements", "policy-composition.yaml", iamCtx("vm-ops", "open-infra-console", map[string]any{
			"statements": []any{map[string]any{"effect": "Allow", "actions": []any{"virtualmachines:Get", "volumes:*", "secrets:Get", "nope:Get"}}}})},
		{"policy-dataplane-only", "policy-composition.yaml", iamCtx("reader", "team-a", map[string]any{
			"dataPlane": map[string]any{"appliesTo": []any{"User::alice"}, "statements": []any{
				map[string]any{"effect": "Allow", "actions": []any{"s3:GetObject"}, "resources": []any{"Bucket::assets"}}}}})},
		{"policy-statements-and-dataplane", "policy-composition.yaml", iamCtx("bucket-full-access", "open-infra-console", map[string]any{
			"statements": []any{map[string]any{"effect": "Allow", "actions": []any{"buckets:*"}, "resources": []any{"*"}}},
			"dataPlane":  map[string]any{"statements": []any{map[string]any{"effect": "Allow", "actions": []any{"s3:*"}, "resources": []any{"*"}}}}})},
		{"policy-empty", "policy-composition.yaml", iamCtx("empty", "open-infra-console", map[string]any{})},
		{"group-poweruser", "group-composition.yaml", iamCtx("builders", "open-infra-console", map[string]any{
			"clusterRole": "open-infra-poweruser", "description": "d"})},
		{"group-readonly", "group-composition.yaml", iamCtx("readers", "open-infra-console", map[string]any{"clusterRole": "open-infra-readonly"})},
		{"user-groups", "user-composition.yaml", iamCtx("alice", "open-infra-console", map[string]any{
			"displayName": "Alice", "groups": []any{"admins"}, "source": "local"})},
		{"user-disabled", "user-composition.yaml", iamCtx("bob", "open-infra-console", map[string]any{
			"displayName": "Bob", "disabled": true})},
		{"role-policies", "role-composition.yaml", iamCtx("app", "stack-ns", map[string]any{
			"policies": []any{"app-access", "aws-amazonssmmanagedinstancecore"}, "trust": []any{"vm"}})},
		{"role-none", "role-composition.yaml", iamCtx("anchor", "stack-ns", map[string]any{"trust": []any{"*"}})},
	}
}

func TestIAMModel_LegacyObjectsRenderAsBefore(t *testing.T) {
	update := os.Getenv("UPDATE_IAM_GOLDEN") != ""
	for _, f := range iamLegacyFixtures() {
		tmpl := extractInlineTemplate(t, filepath.Join("../../platform/abstraction", f.file))
		got := render(t, tmpl, f.ctx)
		path := filepath.Join("testdata", "iam-legacy", f.name+".golden")
		if update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s renders differently than before the IAM model change:\n--- got\n%s\n--- want\n%s", f.name, got, want)
		}
	}
}

// A Policy with only an AWS document renders no ClusterRole — the IAM compiler emits whatever RBAC the
// document needs — and still reports ready (a spec-mirror ConfigMap in its namespace gives the pipeline a
// composed resource, without which a status never lands), carrying its ARN.
func TestIAMModel_DocumentPolicyRendersNoClusterRole(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/policy-composition.yaml")
	out := render(t, tmpl, iamCtx("aws-poweruseraccess", "open-infra-console", map[string]any{
		"policyName": "PowerUserAccess",
		"arn":        "arn:aws:iam::aws:policy/PowerUserAccess",
		"document": map[string]any{"Version": "2012-10-17", "Statement": []any{
			map[string]any{"Effect": "Allow", "NotAction": []any{"iam:*"}, "Resource": "*"}}},
		"dataPlane": map[string]any{"statements": []any{map[string]any{"effect": "Allow", "notActions": []any{"iam:*"}, "resources": []any{"*"}}}},
	}))
	if strings.Contains(out, "kind: ClusterRole") {
		t.Fatalf("a document policy must not render a ClusterRole:\n%s", out)
	}
	for _, want := range []string{"kind: ConfigMap", "name: openinfra-policy-aws-poweruseraccess", "namespace: open-infra-console",
		"ready: true", `arn: "arn:aws:iam::aws:policy/PowerUserAccess"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("document policy render lacks %q:\n%s", want, out)
		}
	}
}

// A Group that names only policies (a policy container, as on AWS) binds no ClusterRole; one that still
// names a clusterRole (deprecated) keeps its binding.
func TestIAMModel_GroupIsAPolicyContainer(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/group-composition.yaml")
	out := render(t, tmpl, iamCtx("developers", "open-infra-console", map[string]any{
		"policies": []any{"aws-poweruseraccess"}}))
	if strings.Contains(out, "ClusterRoleBinding") {
		t.Fatalf("a policy-container group must not bind a ClusterRole:\n%s", out)
	}
	if !strings.Contains(out, "ready: true") || !strings.Contains(out, `boundTo: "openinfra:developers"`) {
		t.Fatalf("group status:\n%s", out)
	}
	empty := render(t, tmpl, iamCtx("nothing", "open-infra-console", map[string]any{}))
	if strings.Contains(empty, "ClusterRoleBinding") {
		t.Fatalf("a group with neither policies nor a clusterRole grants nothing, as on AWS:\n%s", empty)
	}
}
