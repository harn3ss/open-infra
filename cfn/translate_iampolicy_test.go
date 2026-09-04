package main

import (
	"strings"
	"testing"
)

// A pure data-plane inline policy (s3 + dynamodb, recognizable ARNs, no conditions) attached to a
// group translates into an enforced kind: Policy spec.dataPlane — the whole point of the engine.
func TestTranslate_IAMPolicy_DataPlaneFaithful(t *testing.T) {
	m, fs := translateIAMPolicy("AnalystScope", map[string]any{
		"PolicyName": "analyst-scope",
		"Groups":     []any{"analysts"},
		"PolicyDocument": map[string]any{
			"Version": "2012-10-17",
			"Statement": []any{
				map[string]any{"Effect": "Allow", "Action": []any{"s3:GetObject", "s3:PutObject"}, "Resource": "arn:aws:s3:::reports/*"},
				map[string]any{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
				map[string]any{"Effect": "Allow", "Action": "dynamodb:Query", "Resource": "arn:aws:dynamodb:us-east-1:1:table/metrics"},
			},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Policy" || m.APIVersion != "iam.openinfra.dev/v1" {
		t.Fatalf("bad manifest head: %+v", m)
	}
	dp, ok := m.Spec["dataPlane"].(map[string]any)
	if !ok {
		t.Fatalf("no dataPlane block: %#v", m.Spec)
	}
	at, _ := dp["appliesTo"].([]any)
	if len(at) != 1 || at[0] != "Group::analysts" {
		t.Fatalf("appliesTo wrong: %#v", dp["appliesTo"])
	}
	st, _ := dp["statements"].([]any)
	if len(st) != 3 {
		t.Fatalf("want 3 statements, got %d: %#v", len(st), st)
	}
	// The forbid must be carried through as a real Deny (an RBAC grant can't express this).
	if !strings.Contains(strings.ToLower(strings.Join(deepStrings(st), " ")), "deny") {
		t.Fatalf("expected a Deny statement in %#v", st)
	}
}

// deepStrings flattens a nested any-tree to its string leaves + map keys, so a test can assert a
// value survived translation without reaching for encoding/json.
func deepStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, deepStrings(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for k, e := range x {
			out = append(out, k)
			out = append(out, deepStrings(e)...)
		}
		return out
	}
	return nil
}

// A policy with a control-plane action (ec2) BLOCKS with a precise report — never a silent partial.
func TestTranslate_IAMPolicy_ControlPlaneBlocks(t *testing.T) {
	_, fs := translateIAMPolicy("Mixed", map[string]any{
		"Users": []any{"alice"},
		"PolicyDocument": map[string]any{
			"Statement": []any{
				map[string]any{"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
			},
		},
	}, nil)
	txt := findingsText(fs)
	if !strings.Contains(txt, "ec2:RunInstances") || !strings.Contains(txt, "cannot faithfully translate") {
		t.Fatalf("ec2 action must block with a precise report, got: %s", txt)
	}
}

// A Condition can't be imported (a silently-ineffective Deny condition is a hole), so it BLOCKS.
func TestTranslate_IAMPolicy_ConditionBlocks(t *testing.T) {
	_, fs := translateIAMPolicy("Conditioned", map[string]any{
		"Groups": []any{"eng"},
		"PolicyDocument": map[string]any{
			"Statement": []any{
				map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
					"Condition": map[string]any{"Bool": map[string]any{"aws:MultiFactorAuthPresent": "true"}}},
			},
		},
	}, nil)
	txt := findingsText(fs)
	if !strings.Contains(txt, "Condition") {
		t.Fatalf("a Condition must block, got: %s", txt)
	}
}

// An inline policy that attaches to nothing has no principal to govern → block.
func TestTranslate_IAMPolicy_NoPrincipalBlocks(t *testing.T) {
	_, fs := translateIAMPolicy("Orphan", map[string]any{
		"PolicyDocument": map[string]any{
			"Statement": []any{map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}},
		},
	}, nil)
	if !strings.Contains(findingsText(fs), "attach") && !strings.Contains(findingsText(fs), "names no") {
		t.Fatalf("a policy with no principal must block, got: %s", findingsText(fs))
	}
}

// A Role attachment can't be enforced at the shim → block (don't silently no-op the attachment).
func TestTranslate_IAMPolicy_RoleBlocks(t *testing.T) {
	_, fs := translateIAMPolicy("ForRole", map[string]any{
		"Roles": []any{"app-role"},
		"PolicyDocument": map[string]any{
			"Statement": []any{map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}},
		},
	}, nil)
	if !strings.Contains(findingsText(fs), "Role") {
		t.Fatalf("a Role attachment must block, got: %s", findingsText(fs))
	}
}

// A ManagedPolicy with inline Groups + a pure data-plane document translates exactly like an inline
// Policy — same engine, same importer — with its ManagedPolicyName/Description surfaced as caveats.
func TestTranslate_ManagedPolicy_InlineAttachedFaithful(t *testing.T) {
	m, fs := translateManagedPolicy("ReadReports", map[string]any{
		"ManagedPolicyName": "read-reports",
		"Description":       "analysts can read the reports bucket",
		"Path":              "/team/",
		"Groups":            []any{"analysts"},
		"PolicyDocument": map[string]any{
			"Statement": []any{
				map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"},
			},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Policy" || m.APIVersion != "iam.openinfra.dev/v1" {
		t.Fatalf("bad manifest head: %+v", m)
	}
	dp, _ := m.Spec["dataPlane"].(map[string]any)
	at, _ := dp["appliesTo"].([]any)
	if len(at) != 1 || at[0] != "Group::analysts" {
		t.Fatalf("appliesTo wrong: %#v", dp["appliesTo"])
	}
	joined := strings.Join(m.Caveats, " | ")
	if !strings.Contains(joined, "Description") || !strings.Contains(joined, "ManagedPolicyName") {
		t.Fatalf("ManagedPolicy metadata should be declared caveats, got: %s", joined)
	}
}

// A standalone ManagedPolicy (attached elsewhere via ManagedPolicyArns) names no principal here → block.
func TestTranslate_ManagedPolicy_StandaloneBlocks(t *testing.T) {
	_, fs := translateManagedPolicy("Standalone", map[string]any{
		"ManagedPolicyName": "s3-read",
		"PolicyDocument": map[string]any{
			"Statement": []any{map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}},
		},
	}, nil)
	txt := findingsText(fs)
	if !strings.Contains(txt, "names no Users or Groups") {
		t.Fatalf("a standalone ManagedPolicy must block, got: %s", txt)
	}
}

// The control-plane refusal holds for ManagedPolicy too (shared core).
func TestTranslate_ManagedPolicy_ControlPlaneBlocks(t *testing.T) {
	_, fs := translateManagedPolicy("Mixed", map[string]any{
		"Groups": []any{"eng"},
		"PolicyDocument": map[string]any{
			"Statement": []any{map[string]any{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}},
		},
	}, nil)
	if !strings.Contains(findingsText(fs), "iam:PassRole") {
		t.Fatalf("a control-plane action must block, got: %s", findingsText(fs))
	}
}
