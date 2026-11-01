package cfn

import (
	"context"
	"strings"
	"testing"
)

// A pure data-plane inline policy (s3 + dynamodb, recognizable ARNs, no conditions) attached to a
// user translates into an enforced kind: Policy spec.dataPlane — the whole point of the engine.
func TestTranslate_IAMPolicy_DataPlaneFaithful(t *testing.T) {
	m, fs := translateIAMPolicy("AnalystScope", map[string]any{
		"PolicyName": "analyst-scope",
		"Users":      []any{"analyst"},
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
	if len(at) != 1 || at[0] != "User::analyst" {
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

// A Roles attachment now translates (the shim authenticates assumed-role sessions, #111): the imported
// data-plane document is scoped to the Role via appliesTo: [Role::<name>], with a declared caveat that
// the Role must exist + carry a trust policy natively. It no longer blocks (§6 overclaim reconciled).
func TestTranslate_IAMPolicy_RoleTranslatesToAppliesTo(t *testing.T) {
	m, fs := translateIAMPolicy("ForRole", map[string]any{
		"Roles": []any{"app-role"},
		"PolicyDocument": map[string]any{
			"Statement": []any{map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("a Roles attachment must no longer block, got findings: %s", findingsText(fs))
	}
	dp, ok := m.Spec["dataPlane"].(map[string]any)
	if !ok {
		t.Fatalf("no dataPlane block: %#v", m.Spec)
	}
	at, _ := dp["appliesTo"].([]any)
	if len(at) != 1 || at[0] != "Role::app-role" {
		t.Fatalf("appliesTo must be [Role::app-role], got: %#v", dp["appliesTo"])
	}
	// The Role-existence/trust requirement is surfaced as a declared caveat, not a silent partial.
	if !strings.Contains(strings.Join(m.Caveats, " | "), "trust policy") {
		t.Fatalf("expected a declared Role trust caveat, got: %v", m.Caveats)
	}
}

// Users and Roles can be attached together — each maps to its typed principal on the same dataPlane.
func TestTranslate_IAMPolicy_MixedPrincipals(t *testing.T) {
	m, fs := translateIAMPolicy("Mixed", map[string]any{
		"Users": []any{"alice"},
		"Roles": []any{"app-role"},
		"PolicyDocument": map[string]any{
			"Statement": []any{map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	dp, _ := m.Spec["dataPlane"].(map[string]any)
	at, _ := dp["appliesTo"].([]any)
	got := map[string]bool{}
	for _, p := range at {
		got[p.(string)] = true
	}
	for _, want := range []string{"User::alice", "Role::app-role"} {
		if !got[want] {
			t.Fatalf("appliesTo missing %s, got: %#v", want, at)
		}
	}
}

// A ManagedPolicy with inline Users + a pure data-plane document translates exactly like an inline
// Policy — same engine, same importer — with its ManagedPolicyName/Description surfaced as caveats.
func TestTranslate_ManagedPolicy_InlineAttachedFaithful(t *testing.T) {
	m, fs := translateManagedPolicy("ReadReports", map[string]any{
		"ManagedPolicyName": "read-reports",
		"Description":       "analysts can read the reports bucket",
		"Path":              "/team/",
		"Users":             []any{"analyst"},
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
	if len(at) != 1 || at[0] != "User::analyst" {
		t.Fatalf("appliesTo wrong: %#v", dp["appliesTo"])
	}
	joined := strings.Join(m.Caveats, " | ")
	if !strings.Contains(joined, "Description") || !strings.Contains(joined, "ManagedPolicyName") {
		t.Fatalf("ManagedPolicy metadata should be declared caveats, got: %s", joined)
	}
}

// A stack's kind: Policy lives in the stack's namespace, where it governs only that namespace's
// principals. So an in-stack User or Role (by Ref) is governed; a User named from outside the stack must
// exist in the stack's namespace (deploy refuses while it does not, as AWS refuses a policy naming a
// missing user); a Groups attachment refuses — groups are IAM home identities, and a guardrail attached
// to one from a stack would silently govern no one.
func TestTranslate_IAMPolicy_PrincipalsAreTheStackNamespaces(t *testing.T) {
	tmpl := `
Resources:
  Svc: { Type: AWS::IAM::User }
  Ro:
    Type: AWS::IAM::Role
    Properties: { AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ] } }
  Guard:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: guard
      Users: [ !Ref Svc, alice ]
      Roles: [ !Ref Ro ]
      PolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Deny, Action: "s3:DeleteObject", Resource: "*" } ] }
`
	f := &fakeApplier{}
	_, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "User alice does not exist") {
		t.Fatalf("a policy naming a user absent from the stack's namespace must refuse, got %v", err)
	}
	f = &fakeApplier{liveSpecs: map[string]map[string]any{"User/alice": {"source": "local"}}}
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	var at []any
	for _, r := range rec.Resources {
		if r.Kind == "Policy" {
			at, _ = r.Spec["dataPlane"].(map[string]any)["appliesTo"].([]any)
		}
	}
	got := map[string]bool{}
	for _, p := range at {
		got[p.(string)] = true
	}
	for _, want := range []string{"User::s-svc", "User::alice", "Role::s-ro"} {
		if !got[want] {
			t.Errorf("appliesTo is missing %s: %v", want, at)
		}
	}

	grp := strings.Replace(tmpl, "Roles: [ !Ref Ro ]", "Groups: [ admins ]", 1)
	if _, err := Deploy(context.Background(), []byte(grp), deployOpts(), &fakeApplier{}); err == nil || !strings.Contains(err.Error(), "which a stack's policy cannot govern") {
		t.Fatalf("a Groups attachment must refuse, got %v", err)
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

// #7: a CFN IAM policy using NotAction/NotResource translates into a kind: Policy spec.dataPlane that
// carries the complement axes (a dropped complement would silently widen the grant). And a NotResource
// whose exclusion can't be mapped blocks the whole resource, fail-closed.
func TestTranslate_IAMPolicy_Complement(t *testing.T) {
	m, fs := translateIAMPolicy("ComplementScope", map[string]any{
		"PolicyName": "complement-scope",
		"Users":      []any{"alice"},
		"PolicyDocument": map[string]any{
			"Statement": []any{
				map[string]any{"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"},
				map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret"},
			},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	dp := m.Spec["dataPlane"].(map[string]any)
	st, _ := dp["statements"].([]any)
	if len(st) != 2 {
		t.Fatalf("want 2 statements, got %d: %#v", len(st), st)
	}
	s0 := st[0].(map[string]any)
	if _, ok := s0["actions"]; ok {
		t.Error("a NotAction statement must not carry an actions key")
	}
	if na, _ := s0["notActions"].([]any); len(na) != 1 || na[0] != "s3:DeleteObject" {
		t.Errorf("notActions not carried: %#v", s0["notActions"])
	}
	s1 := st[1].(map[string]any)
	if nr, _ := s1["notResources"].([]any); len(nr) != 1 || nr[0] != "Bucket::secret" {
		t.Errorf("notResources not carried: %#v", s1["notResources"])
	}

	// An unmappable NotResource (an unfronted service's ARN) must block the resource, not widen it.
	_, fs = translateIAMPolicy("BadComplement", map[string]any{
		"Users": []any{"alice"},
		"PolicyDocument": map[string]any{
			"Statement": []any{
				map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:ec2:us-east-1:1:instance/i-abc"},
			},
		},
	}, nil)
	if len(fs) == 0 || !strings.Contains(findingsText(fs), "NotResource") {
		t.Fatalf("unmappable NotResource must block with a NotResource finding, got: %s", findingsText(fs))
	}
}
