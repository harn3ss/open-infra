package policyengine

import "testing"

// The whole point: an explicit Deny overrides an Allow, and a condition gates the Allow — the two
// things k8s RBAC cannot do. Modeled as open-infra statements compiled to Cedar.
func TestEngine_DataPlanePolicy(t *testing.T) {
	eng, err := NewEngine([]Statement{
		{
			Effect:    Allow,
			Actions:   []string{"s3:GetObject", "s3:PutObject"},
			Resources: []string{"Bucket::assets"},
			Condition: map[string]string{"authenticated": "true"},
		},
		{
			Effect:    Deny,
			Actions:   []string{"s3:DeleteObject"},
			Resources: []string{"*"},
		},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	alice := Principal{Type: "User", ID: "alice"}
	assets := Resource{Type: "Bucket", ID: "assets"}
	authed := map[string]any{"authenticated": true}

	cases := []struct {
		name    string
		req     Request
		allowed bool
	}{
		{"get on assets, authenticated → allow",
			Request{alice, "s3:GetObject", assets, authed}, true},
		{"put on assets, authenticated → allow",
			Request{alice, "s3:PutObject", assets, authed}, true},
		{"delete → deny (forbid overrides any allow)",
			Request{alice, "s3:DeleteObject", assets, authed}, false},
		{"get on a different bucket → deny (not in allowed resources)",
			Request{alice, "s3:GetObject", Resource{Type: "Bucket", ID: "secrets"}, authed}, false},
		{"get unauthenticated → deny (condition fails)",
			Request{alice, "s3:GetObject", assets, map[string]any{"authenticated": false}}, false},
		{"unknown action → deny (default)",
			Request{alice, "s3:ListBucket", assets, authed}, false},
	}
	for _, c := range cases {
		if got := eng.Authorize(c.req); got.Allowed != c.allowed {
			t.Errorf("%s: allowed=%v, want %v (%s)", c.name, got.Allowed, c.allowed, got.Reason)
		}
	}
}

// A deny with a wildcard action on a specific resource type still overrides a broad allow.
func TestEngine_DenyWildcardAction(t *testing.T) {
	eng, err := NewEngine([]Statement{
		{Effect: Allow, Actions: []string{"*"}, Resources: []string{"*"}},
		{Effect: Deny, Actions: []string{"*"}, Resources: []string{"Table::secrets"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if d := eng.Authorize(Request{Principal{"User", "bob"}, "dynamodb:Query", Resource{"Table", "public"}, nil}); !d.Allowed {
		t.Errorf("query on a public table should be allowed by the wildcard allow")
	}
	if d := eng.Authorize(Request{Principal{"User", "bob"}, "dynamodb:Query", Resource{"Table", "secrets"}, nil}); d.Allowed {
		t.Errorf("query on the secrets table must be denied (forbid on Table::secrets)")
	}
}

// A malformed statement is a loud compile error, never a silently-empty policy set.
func TestEngine_MalformedStatement(t *testing.T) {
	if _, err := NewEngine([]Statement{{Effect: "Maybe", Actions: []string{"*"}}}); err == nil {
		t.Fatal("an invalid effect must fail to compile")
	}
	if _, err := NewEngine([]Statement{{Effect: Allow, Resources: []string{"noTypeSeparator"}}}); err == nil {
		t.Fatal("a resource without Type::id must fail to compile")
	}
}
