package policyengine

import (
	"strings"
	"testing"
)

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

// The deny reason must distinguish an explicit forbid (a Deny overriding an allow) from a plain
// default-deny — they are different security events an audit log must not conflate.
func TestEngine_DenyReasonDistinguishesForbidFromDefault(t *testing.T) {
	eng, err := NewEngine([]Statement{
		{Effect: Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}},
		{Effect: Deny, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::secret"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "u"}
	// GET on secret: the s3:* allow WOULD permit, but the forbid overrides → explicit-forbid reason.
	forbid := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "secret"}, nil})
	if forbid.Allowed || !strings.Contains(forbid.Reason, "forbid") {
		t.Errorf("GET secret should be an explicit forbid, got allowed=%v reason=%q", forbid.Allowed, forbid.Reason)
	}
	// An action no statement mentions at all → default-deny (not a forbid).
	def := eng.Authorize(Request{p, "sns:Publish", Resource{"Topic", "t"}, nil})
	if def.Allowed || strings.Contains(def.Reason, "forbid") || !strings.Contains(def.Reason, "default deny") {
		t.Errorf("sns:Publish should be default-deny, got allowed=%v reason=%q", def.Allowed, def.Reason)
	}
}

// §5: an Allow gated on an IpAddress CIDR permits only in-range sources; out-of-range, absent, and
// MALFORMED sources all fall through to default-deny (a permit fails closed naturally on an errored
// condition, and the engine collapses a malformed IP to "absent").
func TestEngine_IPConditionAllow(t *testing.T) {
	eng, err := NewEngine([]Statement{{
		Effect:       Allow,
		Actions:      []string{"s3:GetObject"},
		Resources:    []string{"Bucket::reports"},
		IPConditions: []IPCondition{{Key: "sourceIp", CIDR: "10.0.0.0/8"}},
	}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "a"}
	get := func(ip any) Decision {
		return eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "reports"}, map[string]any{"sourceIp": ip}})
	}
	if d := get("10.1.2.3"); !d.Allowed {
		t.Errorf("in-range source should be allowed, got %q", d.Reason)
	}
	if d := get("8.8.8.8"); d.Allowed {
		t.Error("out-of-range source must be denied")
	}
	if d := get("not-an-ip"); d.Allowed {
		t.Error("malformed source must be denied (coerced to absent)")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", Resource{"Bucket", "reports"}, nil}); d.Allowed {
		t.Error("absent source must be denied for an IP-gated allow")
	}
}

// §5 THE CRITICAL INVARIANT: a Deny (forbid) gated on a condition key must FAIL CLOSED when that key
// is absent or malformed at request time — otherwise the forbid silently evaporates (Cedar skips an
// errored `when`) and the broad Allow leaks through. Proven for both an IP condition and a bool
// equality condition, each paired with an Allow that would otherwise permit.
func TestEngine_ForbidFailsClosedOnAbsentKey(t *testing.T) {
	p := Principal{Type: "User", ID: "a"}
	res := Resource{Type: "Bucket", ID: "reports"}

	// IpAddress on a forbid: Deny GetObject unless from 10.0.0.0/8. A broad Allow permits GetObject.
	ipEng, err := NewEngine([]Statement{
		{Effect: Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"*"}},
		{Effect: Deny, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::reports"},
			IPConditions: []IPCondition{{Key: "sourceIp", CIDR: "10.0.0.0/8"}}},
	})
	if err != nil {
		t.Fatalf("compile ip: %v", err)
	}
	ipGet := func(ctx map[string]any) Decision {
		return ipEng.Authorize(Request{p, "s3:GetObject", res, ctx})
	}
	if d := ipGet(map[string]any{"sourceIp": "10.1.2.3"}); d.Allowed {
		t.Error("Deny(in-range): source in the forbid's range must be DENIED")
	}
	if d := ipGet(map[string]any{"sourceIp": "8.8.8.8"}); !d.Allowed {
		t.Error("Deny(out-of-range): source outside the forbid's range should be allowed (the broad Allow)")
	}
	if d := ipGet(nil); d.Allowed {
		t.Error("FAIL-OPEN: an ABSENT sourceIp on a Deny condition must DENY, not leak the Allow")
	}
	if d := ipGet(map[string]any{"sourceIp": "garbage"}); d.Allowed {
		t.Error("FAIL-OPEN: a MALFORMED sourceIp on a Deny condition must DENY, not leak the Allow")
	}

	// Bool equality on a forbid: Deny unless authenticated. Absent authenticated must DENY.
	boolEng, err := NewEngine([]Statement{
		{Effect: Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"*"}},
		{Effect: Deny, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::reports"},
			Condition: map[string]string{"authenticated": "false"}},
	})
	if err != nil {
		t.Fatalf("compile bool: %v", err)
	}
	if d := boolEng.Authorize(Request{p, "s3:GetObject", res, map[string]any{"authenticated": false}}); d.Allowed {
		t.Error("Deny(authenticated==false): an unauthenticated request must be DENIED")
	}
	if d := boolEng.Authorize(Request{p, "s3:GetObject", res, nil}); d.Allowed {
		t.Error("FAIL-OPEN: an ABSENT authenticated key on a Deny condition must DENY")
	}
	if d := boolEng.Authorize(Request{p, "s3:GetObject", res, map[string]any{"authenticated": true}}); !d.Allowed {
		t.Error("Deny(authenticated==false) with authenticated==true: the forbid should NOT fire")
	}
}

// §5: NotIpAddress on a forbid denies when the source is NOT in the range; absent still fails closed.
func TestEngine_NotIPConditionForbid(t *testing.T) {
	eng, err := NewEngine([]Statement{
		{Effect: Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"*"}},
		{Effect: Deny, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::reports"},
			IPConditions: []IPCondition{{Key: "sourceIp", CIDR: "10.0.0.0/8", Negate: true}}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "User", ID: "a"}
	res := Resource{Type: "Bucket", ID: "reports"}
	if d := eng.Authorize(Request{p, "s3:GetObject", res, map[string]any{"sourceIp": "10.1.2.3"}}); !d.Allowed {
		t.Error("NotIp Deny: an in-range source is NOT denied (the negated condition is false)")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", res, map[string]any{"sourceIp": "8.8.8.8"}}); d.Allowed {
		t.Error("NotIp Deny: an out-of-range source must be denied")
	}
	if d := eng.Authorize(Request{p, "s3:GetObject", res, nil}); d.Allowed {
		t.Error("NotIp Deny: an absent source must fail closed (deny)")
	}
}

// §4: a permission boundary is the ceiling — the effective permission is the intersection of the
// identity policy and the boundary. Identity allows s3:* on Bucket::*, boundary permits only s3:Get*:
// GetObject is allowed, PutObject/DeleteObject are denied despite the s3:* identity allow.
func TestEngine_PermissionBoundary(t *testing.T) {
	identity := []Statement{{Effect: Allow, Actions: []string{"s3:*"}, Resources: []string{"Bucket::*"}}}
	boundary := []Statement{{Effect: Allow, Actions: []string{"s3:Get*"}, Resources: []string{"Bucket::*"}}}
	eng, err := NewEngineWithBoundary(identity, boundary)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := Principal{Type: "Role", ID: "broad"}
	x := Resource{Type: "Bucket", ID: "x"}
	if d := eng.Authorize(Request{p, "s3:GetObject", x, nil}); !d.Allowed {
		t.Errorf("GetObject is within the boundary → allowed, got %q", d.Reason)
	}
	if d := eng.Authorize(Request{p, "s3:PutObject", x, nil}); d.Allowed {
		t.Error("PutObject is outside the boundary → denied despite s3:* identity allow")
	}
	if d := eng.Authorize(Request{p, "s3:DeleteObject", x, nil}); d.Allowed {
		t.Error("DeleteObject is outside the boundary → denied despite s3:* identity allow")
	}
}

// §4: an empty boundary (allows nothing) forbids everything; a wildcard boundary imposes no ceiling.
func TestEngine_BoundaryEdges(t *testing.T) {
	identity := []Statement{{Effect: Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}}}
	p := Principal{Type: "User", ID: "a"}
	x := Resource{Type: "Bucket", ID: "x"}

	empty, err := NewEngineWithBoundary(identity, nil)
	if err != nil {
		t.Fatalf("compile empty: %v", err)
	}
	if d := empty.Authorize(Request{p, "s3:GetObject", x, nil}); d.Allowed {
		t.Error("an empty boundary must forbid everything (fail closed)")
	}

	wide, err := NewEngineWithBoundary(identity, []Statement{{Effect: Allow, Actions: []string{"*"}, Resources: []string{"*"}}})
	if err != nil {
		t.Fatalf("compile wide: %v", err)
	}
	if d := wide.Authorize(Request{p, "s3:GetObject", x, nil}); !d.Allowed {
		t.Error("a wildcard boundary imposes no ceiling → the identity allow stands")
	}
}
