package dataplaneauthz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/policyengine"
)

func fixedLoader(snap Snapshot, err error) Loader {
	return func(context.Context) (Snapshot, error) { return snap, err }
}

func TestChecker_TightensNeverLoosens(t *testing.T) {
	docs := []PolicyDoc{{
		AppliesTo: []string{"User::alice"},
		Statements: []policyengine.Statement{
			{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"}},
			{Effect: policyengine.Deny, Actions: []string{"s3:DeleteObject"}, Resources: []string{"*"}},
		},
	}}
	c := New(fixedLoader(Snapshot{Docs: docs}, nil), time.Minute)
	ctx := context.Background()

	// Alice is governed: allowed GetObject on assets, denied DeleteObject, denied GetObject elsewhere.
	if a, g, _ := c.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "assets", nil); !a || !g {
		t.Errorf("alice GetObject on assets: allowed=%v governed=%v, want true/true", a, g)
	}
	if a, g, _ := c.Authorize(ctx, "User", "alice", nil, "s3:DeleteObject", "Bucket", "assets", nil); a || !g {
		t.Errorf("alice DeleteObject: allowed=%v governed=%v, want false/true (forbid)", a, g)
	}
	if a, g, _ := c.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "secrets", nil); a || !g {
		t.Errorf("alice GetObject on secrets: allowed=%v governed=%v, want false/true", a, g)
	}
	// Bob is NOT governed (no policy names him) — coarse RBAC stands.
	if a, g, _ := c.Authorize(ctx, "User", "bob", nil, "s3:DeleteObject", "Bucket", "assets", nil); !a || g {
		t.Errorf("bob (ungoverned): allowed=%v governed=%v, want true/false", a, g)
	}
}

func TestChecker_GroupMatch(t *testing.T) {
	docs := []PolicyDoc{{
		AppliesTo:  []string{"Group::eng"},
		Statements: []policyengine.Statement{{Effect: policyengine.Deny, Actions: []string{"*"}, Resources: []string{"Table::prod"}}},
	}}
	c := New(fixedLoader(Snapshot{Docs: docs}, nil), time.Minute)
	// carol is in openinfra:eng (impersonation-prefixed) → the Group::eng policy applies.
	if a, g, _ := c.Authorize(context.Background(), "User", "carol", []string{"openinfra:eng"}, "dynamodb:Query", "Table", "prod", nil); a || !g {
		t.Errorf("eng-group deny on Table::prod: allowed=%v governed=%v, want false/true", a, g)
	}
}

func TestChecker_FailClosed(t *testing.T) {
	// A load error denies (governed=true), never opens the door.
	c := New(fixedLoader(Snapshot{}, errors.New("apiserver down")), time.Minute)
	if a, g, _ := c.Authorize(context.Background(), "User", "alice", nil, "s3:GetObject", "Bucket", "assets", nil); a || !g {
		t.Errorf("load error must fail closed: allowed=%v governed=%v, want false/true", a, g)
	}
	// A nil checker is a no-op (not governed) — the shim works without the engine.
	var nilc *Checker
	if a, g, _ := nilc.Authorize(context.Background(), "User", "alice", nil, "s3:GetObject", "Bucket", "assets", nil); !a || g {
		t.Errorf("nil checker: allowed=%v governed=%v, want true/false", a, g)
	}
}

// A transient loader error on an already-warm cache must NOT deny all data-plane traffic (that would
// turn a control-plane blip into a shim-wide outage); the last good snapshot is served through it.
func TestChecker_ServesStaleThroughRefreshBlip(t *testing.T) {
	good := []PolicyDoc{{
		AppliesTo:  []string{"User::alice"},
		Statements: []policyengine.Statement{{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"}}},
	}}
	var fail bool
	load := func(context.Context) (Snapshot, error) {
		if fail {
			return Snapshot{}, errors.New("apiserver blip")
		}
		return Snapshot{Docs: good}, nil
	}
	c := New(load, time.Millisecond) // tiny TTL so a later call forces a refresh
	ctx := context.Background()

	// Warm the cache with a good load: alice is governed + allowed on assets.
	if a, g, _ := c.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "assets", nil); !a || !g {
		t.Fatalf("warm: allowed=%v governed=%v, want true/true", a, g)
	}
	// The loader now blips; force the TTL to elapse so get() attempts (and fails) a refresh.
	fail = true
	time.Sleep(2 * time.Millisecond)
	if a, g, _ := c.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "assets", nil); !a || !g {
		t.Errorf("refresh blip must serve the last-good snapshot: allowed=%v governed=%v, want true/true", a, g)
	}
	// Recovery: the loader is healthy again → refreshes cleanly and still enforces the policy.
	fail = false
	time.Sleep(2 * time.Millisecond)
	if a, g, _ := c.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "assets", nil); !a || !g {
		t.Errorf("after recovery: allowed=%v governed=%v, want true/true", a, g)
	}
}

// The attachment model (§3): a Policy attached to a Role via spec.policies — WITHOUT its dataPlane
// appliesTo naming the Role — governs an assumed session. This is the managed-attachment axis: the
// Role's own spec.policies confers the Policy's data-plane authority (as its aggregated ClusterRole
// does on the control plane), so "assuming the role picks up the policies attached to it".
func TestChecker_RoleAttachedPolicyGovernsSession(t *testing.T) {
	snap := Snapshot{
		Docs: []PolicyDoc{{
			Name:      "reports-read",
			AppliesTo: nil, // deliberately names no principal — the ONLY link is the attachment
			Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::reports"}},
			},
		}},
		Attach: map[string][]string{"Role::reports-ro": {"reports-read"}},
	}
	c := New(fixedLoader(snap, nil), time.Minute)
	ctx := context.Background()

	// Assume reports-ro: GetObject on reports ⇒ allowed + governed (via the attached Policy).
	if a, g, r := c.Authorize(ctx, "Role", "reports-ro", nil, "s3:GetObject", "Bucket", "reports", nil); !a || !g {
		t.Errorf("assumed role GetObject reports: allowed=%v governed=%v (%s), want true/true", a, g, r)
	}
	// GetObject on a DIFFERENT bucket ⇒ governed (s3 is in allow-list mode) but denied — the grant
	// is scoped to Bucket::reports, not Bucket::payroll.
	if a, g, _ := c.Authorize(ctx, "Role", "reports-ro", nil, "s3:GetObject", "Bucket", "payroll", nil); a || !g {
		t.Errorf("assumed role GetObject payroll: allowed=%v governed=%v, want false/true", a, g)
	}
	// PutObject on reports ⇒ governed, denied (only GetObject is allowed).
	if a, g, _ := c.Authorize(ctx, "Role", "reports-ro", nil, "s3:PutObject", "Bucket", "reports", nil); a || !g {
		t.Errorf("assumed role PutObject reports: allowed=%v governed=%v, want false/true", a, g)
	}
	// A DIFFERENT role with no attachment is NOT governed for s3 ⇒ the coarse RBAC decision stands.
	if a, g, _ := c.Authorize(ctx, "Role", "other", nil, "s3:GetObject", "Bucket", "reports", nil); !a || g {
		t.Errorf("unattached role: allowed=%v governed=%v, want true/false", a, g)
	}
	// Detaching (empty Attach) ⇒ the Policy no longer names the role by any axis ⇒ ungoverned again.
	c2 := New(fixedLoader(Snapshot{Docs: snap.Docs}, nil), time.Minute)
	if a, g, _ := c2.Authorize(ctx, "Role", "reports-ro", nil, "s3:GetObject", "Bucket", "reports", nil); !a || g {
		t.Errorf("after detach: allowed=%v governed=%v, want true/false", a, g)
	}
}

// A managed Policy attached to a Group is inherited by its members (a User in that group), and a
// Policy attached directly to a User via spec.policies governs that User — the same dual meaning as
// on a Role. Also asserts a Policy reached by BOTH the inline appliesTo axis and the managed axis
// contributes its statements once (no double-count), keeping the Cedar decision well-defined.
func TestChecker_UserAndGroupAttachments(t *testing.T) {
	snap := Snapshot{
		Docs: []PolicyDoc{
			// Attached to the eng group; also inline-names Group::eng — must contribute exactly once.
			{Name: "eng-tables", AppliesTo: []string{"Group::eng"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"dynamodb:Query"}, Resources: []string{"Table::metrics"}},
			}},
			// Attached only to the user u (no appliesTo) — pure managed axis.
			{Name: "u-bucket", Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::u-data"}},
			}},
		},
		Attach: map[string][]string{
			"Group::eng": {"eng-tables"},
			"User::u":    {"u-bucket"},
		},
	}
	c := New(fixedLoader(snap, nil), time.Minute)
	ctx := context.Background()

	// u is in openinfra:eng → inherits eng-tables (Query metrics ⇒ allowed) AND carries u-bucket.
	if a, g, r := c.Authorize(ctx, "User", "u", []string{"openinfra:eng"}, "dynamodb:Query", "Table", "metrics", nil); !a || !g {
		t.Errorf("group-inherited Query metrics: allowed=%v governed=%v (%s), want true/true", a, g, r)
	}
	if a, g, r := c.Authorize(ctx, "User", "u", []string{"openinfra:eng"}, "s3:GetObject", "Bucket", "u-data", nil); !a || !g {
		t.Errorf("user-attached GetObject u-data: allowed=%v governed=%v (%s), want true/true", a, g, r)
	}
	// A different table is governed (dynamodb allow-list mode) but denied — the attachment doesn't widen scope.
	if a, g, _ := c.Authorize(ctx, "User", "u", []string{"openinfra:eng"}, "dynamodb:Query", "Table", "other", nil); a || !g {
		t.Errorf("Query other table: allowed=%v governed=%v, want false/true", a, g)
	}
	// A user NOT in eng and with no attachment is ungoverned for dynamodb ⇒ coarse RBAC stands.
	if a, g, _ := c.Authorize(ctx, "User", "stranger", nil, "dynamodb:Query", "Table", "metrics", nil); !a || g {
		t.Errorf("stranger: allowed=%v governed=%v, want true/false", a, g)
	}
}

// §4: a spec.permissionBoundary caps an assumed session at the data plane. The Role's identity policy
// allows s3:* on Bucket::*, but its boundary only-get permits s3:Get* — so GetObject is allowed and
// PutObject/DeleteObject are denied (the intersection), through the live Authorize path (Snapshot
// carries the Boundary index the K8sLoader builds from spec.permissionBoundary).
func TestChecker_PermissionBoundary(t *testing.T) {
	snap := Snapshot{
		Docs: []PolicyDoc{
			{Name: "broad", AppliesTo: []string{"Role::broad"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"s3:*"}, Resources: []string{"Bucket::*"}},
			}},
			{Name: "only-get", Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"s3:Get*"}, Resources: []string{"Bucket::*"}},
			}},
		},
		Boundary: map[string]string{"Role::broad": "only-get"},
	}
	c := New(fixedLoader(snap, nil), time.Minute)
	ctx := context.Background()

	if a, g, r := c.Authorize(ctx, "Role", "broad", nil, "s3:GetObject", "Bucket", "x", nil); !a || !g {
		t.Errorf("GetObject within the boundary: allowed=%v governed=%v (%s), want true/true", a, g, r)
	}
	if a, g, _ := c.Authorize(ctx, "Role", "broad", nil, "s3:PutObject", "Bucket", "x", nil); a || !g {
		t.Errorf("PutObject outside the boundary: allowed=%v governed=%v, want false/true (boundary forbids)", a, g)
	}
	if a, g, _ := c.Authorize(ctx, "Role", "broad", nil, "s3:DeleteObject", "Bucket", "x", nil); a || !g {
		t.Errorf("DeleteObject outside the boundary: allowed=%v governed=%v, want false/true", a, g)
	}

	// A named-but-missing boundary fails CLOSED: the ceiling is deny-all, so even a broad identity
	// allow is capped to nothing for the governed service.
	snap.Boundary = map[string]string{"Role::broad": "does-not-exist"}
	c2 := New(fixedLoader(snap, nil), time.Minute)
	if a, g, _ := c2.Authorize(ctx, "Role", "broad", nil, "s3:GetObject", "Bucket", "x", nil); a || !g {
		t.Errorf("missing boundary must fail closed: allowed=%v governed=%v, want false/true", a, g)
	}
}

// §5: an ipConditions block on a governed policy enforces the CIDR through the live Authorize path,
// and an IP-gated Allow permits nothing when the request carries no source IP (fails closed).
func TestChecker_IPConditionThroughAuthorize(t *testing.T) {
	snap := Snapshot{Docs: []PolicyDoc{{
		Name:      "office-only",
		AppliesTo: []string{"User::alice"},
		Statements: []policyengine.Statement{
			{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::reports"},
				IPConditions: []policyengine.IPCondition{{Key: "sourceIp", CIDR: "10.0.0.0/8"}}},
		},
	}}}
	c := New(fixedLoader(snap, nil), time.Minute)
	ctx := context.Background()
	inRange := map[string]any{"authenticated": true, "sourceIp": "10.1.2.3"}
	outRange := map[string]any{"authenticated": true, "sourceIp": "8.8.8.8"}

	if a, g, r := c.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "reports", inRange); !a || !g {
		t.Errorf("in-range GetObject: allowed=%v governed=%v (%s), want true/true", a, g, r)
	}
	if a, g, _ := c.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "reports", outRange); a || !g {
		t.Errorf("out-of-range GetObject: allowed=%v governed=%v, want false/true", a, g)
	}
	if a, g, _ := c.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "reports", map[string]any{"authenticated": true}); a || !g {
		t.Errorf("absent source IP on an IP-gated allow must deny: allowed=%v governed=%v, want false/true", a, g)
	}
}
