package dataplaneauthz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/policyengine"
)

func fixedLoader(docs []PolicyDoc, err error) Loader {
	return func(context.Context) ([]PolicyDoc, error) { return docs, err }
}

func TestChecker_TightensNeverLoosens(t *testing.T) {
	docs := []PolicyDoc{{
		AppliesTo: []string{"User::alice"},
		Statements: []policyengine.Statement{
			{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"}},
			{Effect: policyengine.Deny, Actions: []string{"s3:DeleteObject"}, Resources: []string{"*"}},
		},
	}}
	c := New(fixedLoader(docs, nil), time.Minute)
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
	c := New(fixedLoader(docs, nil), time.Minute)
	// carol is in openinfra:eng (impersonation-prefixed) → the Group::eng policy applies.
	if a, g, _ := c.Authorize(context.Background(), "User", "carol", []string{"openinfra:eng"}, "dynamodb:Query", "Table", "prod", nil); a || !g {
		t.Errorf("eng-group deny on Table::prod: allowed=%v governed=%v, want false/true", a, g)
	}
}

func TestChecker_FailClosed(t *testing.T) {
	// A load error denies (governed=true), never opens the door.
	c := New(fixedLoader(nil, errors.New("apiserver down")), time.Minute)
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
	load := func(context.Context) ([]PolicyDoc, error) {
		if fail {
			return nil, errors.New("apiserver blip")
		}
		return good, nil
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
