package graphql

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/cache"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// countingStore records how many times the data source was actually hit — a cache hit must skip it.
type countingStore struct {
	n      *int
	result any
}

func (s countingStore) Execute(context.Context, runtime.Operation) (any, error) {
	*s.n++
	return s.result, nil
}

func TestCaching_HitMissAndIdentityIsolation(t *testing.T) {
	var calls int
	e := New(map[string]resolver.Resolver{
		"Query.getThing": {
			Runtime: stubRuntime{}, Source: countingStore{n: &calls, result: map[string]any{"id": "1"}},
			Caching: &resolver.CachingConfig{TTL: time.Minute, Keys: []string{"arguments.id"}},
		},
	}, WithCache(cache.NewMem()))

	alice := authz.NewContext(context.Background(), authz.Identity{Username: "alice"})
	q := `{ getThing(id: "1") { id } }`

	if r := e.ExecuteOp(alice, q, "", nil); len(r.Errors) > 0 {
		t.Fatalf("errored: %+v", r.Errors)
	}
	e.ExecuteOp(alice, q, "", nil) // identical → should hit the cache, not the data source
	if calls != 1 {
		t.Fatalf("second identical call must hit the cache; data-source calls=%d, want 1", calls)
	}

	// A different caller must NOT be served alice's cached entry.
	bob := authz.NewContext(context.Background(), authz.Identity{Username: "bob"})
	e.ExecuteOp(bob, q, "", nil)
	if calls != 2 {
		t.Fatalf("a different identity must miss (no cross-identity leak); calls=%d, want 2", calls)
	}

	// Different arguments must miss.
	e.ExecuteOp(alice, `{ getThing(id: "2") { id } }`, "", nil)
	if calls != 3 {
		t.Fatalf("different arguments must miss; calls=%d, want 3", calls)
	}
}

// A Mutation is NEVER cached even if (mis)configured with caching — a hit would suppress the side effect.
func TestCaching_MutationNeverCached(t *testing.T) {
	var calls int
	e := New(map[string]resolver.Resolver{
		"Mutation.doThing": {
			Runtime: stubRuntime{}, Source: countingStore{n: &calls, result: map[string]any{"ok": true}},
			Caching: &resolver.CachingConfig{TTL: time.Minute},
		},
	}, WithCache(cache.NewMem()))

	ctx := authz.NewContext(context.Background(), authz.Identity{Username: "alice"})
	m := `mutation { doThing { ok } }`
	e.ExecuteOp(ctx, m, "", nil)
	e.ExecuteOp(ctx, m, "", nil)
	if calls != 2 {
		t.Fatalf("a mutation must never be cached; data-source calls=%d, want 2", calls)
	}
}

// A cache HIT must be byte-identical to a MISS — including large integers that JSON's default float64
// decode would truncate (BIGINT / snowflake ids, nanosecond timestamps).
func TestCaching_NumberPrecisionHitEqualsMiss(t *testing.T) {
	big := int64(9007199254740993) // 2^53 + 1 — lossy as float64
	e := New(map[string]resolver.Resolver{
		"Query.getBig": {
			Runtime: stubRuntime{}, Source: countingStore{n: new(int), result: map[string]any{"id": big}},
			Caching: &resolver.CachingConfig{TTL: time.Minute, Keys: []string{"arguments.x"}},
		},
	}, WithCache(cache.NewMem()))
	ctx := authz.NewContext(context.Background(), authz.Identity{Username: "u"})
	q := `{ getBig(x: "1") { id } }`
	mustJSON := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	miss := mustJSON(e.ExecuteOp(ctx, q, "", nil).Data)
	hit := mustJSON(e.ExecuteOp(ctx, q, "", nil).Data)
	if miss != hit {
		t.Fatalf("cache HIT must be byte-identical to MISS:\n miss=%s\n hit =%s", miss, hit)
	}
	if !strings.Contains(hit, "9007199254740993") {
		t.Fatalf("large integer lost precision through the cache: %s", hit)
	}
}

// A caching block with NO author keys must still fold the arguments, so distinct-argument calls don't
// collide onto one entry (the second being served the first's data).
func TestCaching_EmptyKeysFoldsArguments(t *testing.T) {
	var calls int
	e := New(map[string]resolver.Resolver{
		"Query.getThing": {
			Runtime: stubRuntime{}, Source: countingStore{n: &calls, result: map[string]any{"id": "x"}},
			Caching: &resolver.CachingConfig{TTL: time.Minute}, // no Keys
		},
	}, WithCache(cache.NewMem()))
	ctx := authz.NewContext(context.Background(), authz.Identity{Username: "u"})
	e.ExecuteOp(ctx, `{ getThing(id: "1") { id } }`, "", nil)
	e.ExecuteOp(ctx, `{ getThing(id: "2") { id } }`, "", nil) // different args → must NOT collide
	if calls != 2 {
		t.Fatalf("empty keys must still fold arguments (no collision); data-source calls=%d, want 2", calls)
	}
	e.ExecuteOp(ctx, `{ getThing(id: "1") { id } }`, "", nil) // repeat → hit
	if calls != 2 {
		t.Fatalf("a repeated argument must hit the cache; calls=%d, want 2", calls)
	}
}

// With no cache backend (default Noop) a caching-configured resolver simply always runs — correct,
// just uncached.
func TestCaching_NoBackendAlwaysRuns(t *testing.T) {
	var calls int
	e := New(map[string]resolver.Resolver{
		"Query.getThing": {
			Runtime: stubRuntime{}, Source: countingStore{n: &calls, result: map[string]any{"id": "1"}},
			Caching: &resolver.CachingConfig{TTL: time.Minute, Keys: []string{"arguments.id"}},
		},
	}) // no WithCache → Noop
	ctx := authz.NewContext(context.Background(), authz.Identity{Username: "alice"})
	q := `{ getThing(id: "1") { id } }`
	e.ExecuteOp(ctx, q, "", nil)
	e.ExecuteOp(ctx, q, "", nil)
	if calls != 2 {
		t.Fatalf("with no backend the resolver must always run; calls=%d, want 2", calls)
	}
}
