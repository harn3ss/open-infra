package graphql

import (
	"context"
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
