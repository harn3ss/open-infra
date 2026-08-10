package cache

import (
	"context"
	"math"
	"strconv"
	"testing"
	"time"
)

func TestMem_HitMissExpiry(t *testing.T) {
	clock := time.Unix(1000, 0)
	m := NewMem()
	m.now = func() time.Time { return clock }
	ctx := context.Background()

	if _, ok := m.Get(ctx, "k"); ok {
		t.Fatal("empty cache must miss")
	}
	m.Set(ctx, "k", []byte("v"), 30*time.Second)
	if v, ok := m.Get(ctx, "k"); !ok || string(v) != "v" {
		t.Fatalf("live entry must hit with its value; got %q ok=%v", v, ok)
	}
	// Just before expiry — still a hit.
	clock = clock.Add(29 * time.Second)
	if _, ok := m.Get(ctx, "k"); !ok {
		t.Fatal("entry must still be live 1s before TTL")
	}
	// After expiry — a miss.
	clock = clock.Add(2 * time.Second)
	if _, ok := m.Get(ctx, "k"); ok {
		t.Fatal("expired entry must miss")
	}
	// A non-positive TTL stores nothing.
	m.Set(ctx, "z", []byte("v"), 0)
	if _, ok := m.Get(ctx, "z"); ok {
		t.Fatal("a zero-TTL Set must store nothing")
	}
}

// The in-memory cache is hard-bounded: cache keys embed client-controlled argument values, so an
// unbounded map would be an OOM DoS. Writing many distinct keys must never exceed the ceiling.
func TestMem_BoundedSize(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	for i := 0; i < maxMemEntries*2; i++ {
		m.Set(ctx, "key-"+strconv.Itoa(i), []byte("v"), time.Hour)
	}
	m.mu.RLock()
	n := len(m.entries)
	m.mu.RUnlock()
	if n > maxMemEntries {
		t.Fatalf("cache grew to %d entries, exceeding the %d ceiling", n, maxMemEntries)
	}
}

func TestNoop_AlwaysMisses(t *testing.T) {
	var c Cache = Noop{}
	c.Set(context.Background(), "k", []byte("v"), time.Minute)
	if _, ok := c.Get(context.Background(), "k"); ok {
		t.Fatal("Noop must never hit")
	}
}

// The key ALWAYS distinguishes callers: same field+args but different identity → different key, so a
// cached response can never be served across identities.
func TestKey_IdentityIsolation(t *testing.T) {
	args := []any{map[string]any{"id": "1"}}
	mustKey := func(tf, u string, g []string, kv []any) string {
		k, ok := Key(tf, u, g, kv)
		if !ok {
			t.Fatalf("Key(%s,%s) unexpectedly not derivable", tf, u)
		}
		return k
	}
	alice := mustKey("Query.getThing", "alice", []string{"openinfra:users"}, args)
	bob := mustKey("Query.getThing", "bob", []string{"openinfra:users"}, args)
	if alice == bob {
		t.Fatal("different usernames must produce different cache keys (no cross-identity leak)")
	}
	// Same caller + same inputs → same key (a real hit).
	if alice != mustKey("Query.getThing", "alice", []string{"openinfra:users"}, args) {
		t.Fatal("identical inputs must produce a stable key")
	}
	// Group membership is part of identity — a different group set is a different key.
	if alice == mustKey("Query.getThing", "alice", []string{"openinfra:admins"}, args) {
		t.Fatal("different groups must produce different cache keys")
	}
	// Different args → different key.
	if alice == mustKey("Query.getThing", "alice", []string{"openinfra:users"}, []any{map[string]any{"id": "2"}}) {
		t.Fatal("different arguments must produce different cache keys")
	}
	// Group order must not matter (keys are canonicalized).
	if mustKey("Q.f", "u", []string{"a", "b"}, nil) != mustKey("Q.f", "u", []string{"b", "a"}, nil) {
		t.Fatal("group order must not change the key")
	}
	// A non-encodable key value (non-finite float) is NOT derivable → caller must skip caching, never
	// collapse to a shared constant key.
	if _, ok := Key("Q.f", "u", nil, []any{math.Inf(1)}); ok {
		t.Fatal("a non-finite key value must make Key un-derivable (ok=false), not a shared constant")
	}
}

func TestResolveKeyPath(t *testing.T) {
	gctx := map[string]any{
		"args":     map[string]any{"id": "42", "nested": map[string]any{"x": "y"}},
		"identity": map[string]any{"username": "alice"},
	}
	cases := map[string]any{
		"$context.arguments.id": "42",
		"$ctx.args.id":          "42",
		"arguments.id":          "42",
		"args.nested.x":         "y",
		"identity.username":     "alice",
		"arguments.missing":     nil, // present-but-empty, stable
	}
	for path, want := range cases {
		if got := ResolveKeyPath(gctx, path); got != want {
			t.Errorf("ResolveKeyPath(%q) = %v, want %v", path, got, want)
		}
	}
}
