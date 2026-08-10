// Package cache is open-appsync's per-resolver response cache — the analog of AppSync's caching
// behavior. It is deliberately BEST-EFFORT: a cache miss, or any backend error, degrades to running
// the resolver, never to a wrong result or a failed request. Correctness never depends on the cache.
//
// Backend (this rung): a per-process in-memory cache — fully correct and shared for a single-replica
// engine (the default). Under multiple replicas it is per-replica, so an entry set on one replica is a
// miss on another: never wrong, just a lower hit rate. The NEXT rung is a shared NATS JetStream KV
// backend (all replicas see the same entries, like AppSync's external ElastiCache), which graduates
// separately — a per-API bucket plus a live round-trip test — exactly as the subscription bus went
// MemBus → JetStreamBus. Both satisfy the same Cache contract, so the executor is backend-unaware.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

// Cache is the neutral response-cache contract. Get returns (value, true) on a live hit; Set stores a
// value with a time-to-live. Neither returns an error: a cache is best-effort, so a backend failure is
// a miss (Get) or a no-op (Set), and the caller just runs the resolver.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration)
}

// Noop is the disabled cache: every lookup misses, every store is dropped. Used when no backend is
// configured, so a resolver with caching config simply always runs (correct, just not cached).
type Noop struct{}

func (Noop) Get(context.Context, string) ([]byte, bool)         { return nil, false }
func (Noop) Set(context.Context, string, []byte, time.Duration) {}

// Mem is a per-process in-memory cache with per-entry expiry — the single-node/dev backend. It is
// goroutine-safe. Expired entries are ignored on read and lazily overwritten; a background sweeper is
// unnecessary for the engine's scale (bounded by distinct cache keys, each short-lived).
type Mem struct {
	mu      sync.RWMutex
	entries map[string]memEntry
	now     func() time.Time // injectable for tests
}

type memEntry struct {
	value     []byte
	expiresAt time.Time
}

// NewMem builds an empty in-memory cache.
func NewMem() *Mem { return &Mem{entries: map[string]memEntry{}, now: time.Now} }

func (m *Mem) Get(_ context.Context, key string) ([]byte, bool) {
	m.mu.RLock()
	e, ok := m.entries[key]
	m.mu.RUnlock()
	if !ok || m.now().After(e.expiresAt) {
		return nil, false
	}
	return e.value, true
}

func (m *Mem) Set(_ context.Context, key string, value []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	m.mu.Lock()
	m.entries[key] = memEntry{value: value, expiresAt: m.now().Add(ttl)}
	m.mu.Unlock()
}

// Key derives a stable, collision-resistant cache key for a resolver invocation. It ALWAYS folds in the
// type/field and the caller identity (username + sorted groups), so a cached response can NEVER leak
// across identities even if the author forgot an identity caching key — safer by default than AppSync,
// where omitting $context.identity from cachingKeys silently shares one entry across all callers. The
// author's caching keys (resolved $context paths) add further specificity. The result is a hex SHA-256,
// safe for any KV key charset.
func Key(typeField, username string, groups []string, keyValues []any) string {
	sortedGroups := append([]string(nil), groups...)
	sort.Strings(sortedGroups)
	// A canonical, unambiguous encoding: JSON of a fixed-shape struct. Distinct inputs cannot collide
	// into the same bytes (arrays are length-delimited, fields are named).
	payload := struct {
		F string   `json:"f"`
		U string   `json:"u"`
		G []string `json:"g"`
		K []any    `json:"k"`
	}{F: typeField, U: username, G: sortedGroups, K: keyValues}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ResolveKeyPath reads a $context path (as used in caching keys) out of the resolver's context map.
// It accepts AppSync-style paths ("$context.arguments.id", "$ctx.args.id", "arguments.id") and maps the
// leading segment onto the engine's context shape (arguments→args, identity→identity, source→source),
// then walks nested maps. A path that doesn't resolve yields nil — a stable, present-but-empty key
// component, so a missing argument doesn't collapse distinct calls together (it's part of the hash).
func ResolveKeyPath(gctx map[string]any, path string) any {
	p := strings.TrimSpace(path)
	p = strings.TrimPrefix(p, "$context.")
	p = strings.TrimPrefix(p, "$ctx.")
	segs := strings.Split(p, ".")
	if len(segs) == 0 {
		return nil
	}
	switch segs[0] {
	case "arguments":
		segs[0] = "args"
	case "args", "identity", "source", "stash":
		// already the engine's key
	default:
		// Unknown root — not a resolvable context path; contributes as its literal name (stable).
		return path
	}
	var cur any = gctx
	for _, s := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[s]
	}
	return cur
}
