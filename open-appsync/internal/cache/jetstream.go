package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nats-io/nats.go"
)

// JetStream is the SHARED cache backend: a NATS JetStream KV bucket every engine replica reads and
// writes, so a value set on one replica is a hit on another — the multi-replica analog of AppSync's
// external cache, and the graduation of the in-memory Mem backend (one bucket per API, so distinct APIs
// sharing the platform NATS can't collide). Like Mem it is BEST-EFFORT: any NATS error is a miss (Get)
// or a dropped write (Set), so the engine falls back to running the resolver and correctness never
// depends on the cache or on NATS being up.
//
// Per-resolver TTLs are enforced at the application layer (each value carries its own expiry), because a
// KV bucket has a single bucket-wide max-age; the bucket max-age is a storage backstop that GCs entries
// the app-level check would already treat as expired. So effective TTL = min(resolver TTL, bucketMaxAge).
type JetStream struct {
	nc  *nats.Conn
	kv  nats.KeyValue
	now func() time.Time
}

var _ Cache = (*JetStream)(nil)

// bucketMaxAge caps how long any entry survives in the bucket (storage GC). Resolver TTLs above this are
// effectively capped here; it is generous relative to any sensible response-cache TTL.
const bucketMaxAge = 24 * time.Hour

// NewJetStream connects to NATS and opens (creating if absent) the per-API KV bucket. A connection or
// bucket failure is returned so the caller can fall back to the in-memory backend rather than disabling
// caching. bucket must match NATS's KV name charset ([A-Za-z0-9_-]); the composition derives it from the
// API name.
func NewJetStream(url, bucket string) (*JetStream, error) {
	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true), nats.MaxReconnects(-1), nats.Timeout(2*time.Second))
	if err != nil {
		return nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, err
	}
	kv, err := js.KeyValue(bucket)
	if err != nil {
		kv, err = js.CreateKeyValue(&nats.KeyValueConfig{Bucket: bucket, TTL: bucketMaxAge, History: 1})
		if err != nil {
			// Another replica may have created the bucket between our Get and Create (multi-replica
			// startup) — CreateKeyValue then fails "already in use". Try to open it once more before
			// giving up, so a lost creation race doesn't strand this replica on the fallback cache.
			if kv2, err2 := js.KeyValue(bucket); err2 == nil {
				kv = kv2
			} else {
				nc.Close()
				return nil, err
			}
		}
	}
	return &JetStream{nc: nc, kv: kv, now: time.Now}, nil
}

// envelope wraps a cached value with its app-level expiry (Unix nanoseconds).
type envelope struct {
	E int64           `json:"e"`
	V json.RawMessage `json:"v"`
}

func (c *JetStream) Get(_ context.Context, key string) ([]byte, bool) {
	entry, err := c.kv.Get(key)
	if err != nil {
		return nil, false // not found / any backend error → miss
	}
	var env envelope
	if err := json.Unmarshal(entry.Value(), &env); err != nil {
		return nil, false
	}
	if c.now().UnixNano() > env.E {
		return nil, false // app-level expiry (the bucket max-age is only a storage backstop)
	}
	return env.V, true
}

func (c *JetStream) Set(_ context.Context, key string, value []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	env := envelope{E: c.now().Add(ttl).UnixNano(), V: json.RawMessage(value)}
	b, err := json.Marshal(env)
	if err != nil {
		return
	}
	_, _ = c.kv.Put(key, b) // best-effort: a failed write is just a future miss
}

// Close drains the NATS connection.
func (c *JetStream) Close() { _ = c.nc.Drain() }
