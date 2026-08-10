//go:build integration

package cache

import (
	"context"
	"os"
	"testing"
	"time"
)

// A live NATS JetStream KV round-trip: Set → Get hits, an expired entry misses, and a distinct key
// misses. Needs a running NATS/JetStream at NATS_TEST_URL (e.g. nats://localhost:4222). Run:
// go test -tags integration ./internal/cache/. This proves the shared backend's wiring end-to-end
// against real JetStream; the multi-replica "one replica's write is another's hit" property follows
// from it being the same bucket, and is what the chaos/streak work will exercise on-cluster.
func TestJetStream_RoundTrip(t *testing.T) {
	uri := os.Getenv("NATS_TEST_URL")
	if uri == "" {
		t.Skip("set NATS_TEST_URL to run the JetStream cache integration test")
	}
	// A unique bucket per run so repeated runs don't see stale entries.
	c, err := NewJetStream(uri, "open_appsync_cache_it_"+time.Now().Format("150405"))
	if err != nil {
		t.Fatalf("connect/open bucket: %v", err)
	}
	defer c.Close()
	ctx := context.Background()

	if _, ok := c.Get(ctx, "missing"); ok {
		t.Fatal("a missing key must miss")
	}
	c.Set(ctx, "k", []byte(`{"id":"1"}`), time.Minute)
	v, ok := c.Get(ctx, "k")
	if !ok || string(v) != `{"id":"1"}` {
		t.Fatalf("live entry must hit with its exact value; got %q ok=%v", v, ok)
	}
	// An entry written with a negative/zero TTL is not stored.
	c.Set(ctx, "z", []byte(`1`), 0)
	if _, ok := c.Get(ctx, "z"); ok {
		t.Fatal("a zero-TTL Set must store nothing")
	}
	// App-level expiry: a very short TTL is a miss after it elapses.
	c.Set(ctx, "short", []byte(`1`), 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get(ctx, "short"); ok {
		t.Fatal("an expired entry must miss (app-level TTL)")
	}
}
