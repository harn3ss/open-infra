//go:build integration

package subscription

import (
	"context"
	"os"
	"testing"
	"time"
)

// A live JetStream round-trip: publish → durable subscribe delivers. Needs a running NATS/JetStream at
// NATS_TEST_URL (e.g. nats://localhost:4222). Run: go test -tags integration ./internal/subscription/.
// The node-kill reconnect/resume proof is the CHAOS scenario (chaos/scenarios/08-*), not a unit test —
// this only proves the bus wiring end-to-end against real JetStream.
func TestJetStreamBus_RoundTrip(t *testing.T) {
	uri := os.Getenv("NATS_TEST_URL")
	if uri == "" {
		t.Skip("set NATS_TEST_URL to run the JetStream integration test")
	}
	bus, err := NewJetStreamBus(uri, "open_appsync_test", "subtest")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer bus.Close()

	got := make(chan map[string]any, 1)
	closer, err := bus.Subscribe(context.Background(), "subtest.onCreate", func(e map[string]any) { got <- e })
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer closer.Close()

	if err := bus.Publish(context.Background(), "subtest.onCreate", map[string]any{"id": "1", "owner": "ada"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case e := <-got:
		if e["owner"] != "ada" {
			t.Fatalf("event not delivered faithfully: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("durable subscriber did not receive the published event")
	}
}
