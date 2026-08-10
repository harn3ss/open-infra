//go:build integration

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// A live async round-trip: publish an Event invocation → the durable JetStream worker POSTs it to the
// function. Needs a running NATS/JetStream at NATS_TEST_URL. Run: go test -tags integration ./cmd/aws-shim/.
// The function URL builder is overridden to point at a local httptest server (on a cluster it resolves
// name.fnNS.svcSuffix via DNS instead).
func TestAsyncInvoker_RoundTrip(t *testing.T) {
	uri := os.Getenv("NATS_TEST_URL")
	if uri == "" {
		t.Skip("set NATS_TEST_URL to run the async-invoke integration test")
	}
	got := make(chan string, 1)
	fn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case got <- string(b):
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer fn.Close()

	ai, err := newAsyncInvoker(uri, "default", "svc.cluster.local", 3, discardLogger())
	if err != nil {
		t.Fatalf("newAsyncInvoker: %v", err)
	}
	defer ai.Close()
	ai.urlFor = func(string) string { return fn.URL + "/" } // deliver to the local fake function

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ai.run(ctx)

	if err := ai.publish("orders", "application/json", []byte(`{"hello":"async"}`), "r-int"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case body := <-got:
		if !strings.Contains(body, "async") {
			t.Errorf("function received %q, want the published payload", body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("async invocation was not delivered to the function within 10s")
	}
}
