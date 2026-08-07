package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/subscription"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// End-to-end WebSocket subscription over the real graphql-transport-ws protocol with a real gorilla
// client: connection_init/ack, subscribe with an argument filter, a matching publish delivers a `next`,
// a non-matching publish delivers nothing, and complete ends it. This proves the transport (the "easy
// half") over the semantic core; the node-kill chaos bar (the temporal proof) remains external.
func TestSubscriptionWS_EndToEnd(t *testing.T) {
	mgr := subscription.NewManager(subscription.NewMemBus(), authz.AllowAll{}, []subscription.Field{{
		Name:     "onCreateTodo",
		Subject:  "sub.onCreateTodo",
		Response: vtlruntime.New(vtl.New(), "", `$util.toJson($ctx.result)`),
	}})
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	ts := httptest.NewServer(SubscriptionHandler(mgr))
	defer ts.Close()

	d := websocket.Dialer{Subprotocols: []string{"graphql-transport-ws"}}
	conn, _, err := d.Dial("ws"+strings.TrimPrefix(ts.URL, "http"), http.Header{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	send := func(m map[string]any) {
		if err := conn.WriteJSON(m); err != nil {
			t.Fatal(err)
		}
	}
	read := func() map[string]any {
		var m map[string]any
		if err := conn.ReadJSON(&m); err != nil {
			t.Fatalf("read: %v", err)
		}
		return m
	}

	// connection_init → connection_ack.
	send(map[string]any{"type": "connection_init"})
	if ack := read(); ack["type"] != "connection_ack" {
		t.Fatalf("expected connection_ack, got %v", ack)
	}

	// Subscribe, filtered by argument owner == "ada".
	send(map[string]any{"type": "subscribe", "id": "1", "payload": map[string]any{
		"query": `subscription { onCreateTodo(owner: "ada") { id owner } }`,
	}})
	// Wait for the server to register the subscriber before publishing.
	for i := 0; i < 100 && mgr.Active() == 0; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if mgr.Active() != 1 {
		t.Fatalf("subscription not registered (active=%d)", mgr.Active())
	}

	// A matching mutation event → a `next` carrying data.onCreateTodo.
	_ = mgr.Publish(context.Background(), "onCreateTodo", map[string]any{"id": "1", "owner": "ada"})
	msg := read()
	if msg["type"] != "next" || msg["id"] != "1" {
		t.Fatalf("expected next for id 1, got %v", msg)
	}
	data := msg["payload"].(map[string]any)["data"].(map[string]any)["onCreateTodo"].(map[string]any)
	if data["owner"] != "ada" {
		t.Fatalf("delivered payload not shaped by the response step: %v", data)
	}

	// A NON-matching event (owner: bob) must deliver nothing — the argument filter excludes it.
	_ = mgr.Publish(context.Background(), "onCreateTodo", map[string]any{"id": "2", "owner": "bob"})
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("a non-matching event must not be delivered")
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Complete ends the subscription server-side.
	send(map[string]any{"type": "complete", "id": "1"})
	for i := 0; i < 100 && mgr.Active() == 1; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if mgr.Active() != 0 {
		t.Fatalf("complete did not unregister the subscription (active=%d)", mgr.Active())
	}
}

// A subscribe before connection_init is rejected (protocol 4401) and registers nothing.
func TestSubscriptionWS_RequiresInit(t *testing.T) {
	mgr := subscription.NewManager(subscription.NewMemBus(), authz.AllowAll{}, []subscription.Field{{
		Name: "onCreateTodo", Subject: "sub.onCreateTodo",
		Response: vtlruntime.New(vtl.New(), "", `$util.toJson($ctx.result)`),
	}})
	_ = mgr.Start(context.Background())
	defer mgr.Stop()
	ts := httptest.NewServer(SubscriptionHandler(mgr))
	defer ts.Close()

	d := websocket.Dialer{Subprotocols: []string{"graphql-transport-ws"}}
	conn, _, err := d.Dial("ws"+strings.TrimPrefix(ts.URL, "http"), http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.WriteJSON(map[string]any{"type": "subscribe", "id": "1", "payload": map[string]any{
		"query": `subscription { onCreateTodo { id } }`}})
	// The server closes the connection; a read returns an error and nothing was registered.
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("subscribe before connection_init must be rejected")
	}
	if mgr.Active() != 0 {
		t.Fatalf("nothing must be registered before init, active=%d", mgr.Active())
	}
}
