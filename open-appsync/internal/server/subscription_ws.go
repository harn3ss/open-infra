package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/metrics"
	"github.com/harn3ss/open-infra/open-appsync/internal/subscription"
)

// SubscriptionHandler serves GraphQL subscriptions over the `graphql-transport-ws` WebSocket protocol
// (the modern graphql-ws subprotocol Amplify/urql/Apollo speak). This is the "easy half" of the
// subscription rung — the transport — over the semantic core in internal/subscription. The caller's
// identity is taken from the same X-OpenInfra-* headers as the HTTP path (set upstream by the shim),
// and the subscribe-time auth gate + filter matching live in the Manager, not here.
//
// Per client subscription, arguments become an equality filter (AppSync's default: a subscription
// onX(owner:"ada") receives only events where owner == "ada").
func SubscriptionHandler(mgr *subscription.Manager) http.HandlerFunc {
	upgrader := websocket.Upgrader{
		Subprotocols:    []string{"graphql-transport-ws"},
		CheckOrigin:     func(*http.Request) bool { return true }, // origin is enforced at the ingress/mesh
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade already wrote the error
		}
		// Track the live-connection gauge for the length of the connection (serve blocks until close).
		metrics.IncSubscriptions()
		defer metrics.DecSubscriptions()
		c := &wsConn{conn: conn, mgr: mgr, ctx: authz.NewContext(r.Context(), identityFromHeaders(r)), subs: map[string]func(){}}
		c.serve()
	}
}

// wsConn is one WebSocket connection: it owns its subscriptions and serializes writes (deliveries
// arrive from the bus fanout goroutine, distinct from the read loop).
type wsConn struct {
	conn   *websocket.Conn
	mgr    *subscription.Manager
	ctx    context.Context
	writeM sync.Mutex
	mu     sync.Mutex
	subs   map[string]func() // subscription id → unsubscribe
	acked  bool
}

// wsMessage is the graphql-transport-ws envelope.
type wsMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func (c *wsConn) serve() {
	defer c.closeAll()
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		var msg wsMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			c.writeJSON(wsMessage{Type: "error", Payload: jsonRaw(`{"message":"invalid message"}`)})
			continue
		}
		switch msg.Type {
		case "connection_init":
			c.acked = true
			c.writeJSON(wsMessage{Type: "connection_ack"})
		case "ping":
			c.writeJSON(wsMessage{Type: "pong"})
		case "subscribe":
			c.onSubscribe(msg)
		case "complete":
			c.stop(msg.ID)
		}
	}
}

func (c *wsConn) onSubscribe(msg wsMessage) {
	if !c.acked {
		// graphql-transport-ws: a subscribe before connection_init is a protocol error (4401).
		_ = c.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(4401, "Unauthorized"), time.Now().Add(time.Second))
		return
	}
	var p struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		c.writeError(msg.ID, "invalid subscribe payload")
		return
	}
	field, args, err := graphql.ParseSubscription(p.Query, p.Variables)
	if err != nil {
		c.writeError(msg.ID, err.Error())
		return
	}
	filter := filterFromArgs(args)
	id := msg.ID
	deliver := func(payload any) {
		c.writeJSON(wsMessage{ID: id, Type: "next", Payload: jsonRaw(mustJSON(map[string]any{
			"data": map[string]any{field: payload},
		}))})
	}
	unsub, err := c.mgr.Subscribe(c.ctx, id, field, filter, deliver)
	if err != nil {
		c.writeError(id, err.Error()) // includes a subscribe-time authorization denial
		return
	}
	c.mu.Lock()
	c.subs[id] = unsub
	c.mu.Unlock()
}

// stop ends one subscription and tells the client it is complete.
func (c *wsConn) stop(id string) {
	c.mu.Lock()
	unsub := c.subs[id]
	delete(c.subs, id)
	c.mu.Unlock()
	if unsub != nil {
		unsub()
		c.writeJSON(wsMessage{ID: id, Type: "complete"})
	}
}

func (c *wsConn) closeAll() {
	c.mu.Lock()
	for _, unsub := range c.subs {
		unsub()
	}
	c.subs = map[string]func(){}
	c.mu.Unlock()
	_ = c.conn.Close()
}

func (c *wsConn) writeJSON(m wsMessage) {
	c.writeM.Lock()
	defer c.writeM.Unlock()
	_ = c.conn.WriteJSON(m)
}

func (c *wsConn) writeError(id, message string) {
	c.writeJSON(wsMessage{ID: id, Type: "error", Payload: jsonRaw(mustJSON([]any{map[string]any{"message": message}}))})
}

// filterFromArgs turns a subscription's arguments into an equality filter group — AppSync's default
// argument-based filtering (onX(owner:"ada") receives only events with owner == "ada").
func filterFromArgs(args map[string]any) subscription.FilterGroup {
	if len(args) == 0 {
		return subscription.FilterGroup{}
	}
	conds := make([]subscription.Condition, 0, len(args))
	for k, v := range args {
		conds = append(conds, subscription.Condition{Field: k, Operator: "eq", Value: v})
	}
	return subscription.FilterGroup{Filters: []subscription.Filter{{Conditions: conds}}}
}

func jsonRaw(s string) json.RawMessage { return json.RawMessage(s) }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}
