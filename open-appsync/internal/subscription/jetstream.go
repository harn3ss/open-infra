// JetStreamBus is the durable, multi-node Bus: subscription events ride a NATS JetStream stream (file
// storage), and each engine node fans them out to its own WebSocket subscribers via its own EPHEMERAL
// consumer (see Subscribe for why fan-out, not a shared durable). The events' durability lives in the
// stream, so a node kill loses only that node's in-flight fan-out and every acknowledged event remains
// on the stream for the survivors — which is what the node-kill chaos scenario asserts (via the
// stream's message count), and why that proof is temporal, not a unit test. It compiles into the engine
// binary (main selects it when NATS_URL is set; otherwise the in-memory bus). Its live test — which
// needs a running NATS — is build-tagged `integration` (jetstream_integration_test.go).
package subscription

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/nats-io/nats.go"
)

// JetStreamBus implements Bus over NATS JetStream.
type JetStreamBus struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	stream string
}

var _ Bus = (*JetStreamBus)(nil)

// NewJetStreamBus connects to NATS at url and ensures a stream covering subjectPrefix.* exists. The
// connection is configured to retry forever, so a dropped node reconnects and its durable consumers
// resume automatically.
func NewJetStreamBus(url, stream, subjectPrefix string) (*JetStreamBus, error) {
	nc, err := nats.Connect(url, nats.RetryOnFailedConnect(true), nats.MaxReconnects(-1))
	if err != nil {
		return nil, fmt.Errorf("subscription: connect NATS: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("subscription: jetstream context: %w", err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name:     stream,
		Subjects: []string{subjectPrefix + ".>"},
		Storage:  nats.FileStorage, // durable across restarts
	}); err != nil && err != nats.ErrStreamNameAlreadyInUse {
		nc.Close()
		return nil, fmt.Errorf("subscription: ensure stream: %w", err)
	}
	return &JetStreamBus{nc: nc, js: js, stream: stream}, nil
}

func (b *JetStreamBus) Publish(_ context.Context, subject string, event map[string]any) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = b.js.Publish(subject, data)
	return err
}

// Subscribe fans a subject's events out to THIS node with its own EPHEMERAL consumer. Subscriptions
// need fan-out, not load-balancing: every engine replica must see every event so it can match it
// against ITS OWN connected WebSocket subscribers — so each replica gets an independent consumer
// (a shared *durable* push consumer is single-active and a second replica binding it errors with
// "consumer is already bound"). Durability of the events themselves lives in the STREAM (file
// storage): a node kill loses only that node's in-flight fan-out, and the events remain on the stream
// for the survivors and any restarted node. (Per-connection gapless replay across a reconnect is a
// separate, future rung; graphql-ws clients resubscribe on reconnect.)
func (b *JetStreamBus) Subscribe(_ context.Context, subject string, handler func(map[string]any)) (io.Closer, error) {
	sub, err := b.js.Subscribe(subject, func(msg *nats.Msg) {
		var event map[string]any
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			return
		}
		handler(event)
	}, nats.DeliverNew(), nats.AckNone())
	if err != nil {
		return nil, fmt.Errorf("subscription: subscribe %q: %w", subject, err)
	}
	return jetstreamCloser{sub: sub}, nil
}

// Close drains the connection (best-effort) — used at engine shutdown.
func (b *JetStreamBus) Close() { b.nc.Drain() }

type jetstreamCloser struct{ sub *nats.Subscription }

func (c jetstreamCloser) Close() error { return c.sub.Unsubscribe() }
