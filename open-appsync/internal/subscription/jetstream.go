//go:build integration

// JetStreamBus is the DURABLE, multi-node Bus (forward-map §3): subscription events ride a NATS
// JetStream stream, and each engine node consumes them with a DURABLE consumer, so a node kill →
// reconnect resumes from the last acked sequence with no lost and no duplicated events past that point.
// That reconnect/resume behaviour is exactly what the node-kill chaos scenario (the rung's graduation
// bar) exercises — which is why it is temporal and cannot be a unit test. Build-tagged `integration`:
// it needs a live NATS/JetStream, so it is out of the default unit build (mirrors the FerretDB store).
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

// Subscribe creates a DURABLE consumer for subject; on reconnect the durable resumes from the last
// acked message, so events are neither lost nor (past the ack point) duplicated. Manual ack after the
// handler runs makes delivery at-least-once up to the handler.
func (b *JetStreamBus) Subscribe(_ context.Context, subject string, handler func(map[string]any)) (io.Closer, error) {
	durable := "openappsync-" + sanitize(subject)
	sub, err := b.js.Subscribe(subject, func(msg *nats.Msg) {
		var event map[string]any
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			_ = msg.Nak()
			return
		}
		handler(event)
		_ = msg.Ack()
	}, nats.Durable(durable), nats.ManualAck(), nats.DeliverAll())
	if err != nil {
		return nil, fmt.Errorf("subscription: durable subscribe %q: %w", subject, err)
	}
	return jetstreamCloser{sub: sub}, nil
}

// Close drains the connection (best-effort) — used at engine shutdown.
func (b *JetStreamBus) Close() { b.nc.Drain() }

type jetstreamCloser struct{ sub *nats.Subscription }

func (c jetstreamCloser) Close() error { return c.sub.Unsubscribe() }

func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '.' || r == '*' || r == '>' {
			out = append(out, '_')
		} else {
			out = append(out, r)
		}
	}
	return string(out)
}
