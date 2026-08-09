package eventbridgesource

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go"
)

// natsPublisher publishes events to NATS — open-infra's event bus (the same backbone subscriptions ride).
// It uses core NATS publish, which is fire-and-forget, matching EventBridge's PutEvents semantics. The
// connection retries so a briefly-unavailable NATS at startup doesn't fail engine load.
type natsPublisher struct{ nc *nats.Conn }

// NewNATSPublisher connects to NATS at url (retrying) and returns a Publisher over it.
func NewNATSPublisher(url string) (*natsPublisher, error) {
	nc, err := nats.Connect(url, nats.RetryOnFailedConnect(true), nats.MaxReconnects(-1))
	if err != nil {
		return nil, fmt.Errorf("eventbridgesource: connect NATS: %w", err)
	}
	return &natsPublisher{nc: nc}, nil
}

func (p *natsPublisher) Publish(_ context.Context, subject string, data []byte) error {
	return p.nc.Publish(subject, data)
}

// Close drains the connection (best-effort) at engine shutdown.
func (p *natsPublisher) Close() { _ = p.nc.Drain() }
