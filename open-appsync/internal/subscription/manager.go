// The subscription Manager is the setup-then-push LIFECYCLE (contrast the unit/pipeline lifecycles in
// internal/resolver, which are call-then-return). It ties together the registry (connection state), the
// bus (push source), authorization, and the response step. It deliberately reuses the SAME primitives
// as the other lifecycles — runtime.Runtime for the response step, authz for the gate — so subscriptions
// are an EXTENSION of open-appsync, not a fork.
package subscription

import (
	"context"
	"fmt"
	"io"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Field is a registered subscription field: which subject its events ride, its response step, and its
// authorization requirement (checked at subscribe time — the setup step). The response step is a
// runtime.Runtime (only its response phase is used — the push source calls the subscriber, so there is
// no request phase / data-source call), which keeps subscriptions on the same step abstraction as
// every other lifecycle.
type Field struct {
	Name     string
	Subject  string
	Response runtime.Runtime
	Auth     authz.Requirement
}

// Manager owns a node's subscriptions: the registry (local connection state), the bus (cross-node push
// source), the authorizer (subscribe-time gate), and the field catalog.
type Manager struct {
	registry   *Registry
	bus        Bus
	authorizer authz.Authorizer
	fields     map[string]Field
	closers    map[string]io.Closer // one bus subscription per subject
}

// NewManager builds a subscription manager. authorizer may be authz.AllowAll for no enforcement.
func NewManager(bus Bus, authorizer authz.Authorizer, fields []Field) *Manager {
	if authorizer == nil {
		authorizer = authz.AllowAll{}
	}
	m := &Manager{
		registry:   NewRegistry(),
		bus:        bus,
		authorizer: authorizer,
		fields:     map[string]Field{},
		closers:    map[string]io.Closer{},
	}
	for _, f := range fields {
		m.fields[f.Name] = f
	}
	return m
}

// Start wires each field's subject on the bus so published events fan out to local subscribers. Call
// once at boot; Stop tears the bus subscriptions down.
func (m *Manager) Start(ctx context.Context) error {
	for _, f := range m.fields {
		field := f // capture
		if _, done := m.closers[field.Subject]; done {
			continue // one bus subscription per subject
		}
		closer, err := m.bus.Subscribe(ctx, field.Subject, func(event map[string]any) {
			m.registry.Fanout(field.Name, event)
		})
		if err != nil {
			return fmt.Errorf("subscription: subscribe to %q: %w", field.Subject, err)
		}
		m.closers[field.Subject] = closer
	}
	return nil
}

// Stop closes the bus subscriptions.
func (m *Manager) Stop() {
	for _, c := range m.closers {
		_ = c.Close()
	}
	m.closers = map[string]io.Closer{}
}

// Subscribe is the SETUP step: authorize the caller for the field (the subscribe-time gate), then
// register the subscriber with its filter and delivery function. It returns the subscription id and an
// unsubscribe func. A denied caller never registers (prove the "no").
func (m *Manager) Subscribe(ctx context.Context, id string, fieldName string, filter FilterGroup, deliver func(any)) (func(), error) {
	f, ok := m.fields[fieldName]
	if !ok {
		return nil, fmt.Errorf("subscription: no subscription field %q", fieldName)
	}
	identity := authz.FromContext(ctx)
	if !f.Auth.IsZero() {
		if err := m.authorizer.Authorize(ctx, identity, f.Auth); err != nil {
			return nil, err // denied at subscribe time; nothing registered
		}
	}
	m.registry.Register(&Subscriber{
		ID:       id,
		Field:    fieldName,
		Filter:   filter,
		Response: f.Response,
		Identity: identity,
		Deliver:  deliver,
	})
	return func() { m.registry.Unregister(id) }, nil
}

// Publish is invoked when a mutation linked to a subscription field succeeds: it puts the mutation's
// result onto the field's subject, from where every node fans it out to matching local subscribers.
func (m *Manager) Publish(ctx context.Context, fieldName string, event map[string]any) error {
	f, ok := m.fields[fieldName]
	if !ok {
		return fmt.Errorf("subscription: no subscription field %q", fieldName)
	}
	return m.bus.Publish(ctx, f.Subject, event)
}

// Active is the number of open subscribers on this node (metrics/tests).
func (m *Manager) Active() int { return m.registry.Count() }
