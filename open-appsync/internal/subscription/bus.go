package subscription

import (
	"context"
	"io"
	"sync"
)

// Bus is the push-source port (the the call-vs-stream split distinction: NOT a datasource.Store). A mutation Publishes an
// event to a subject; every engine node Subscribes to the subject and fans the event out to its local
// registry. The durable, multi-node implementation is JetStream (jetstream.go, build-tagged), where a
// subscriber is a durable consumer and reconnect/resume is replay from the last acked sequence — which
// is what the node-kill chaos bar exercises. MemBus (below) is the single-node/in-memory implementation
// used by tests and a single-replica engine.
type Bus interface {
	// Publish delivers an event to all current subscribers of subject.
	Publish(ctx context.Context, subject string, event map[string]any) error
	// Subscribe registers handler for subject; the returned Closer stops delivery.
	Subscribe(ctx context.Context, subject string, handler func(event map[string]any)) (io.Closer, error)
}

// MemBus is an in-process Bus: fine for a single engine replica and for tests. It is NOT durable and
// does NOT survive a node kill — that is exactly why the durable path is JetStream.
type MemBus struct {
	mu   sync.RWMutex
	subs map[string][]*memSub
}

type memSub struct {
	bus     *MemBus
	subject string
	handler func(map[string]any)
}

func NewMemBus() *MemBus { return &MemBus{subs: map[string][]*memSub{}} }

func (b *MemBus) Publish(_ context.Context, subject string, event map[string]any) error {
	b.mu.RLock()
	handlers := append([]*memSub(nil), b.subs[subject]...)
	b.mu.RUnlock()
	for _, s := range handlers {
		s.handler(event)
	}
	return nil
}

func (b *MemBus) Subscribe(_ context.Context, subject string, handler func(map[string]any)) (io.Closer, error) {
	s := &memSub{bus: b, subject: subject, handler: handler}
	b.mu.Lock()
	b.subs[subject] = append(b.subs[subject], s)
	b.mu.Unlock()
	return s, nil
}

func (s *memSub) Close() error {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	cur := s.bus.subs[s.subject]
	for i, x := range cur {
		if x == s {
			s.bus.subs[s.subject] = append(cur[:i], cur[i+1:]...)
			break
		}
	}
	return nil
}
