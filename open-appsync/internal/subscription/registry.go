package subscription

import (
	"sync"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Subscriber is one open subscription on one node — the connection-scoped state the handoff flagged as
// "the one new piece of state" subscriptions introduce. It holds the client's filter, the response
// step that shapes each pushed event, the caller's identity, and how to deliver a payload (a channel
// send / WebSocket write, injected by the transport).
type Subscriber struct {
	ID       string
	Field    string
	Filter   FilterGroup
	Response runtime.Runtime // shapes the pushed event (RenderResponse with $ctx.result = event)
	Identity authz.Identity
	Deliver  func(payload any)
}

// Registry is the per-node set of open subscribers, keyed by id. Fanout is deliberately naive
// (O(subscribers-on-field)) — honest and correct at the scale this rung targets; a filter index is
// explicitly deferred until a load/chaos scenario proves it is the bottleneck (no premature index).
type Registry struct {
	mu   sync.RWMutex
	subs map[string]*Subscriber
}

func NewRegistry() *Registry { return &Registry{subs: map[string]*Subscriber{}} }

func (r *Registry) Register(s *Subscriber) {
	r.mu.Lock()
	r.subs[s.ID] = s
	r.mu.Unlock()
}

func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	delete(r.subs, id)
	r.mu.Unlock()
}

// Count is the number of open subscribers (for metrics / tests).
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.subs)
}

// Fanout delivers an event to every subscriber on the field whose filter matches: it renders the
// subscriber's response step against $ctx.result = event and calls Deliver with the shaped payload. A
// response-render error drops that one delivery (logged by the caller); it never blocks the others.
func (r *Registry) Fanout(field string, event map[string]any) []error {
	r.mu.RLock()
	targets := make([]*Subscriber, 0)
	for _, s := range r.subs {
		if s.Field == field && s.Filter.Match(event) {
			targets = append(targets, s)
		}
	}
	r.mu.RUnlock()

	var errs []error
	for _, s := range targets {
		ctx := map[string]any{
			"result":   event,
			"identity": identityMap(s.Identity),
		}
		payload, err := s.Response.RenderResponse(ctx)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.Deliver(payload)
	}
	return errs
}

func identityMap(id authz.Identity) map[string]any {
	groups := make([]any, len(id.Groups))
	for i, g := range id.Groups {
		groups[i] = g
	}
	return map[string]any{"username": id.Username, "groups": groups}
}
