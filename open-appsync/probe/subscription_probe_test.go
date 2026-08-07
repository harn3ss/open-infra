package probe

import (
	"context"
	"sync"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/subscription"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// The subscription lifecycle probe: the setup-then-push flow proven end-to-end with
// the in-memory bus. A mutation event is Published; only subscribers whose enhanced filter matches
// receive it, shaped by their response step. Also proves unsubscribe and the subscribe-time auth gate.
// (The DURABLE path is JetStream; the graduation bar is a node-kill chaos run — held, not claimed.)

type collector struct {
	mu  sync.Mutex
	got []any
}

func (c *collector) deliver(p any) { c.mu.Lock(); c.got = append(c.got, p); c.mu.Unlock() }
func (c *collector) count() int    { c.mu.Lock(); defer c.mu.Unlock(); return len(c.got) }

func todoField(auth authz.Requirement) subscription.Field {
	return subscription.Field{
		Name:     "onCreateTodo",
		Subject:  "todos.created",
		Response: vtlruntime.New(engine(), "", `$util.toJson($ctx.result)`),
		Auth:     auth,
	}
}

func TestSubscriptionProbe_FilteredFanout(t *testing.T) {
	m := subscription.NewManager(subscription.NewMemBus(), authz.AllowAll{}, []subscription.Field{todoField(authz.Requirement{})})
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	ada := &collector{}
	bob := &collector{}
	// ada subscribes filtered to owner == "ada"; bob to owner == "bob".
	filter := func(owner string) subscription.FilterGroup {
		return subscription.FilterGroup{Filters: []subscription.Filter{{Conditions: []subscription.Condition{{Field: "owner", Operator: "eq", Value: owner}}}}}
	}
	if _, err := m.Subscribe(context.Background(), "sub-ada", "onCreateTodo", filter("ada"), ada.deliver); err != nil {
		t.Fatal(err)
	}
	unsubBob, err := m.Subscribe(context.Background(), "sub-bob", "onCreateTodo", filter("bob"), bob.deliver)
	if err != nil {
		t.Fatal(err)
	}
	if m.Active() != 2 {
		t.Fatalf("expected 2 active subscribers, got %d", m.Active())
	}

	// A mutation creates a todo owned by ada → only ada is delivered to, shaped by the response step.
	event := map[string]any{"id": "1", "owner": "ada", "name": "write docs"}
	if err := m.Publish(context.Background(), "onCreateTodo", event); err != nil {
		t.Fatal(err)
	}
	if ada.count() != 1 || bob.count() != 0 {
		t.Fatalf("filtered fanout wrong: ada=%d bob=%d", ada.count(), bob.count())
	}
	if got := ada.got[0].(map[string]any); got["owner"] != "ada" || got["name"] != "write docs" {
		t.Fatalf("response step did not shape the pushed event: %v", got)
	}

	// Unsubscribe bob, publish a bob event → nobody home for bob; ada unaffected.
	unsubBob()
	if m.Active() != 1 {
		t.Fatalf("unsubscribe did not remove the subscriber, active=%d", m.Active())
	}
	_ = m.Publish(context.Background(), "onCreateTodo", map[string]any{"id": "2", "owner": "bob"})
	if bob.count() != 0 {
		t.Fatalf("an unsubscribed client must receive nothing, got %d", bob.count())
	}
}

// The subscribe-time gate: a field requiring authorization denies a caller the boundary rejects, and
// NOTHING is registered (prove the "no").
func TestSubscriptionProbe_SubscribeAuthDenies(t *testing.T) {
	m := subscription.NewManager(subscription.NewMemBus(), denyAll{}, []subscription.Field{
		todoField(authz.Requirement{Group: "openinfra.dev", Resource: "graphqlapis", Verb: "get"}),
	})
	_ = m.Start(context.Background())
	defer m.Stop()

	_, err := m.Subscribe(context.Background(), "sub-x", "onCreateTodo", subscription.FilterGroup{}, func(any) {})
	if err == nil {
		t.Fatal("a denied caller must not be able to subscribe")
	}
	if m.Active() != 0 {
		t.Fatalf("a denied subscribe must register nothing, active=%d", m.Active())
	}
}

type denyAll struct{}

func (denyAll) Authorize(context.Context, authz.Identity, authz.Requirement) error {
	return authz.ErrDenied
}
