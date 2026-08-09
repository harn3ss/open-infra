package eventbridgesource

import (
	"context"
	"errors"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

type fakePublisher struct {
	published []struct {
		subject string
		data    []byte
	}
	failOn string // subject substring to fail
}

func (f *fakePublisher) Publish(_ context.Context, subject string, data []byte) error {
	if f.failOn != "" && subject == f.failOn {
		return errors.New("publish failed")
	}
	f.published = append(f.published, struct {
		subject string
		data    []byte
	}{subject, data})
	return nil
}

func newStore(pub Publisher) *Store {
	return New(pub, WithIDFunc(func() string { return "evt-id" }))
}

// PutEvents publishes each event to a subject derived from bus/source/detail-type, and returns a
// PutEvents-shaped receipt with an EventId per entry.
func TestEventBridge_PutEvents(t *testing.T) {
	pub := &fakePublisher{}
	s := newStore(pub)
	res, err := s.Execute(context.Background(), runtime.Operation{
		"operation": "PutEvents",
		"events": []any{
			map[string]any{"source": "com.acme.orders", "detailType": "OrderPlaced", "eventBusName": "orders", "detail": map[string]any{"id": "1"}},
			map[string]any{"source": "com.acme.users", "detail-type": "UserSignedUp", "detail": map[string]any{"u": "ada"}},
		},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Subjects: prefix.bus.source.detailType (default bus when omitted; dots in source become _).
	wantSubjects := []string{"events.orders.com_acme_orders.OrderPlaced", "events.default.com_acme_users.UserSignedUp"}
	if len(pub.published) != 2 || pub.published[0].subject != wantSubjects[0] || pub.published[1].subject != wantSubjects[1] {
		t.Fatalf("published subjects = %v, want %v", subjectsOf(pub), wantSubjects)
	}
	m := res.(map[string]any)
	if m["FailedEntryCount"] != 0 {
		t.Errorf("FailedEntryCount = %v, want 0", m["FailedEntryCount"])
	}
	entries := m["Entries"].([]any)
	if len(entries) != 2 || entries[0].(map[string]any)["EventId"] != "evt-id" {
		t.Errorf("entries = %v", entries)
	}
}

// A per-event publish failure is reported in that entry and counted — the whole call still succeeds
// (EventBridge partial-failure semantics).
func TestEventBridge_PartialFailure(t *testing.T) {
	pub := &fakePublisher{failOn: "events.default.com_acme_a._"}
	// note: detailType empty → subject has no detailType token; build the fail subject accordingly.
	pub.failOn = "events.default.a"
	s := newStore(pub)
	res, err := s.Execute(context.Background(), runtime.Operation{
		"events": []any{
			map[string]any{"source": "a"},
			map[string]any{"source": "b"},
		},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	m := res.(map[string]any)
	if m["FailedEntryCount"] != 1 {
		t.Errorf("FailedEntryCount = %v, want 1", m["FailedEntryCount"])
	}
	entries := m["Entries"].([]any)
	if entries[0].(map[string]any)["ErrorCode"] != "InternalException" {
		t.Errorf("failed entry = %v, want ErrorCode", entries[0])
	}
	if entries[1].(map[string]any)["EventId"] != "evt-id" {
		t.Errorf("second entry should succeed: %v", entries[1])
	}
}

// A non-PutEvents operation is rejected (only PutEvents is supported).
func TestEventBridge_UnsupportedOperation(t *testing.T) {
	if _, err := newStore(&fakePublisher{}).Execute(context.Background(), runtime.Operation{"operation": "Query", "events": []any{}}); err == nil {
		t.Error("a non-PutEvents operation must be rejected")
	}
}

func subjectsOf(f *fakePublisher) []string {
	out := make([]string, len(f.published))
	for i, p := range f.published {
		out[i] = p.subject
	}
	return out
}
