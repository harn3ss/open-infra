// Package eventbridgesource is the "EventBridge" data source. It is the one source that stretches the
// neutral datasource.Store contract: every other source is call-and-return (send an operation, get data
// back), but EventBridge is a PUBLISH — fire-and-forget an event to a bus. It still fits Store.Execute
// mechanically (the "result" is the PutEvents receipt, not queried data), which is the seam asymmetry to
// keep in mind.
//
// It mirrors AppSync's EventBridge data source — the request mapping emits
//
//	{"version":"2018-05-29","operation":"PutEvents","events":[
//	  {"source":"com.acme.orders","detailType":"OrderPlaced","detail":{…},"eventBusName":"orders"}]}
//
// and the result is a PutEvents-shaped receipt: {"Entries":[{"EventId":"…"}],"FailedEntryCount":0}. In
// open-infra the event bus is NATS: each event is published to a subject derived from the bus, source,
// and detail-type, so NATS subscribers can filter with subject wildcards the way EventBridge rules match.
package eventbridgesource

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Publisher publishes one event's bytes to a subject (fire-and-forget). NATS backs it in production; a
// fake backs it in tests.
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// Store publishes events to the bus.
type Store struct {
	pub        Publisher
	prefix     string // subject prefix (default "events")
	defaultBus string // eventBusName when an event omits one (default "default")
	newID      func() string
}

var _ datasource.Store = (*Store)(nil)

// Option configures a Store.
type Option func(*Store)

// WithSubjectPrefix overrides the subject prefix (default "events").
func WithSubjectPrefix(p string) Option { return func(s *Store) { s.prefix = p } }

// WithDefaultBus overrides the default eventBusName (default "default").
func WithDefaultBus(b string) Option { return func(s *Store) { s.defaultBus = b } }

// WithIDFunc overrides the event-id generator (tests inject a deterministic one).
func WithIDFunc(f func() string) Option { return func(s *Store) { s.newID = f } }

// New builds an EventBridge source over a Publisher.
func New(pub Publisher, opts ...Option) *Store {
	s := &Store{pub: pub, prefix: "events", defaultBus: "default", newID: randomID}
	for _, o := range opts {
		o(s)
	}
	return s
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Execute publishes each event and returns a PutEvents-shaped receipt. A per-event publish failure is
// reported in that entry (ErrorCode/ErrorMessage) and counted, mirroring EventBridge's partial-failure
// semantics — the whole call does not fail because one entry did.
func (s *Store) Execute(ctx context.Context, op runtime.Operation) (any, error) {
	if operation, ok := op["operation"].(string); ok && operation != "" && operation != "PutEvents" {
		return nil, fmt.Errorf("eventbridgesource: unsupported operation %q (only PutEvents)", operation)
	}
	events, err := toSlice(op["events"])
	if err != nil {
		return nil, fmt.Errorf("eventbridgesource: %w", err)
	}

	entries := make([]any, 0, len(events))
	failed := 0
	for _, e := range events {
		event, ok := e.(map[string]any)
		if !ok {
			failed++
			entries = append(entries, map[string]any{"ErrorCode": "MalformedEntry", "ErrorMessage": "event is not an object"})
			continue
		}
		subject := s.subjectFor(event)
		data, merr := json.Marshal(event)
		if merr != nil {
			failed++
			entries = append(entries, map[string]any{"ErrorCode": "MalformedEntry", "ErrorMessage": merr.Error()})
			continue
		}
		if perr := s.pub.Publish(ctx, subject, data); perr != nil {
			failed++
			entries = append(entries, map[string]any{"ErrorCode": "InternalException", "ErrorMessage": perr.Error()})
			continue
		}
		entries = append(entries, map[string]any{"EventId": s.newID()})
	}
	return map[string]any{"Entries": entries, "FailedEntryCount": failed}, nil
}

// subjectFor builds a NATS subject from the bus + source + detail-type (AppSync accepts detailType or
// detail-type). Empty parts are dropped; each token is sanitized (NATS reserves space, ., *, >).
func (s *Store) subjectFor(event map[string]any) string {
	bus := str(event["eventBusName"], s.defaultBus)
	source := str(event["source"], "")
	detailType := str(event["detailType"], str(event["detail-type"], ""))
	parts := []string{s.prefix, sanitize(bus)}
	if source != "" {
		parts = append(parts, sanitize(source))
	}
	if detailType != "" {
		parts = append(parts, sanitize(detailType))
	}
	return strings.Join(parts, ".")
}

func sanitize(tok string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, tok)
}

func str(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func toSlice(v any) ([]any, error) {
	switch t := v.(type) {
	case []any:
		return t, nil
	case nil:
		return nil, fmt.Errorf("no events")
	default:
		return nil, fmt.Errorf("events must be a list")
	}
}
