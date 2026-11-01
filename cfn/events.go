// Stack events (#347 item I): the per-resource history DescribeStackEvents returns.
//
// AWS records an event for every status a stack and each of its resources passes through — the stack's
// own CREATE_IN_PROGRESS ("User Initiated"), each resource's CREATE_IN_PROGRESS / CREATE_COMPLETE, a
// failed resource's CREATE_FAILED with its reason, the rollback, and the stack's final status. CI tools
// read them, and `aws cloudformation deploy` points to them when a stack fails. The engine records the
// same transitions on the stack record as they happen; the record is written after each one, so a caller
// polling DescribeStackEvents sees a create progress resource by resource.
package cfn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// StackTypeName is the ResourceType of an event about the stack itself.
const StackTypeName = "AWS::CloudFormation::Stack"

// maxStackEvents bounds the events kept on a record (oldest dropped first), so a long-lived stack's record
// stays well under the Secret size limit.
const maxStackEvents = 400

// StackEvent is one DescribeStackEvents entry.
type StackEvent struct {
	EventID    string `json:"eventId"`
	LogicalID  string `json:"logicalId"`
	PhysicalID string `json:"physicalId,omitempty"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Timestamp  string `json:"timestamp"`
}

// eventTime is an event's timestamp: millisecond precision, as AWS reports them, so events in one second
// still sort.
func eventTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// addEvent records a transition. A stack event's LogicalID is the stack's name, as on AWS.
func (rec *StackRecord) addEvent(logicalID, physicalID, typ, status, reason string) {
	now := time.Now()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d|%d", rec.Name, logicalID, status, now.UnixNano(), len(rec.Events))))
	id := hex.EncodeToString(sum[:8])
	if typ != StackTypeName {
		id = logicalID + "-" + status + "-" + id
	}
	rec.Events = append(rec.Events, StackEvent{EventID: id, LogicalID: logicalID, PhysicalID: physicalID, Type: typ,
		Status: status, Reason: reason, Timestamp: eventTime(now)})
	if n := len(rec.Events); n > maxStackEvents {
		rec.Events = append([]StackEvent(nil), rec.Events[n-maxStackEvents:]...)
	}
}

// stackEvent records a transition of the stack itself.
func (rec *StackRecord) stackEvent(status, reason string) {
	rec.addEvent(rec.Name, "", StackTypeName, status, reason)
}

// resourceEvent records a transition of one resource and sets that resource's own status on the record
// (DescribeStackResources reports it). The resource is matched by logical id in Resources and Pending.
func (rec *StackRecord) resourceEvent(r StackResource, status, reason string) {
	typ := r.Type
	if typ == "" {
		typ = r.Kind
	}
	phys := r.PhysicalID
	if phys == "" {
		phys = r.Name
	}
	rec.addEvent(r.LogicalID, phys, typ, status, reason)
	for i := range rec.Resources {
		if rec.Resources[i].LogicalID == r.LogicalID {
			rec.Resources[i].Status, rec.Resources[i].StatusReason = status, reason
			rec.Resources[i].Timestamp = eventTime(time.Now())
		}
	}
}

// EventSink is an optional Applier capability: persist a stack's events as they happen, apart from the
// stack record, so a caller polling DescribeStackEvents sees an operation progress resource by resource
// (the record itself is written at the operation's milestones). The full, newest list is passed each time.
type EventSink interface {
	PutEvents(ctx context.Context, stackName string, events []StackEvent) error
}

// flushEvents hands the record's events to the Applier's EventSink, if it has one (best effort: the
// record keeps them regardless).
func flushEvents(ctx context.Context, ap Applier, rec *StackRecord) {
	if es, ok := ap.(EventSink); ok {
		_ = es.PutEvents(ctx, rec.Name, rec.Events)
	}
}

// carryEvents copies an earlier record's events onto a record that is about to replace it (an update or
// a delete writes a fresh record), so the stack's history is kept across operations.
func (rec *StackRecord) carryEvents(from *StackRecord) {
	if from == nil || len(rec.Events) > 0 {
		return
	}
	rec.Events = append([]StackEvent(nil), from.Events...)
}

// EventsNewestFirst returns the record's events newest first, the order DescribeStackEvents uses.
func EventsNewestFirst(rec *StackRecord) []StackEvent {
	out := make([]StackEvent, 0, len(rec.Events))
	for i := len(rec.Events) - 1; i >= 0; i-- {
		out = append(out, rec.Events[i])
	}
	return out
}
