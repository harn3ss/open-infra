package main

import (
	"strings"
	"testing"
)

// The dead-letter subject namespace must not collide with anything, or JetStream silently refuses to
// create the DLQ stream (overlapping subjects) or the worker re-consumes its own dead-letters (a loop).
// This locks the two invariants a live run proved essential:
//   - NOT under "dlq.*" — that overlaps the platform-wide "dlq.>" stream apply-sink owns.
//   - NOT under the work subject "lambda.async.*" — the worker consumes "lambda.async.>", so a DLQ
//     subject there would be redelivered forever.
func TestAsyncDLQSubjectNamespace(t *testing.T) {
	if strings.HasPrefix(asyncDLQPre, "dlq.") || strings.HasPrefix(asyncDLQAll, "dlq.") {
		t.Errorf("DLQ subject %q/%q must not be under dlq.* (overlaps apply-sink's dlq.> stream)", asyncDLQPre, asyncDLQAll)
	}
	if strings.HasPrefix(asyncDLQPre, asyncSubjectPre) || strings.HasPrefix(asyncDLQAll, asyncSubjectPre) {
		t.Errorf("DLQ subject %q/%q must not be under the work subject %q (would be re-consumed → loop)", asyncDLQPre, asyncDLQAll, asyncSubjectPre)
	}
	// The DLQ prefix must be a strict subject prefix of the DLQ wildcard, so published dead-letters land
	// in the DLQ stream.
	if !strings.HasPrefix(asyncDLQPre, strings.TrimSuffix(asyncDLQAll, ">")) {
		t.Errorf("DLQ per-function prefix %q is not covered by the DLQ stream wildcard %q", asyncDLQPre, asyncDLQAll)
	}
}
