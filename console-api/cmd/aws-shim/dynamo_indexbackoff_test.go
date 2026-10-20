package main

import (
	"testing"
	"time"
)

// TestIndexRetryBackoff: a failing (table,index) is suppressed within the window and re-allowed
// once it succeeds — so the table-sync ticker can't re-attempt/re-log a dead index every cycle.
func TestIndexRetryBackoff(t *testing.T) {
	h := &dynamoHandler{idxFail: map[string]time.Time{}}
	k := "gsi:orders:byCustomer"

	if !h.indexAttemptAllowed(k) {
		t.Fatal("first attempt should be allowed")
	}
	h.recordIndexResult(k, true) // it failed
	if h.indexAttemptAllowed(k) {
		t.Error("a just-failed index should be backed off, not re-attempted")
	}
	h.recordIndexResult(k, false) // later it succeeded (backend fixed)
	if !h.indexAttemptAllowed(k) {
		t.Error("a success should clear the backoff")
	}
}
