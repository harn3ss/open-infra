package main

import (
	"net/http"
	"testing"
)

// The separation-of-duties gate on grant approval (AC-5). Only a distinct, authenticated approver of a
// not-yet-approved grant may proceed; every other case is refused with a specific status.
func TestApprovalDecision(t *testing.T) {
	cases := []struct {
		name               string
		approver           string
		requestedBy        string
		existingApprovedBy string
		wantStatus         int // 0 == allowed
	}{
		{"distinct approver, unapproved", "carol", "alice", "", 0},
		{"requester known-empty (kubectl grant), distinct approver ok", "carol", "", "", 0},
		{"self-approval refused", "alice", "alice", "", http.StatusConflict},
		{"unauthenticated approver refused", "", "alice", "", http.StatusBadRequest},
		{"already approved refused", "dave", "alice", "carol", http.StatusConflict},
		{"already approved takes precedence over self-approval", "alice", "alice", "carol", http.StatusConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, msg := approvalDecision(c.approver, c.requestedBy, c.existingApprovedBy)
			if status != c.wantStatus {
				t.Fatalf("status = %d (%q), want %d", status, msg, c.wantStatus)
			}
			if (c.wantStatus == 0) != (msg == "") {
				t.Fatalf("status/msg disagree: status=%d msg=%q", status, msg)
			}
		})
	}
}
