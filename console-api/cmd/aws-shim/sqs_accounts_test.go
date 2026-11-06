package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// SQS keeps each account's queues apart, so the router marks its requests as an account-scoped door's.
func TestSQS_IsAnAccountScopedDoor(t *testing.T) {
	if !accountScopedServices["sqs"] {
		t.Fatalf("accountScopedServices = %v, want sqs", accountScopedServices)
	}
}

// A queue URL's path names its account (<base>/<account>/<name>); anything else names none.
func TestQueueURLAccount(t *testing.T) {
	for u, want := range map[string]string{
		"http://shim.local:4566/912345678901/jobs":            "912345678901",
		"https://sqs.us-east-1.amazonaws.com/000000000000/q":  "000000000000",
		"http://shim.example/sqs/912345678901/jobs.fifo":      "912345678901",
		"http://shim.local:4566/open-infra/jobs":              "",
		"http://shim.local:4566/jobs":                         "",
		"jobs":                                                "",
		"http://shim.local:4566/9123456789012/jobs":           "",
		"http://shim.local:4566/912345678901/":                "",
		"http://shim.local:4566/912345678901/jobs/extra/path": "",
	} {
		if got := queueURLAccount(u); got != want {
			t.Errorf("queueURLAccount(%q) = %q, want %q", u, got, want)
		}
	}
}

// The management account's id, however it is written, is the handler's.
func TestNormAccount(t *testing.T) {
	const mgmt = "123456789012"
	for in, want := range map[string]string{"": mgmt, mgmt: mgmt, testMgmt: mgmt, testMember: testMember} {
		if got := normAccount(mgmt, in); got != want {
			t.Errorf("normAccount(%q) = %q, want %q", in, got, want)
		}
	}
	h := &sqsHandler{account: mgmt}
	if h.keyFor(testMgmt, "q") != "q" || h.keyFor(mgmt, "q") != "q" || h.keyFor(testMember, "q") != testMember+":q" {
		t.Error("a queue's key is its name in the management account, <account>:<name> in a member's")
	}
	if !knownMember(testDirectory(), testMember) || knownMember(testDirectory(), testMgmt) || knownMember(testDirectory(), "555555555555") || knownMember(nil, testMember) {
		t.Error("knownMember must know the organization's member accounts alone")
	}
}

// A request on another account's resource is decided across accounts, whoever asks: the management
// account's caller too — whose legacy check knows no accounts, so it refuses; a member account's own
// resource is its own account's.
func TestAccountAuthz_AcrossAccounts(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	allow := func() (bool, string) { return true, "rbac" }
	mgmt := iam.Claims{Sub: "alice", Groups: []string{"openinfra:admins"}}
	authz := checkerInMode(t, "legacy",
		dataplaneauthz.PolicyDoc{Name: "bob-sqs", AppliesTo: []string{"User::" + memberHome + "/bob"},
			Statements: []policyengine.Statement{dpAllow([]string{"sqs:*"}, "*")}})
	h := &sqsHandler{account: testMgmt}

	ctx := context.Background()
	opts, legacy := h.accountAuthz(ctx, testMgmt, allow)
	if ok, why := decide(ctx, r, authz, mgmt, "sqs:SendMessage", "Queue", "jobs", legacy, opts...); !ok || len(opts) != 0 {
		t.Errorf("the management account's own queue must be decided exactly as before: %v %s (opts %d)", ok, why, len(opts))
	}
	opts, legacy = h.accountAuthz(ctx, testMember, allow)
	if ok, _ := decide(ctx, r, authz, mgmt, "sqs:SendMessage", "Queue", "jobs", legacy, opts...); ok {
		t.Error("the management account's caller reached a member account's queue on its RBAC alone")
	}

	member := iam.Claims{Sub: "bob", Account: testMember}
	mctx := inAccountScope(memberCtx())
	opts, legacy = h.accountAuthz(mctx, testMember, nil)
	if ok, why := decide(mctx, r, authz, member, "sqs:SendMessage", "Queue", "jobs", legacy, opts...); !ok {
		t.Errorf("a member account's principal was refused its own queue: %s", why)
	}
	opts, legacy = h.accountAuthz(mctx, testMgmt, nil)
	if ok, _ := decide(mctx, r, authz, member, "sqs:SendMessage", "Queue", "jobs", legacy, opts...); ok {
		t.Error("a member account's principal reached the management account's queue on its identity policy alone")
	}
}
