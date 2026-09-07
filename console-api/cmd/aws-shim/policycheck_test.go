package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// checkerFor builds a Checker whose single policy (for principal "User::tester") carries the given
// statements — the realistic "allow the service, forbid one action" shape.
func checkerFor(stmts ...policyengine.Statement) *dataplaneauthz.Checker {
	return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::tester"}, Statements: stmts}}}, nil
	}, time.Minute)
}

// A data-plane policy that allows dynamodb but forbids DeleteItem: the forbid overrides (a Deny RBAC
// can't express), while other dynamodb ops and other services are unaffected.
func TestDynamo_DataPlaneDeny(t *testing.T) {
	h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "db", discardLogger())
	h.authz = checkerFor(
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"dynamodb:*"}, Resources: []string{"*"}},
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"dynamodb:DeleteItem"}, Resources: []string{"*"}},
	)
	claims := iam.Claims{Sub: "tester"}
	deny := func(op, body string) int {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), claims, "r")
		return w.Code
	}
	// DeleteItem: forbidden by the data-plane policy (403).
	if code := deny("DeleteItem", `{"TableName":"orders","Key":{"id":{"S":"1"}}}`); code != 403 {
		t.Fatalf("DeleteItem must be denied by data-plane policy, got %d", code)
	}
	// GetItem: allowed by the policy → passes the data-plane check (then hits the db-nil 501, not 403).
	if code := deny("GetItem", `{"TableName":"orders","Key":{"id":{"S":"1"}}}`); code == 403 {
		t.Fatalf("GetItem must NOT be denied (dynamodb:* allows it), got 403")
	}
	// An ungoverned principal is unaffected by this policy.
	w := httptest.NewRecorder()
	h.serve(w, dynamoReq("DynamoDB_20120810.DeleteItem", `{"TableName":"orders","Key":{"id":{"S":"1"}}}`), iam.Claims{Sub: "other"}, "r")
	if w.Code == 403 {
		t.Fatalf("an ungoverned principal must not be denied by another's policy, got 403")
	}
}

// A principal governed only for S3 is unaffected on DynamoDB (per-service governance — no
// cross-service surprise).
func TestDynamo_UngovernedService(t *testing.T) {
	h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "db", discardLogger())
	h.authz = checkerFor(policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"}})
	w := httptest.NewRecorder()
	h.serve(w, dynamoReq("DynamoDB_20120810.GetItem", `{"TableName":"orders","Key":{"id":{"S":"1"}}}`), iam.Claims{Sub: "tester"}, "r")
	if w.Code == 403 {
		t.Fatalf("an S3-only policy must not govern DynamoDB, got 403 %s", w.Body.String())
	}
}

// S3: allow the service, forbid DeleteObject — the DELETE is blocked at the shim.
func TestS3_DataPlaneDeny(t *testing.T) {
	h := &s3Handler{cs: csWithSAR(true), logger: discardLogger(), authz: checkerFor(
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}},
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"s3:DeleteObject"}, Resources: []string{"Bucket::reports"}},
	)}
	w := httptest.NewRecorder()
	h.serve(w, httptest.NewRequest("DELETE", "/reports/q3.csv", nil), iam.Claims{Sub: "tester"}, "r")
	if w.Code != 403 {
		t.Fatalf("s3 DeleteObject on reports must be denied by data-plane policy, got %d %s", w.Code, w.Body.String())
	}
}

// §5 DRIFT GATE (security-critical). The AWS condition importer may map a condition key ONLY if the
// aws-shim actually populates that request-context attribute at request time — otherwise a Deny gated
// on the key would silently never fire (Cedar SKIPS a forbid whose `when` errors on an absent
// attribute), the fail-open hole the wholesale condition refusal originally guarded.
// policyengine.SupportedConditionAttrs() is the importable-key set (the SINGLE source of truth the
// importer consults); requestContext() is the SINGLE source of truth for what the shim populates. This
// test fails if the two ever diverge — e.g. someone adds an importable key without populating it, or
// removes a populated key that is still importable. Keep them one shared list.
func TestSupportedConditionKeysMatchRequestContext(t *testing.T) {
	// Exercise requestContext with a request that populates every attribute it can set: a RemoteAddr
	// yields the source IP, and authenticated is always set.
	req := httptest.NewRequest("GET", "http://shim/", nil)
	req.RemoteAddr = "203.0.113.7:5555"
	populated := map[string]bool{}
	for k := range requestContext(req) {
		populated[k] = true
	}

	importable := policyengine.SupportedConditionAttrs()
	for attr := range importable {
		if !populated[attr] {
			t.Errorf("FAIL-OPEN RISK: SupportedConditionKeys maps %q but requestContext() never populates it — a Deny "+
				"gated on it would silently never fire. Populate it in requestContext() or drop it from the whitelist.", attr)
		}
	}
	for attr := range populated {
		if !importable[attr] {
			t.Errorf("drift: requestContext() populates %q but it is not in SupportedConditionKeys — decide whether it "+
				"should be importable (add it there) or is intentionally excluded (then update this test's expectation).", attr)
		}
	}
}
