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
	return dataplaneauthz.New(func(context.Context) ([]dataplaneauthz.PolicyDoc, error) {
		return []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::tester"}, Statements: stmts}}, nil
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
