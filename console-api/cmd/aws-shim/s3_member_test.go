package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// Object storage keeps the management account's buckets and its gate knows no account: a member
// account's principal is refused there, whatever its policies, rather than evaluated as a management
// principal of the same name.
func TestS3_MemberAccountPrincipalIsRefused(t *testing.T) {
	h := &s3Handler{logger: discardLogger(), authz: checkerInMode(t, "enforce", dataplaneauthz.PolicyDoc{Name: "all",
		AppliesTo: []string{"User::bob", "User::" + memberHome + "/bob"}, Statements: []policyengine.Statement{dpAllow([]string{"*"}, "*")}})}
	r := httptest.NewRequest(http.MethodGet, "/assets/report.csv", nil)
	if h.allowedIn(nil, r, iam.Claims{Sub: "bob", Account: testMember}, s3op{kind: "get", bucket: "assets", key: "report.csv"}) {
		t.Fatal("a member account's principal was allowed a management-account object")
	}
}
