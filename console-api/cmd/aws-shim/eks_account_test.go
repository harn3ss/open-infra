package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// eksMemberReq is r as the router hands a member account's request to an account-scoped door.
func eksMemberReq(r *http.Request) *http.Request {
	ctx := awsidentity.WithIdentity(withAccountHome(r.Context(), memberHome), awsidentity.Current().ForAccount(testMember, memberHome))
	return r.WithContext(inAccountScope(ctx))
}

// A member account describes the cluster in its own account: the cluster's ARN and role ARN carry the
// member account; the connection details are the cluster's. The management account's answer is
// unchanged; a member principal its own policy does not allow is refused.
func TestEKS_MemberAccountDescribesTheClusterInItsAccount(t *testing.T) {
	h := newEKSTestHandler(true)
	h.account = "000000000000"
	h.authz = checkerInMode(t, "legacy", dataplaneauthz.PolicyDoc{Name: "eks", AppliesTo: []string{"User::" + memberHome + "/bob"},
		Statements: []policyengine.Statement{dpAllow([]string{"eks:*"}, "*")}})
	describe := func(r *http.Request, claims iam.Claims) (*httptest.ResponseRecorder, map[string]any) {
		w := httptest.NewRecorder()
		h.serve(w, r, claims, "r-1")
		var out struct{ Cluster map[string]any }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w, out.Cluster
	}
	w, c := describe(eksMemberReq(eksReq(http.MethodGet, "/clusters/open-infra")), iam.Claims{Sub: "bob", Account: testMember})
	if w.Code != http.StatusOK || c["arn"] != "arn:aws:eks:us-east-1:"+testMember+":cluster/open-infra" ||
		c["roleArn"] != "arn:aws:iam::"+testMember+":role/open-infra-eks-cluster-role" || c["endpoint"] != "https://10.0.0.1:6443" {
		t.Errorf("the member's DescribeCluster = %d %v", w.Code, c)
	}
	w, c = describe(eksReq(http.MethodGet, "/clusters/open-infra"), eksClaims())
	if w.Code != http.StatusOK || c["arn"] != "arn:aws:eks:us-east-1:000000000000:cluster/open-infra" ||
		c["roleArn"] != "arn:aws:iam::000000000000:role/open-infra-eks-cluster-role" {
		t.Errorf("the management account's DescribeCluster = %d %v", w.Code, c)
	}
	if w, _ := describe(eksMemberReq(eksReq(http.MethodGet, "/clusters/open-infra")), iam.Claims{Sub: "eve", Account: testMember}); w.Code != http.StatusForbidden {
		t.Errorf("a member principal with no policy = %d, want 403", w.Code)
	}
	if !accountScopedServices["eks"] {
		t.Error("eks is not registered as account-scoped")
	}
}
