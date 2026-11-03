package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// #348: a User's data-plane Deny holds at the IAM front door, as at every other. It ran for assumed roles
// only, so a User's iam Deny — native, or imported from an AWS policy now that the importer accepts iam —
// was never met by the User's own IAM calls.
func TestIAM_UserDataPlaneDenyHolds(t *testing.T) {
	cs := csWithSAR(true)
	keys := awskeys.NewStore(cs, "default")
	authz := policyFor("alice",
		dpAllow([]string{"iam:*"}, "*"),
		dpDeny([]string{"iam:DeleteRole"}, "Role::prod-deployer"),
		dpDeny([]string{"iam:CreateAccessKey"}, "User::alice"))
	h := newIAMHandler(cs, fakeDynWith(gvrUsers, gvrRoles, gvrPolicies), keys, authz, "default", "open-infra", "us-east-1", discardLogger())
	alice := iam.Claims{Sub: "alice"}

	if w := serveWith(h, formOp(url.Values{"Action": {"DeleteRole"}, "RoleName": {"prod-deployer"}}), alice); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Errorf("DeleteRole of a role the User's policy denies: %d %s, want 403 AccessDenied", w.Code, w.Body.String())
	}
	// An access-key op that names no user acts on the caller, so the Deny on User::alice holds for it.
	if w := serveWith(h, formOp(url.Values{"Action": {"CreateAccessKey"}}), alice); w.Code != http.StatusForbidden {
		t.Errorf("CreateAccessKey for the caller under a Deny on User::alice: %d %s, want 403", w.Code, w.Body.String())
	}
	// Not denied: another role, still allowed (the check only tightens).
	if w := serveWith(h, formOp(url.Values{"Action": {"DeleteRole"}, "RoleName": {"scratch"}}), alice); w.Code == http.StatusForbidden {
		t.Errorf("DeleteRole of a role the policy does not deny was refused: %s", w.Body.String())
	}
	// A User no data-plane policy governs is unchanged.
	if w := serveWith(h, formOp(url.Values{"Action": {"DeleteRole"}, "RoleName": {"prod-deployer"}}), iam.Claims{Sub: "bob"}); w.Code == http.StatusForbidden {
		t.Errorf("an ungoverned User was refused: %s", w.Body.String())
	}
}

// The same at the AppSync front door: management, the reads, and an explicit Deny of appsync:GraphQL.
func TestAppsync_UserDataPlaneDenyHolds(t *testing.T) {
	authz := policyFor("alice",
		dpAllow([]string{"appsync:*"}, "*"),
		dpDeny([]string{"appsync:GetResolver", "appsync:GetGraphqlApi"}, "GraphQLApi::team-a.notes"),
		dpDeny([]string{"appsync:GraphQL"}, "*"))
	alice := iam.Claims{Sub: "alice"}

	h, _ := readAppsync(allowAll)
	h.authz = authz
	if w, _ := appsyncRead(h, alice, "/v1/apis/team-a.notes"); w.Code != http.StatusForbidden {
		t.Errorf("GetGraphqlApi under the User's Deny: %d %s, want 403", w.Code, w.Body.String())
	}
	if w, _ := appsyncRead(h, alice, "/v1/apis/team-a.notes/types/Query/resolvers/getTodo"); w.Code != http.StatusForbidden {
		t.Errorf("GetResolver under the User's Deny: %d %s, want 403", w.Code, w.Body.String())
	}
	if w, _ := appsyncRead(h, iam.Claims{Sub: "bob"}, "/v1/apis/team-a.notes"); w.Code != http.StatusOK {
		t.Errorf("GetGraphqlApi by an ungoverned User: %d %s, want 200", w.Code, w.Body.String())
	}

	g := newAppsyncHandler(csWithSAR(true), "http://127.0.0.1:1", "default", discardLogger())
	g.authz = authz
	w := serveWith(g, httptest.NewRequest(http.MethodPost, "http://shim/graphql", strings.NewReader(`{"query":"{a}"}`)), alice)
	if !isDenied(w, "UnauthorizedException") {
		t.Errorf("GraphQL under the User's explicit Deny of appsync:GraphQL: %d %s, want UnauthorizedException", w.Code, w.Body.String())
	}
}
