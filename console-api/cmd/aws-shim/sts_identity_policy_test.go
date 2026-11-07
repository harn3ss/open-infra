package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// sts:AssumeRole is decided as AWS decides it: the role's trust is its resource policy, and the caller's own
// policy is the other side. Within one account a trust naming the caller grants the assume on its own (an
// explicit Deny still refuses it); a trust naming the caller's account root delegates to the account, whose
// policy must allow sts:AssumeRole on the role; another account's role needs both, whatever its trust names.
func TestAssumeRole_IdentityPolicy(t *testing.T) {
	assume := []string{"sts:AssumeRole"}
	allowOn := func(principal, role string) dataplaneauthz.PolicyDoc {
		return dataplaneauthz.PolicyDoc{Name: "assume-" + role, AppliesTo: []string{principal},
			Statements: []policyengine.Statement{dpAllow(assume, "Role::"+role)}}
	}
	denyAll := func(principal string) dataplaneauthz.PolicyDoc {
		return dataplaneauthz.PolicyDoc{Name: "no-assume", AppliesTo: []string{principal},
			Statements: []policyengine.Statement{dpDeny(assume, "*")}}
	}
	mgmtRoot := "arn:aws:iam::" + testMgmt + ":root"
	memberRoot := "arn:aws:iam::" + testMember + ":root"
	mgmtRoles := fakeRoles{
		"named":     {trust: []string{"alice"}},
		"named-arn": {trust: []string{"arn:aws:iam::" + testMgmt + ":user/alice"}},
		"anyone":    {trust: []string{"*"}},
		"delegated": {trust: []string{mgmtRoot}},
		"for-bob":   {trust: []string{memberRoot}},
		"bob-named": {trust: []string{"arn:aws:iam::" + testMember + ":user/bob"}},
	}
	memberRoles := fakeRoles{
		memberHome + "/admin":       {trust: []string{mgmtRoot}},
		memberHome + "/alice-named": {trust: []string{"arn:aws:iam::" + testMgmt + ":user/alice"}},
	}
	alice := iam.Claims{Sub: "alice"}
	bob := iam.Claims{Sub: "bob", Account: testMember}
	bobPrincipal := "User::" + memberHome + "/bob"

	cases := []struct {
		name   string
		docs   []dataplaneauthz.PolicyDoc
		claims iam.Claims
		arn    string
		want   int
	}{
		// within the management account
		{"a trust naming the caller needs no policy", nil, alice, "arn:aws:iam::" + testMgmt + ":role/named", 200},
		{"a trust naming the caller's ARN needs no policy", nil, alice, "arn:aws:iam::" + testMgmt + ":role/named-arn", 200},
		{"a trust of anyone needs no policy", nil, alice, "arn:aws:iam::" + testMgmt + ":role/anyone", 200},
		{"an explicit Deny refuses a named caller", []dataplaneauthz.PolicyDoc{denyAll("User::alice")}, alice, "arn:aws:iam::" + testMgmt + ":role/named", 403},
		{"the account's root delegates: no policy is refused", nil, alice, "arn:aws:iam::" + testMgmt + ":role/delegated", 403},
		{"the account's root delegates: a policy on another role is refused", []dataplaneauthz.PolicyDoc{allowOn("User::alice", "named")}, alice, "arn:aws:iam::" + testMgmt + ":role/delegated", 403},
		{"the account's root delegates: a policy on the role allows", []dataplaneauthz.PolicyDoc{allowOn("User::alice", "delegated")}, alice, "arn:aws:iam::" + testMgmt + ":role/delegated", 200},
		// the management account's user into a member account's role
		{"another account's role needs the caller's policy", nil, alice, "arn:aws:iam::" + testMember + ":role/admin", 403},
		{"another account's role naming the caller still needs its policy", nil, alice, "arn:aws:iam::" + testMember + ":role/alice-named", 403},
		{"another account's role with the caller's policy", []dataplaneauthz.PolicyDoc{allowOn("User::alice", "admin")}, alice, "arn:aws:iam::" + testMember + ":role/admin", 200},
		// a member account's user into the management account's role
		{"a member's user with no policy is refused", nil, bob, "arn:aws:iam::" + testMgmt + ":role/for-bob", 403},
		{"a member's user named by the trust still needs its policy", nil, bob, "arn:aws:iam::" + testMgmt + ":role/bob-named", 403},
		{"a member's user with its policy", []dataplaneauthz.PolicyDoc{allowOn(bobPrincipal, "for-bob")}, bob, "arn:aws:iam::" + testMgmt + ":role/for-bob", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &stsHandler{account: testMgmt, minter: testMinter(t), roles: fakeRolesIn{fakeRoles: mgmtRoles, in: memberRoles},
				accounts: testDirectory(), authz: checkerInMode(t, "enforce", tc.docs...), logger: discardLogger()}
			r := assumeRequest(tc.arn, "s1")
			if tc.claims.Account != "" {
				r = r.WithContext(memberCtx())
			}
			w := httptest.NewRecorder()
			h.serve(w, r, tc.claims, "rid")
			if w.Code != tc.want {
				t.Fatalf("AssumeRole %s = %d, want %d: %s", tc.arn, w.Code, tc.want, w.Body)
			}
			if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") {
				t.Errorf("a refusal is AWS's AccessDenied: %s", w.Body)
			}
		})
	}
}

// The refusal names who, the action and the role, as AWS's does.
func TestAssumeRole_IdentityPolicyRefusalIsAWSs(t *testing.T) {
	h := &stsHandler{account: testMgmt, minter: testMinter(t), roles: fakeRoles{"delegated": {trust: []string{"arn:aws:iam::" + testMgmt + ":root"}}},
		authz: checkerInMode(t, "enforce"), logger: discardLogger()}
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("arn:aws:iam::"+testMgmt+":role/delegated", "s1").WithContext(context.Background()), iam.Claims{Sub: "alice"}, "rid")
	body := w.Body.String()
	if w.Code != http.StatusForbidden || !strings.Contains(body, "is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::"+testMgmt+":role/delegated") {
		t.Fatalf("refusal = %d %s", w.Code, body)
	}
}
