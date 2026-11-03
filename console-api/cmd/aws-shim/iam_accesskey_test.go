package main

import (
	"context"
	"net/url"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// An access-key op acts only on a key the named user owns: naming one user (the one the caller holds
// authority over) and another user's AccessKeyId is NoSuchEntity, and the other user's key is untouched.
func TestIAM_AccessKeyOpsActOnlyOnTheNamedUsersKey(t *testing.T) {
	cs := csWithSAR(true)
	keys := awskeys.NewStore(cs, "default")
	ctx := context.Background()
	for _, k := range []awskeys.Key{{AccessKeyID: "AKIAALICE", SecretKey: "s1", Owner: "alice"}, {AccessKeyID: "AKIABOB", SecretKey: "s2", Owner: "bob"}} {
		if err := keys.Put(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	h := newIAMHandler(cs, fakeDynWith(gvrUsers), keys, nil, "default", "open-infra", "us-east-1", discardLogger())
	alice := iam.Claims{Sub: "alice"}

	for _, tc := range []struct {
		name   string
		params url.Values
	}{
		{"UpdateAccessKey naming alice, bob's key", url.Values{"Action": {"UpdateAccessKey"}, "UserName": {"alice"}, "AccessKeyId": {"AKIABOB"}, "Status": {"Inactive"}}},
		{"UpdateAccessKey with no UserName (the caller), bob's key", url.Values{"Action": {"UpdateAccessKey"}, "AccessKeyId": {"AKIABOB"}, "Status": {"Inactive"}}},
		{"DeleteAccessKey naming alice, bob's key", url.Values{"Action": {"DeleteAccessKey"}, "UserName": {"alice"}, "AccessKeyId": {"AKIABOB"}}},
		{"DeleteAccessKey with no UserName (the caller), bob's key", url.Values{"Action": {"DeleteAccessKey"}, "AccessKeyId": {"AKIABOB"}}},
		{"DeleteAccessKey of a key that does not exist", url.Values{"Action": {"DeleteAccessKey"}, "UserName": {"alice"}, "AccessKeyId": {"AKIANONE"}}},
	} {
		w := serveWith(h, formOp(tc.params), alice)
		if w.Code != 404 {
			t.Errorf("%s: status %d, want 404 NoSuchEntity (%s)", tc.name, w.Code, w.Body.String())
		}
	}
	if _, ok := keys.Lookup(ctx, "AKIABOB"); !ok {
		t.Fatal("bob's key was revoked or deleted through a request naming another user")
	}

	// The named user's own key: deactivated, then deleted.
	if w := serveWith(h, formOp(url.Values{"Action": {"UpdateAccessKey"}, "AccessKeyId": {"AKIAALICE"}, "Status": {"Inactive"}}), alice); w.Code != 200 {
		t.Fatalf("UpdateAccessKey of the caller's own key = %d %s", w.Code, w.Body.String())
	}
	if _, ok := keys.Lookup(ctx, "AKIAALICE"); ok {
		t.Fatal("the caller's key is still active after UpdateAccessKey Inactive")
	}
	if w := serveWith(h, formOp(url.Values{"Action": {"DeleteAccessKey"}, "UserName": {"alice"}, "AccessKeyId": {"AKIAALICE"}}), alice); w.Code != 200 {
		t.Fatalf("DeleteAccessKey of alice's key = %d %s", w.Code, w.Body.String())
	}
	if _, ok := keys.Describe(ctx, "AKIAALICE"); ok {
		t.Fatal("alice's key survived its DeleteAccessKey")
	}
}

// A role session granted iam:UpdateAccessKey on one user cannot reach another user's key by naming the
// granted user, and must name a user (it has none of its own).
func TestIAM_RoleAccessKeyGrantStaysOnItsUser(t *testing.T) {
	cs := csWithSAR(true)
	keys := awskeys.NewStore(cs, "default")
	ctx := context.Background()
	if err := keys.Put(ctx, awskeys.Key{AccessKeyID: "AKIABOB", SecretKey: "s", Owner: "bob"}); err != nil {
		t.Fatal(err)
	}
	authz := roleChecker(policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"iam:UpdateAccessKey", "iam:ListAccessKeys"}, Resources: []string{"User::svc", "User::*"}})
	h := newIAMHandler(cs, fakeDynWith(gvrUsers), keys, authz, "default", "open-infra", "us-east-1", discardLogger())
	role := ecrRoleClaims()
	if w := serveWith(h, formOp(url.Values{"Action": {"UpdateAccessKey"}, "UserName": {"svc"}, "AccessKeyId": {"AKIABOB"}, "Status": {"Inactive"}}), role); w.Code != 404 {
		t.Fatalf("a role granted UpdateAccessKey on User::svc revoked bob's key: %d %s", w.Code, w.Body.String())
	}
	if _, ok := keys.Lookup(ctx, "AKIABOB"); !ok {
		t.Fatal("bob's key was revoked")
	}
	if w := serveWith(h, formOp(url.Values{"Action": {"ListAccessKeys"}}), role); w.Code == 200 {
		t.Fatalf("a role session listed access keys without naming a user: %s", w.Body.String())
	}
}
