package main

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

func memberCtx() context.Context {
	ctx := withAccountHome(context.Background(), memberHome)
	return awsidentity.WithIdentity(ctx, awsidentity.Current().ForAccount(testMember, memberHome))
}

// The management account's resources keep their names, namespaces and keys; a member account's are its
// own, beside them, and never the management account's or another member's.
func TestAccountScope_KeysAndNamespaces(t *testing.T) {
	mgmt, member := context.Background(), memberCtx()
	if accountKey(mgmt, "orders") != "orders" || accountNamespace(mgmt, "open-infra-cfn") != "open-infra-cfn" {
		t.Fatal("the management account's keys and namespaces must not change")
	}
	k := accountKey(member, "orders")
	if k != testMember+":orders" || accountNamespace(member, "open-infra-cfn") != memberHome {
		t.Fatalf("member key %q, namespace %q", k, accountNamespace(member, "open-infra-cfn"))
	}
	if n, ok := nameOfAccountKey(member, k); !ok || n != "orders" {
		t.Errorf("the member's own key: %q %v", n, ok)
	}
	if _, ok := nameOfAccountKey(member, "orders"); ok {
		t.Error("a member account listed the management account's key")
	}
	if _, ok := nameOfAccountKey(member, "955555555555:orders"); ok {
		t.Error("a member account listed another member's key")
	}
	if _, ok := nameOfAccountKey(mgmt, k); ok {
		t.Error("the management account listed a member account's key as its own")
	}
	if n, ok := nameOfAccountKey(mgmt, "orders"); !ok || n != "orders" {
		t.Error("the management account's own key")
	}
	if n, ok := nameOfAccountKey(mgmt, "/app/config"); !ok || n != "/app/config" {
		t.Error("a management parameter path is the management account's own")
	}
	noHome := awsidentity.WithIdentity(context.Background(), awsidentity.Current().ForAccount(testMember, ""))
	if ns := accountNamespace(noHome, "open-infra-cfn"); ns == "open-infra-cfn" {
		t.Error("a member request without a home must not reach the door's own namespace")
	}
}

// A key names its account outright, for the work that runs without a request.
func TestAccountScope_KeysForAnAccount(t *testing.T) {
	mgmt := awsidentity.Current().AccountID
	if accountKeyFor(mgmt, "jobs") != "jobs" || accountKeyFor("", "jobs") != "jobs" {
		t.Fatal("the management account's key is the name")
	}
	k := accountKeyFor(testMember, "jobs")
	if a, n := splitAccountKey(k); a != testMember || n != "jobs" {
		t.Fatalf("split %q = %q %q", k, a, n)
	}
	if a, n := splitAccountKey("jobs"); a != mgmt || n != "jobs" {
		t.Fatalf("a bare key is the management account's: %q %q", a, n)
	}
	ctx := withAccount(context.Background(), testMember, memberHome)
	if callerAccount(ctx) != testMember || accountKey(ctx, "jobs") != k || accountNamespace(ctx, "x") != memberHome {
		t.Fatalf("a background context in the member account: %q %q %q", callerAccount(ctx), accountKey(ctx, "jobs"), accountNamespace(ctx, "x"))
	}
	if withAccount(context.Background(), mgmt, "") != context.Background() {
		t.Error("the management account's background context is unchanged")
	}
}
