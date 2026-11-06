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
