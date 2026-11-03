package main

// Every key a KMS request touches is authorized (real Postgres store, OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go): ReEncrypt needs kms:ReEncryptFrom on the ciphertext's key as well as
// kms:ReEncryptTo on the destination, and an alias is moved or deleted only with the action on the key
// it names now, not just the key it is moved to.

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/policyengine"
)

// policyFor is a data-plane checker whose one policy applies to User::<user>.
func policyFor(user string, stmts ...policyengine.Statement) *dataplaneauthz.Checker {
	return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::" + user}, Statements: stmts}}}, nil
	}, time.Minute)
}

func (f *svcFixture) createKMSKey(t *testing.T) string {
	t.Helper()
	code, out := f.callJSON(t, f.kms.serve, "TrentService.CreateKey", map[string]any{})
	md, _ := out["KeyMetadata"].(map[string]any)
	id, _ := md["KeyId"].(string)
	if code != 200 || id == "" {
		t.Fatalf("CreateKey = %d %v", code, out)
	}
	return id
}

func TestServicesPG_KMSReEncryptAuthorizesSourceKey(t *testing.T) {
	f := newSvcFixture(t)
	src, dst := f.createKMSKey(t), f.createKMSKey(t)
	code, out := f.callJSON(t, f.kms.serve, "TrentService.Encrypt", map[string]any{"KeyId": src, "Plaintext": base64.StdEncoding.EncodeToString([]byte("secret"))})
	if code != 200 {
		t.Fatalf("Encrypt = %d %v", code, out)
	}
	blob := out["CiphertextBlob"]
	allowAll := policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"kms:*"}, Resources: []string{"*"}}
	reEncrypt := func() int {
		code, _ := f.callJSON(t, f.kms.serve, "TrentService.ReEncrypt", map[string]any{"CiphertextBlob": blob, "DestinationKeyId": dst})
		return code
	}

	f.kms.authz = policyFor("alice", allowAll)
	if code := reEncrypt(); code != 200 {
		t.Fatalf("ReEncrypt with kms:* = %d, want 200", code)
	}
	// The source key's Deny: the ciphertext cannot be moved out from under a key the caller may not read
	// through (the old code checked only the destination).
	f.kms.authz = policyFor("alice", allowAll,
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"kms:ReEncryptFrom"}, Resources: []string{"Key::" + src}})
	if code := reEncrypt(); code != 403 {
		t.Fatalf("ReEncrypt from a key denying kms:ReEncryptFrom = %d, want 403", code)
	}
	f.kms.authz = policyFor("alice", allowAll,
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"kms:ReEncryptTo"}, Resources: []string{"Key::" + dst}})
	if code := reEncrypt(); code != 403 {
		t.Fatalf("ReEncrypt to a key denying kms:ReEncryptTo = %d, want 403", code)
	}
	// A Deny on the source key's ReEncryptTo does not stop re-encrypting out of it: the actions are distinct.
	f.kms.authz = policyFor("alice", allowAll,
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"kms:ReEncryptTo"}, Resources: []string{"Key::" + src}})
	if code := reEncrypt(); code != 200 {
		t.Fatalf("ReEncrypt with ReEncryptTo denied only on the source = %d, want 200", code)
	}
}

func TestServicesPG_KMSAliasAuthorizesItsCurrentKey(t *testing.T) {
	f := newSvcFixture(t)
	a, b := f.createKMSKey(t), f.createKMSKey(t)
	if code, out := f.callJSON(t, f.kms.serve, "TrentService.CreateAlias", map[string]any{"AliasName": "alias/app", "TargetKeyId": a}); code != 200 {
		t.Fatalf("CreateAlias = %d %v", code, out)
	}
	allowAll := policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"kms:*"}, Resources: []string{"*"}}
	deny := func(action, key string) *dataplaneauthz.Checker {
		return policyFor("alice", allowAll, policyengine.Statement{Effect: policyengine.Deny, Actions: []string{action}, Resources: []string{"Key::" + key}})
	}
	update := func(target string) int {
		code, _ := f.callJSON(t, f.kms.serve, "TrentService.UpdateAlias", map[string]any{"AliasName": "alias/app", "TargetKeyId": target})
		return code
	}

	// The key the alias names now: a caller denied UpdateAlias on it cannot take the alias away from it.
	f.kms.authz = deny("kms:UpdateAlias", a)
	if code := update(b); code != 403 {
		t.Fatalf("UpdateAlias off a key denying kms:UpdateAlias = %d, want 403", code)
	}
	// The key it would name.
	f.kms.authz = deny("kms:UpdateAlias", b)
	if code := update(b); code != 403 {
		t.Fatalf("UpdateAlias onto a key denying kms:UpdateAlias = %d, want 403", code)
	}
	// DeleteAlias is authorized on the key the alias names.
	f.kms.authz = deny("kms:DeleteAlias", a)
	if code, _ := f.callJSON(t, f.kms.serve, "TrentService.DeleteAlias", map[string]any{"AliasName": "alias/app"}); code != 403 {
		t.Fatalf("DeleteAlias of an alias on a key denying kms:DeleteAlias = %d, want 403", code)
	}
	f.kms.authz = policyFor("alice", allowAll)
	if code := update(b); code != 200 {
		t.Fatalf("UpdateAlias with kms:* = %d, want 200", code)
	}
	if id, ok, _ := f.kms.store.aliasTarget(context.Background(), "alias/app"); !ok || id != b {
		t.Fatalf("alias/app names %q, want %q", id, b)
	}
}

// A stack's alias is checked as the KMS front door checks it: moved off, or deleted from, the key it names
// now only with the action on that key — an alias repointed outside the stack is not the stack's to move.
func TestServicesPG_KMSStackAliasAuthorizesItsCurrentKey(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	a, b, c := f.createKMSKey(t), f.createKMSKey(t), f.createKMSKey(t)
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindKMSAlias, "alias/st", "st", map[string]any{"aliasName": "alias/st", "targetKeyId": b})); err != nil {
		t.Fatal(err)
	}
	// Pointed elsewhere through the API: the alias now names a.
	if code, out := f.callJSON(t, f.kms.serve, "TrentService.UpdateAlias", map[string]any{"AliasName": "alias/st", "TargetKeyId": a}); code != 200 {
		t.Fatalf("UpdateAlias = %d %v", code, out)
	}
	allowAll := policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"kms:*"}, Resources: []string{"*"}}
	f.ap.door.authz = policyFor("alice", allowAll,
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"kms:UpdateAlias", "kms:DeleteAlias"}, Resources: []string{"Key::" + a}})
	if err := f.ap.Apply(ctx, svcManifest(cfn.KindKMSAlias, "alias/st", "st", map[string]any{"aliasName": "alias/st", "targetKeyId": c})); err == nil {
		t.Fatal("a stack update moved an alias off a key denying kms:UpdateAlias")
	}
	if err := f.ap.Delete(ctx, cfn.ServiceAPIVersion, cfn.KindKMSAlias, "alias/st"); err == nil {
		t.Fatal("a stack delete removed an alias naming a key denying kms:DeleteAlias")
	}
	if id, _, _ := f.kms.store.aliasTarget(ctx, "alias/st"); id != a {
		t.Fatalf("alias/st names %q, want %q (unchanged)", id, a)
	}
	f.ap.door.authz = policyFor("alice", allowAll)
	if err := f.ap.Apply(ctx, svcManifest(cfn.KindKMSAlias, "alias/st", "st", map[string]any{"aliasName": "alias/st", "targetKeyId": c})); err != nil {
		t.Fatalf("a permitted stack update: %v", err)
	}
}
