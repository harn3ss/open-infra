package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A VM is its account's instance, as on AWS: a member account's VM assumes its instance role in that
// account, its identity document names that account, and a call signed with that document acts in it. The
// management account's VMs are exactly as before accounts.

// vmTestDirectory is testDirectory with a member account's second (not home) namespace.
func vmTestDirectory() *accounts.Directory {
	d := testDirectory()
	d.Observe(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a-dev", Labels: map[string]string{accounts.LabelAccountID: testMember}}})
	return d
}

func TestVMCreds_AMemberAccountsVMActsInItsAccount(t *testing.T) {
	h, m := testVMCreds(t)
	h.resolver = fakeSAResolver{byToken: map[string]saIdentity{
		"mgmt":      {role: "vmapp", namespace: "default", caller: "system:serviceaccount:default:vm-web01", vmName: "web01"},
		"member":    {role: "vmapp", namespace: memberHome, caller: "system:serviceaccount:team-a:vm-web01", vmName: "web01"},
		"memberdev": {role: "vmapp", namespace: "team-a-dev", caller: "system:serviceaccount:team-a-dev:vm-x", vmName: "x"},
		"suspended": {role: "vmapp", namespace: "team-b", caller: "system:serviceaccount:team-b:vm-y", vmName: "y"},
	}}
	h.trust = fakeTrust{vmRoles: map[string]bool{"default/vmapp": true, memberHome + "/vmapp": true, "team-a-dev/vmapp": true, "team-b/vmapp": true}}
	h.useAccounts(vmTestDirectory())
	session := func(token string) (string, string) {
		t.Helper()
		w := callVMCreds(h, http.MethodGet, token)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", token, w.Code, w.Body.String())
		}
		var c containerCreds
		_ = json.Unmarshal(w.Body.Bytes(), &c)
		sess, ok := m.Verify(c.AccessKeyID, c.Token)
		if !ok {
			t.Fatalf("%s: the minted token must verify", token)
		}
		return sess.Account, sess.Namespace
	}
	if acct, ns := session("mgmt"); acct != "" || ns != "default" {
		t.Errorf("the management account's VM: account %q namespace %q (as before accounts)", acct, ns)
	}
	if acct, ns := session("member"); acct != testMember || ns != memberHome {
		t.Errorf("the member account's VM: account %q namespace %q", acct, ns)
	}
	if acct, ns := session("memberdev"); acct != testMember || ns != "team-a-dev" {
		t.Errorf("a VM in the member account's other namespace: account %q namespace %q (its role lives there)", acct, ns)
	}
	if w := callVMCreds(h, http.MethodGet, "suspended"); w.Code != http.StatusForbidden {
		t.Errorf("a suspended account's VM gets no credentials: %d", w.Code)
	}
}

func TestVMIdentity_AMemberAccountsInstanceDocumentsItsAccount(t *testing.T) {
	dyn := identityDyn()
	addVM(t, dyn, "apps", "web", "uid-web", "Running")
	addVM(t, dyn, memberHome, "mweb", "uid-member-web", "Running") // composites are cluster-wide: another name
	h, s := testIdentityHandler(t, dyn, map[string]saIdentity{
		"tok-mgmt":   {namespace: "apps", vmName: "web"},
		"tok-member": {namespace: memberHome, vmName: "mweb"},
	})
	docOf := func(token string) map[string]any {
		t.Helper()
		rr := getIdentity(h, token)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", token, rr.Code, rr.Body)
		}
		var out signedIdentity
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		var doc map[string]any
		_ = json.Unmarshal([]byte(out.Document), &doc)
		return doc
	}
	// Without the directory every instance is the management account's, as before accounts.
	if doc := docOf("tok-member"); doc["accountId"] != "000000000000" {
		t.Errorf("no directory: %v", doc)
	}
	vmc := &vmCredsHandler{identity: h}
	vmc.useAccounts(vmTestDirectory())
	if doc := docOf("tok-mgmt"); doc["accountId"] != "000000000000" || doc["instanceId"] != instanceIDForUID("uid-web") {
		t.Errorf("the management account's instance: %v", doc)
	}
	if doc := docOf("tok-member"); doc["accountId"] != testMember || doc["instanceId"] != instanceIDForUID("uid-member-web") {
		t.Errorf("the member account's instance: %v", doc)
	}
	if s.accounts == nil {
		t.Error("the signer verifies with the directory too")
	}
}

// A document of an active member account verifies (CFN_V1), and the call acts in that account; another
// install's account, a suspended account, and a member account's document with no directory do not.
func TestIdentitySigner_VerifiesAMemberAccountsDocument(t *testing.T) {
	s, _, now := testIDSigner(t)
	fields := func(acct string) identityFields {
		return identityFields{AccountID: acct, Region: "us-east-1", AvailabilityZone: "us-east-1a", Architecture: "x86_64",
			ImageID: imageIDForOS("ubuntu-24.04"), InstanceID: instanceIDForUID("uid-x"), PendingTime: "2026-11-03T10:00:00Z"}
	}
	header := func(acct string) string { return cfnV1Auth(t, s, fields(acct), now.Add(s.ttl)) }
	ctx := context.Background()
	if _, err := s.verifyIdentity(ctx, header(testMember), "000000000000", "us-east-1"); err == nil {
		t.Fatal("with no directory a member account's document is another account's")
	}
	s.accounts = vmTestDirectory()
	c, err := s.verifyIdentity(ctx, header("000000000000"), "000000000000", "us-east-1")
	if err != nil || s.identityContext(ctx, c) != ctx {
		t.Fatalf("the management account's document, acting as before: %v", err)
	}
	c, err = s.verifyIdentity(ctx, header(testMember), "000000000000", "us-east-1")
	if err != nil {
		t.Fatalf("an active member account's document: %v", err)
	}
	mctx := s.identityContext(ctx, c)
	if callerAccount(mctx) != testMember || accountNamespace(mctx, "open-infra-cfn") != memberHome {
		t.Errorf("the call acts in the member account: %q %q", callerAccount(mctx), accountNamespace(mctx, "open-infra-cfn"))
	}
	for _, acct := range []string{"923456789012" /* suspended */, "955555555555" /* unknown */} {
		if _, err := s.verifyIdentity(ctx, header(acct), "000000000000", "us-east-1"); err == nil {
			t.Errorf("account %s's document must not verify", acct)
		}
	}
}
