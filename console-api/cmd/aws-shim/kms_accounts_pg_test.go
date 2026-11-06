package main

// Each account's KMS keys, aliases and key policies are its own (real Postgres store, OPENINFRA_TEST_PG_URI;
// see cfn_services_pg_test.go): a member account's key carries its account in its ARN, the same alias name
// lives in both accounts independently, and neither account resolves, lists, decrypts under or re-points
// the other's.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// doorCaller calls a front door as one account's principal, as the router does: a member account's
// request carries its identity and home, and a request to an account-scoped door is marked so.
type doorCaller struct {
	ctx    context.Context
	claims iam.Claims
}

// mgmtDoorCaller is the management account's alice; memberDoorCaller the member account's bob.
func mgmtDoorCaller() doorCaller {
	return doorCaller{ctx: inAccountScope(context.Background()), claims: iam.Claims{Sub: "alice"}}
}

func memberDoorCaller() doorCaller {
	return doorCaller{ctx: inAccountScope(memberCtx()), claims: iam.Claims{Sub: "bob", Account: testMember}}
}

// doorAccountsAuthz decides by IAM policy alone (enforce): the management account's alice and the member
// account's bob may each do anything, so every refusal in these tests is the door keeping accounts apart.
func doorAccountsAuthz(t *testing.T) *dataplaneauthz.Checker {
	all := []policyengine.Statement{dpAllow([]string{"*"}, "*")}
	return checkerInMode(t, "enforce",
		dataplaneauthz.PolicyDoc{Name: "alice-all", AppliesTo: []string{"User::alice"}, Statements: all},
		dataplaneauthz.PolicyDoc{Name: "bob-all", AppliesTo: []string{"User::" + memberHome + "/bob"}, Statements: all})
}

func (c doorCaller) call(t *testing.T, serve func(http.ResponseWriter, *http.Request, iam.Claims, string), target string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "http://shim.local:4566/", bytes.NewReader(b)).WithContext(c.ctx)
	r.Header.Set("X-Amz-Target", target)
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	w := httptest.NewRecorder()
	serve(w, r, c.claims, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// jsonErrType is an AWS JSON error's __type ("" for a success).
func jsonErrType(out map[string]any) string { s, _ := out["__type"].(string); return s }

func TestKMSPG_EachAccountKeepsItsOwnKeys(t *testing.T) {
	ctx := context.Background()
	st := &kmsStore{db: freshPGDB(t)}
	if err := st.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvrPolicies: "PolicyList"})
	const policiesNS = "open-infra-console"
	h := newKMSHandler(csWithSAR(true), dyn, policiesNS, "authz", testMgmt, "us-east-1", fakeVault(t), st, discardLogger())
	h.authz = doorAccountsAuthz(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	kms := func(c doorCaller, op string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return c.call(t, h.serve, "TrentService."+op, body)
	}
	createKey := func(c doorCaller) map[string]any {
		t.Helper()
		code, out := kms(c, "CreateKey", map[string]any{})
		md, _ := out["KeyMetadata"].(map[string]any)
		if code != 200 || md == nil {
			t.Fatalf("CreateKey = %d %v", code, out)
		}
		return md
	}
	mk, bk := createKey(mgmt), createKey(member)
	mID, bID := mk["KeyId"].(string), bk["KeyId"].(string)
	mARN, bARN := "arn:aws:kms:us-east-1:"+testMgmt+":key/"+mID, "arn:aws:kms:us-east-1:"+testMember+":key/"+bID
	if mk["Arn"] != mARN || mk["AWSAccountId"] != testMgmt {
		t.Errorf("the management account's key: %v %v", mk["Arn"], mk["AWSAccountId"])
	}
	if bk["Arn"] != bARN || bk["AWSAccountId"] != testMember {
		t.Errorf("the member account's key must carry its account: %v %v", bk["Arn"], bk["AWSAccountId"])
	}

	// The same alias name in both accounts, each its own.
	for _, c := range []struct {
		who doorCaller
		key string
	}{{mgmt, mID}, {member, bID}} {
		if code, out := kms(c.who, "CreateAlias", map[string]any{"AliasName": "alias/app", "TargetKeyId": c.key}); code != 200 {
			t.Fatalf("CreateAlias = %d %v", code, out)
		}
	}
	if id, ok, _ := st.aliasTarget(ctx, "alias/app"); !ok || id != mID {
		t.Errorf("the management account's alias is stored as it always was: %q %v", id, ok)
	}
	if id, ok, _ := st.aliasTarget(ctx, testMember+":alias/app"); !ok || id != bID {
		t.Errorf("the member account's alias is stored under its account's key: %q %v", id, ok)
	}

	describe := func(c doorCaller, ref string) (int, string) {
		t.Helper()
		code, out := kms(c, "DescribeKey", map[string]any{"KeyId": ref})
		md, _ := out["KeyMetadata"].(map[string]any)
		id, _ := md["KeyId"].(string)
		if code != 200 {
			return code, jsonErrType(out)
		}
		return code, id
	}
	// Each account reaches its own key by id, ARN and alias — and never the other's.
	for _, tc := range []struct {
		name     string
		who      doorCaller
		ref, key string
	}{
		{"member by id", member, bID, bID},
		{"member by ARN", member, bARN, bID},
		{"member by alias", member, "alias/app", bID},
		{"member by alias ARN", member, "arn:aws:kms:us-east-1:" + testMember + ":alias/app", bID},
		{"management by id", mgmt, mID, mID},
		{"management by alias", mgmt, "alias/app", mID},
		// A ref spelled as the member account's alias key is read as an alias ARN: the management
		// account's own alias of that name, never the member's.
		{"management, the member account's alias store key", mgmt, testMember + ":alias/app", mID},
	} {
		if code, got := describe(tc.who, tc.ref); code != 200 || got != tc.key {
			t.Errorf("%s: %d %s, want %s", tc.name, code, got, tc.key)
		}
	}
	for _, tc := range []struct {
		name string
		who  doorCaller
		ref  string
	}{
		{"member, the management account's key id", member, mID},
		{"member, the management account's key ARN", member, mARN},
		{"member, the management account's alias ARN", member, "arn:aws:kms:us-east-1:" + testMgmt + ":alias/app"},
		{"management, the member account's key id", mgmt, bID},
		{"management, the member account's key ARN", mgmt, bARN},
	} {
		if code, got := describe(tc.who, tc.ref); code != 400 || got != "NotFoundException" {
			t.Errorf("%s: %d %s, want NotFoundException", tc.name, code, got)
		}
	}

	// Listings: each account's own keys and aliases alone.
	listKeys := func(c doorCaller) []string {
		t.Helper()
		_, out := kms(c, "ListKeys", map[string]any{})
		var ids []string
		for _, k := range sliceOf(out["Keys"]) {
			ids = append(ids, k.(map[string]any)["KeyId"].(string))
		}
		return ids
	}
	if got := listKeys(member); len(got) != 1 || got[0] != bID {
		t.Errorf("the member account's ListKeys = %v, want [%s]", got, bID)
	}
	if got := listKeys(mgmt); len(got) != 1 || got[0] != mID {
		t.Errorf("the management account's ListKeys = %v, want [%s]", got, mID)
	}
	for _, tc := range []struct {
		who       doorCaller
		acct, key string
	}{{member, testMember, bID}, {mgmt, testMgmt, mID}} {
		_, out := kms(tc.who, "ListAliases", map[string]any{})
		as := sliceOf(out["Aliases"])
		if len(as) != 1 {
			t.Fatalf("ListAliases (%s) = %v", tc.acct, out)
		}
		a := as[0].(map[string]any)
		if a["AliasName"] != "alias/app" || a["TargetKeyId"] != tc.key || a["AliasArn"] != "arn:aws:kms:us-east-1:"+tc.acct+":alias/app" {
			t.Errorf("ListAliases (%s) = %v", tc.acct, a)
		}
	}

	// Ciphertext under one account's key does not decrypt in the other.
	pt := base64.StdEncoding.EncodeToString([]byte("secret"))
	_, out := kms(member, "Encrypt", map[string]any{"KeyId": "alias/app", "Plaintext": pt})
	memberBlob := out["CiphertextBlob"]
	_, out = kms(mgmt, "Encrypt", map[string]any{"KeyId": "alias/app", "Plaintext": pt})
	mgmtBlob := out["CiphertextBlob"]
	if code, out := kms(member, "Decrypt", map[string]any{"CiphertextBlob": memberBlob}); code != 200 || out["Plaintext"] != pt || out["KeyId"] != bARN {
		t.Errorf("the member account decrypting its own ciphertext: %d %v", code, out)
	}
	if code, out := kms(mgmt, "Decrypt", map[string]any{"CiphertextBlob": memberBlob}); code != 400 || jsonErrType(out) != "NotFoundException" {
		t.Errorf("the management account decrypted under the member account's key: %d %v", code, out)
	}
	if code, out := kms(member, "Decrypt", map[string]any{"CiphertextBlob": mgmtBlob}); code != 400 || jsonErrType(out) != "NotFoundException" {
		t.Errorf("the member account decrypted under the management account's key: %d %v", code, out)
	}
	if code, out := kms(member, "ReEncrypt", map[string]any{"CiphertextBlob": mgmtBlob, "DestinationKeyId": bID}); code != 400 {
		t.Errorf("the member account re-encrypted out of the management account's key: %d %v", code, out)
	}

	// Aliases: the management account never reaches the member's by its store key, and a member's alias
	// never names the management account's key.
	if code, _ := kms(mgmt, "DeleteAlias", map[string]any{"AliasName": testMember + ":alias/app"}); code != 400 {
		t.Errorf("the management account deleted the member account's alias: %d", code)
	}
	if code, _ := kms(mgmt, "UpdateAlias", map[string]any{"AliasName": testMember + ":alias/app", "TargetKeyId": mID}); code != 400 {
		t.Errorf("the management account re-pointed the member account's alias: %d", code)
	}
	if code, _ := kms(member, "CreateAlias", map[string]any{"AliasName": "alias/other", "TargetKeyId": mID}); code != 400 {
		t.Errorf("the member account aliased the management account's key: %d", code)
	}
	if id, _, _ := st.aliasTarget(ctx, testMember+":alias/app"); id != bID {
		t.Errorf("the member account's alias names %q, want %q (unchanged)", id, bID)
	}
	// An alias in the management account's names that names a member account's key (written to the store
	// directly, as no front-door call can) is neither listed nor resolved there.
	if err := st.createAlias(ctx, "alias/stray", bID); err != nil {
		t.Fatal(err)
	}
	if code, got := describe(mgmt, "alias/stray"); code != 400 || got != "NotFoundException" {
		t.Errorf("the management account resolved an alias naming the member account's key: %d %s", code, got)
	}
	if _, out := kms(mgmt, "ListAliases", map[string]any{}); len(sliceOf(out["Aliases"])) != 1 {
		t.Errorf("the management account listed an alias naming the member account's key: %v", out)
	}

	// Key policies: the default names the key's own account's root; an imported policy's objects live in
	// the key's account's namespace; a member account's key policy grants its own principals only.
	if _, out := kms(member, "GetKeyPolicy", map[string]any{"KeyId": bID}); !strings.Contains(out["Policy"].(string), "arn:aws:iam::"+testMember+":root") {
		t.Errorf("the member account's default key policy: %v", out["Policy"])
	}
	if _, out := kms(mgmt, "GetKeyPolicy", map[string]any{"KeyId": mID}); !strings.Contains(out["Policy"].(string), "arn:aws:iam::"+testMgmt+":root") {
		t.Errorf("the management account's default key policy: %v", out["Policy"])
	}
	policy := func(principal string) string {
		return `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"` + principal + `"},"Action":"kms:Decrypt","Resource":"*"}]}`
	}
	if code, out := kms(member, "PutKeyPolicy", map[string]any{"KeyId": bID, "Policy": policy("arn:aws:iam::" + testMember + ":user/carol")}); code != 200 {
		t.Fatalf("the member account's PutKeyPolicy = %d %v", code, out)
	}
	if code, out := kms(mgmt, "PutKeyPolicy", map[string]any{"KeyId": mID, "Policy": policy("arn:aws:iam::" + testMgmt + ":user/dave")}); code != 200 {
		t.Fatalf("the management account's PutKeyPolicy = %d %v", code, out)
	}
	if code, out := kms(member, "PutKeyPolicy", map[string]any{"KeyId": bID, "Policy": policy("arn:aws:iam::" + testMgmt + ":user/dave")}); code != 400 || jsonErrType(out) != "MalformedPolicyDocumentException" {
		t.Errorf("a member account's key policy granted another account's principal: %d %v", code, out)
	}
	policyCRs := func(ns, keyID string) int {
		t.Helper()
		l, err := dyn.Resource(gvrPolicies).Namespace(ns).List(ctx, metav1.ListOptions{LabelSelector: kmsKeyPolicyLabel + "=" + keyID})
		if err != nil {
			t.Fatal(err)
		}
		return len(l.Items)
	}
	if policyCRs(memberHome, bID) != 1 || policyCRs(policiesNS, bID) != 0 {
		t.Errorf("the member account's key policy objects: %d in its home, %d in the management account's", policyCRs(memberHome, bID), policyCRs(policiesNS, bID))
	}
	if policyCRs(policiesNS, mID) != 1 {
		t.Errorf("the management account's key policy objects: %d", policyCRs(policiesNS, mID))
	}

	// The reaper crypto-erases each account's key once its window has passed, and its policy objects
	// with it, in its own account's namespace.
	if code, out := kms(member, "ScheduleKeyDeletion", map[string]any{"KeyId": bID, "PendingWindowInDays": 7}); code != 200 {
		t.Fatalf("ScheduleKeyDeletion = %d %v", code, out)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE kms_keys SET deletion_date = now() - interval '1 minute' WHERE key_id=$1`, bID); err != nil {
		t.Fatal(err)
	}
	if err := h.reapDeleted(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := st.getKey(ctx, bID); found {
		t.Error("the member account's key was not reaped")
	}
	if policyCRs(memberHome, bID) != 0 {
		t.Error("the member account's key policy objects outlived its key")
	}
	if _, found, _ := st.getKey(ctx, mID); !found || policyCRs(policiesNS, mID) != 1 {
		t.Error("reaping the member account's key touched the management account's")
	}
}

// A key belongs to the account its ARN names: the management account's for its own account (the install's,
// or the handler's) or none, a member account's for that account alone.
func TestKMS_KeyBelongsToTheAccountItsARNNames(t *testing.T) {
	h := newKMSHandler(csWithSAR(true), nil, "p", "authz", "123456789012", "us-east-1", nil, nil, discardLogger())
	mgmt, member := context.Background(), memberCtx()
	for _, tc := range []struct {
		arn                  string
		mgmtOwns, memberOwns bool
	}{
		{"arn:aws:kms:us-east-1:123456789012:key/k", true, false},
		{"arn:aws:kms:us-east-1:" + testMgmt + ":key/k", true, false},
		{"arn:aws:kms:us-east-1:open-infra:key/k", true, false},
		{"", true, false},
		{"arn:aws:kms:us-east-1:" + testMember + ":key/k", false, true},
		{"arn:aws:kms:us-east-1:955555555555:key/k", false, false},
	} {
		m := keyMeta{KeyID: "k", Arn: tc.arn}
		if got := h.ownsKey(mgmt, m); got != tc.mgmtOwns {
			t.Errorf("%q: the management account owns it = %v, want %v", tc.arn, got, tc.mgmtOwns)
		}
		if got := h.ownsKey(member, m); got != tc.memberOwns {
			t.Errorf("%q: the member account owns it = %v, want %v", tc.arn, got, tc.memberOwns)
		}
	}
	if h.keyARNIn(mgmt, "k") != h.keyARN("k") || h.keyARNIn(member, "k") != "arn:aws:kms:us-east-1:"+testMember+":key/k" {
		t.Errorf("key ARNs: %q %q", h.keyARNIn(mgmt, "k"), h.keyARNIn(member, "k"))
	}
	if !h.foreignRef(member, "arn:aws:kms:us-east-1:"+testMgmt+":key/k") || h.foreignRef(member, "arn:aws:kms:us-east-1:"+testMember+":key/k") ||
		h.foreignRef(mgmt, "arn:aws:kms:us-east-1:"+testMember+":key/k") || h.foreignRef(member, "alias/x") {
		t.Error("foreignRef: a member account's request naming another account's ARN, only")
	}
}

// A member account's key policy grants its own account's principals only; the management account's
// translation is unchanged.
func TestKMS_MemberKeyPolicyRefusesAnotherAccountsPrincipal(t *testing.T) {
	h := newKMSHandler(csWithSAR(true), nil, "p", "authz", testMgmt, "us-east-1", nil, nil, discardLogger())
	doc := func(p string) string {
		return `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["` + p + `"]},"Action":"kms:Decrypt","Resource":"*"}]}`
	}
	if _, err := h.translateKeyPolicyIn(memberCtx(), doc("arn:aws:iam::"+testMember+":role/app"), testKeyID); err != nil {
		t.Errorf("the member account's own role: %v", err)
	}
	for _, p := range []string{"arn:aws:iam::" + testMgmt + ":role/app", "arn:aws:iam::" + testMgmt + ":root", testMgmt} {
		if _, err := h.translateKeyPolicyIn(memberCtx(), doc(p), testKeyID); err == nil {
			t.Errorf("the member account's key policy granted %q", p)
		}
	}
	if _, err := h.translateKeyPolicyIn(context.Background(), doc("arn:aws:iam::"+testMember+":role/app"), testKeyID); err != nil {
		t.Errorf("the management account's translation must not change: %v", err)
	}
}

// KMS keeps each account's keys apart, so the router decides a member account's principal there on its own
// account's keys.
func TestKMS_IsAccountScoped(t *testing.T) {
	if !accountScopedServices["kms"] {
		t.Error("kms is not listed as account-scoped")
	}
}
