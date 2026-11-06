package main

// Each account's secrets are its own (real Postgres store, OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go): the same name in both accounts, each with its own ARN, versions and value —
// a member account's value bound to its account's key — and neither account reads, lists or plants the
// other's.

import (
	"context"
	"strings"
	"testing"
)

func TestSecretsPG_EachAccountKeepsItsOwnSecrets(t *testing.T) {
	ctx := context.Background()
	st := &secretsStore{db: freshPGDB(t)}
	if err := st.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	h := newSecretsHandler(csWithSAR(true), "authz", testMgmt, "us-east-1", fakeVault(t), st, discardLogger())
	h.authz = doorAccountsAuthz(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	sm := func(c doorCaller, op string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return c.call(t, h.serve, "secretsmanager."+op, body)
	}

	// The same name in both accounts.
	arns := map[string]string{}
	for _, c := range []struct {
		who        doorCaller
		acct, word string
	}{{mgmt, testMgmt, "mgmt-pw"}, {member, testMember, "member-pw"}} {
		code, out := sm(c.who, "CreateSecret", map[string]any{"Name": "db/password", "SecretString": c.word})
		arn, _ := out["ARN"].(string)
		if code != 200 || out["Name"] != "db/password" || !strings.HasPrefix(arn, "arn:aws:secretsmanager:us-east-1:"+c.acct+":secret:db/password-") {
			t.Fatalf("CreateSecret (%s) = %d %v", c.acct, code, out)
		}
		arns[c.acct] = arn
	}
	if m, ok, _ := st.getSecret(ctx, "db/password"); !ok || m.Arn != arns[testMgmt] {
		t.Errorf("the management account's secret is stored as it always was: %v %v", m.Arn, ok)
	}
	if m, ok, _ := st.getSecret(ctx, testMember+":db/password"); !ok || m.Arn != arns[testMember] {
		t.Errorf("the member account's secret is stored under its account's key: %v %v", m.Arn, ok)
	}

	// Each reads its own value, by name and by its own ARN.
	for _, c := range []struct {
		who        doorCaller
		acct, word string
	}{{mgmt, testMgmt, "mgmt-pw"}, {member, testMember, "member-pw"}} {
		for _, id := range []string{"db/password", arns[c.acct]} {
			code, out := sm(c.who, "GetSecretValue", map[string]any{"SecretId": id})
			if code != 200 || out["SecretString"] != c.word || out["Name"] != "db/password" || out["ARN"] != arns[c.acct] {
				t.Errorf("GetSecretValue (%s, %s) = %d %v", c.acct, id, code, out)
			}
		}
	}
	// A member account's value is bound to its account's key: it does not decrypt as the management
	// account's secret of that name.
	_, ct, _, _, _ := st.versionByStage(ctx, testMember+":db/password", "AWSCURRENT")
	if _, err := h.decryptValue(ctx, "db/password", ct); err == nil {
		t.Error("the member account's ciphertext decrypted as the management account's secret")
	}

	// Neither reaches the other's: by the other's ARN, or by the member account's store key.
	for _, tc := range []struct {
		name string
		who  doorCaller
		id   string
	}{
		{"member, the management account's ARN", member, arns[testMgmt]},
		{"management, the member account's store key", mgmt, testMember + ":db/password"},
	} {
		for _, op := range []string{"GetSecretValue", "DescribeSecret", "PutSecretValue", "DeleteSecret"} {
			code, out := sm(tc.who, op, map[string]any{"SecretId": tc.id, "SecretString": "planted"})
			if code != 400 || jsonErrType(out) != "ResourceNotFoundException" {
				t.Errorf("%s, %s = %d %v, want ResourceNotFoundException", tc.name, op, code, out)
			}
		}
	}
	// The management account cannot plant a secret in the member account's keys.
	if code, out := sm(mgmt, "CreateSecret", map[string]any{"Name": testMember + ":planted", "SecretString": "x"}); code != 400 || jsonErrType(out) != "InvalidParameterException" {
		t.Errorf("the management account created a secret under a member account's key: %d %v", code, out)
	}

	// Listings: each account's own secrets alone.
	if code, out := sm(member, "CreateSecret", map[string]any{"Name": "member-only", "SecretString": "x"}); code != 200 {
		t.Fatalf("CreateSecret = %d %v", code, out)
	}
	list := func(c doorCaller) map[string]string {
		t.Helper()
		_, out := sm(c, "ListSecrets", map[string]any{})
		got := map[string]string{}
		for _, e := range sliceOf(out["SecretList"]) {
			m := e.(map[string]any)
			got[m["Name"].(string)], _ = m["ARN"].(string)
		}
		return got
	}
	if got := list(member); len(got) != 2 || got["db/password"] != arns[testMember] || got["member-only"] == "" {
		t.Errorf("the member account's ListSecrets = %v", got)
	}
	if got := list(mgmt); len(got) != 1 || got["db/password"] != arns[testMgmt] {
		t.Errorf("the management account's ListSecrets = %v", got)
	}

	// Deleting the member account's secret leaves the management account's of the same name.
	if code, out := sm(member, "DeleteSecret", map[string]any{"SecretId": "db/password", "ForceDeleteWithoutRecovery": true}); code != 200 {
		t.Fatalf("DeleteSecret = %d %v", code, out)
	}
	if code, out := sm(mgmt, "GetSecretValue", map[string]any{"SecretId": "db/password"}); code != 200 || out["SecretString"] != "mgmt-pw" {
		t.Errorf("the management account's secret after the member account deleted its own: %d %v", code, out)
	}
	if code, _ := sm(member, "GetSecretValue", map[string]any{"SecretId": "db/password"}); code != 400 {
		t.Errorf("the member account's deleted secret still reads: %d", code)
	}
}

// Secrets Manager keeps each account's secrets apart, so the router decides a member account's principal
// there on its own account's secrets.
func TestSecrets_IsAccountScoped(t *testing.T) {
	if !accountScopedServices["secretsmanager"] {
		t.Error("secretsmanager is not listed as account-scoped")
	}
}
