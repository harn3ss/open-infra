package main

// Each account's parameters are its own (real Postgres store, OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go): the same name in both accounts, each with its own versions, ARN and — for a
// SecureString — value bound to its account's key; a path query reads one account's subtree, and neither
// account reads, lists, tags or deletes the other's. The calls are made as the router makes them once the
// "ssm" door is listed as account-scoped (see ssm.go).

import (
	"context"
	"sort"
	"testing"
)

func TestSSMPG_EachAccountKeepsItsOwnParameters(t *testing.T) {
	ctx := context.Background()
	st := &ssmStore{db: freshPGDB(t)}
	if err := st.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	h := newSSMHandler(csWithSAR(true), "authz", testMgmt, "us-east-1", fakeVault(t), st, discardLogger())
	h.authz = doorAccountsAuthz(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	ssm := func(c doorCaller, op string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return c.call(t, h.serve, "AmazonSSM."+op, body)
	}
	put := func(c doorCaller, name, typ, value string) {
		t.Helper()
		if code, out := ssm(c, "PutParameter", map[string]any{"Name": name, "Type": typ, "Value": value}); code != 200 {
			t.Fatalf("PutParameter %s = %d %v", name, code, out)
		}
	}
	put(mgmt, "/app/db/host", "String", "mgmt-host")
	put(mgmt, "/app/db/pass", "SecureString", "mgmt-pw")
	put(member, "/app/db/host", "String", "member-host")
	put(member, "/app/db/pass", "SecureString", "member-pw")
	put(member, "/app/only-member", "String", "x")
	if _, ok, _ := st.getParam(ctx, "/app/db/host"); !ok {
		t.Error("the management account's parameter is stored as it always was")
	}
	if _, ok, _ := st.getParam(ctx, testMember+":/app/db/host"); !ok {
		t.Error("the member account's parameter is stored under its account's key")
	}

	// Each reads its own, with its own ARN; a SecureString decrypts to its own account's value.
	for _, c := range []struct {
		who              doorCaller
		acct, host, pass string
	}{{mgmt, testMgmt, "mgmt-host", "mgmt-pw"}, {member, testMember, "member-host", "member-pw"}} {
		_, out := ssm(c.who, "GetParameter", map[string]any{"Name": "/app/db/host"})
		p, _ := out["Parameter"].(map[string]any)
		if p["Value"] != c.host || p["Name"] != "/app/db/host" || p["ARN"] != "arn:aws:ssm:us-east-1:"+c.acct+":parameter/app/db/host" {
			t.Errorf("GetParameter (%s) = %v", c.acct, out)
		}
		_, out = ssm(c.who, "GetParameter", map[string]any{"Name": "/app/db/pass", "WithDecryption": true})
		if p, _ := out["Parameter"].(map[string]any); p["Value"] != c.pass {
			t.Errorf("GetParameter WithDecryption (%s) = %v", c.acct, out)
		}
		_, out = ssm(c.who, "GetParameterHistory", map[string]any{"Name": "/app/db/pass", "WithDecryption": true})
		if ps := sliceOf(out["Parameters"]); len(ps) != 1 || ps[0].(map[string]any)["Value"] != c.pass {
			t.Errorf("GetParameterHistory (%s) = %v", c.acct, out)
		}
	}
	// A member account's SecureString is bound to its account's key: it does not decrypt as the
	// management account's parameter of that name.
	ct, _, _ := st.getVersion(ctx, testMember+":/app/db/pass", 1)
	if _, err := h.decryptValue(ctx, "/app/db/pass", ct); err == nil {
		t.Error("the member account's SecureString decrypted as the management account's parameter")
	}

	// Path queries and listings: each account's own parameters alone.
	names := func(out map[string]any) []string {
		var ns []string
		for _, p := range sliceOf(out["Parameters"]) {
			ns = append(ns, p.(map[string]any)["Name"].(string))
		}
		sort.Strings(ns)
		return ns
	}
	same := func(got []string, want ...string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}
	_, out := ssm(member, "GetParametersByPath", map[string]any{"Path": "/app", "Recursive": true})
	if got := names(out); !same(got, "/app/db/host", "/app/db/pass", "/app/only-member") {
		t.Errorf("the member account's GetParametersByPath = %v", got)
	}
	_, out = ssm(member, "GetParametersByPath", map[string]any{"Path": "/app"})
	if got := names(out); !same(got, "/app/only-member") {
		t.Errorf("the member account's one-level GetParametersByPath = %v", got)
	}
	_, out = ssm(mgmt, "GetParametersByPath", map[string]any{"Path": "/app", "Recursive": true})
	if got := names(out); !same(got, "/app/db/host", "/app/db/pass") {
		t.Errorf("the management account's GetParametersByPath = %v", got)
	}
	for _, path := range []string{testMember + ":/app", testMember + ":", "%"} {
		_, out = ssm(mgmt, "GetParametersByPath", map[string]any{"Path": path, "Recursive": true})
		for _, n := range names(out) {
			if n != "/app/db/host" && n != "/app/db/pass" {
				t.Errorf("the management account's GetParametersByPath %q listed %q", path, n)
			}
		}
	}
	_, out = ssm(member, "DescribeParameters", map[string]any{})
	if got := names(out); !same(got, "/app/db/host", "/app/db/pass", "/app/only-member") {
		t.Errorf("the member account's DescribeParameters = %v", got)
	}
	for _, p := range sliceOf(out["Parameters"]) {
		if p := p.(map[string]any); p["ARN"] != "arn:aws:ssm:us-east-1:"+testMember+":parameter"+p["Name"].(string) {
			t.Errorf("the member account's DescribeParameters ARN %v", p["ARN"])
		}
	}
	_, out = ssm(mgmt, "DescribeParameters", map[string]any{})
	if got := names(out); !same(got, "/app/db/host", "/app/db/pass") {
		t.Errorf("the management account's DescribeParameters = %v", got)
	}

	// Neither reaches the other's.
	if code, out := ssm(member, "GetParameter", map[string]any{"Name": "arn:aws:ssm:us-east-1:" + testMgmt + ":parameter/app/db/host"}); code != 400 || jsonErrType(out) != "ParameterNotFound" {
		t.Errorf("the member account read the management account's parameter by its ARN: %d %v", code, out)
	}
	_, out = ssm(mgmt, "GetParameters", map[string]any{"Names": []any{"/app/only-member", "/app/db/host"}})
	if got := names(out); !same(got, "/app/db/host") || len(sliceOf(out["InvalidParameters"])) != 1 {
		t.Errorf("the management account's GetParameters = %v", out)
	}
	for _, op := range []string{"ListTagsForResource", "AddTagsToResource"} {
		if code, out := ssm(mgmt, op, map[string]any{"ResourceType": "Parameter", "ResourceId": testMember + ":/app/db/host",
			"Tags": []any{map[string]any{"Key": "k", "Value": "v"}}}); code != 400 || jsonErrType(out) != "InvalidResourceId" {
			t.Errorf("the management account's %s on the member account's store key = %d %v", op, code, out)
		}
	}
	if code, out := ssm(mgmt, "LabelParameterVersion", map[string]any{"Name": "/app/only-member", "Labels": []any{"prod"}}); code != 400 {
		t.Errorf("the management account labelled the member account's parameter: %d %v", code, out)
	}
	if code, out := ssm(member, "LabelParameterVersion", map[string]any{"Name": "/app/only-member", "Labels": []any{"prod"}}); code != 200 {
		t.Errorf("the member account's LabelParameterVersion = %d %v", code, out)
	}
	if _, out := ssm(member, "GetParameter", map[string]any{"Name": "/app/only-member:prod"}); out["Parameter"] == nil {
		t.Errorf("the member account's parameter by its label: %v", out)
	}

	// Deleting the member account's parameter leaves the management account's of the same name.
	if code, out := ssm(member, "DeleteParameter", map[string]any{"Name": "/app/db/host"}); code != 200 {
		t.Fatalf("DeleteParameter = %d %v", code, out)
	}
	_, out = ssm(member, "DeleteParameters", map[string]any{"Names": []any{"/app/db/pass"}})
	if len(sliceOf(out["DeletedParameters"])) != 1 {
		t.Fatalf("DeleteParameters = %v", out)
	}
	for _, name := range []string{"/app/db/host", "/app/db/pass"} {
		if _, out := ssm(mgmt, "GetParameter", map[string]any{"Name": name}); out["Parameter"] == nil {
			t.Errorf("the management account's %s after the member account deleted its own: %v", name, out)
		}
	}
	if code, _ := ssm(mgmt, "DeleteParameter", map[string]any{"Name": "/app/only-member"}); code != 400 {
		t.Errorf("the management account deleted the member account's parameter: %d", code)
	}
}
