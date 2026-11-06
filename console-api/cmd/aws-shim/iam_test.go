package main

import (
	"reflect"
	"sort"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

func TestParseTrustPolicy(t *testing.T) {
	// single statement, single principal user ARN
	got, err := parseTrustPolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::acct:user/alice"},"Action":"sts:AssumeRole"}]}`, "acct")
	if err != nil || !reflect.DeepEqual(got, []string{"alice"}) {
		t.Fatalf("single user: got %v err %v", got, err)
	}
	// principal "*" → "*"
	got, err = parseTrustPolicy(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`, "acct")
	if err != nil || !reflect.DeepEqual(got, []string{"*"}) {
		t.Fatalf("star principal: got %v err %v", got, err)
	}
	// list of AWS principals
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::a:user/bob","arn:aws:iam::a:user/carol"]},"Action":"sts:AssumeRole"}]}`, "a")
	sort.Strings(got)
	if err != nil || !reflect.DeepEqual(got, []string{"bob", "carol"}) {
		t.Fatalf("list principals: got %v err %v", got, err)
	}
	// a role ARN → that role's sessions (Role::), never a User of the same name
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::a:role/deployer"},"Action":"sts:AssumeRole"}]}`, "a")
	if err != nil || !reflect.DeepEqual(got, []string{"Role::deployer"}) {
		t.Fatalf("role principal: got %v err %v", got, err)
	}
	// an account's root ARN stays that ARN — the account's principals, matched by account — never "*"
	// (any principal of any account)
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}`, "111111111111")
	if err != nil || !reflect.DeepEqual(got, []string{"arn:aws:iam::111111111111:root"}) {
		t.Fatalf("root principal: got %v err %v", got, err)
	}
	// a bare account id is that account's root
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"sts:AssumeRole"}]}`, "111111111111")
	if err != nil || !reflect.DeepEqual(got, []string{"arn:aws:iam::222222222222:root"}) {
		t.Fatalf("account id principal: got %v err %v", got, err)
	}
	// another account's user or role stays its ARN, never a principal of this account of the same name
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::222222222222:user/bob","arn:aws:iam::222222222222:role/deployer"]},"Action":"sts:AssumeRole"}]}`, "111111111111")
	if err != nil || !reflect.DeepEqual(got, []string{"arn:aws:iam::222222222222:user/bob", "arn:aws:iam::222222222222:role/deployer"}) {
		t.Fatalf("another account's principals: got %v err %v", got, err)
	}
	// service principals, as an execution role's trust names them: EC2's is the instance principal "vm"
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"Service":["states.amazonaws.com","ec2.amazonaws.com"]},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, "111111111111")
	if err != nil || !reflect.DeepEqual(got, []string{"Service::states.amazonaws.com", "vm", "Service::lambda.amazonaws.com"}) {
		t.Fatalf("service principals: got %v err %v", got, err)
	}
	if !trustsService(got, "states.amazonaws.com") || trustsService(got, "ecs-tasks.amazonaws.com") {
		t.Fatal("trustsService")
	}
	// a user path is the user's name
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/team/alice"},"Action":"sts:AssumeRole"}]}`, "111111111111")
	if err != nil || !reflect.DeepEqual(got, []string{"alice"}) {
		t.Fatalf("user with a path: got %v err %v", got, err)
	}
	// Deny statements ignored → no principal → error
	if _, err := parseTrustPolicy(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}`, "acct"); err == nil {
		t.Error("a Deny-only trust policy should yield no assumable principal")
	}
	// empty → error
	if _, err := parseTrustPolicy("", "acct"); err == nil {
		t.Error("empty trust policy should error")
	}
	// non-JSON → error
	if _, err := parseTrustPolicy("not json", "acct"); err == nil {
		t.Error("non-JSON trust policy should error")
	}
}

// NotAction/NotResource are no longer refused up front — they translate to the engine's complement axes,
// and statementsToSpecAny must carry those axes into the stored kind: Policy spec.dataPlane shape (a
// dropped complement would silently widen a NotAction grant to "any action"). This asserts the write half
// of that round-trip; the read half (K8sLoader) is covered in internal/dataplaneauthz.
func TestStatementsToSpecAnyComplement(t *testing.T) {
	out := statementsToSpecAny([]policyengine.Statement{
		{Effect: policyengine.Allow, NotActions: []string{"s3:DeleteObject"}, Resources: []string{"*"}},
		{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, NotResources: []string{"Bucket::secret"}},
	})
	if len(out) != 2 {
		t.Fatalf("want 2 statements, got %d", len(out))
	}
	m0 := out[0].(map[string]any)
	if _, ok := m0["actions"]; ok {
		t.Error("a NotAction statement must not emit an actions key")
	}
	na, ok := m0["notActions"].([]any)
	if !ok || len(na) != 1 || na[0] != "s3:DeleteObject" {
		t.Errorf("notActions not carried: %#v", m0["notActions"])
	}
	m1 := out[1].(map[string]any)
	nr, ok := m1["notResources"].([]any)
	if !ok || len(nr) != 1 || nr[0] != "Bucket::secret" {
		t.Errorf("notResources not carried: %#v", m1["notResources"])
	}
	if _, ok := m1["resources"]; ok {
		t.Error("a NotResource statement must not emit a resources key")
	}
}

func TestPolicyAndPrincipalArns(t *testing.T) {
	if policyNameFromArn("arn:aws:iam::acct:policy/reports-read") != "reports-read" {
		t.Error("policyNameFromArn")
	}
	if policyNameFromArn("reports-read") != "reports-read" {
		t.Error("policyNameFromArn passthrough")
	}
	if ty, id := principalFromArn("arn:aws:iam::acct:role/app"); ty != "Role" || id != "app" {
		t.Errorf("principalFromArn role = %q/%q", ty, id)
	}
	if ty, id := principalFromArn("arn:aws:iam::acct:user/alice"); ty != "User" || id != "alice" {
		t.Errorf("principalFromArn user = %q/%q", ty, id)
	}
}

func TestArnToResourceShim(t *testing.T) {
	cases := []struct{ arn, rt, rid string }{
		{"arn:aws:s3:::reports", "Bucket", "reports"},
		{"arn:aws:s3:::reports/data/x", "Bucket", "reports/data/x"}, // an object: checked as the object
		{"arn:aws:dynamodb:us-east-1:a:table/orders", "Table", "orders"},
		{"arn:aws:lambda:us-east-1:a:function:worker", "Function", "worker"},
		{"*", "*", "*"},
	}
	for _, c := range cases {
		rt, rid := arnToResourceShim(c.arn)
		if rt != c.rt || rid != c.rid {
			t.Errorf("arnToResourceShim(%q) = (%q,%q), want (%q,%q)", c.arn, rt, rid, c.rt, c.rid)
		}
	}
}

func TestStatementsToSpecAny(t *testing.T) {
	stmts := []policyengine.Statement{
		{Effect: policyengine.Allow, Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::reports"}},
		{Effect: policyengine.Deny, Actions: []string{"s3:DeleteObject"}, Resources: []string{"Bucket::reports"}},
	}
	out := statementsToSpecAny(stmts)
	if len(out) != 2 {
		t.Fatalf("want 2 statements, got %d", len(out))
	}
	m0 := out[0].(map[string]any)
	if m0["effect"] != "Allow" {
		t.Errorf("stmt0 effect = %v", m0["effect"])
	}
	m1 := out[1].(map[string]any)
	if m1["effect"] != "Deny" {
		t.Errorf("stmt1 effect = %v (Deny must translate to a forbid)", m1["effect"])
	}
}

func TestVerbForIAMOp(t *testing.T) {
	if v, res, ok := verbForIAMOp("CreateRole"); !ok || v != "create" || res != "roles" {
		t.Errorf("CreateRole => (%q,%q,%v)", v, res, ok)
	}
	if v, res, ok := verbForIAMOp("CreatePolicy"); !ok || v != "create" || res != "policies" {
		t.Errorf("CreatePolicy => (%q,%q,%v)", v, res, ok)
	}
	if v, res, ok := verbForIAMOp("CreateAccessKey"); !ok || v != "create" || res != "users" {
		t.Errorf("CreateAccessKey => (%q,%q,%v)", v, res, ok)
	}
	if v, _, ok := verbForIAMOp("SimulatePrincipalPolicy"); !ok || v != "get" {
		t.Errorf("SimulatePrincipalPolicy => (%q,%v)", v, ok)
	}
	if _, _, ok := verbForIAMOp("Nope"); ok {
		t.Error("unknown op should be unknown")
	}
}

func TestRoleIDStable(t *testing.T) {
	if roleID("app") != roleID("app") {
		t.Error("roleID must be stable for a name")
	}
	if roleID("app") == roleID("other") {
		t.Error("roleID must differ by name")
	}
	if len(roleID("app")) < 8 {
		t.Error("roleID too short")
	}
}
