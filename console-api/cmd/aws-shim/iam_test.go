package main

import (
	"reflect"
	"sort"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

func TestParseTrustPolicy(t *testing.T) {
	// single statement, single principal user ARN
	got, err := parseTrustPolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::acct:user/alice"},"Action":"sts:AssumeRole"}]}`)
	if err != nil || !reflect.DeepEqual(got, []string{"alice"}) {
		t.Fatalf("single user: got %v err %v", got, err)
	}
	// principal "*" → "*"
	got, err = parseTrustPolicy(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`)
	if err != nil || !reflect.DeepEqual(got, []string{"*"}) {
		t.Fatalf("star principal: got %v err %v", got, err)
	}
	// list of AWS principals
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::a:user/bob","arn:aws:iam::a:user/carol"]},"Action":"sts:AssumeRole"}]}`)
	sort.Strings(got)
	if err != nil || !reflect.DeepEqual(got, []string{"bob", "carol"}) {
		t.Fatalf("list principals: got %v err %v", got, err)
	}
	// root ARN → "*"
	got, err = parseTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::acct:root"},"Action":"sts:AssumeRole"}]}`)
	if err != nil || !reflect.DeepEqual(got, []string{"*"}) {
		t.Fatalf("root principal: got %v err %v", got, err)
	}
	// Deny statements ignored → no principal → error
	if _, err := parseTrustPolicy(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}`); err == nil {
		t.Error("a Deny-only trust policy should yield no assumable principal")
	}
	// empty → error
	if _, err := parseTrustPolicy(""); err == nil {
		t.Error("empty trust policy should error")
	}
	// non-JSON → error
	if _, err := parseTrustPolicy("not json"); err == nil {
		t.Error("non-JSON trust policy should error")
	}
}

func TestHasNotActionOrResource(t *testing.T) {
	if !hasNotActionOrResource(`{"Statement":[{"Effect":"Allow","NotAction":"s3:*","Resource":"*"}]}`) {
		t.Error("NotAction should be detected")
	}
	if !hasNotActionOrResource(`{"Statement":[{"Effect":"Deny","Action":"s3:*","NotResource":"arn:aws:s3:::public/*"}]}`) {
		t.Error("NotResource should be detected")
	}
	if hasNotActionOrResource(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`) {
		t.Error("a normal policy should not be flagged")
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
		{"arn:aws:s3:::reports/data/x", "Bucket", "reports"},
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
