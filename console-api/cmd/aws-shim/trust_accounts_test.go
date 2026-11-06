package main

import (
	"net/http"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A trust policy names another account's principal only by ARN, as on AWS: a bare name is a principal of
// the role's own account, and never one of the same name in another account.
func TestTrustedFrom_AnotherAccountIsNamedByARN(t *testing.T) {
	const own, other = "111111111111", "222222222222"
	trust := []string{"bob", "Role::deployer", "arn:aws:iam::" + other + ":user/carol"}
	for _, c := range []struct {
		name string
		who  trustCaller
		want bool
	}{
		{"own account's bob", trustCaller{kind: "User", name: "bob", account: own}, true},
		{"another account's bob", trustCaller{kind: "User", name: "bob", account: other}, false},
		{"another account's deployer session", trustCaller{kind: "Role", name: "deployer", account: other}, false},
		{"own account's deployer session", trustCaller{kind: "Role", name: "deployer", account: own}, true},
		{"the other account's carol, named by ARN", trustCaller{kind: "User", name: "carol", account: other}, true},
	} {
		if got := trustedFrom(c.who, trust, own); got != c.want {
			t.Errorf("%s: trustedFrom = %v, want %v", c.name, got, c.want)
		}
	}
	root := []string{"arn:aws:iam::" + own + ":root"}
	if !trustedFrom(trustCaller{kind: "User", name: "x", account: own}, root, own) {
		t.Error("an account's root trusts that account's principals")
	}
	if trustedFrom(trustCaller{kind: "User", name: "x", account: other}, root, own) {
		t.Error("an account's root never trusts another account's principals")
	}
	if !trustedFrom(trustCaller{kind: "User", name: "x", account: other}, []string{"*"}, own) {
		t.Error(`Principal "*" is any principal, as on AWS`)
	}
}

// A state machine runs under a role that trusts the Step Functions service, as on AWS: passing the role
// took iam:PassRole at CreateStateMachine, and StartExecution needs no trust entry naming the caller.
func TestSFN_RoleTrustingTheServiceRunsExecutions(t *testing.T) {
	sm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "StateMachine",
		"metadata": map[string]any{"name": "sm1", "namespace": "open-infra-aws-shim"},
		"spec":     map[string]any{"definition": passRoleDef, "type": "Standard", "roleArn": "runner"},
	}}
	h, _ := sfnPassRoleHandler(t, true, nil, sm)
	bob := iam.Claims{Sub: "bob", Groups: []string{"openinfra:powerusers"}}
	start := map[string]any{"stateMachineArn": "arn:aws:states:us-east-1:000000000000:stateMachine:sm1", "name": "run1"}
	// The fixture's role trusts alice only: bob is refused.
	if w := sfnCall(h, bob, "StartExecution", start); w.Code != http.StatusForbidden {
		t.Fatalf("a role whose trust names neither the service nor the caller: %d %s", w.Code, w.Body.String())
	}
	h.roles = fakeRoles{"runner": {trust: []string{"Service::states.amazonaws.com"}}}
	if w := sfnCall(h, bob, "StartExecution", start); w.Code != http.StatusOK {
		t.Fatalf("a role trusting states.amazonaws.com: %d %s", w.Code, w.Body.String())
	}
	h.roles = fakeRoles{"runner": {trust: []string{"Service::lambda.amazonaws.com"}}}
	start["name"] = "run2"
	if w := sfnCall(h, bob, "StartExecution", start); w.Code != http.StatusForbidden {
		t.Fatalf("a role trusting another service: %d %s", w.Code, w.Body.String())
	}
}
