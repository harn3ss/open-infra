package main

import (
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func sfnExecution(name, sm string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Execution",
		"metadata": map[string]any{"name": name, "namespace": "open-infra-aws-shim"},
		"spec":     map[string]any{"stateMachineRef": map[string]any{"name": sm}, "input": "{}"},
		"status":   map[string]any{"phase": "Running"},
	}}
}

func sfnExecArn(sm, name string) string {
	return "arn:aws:states:us-east-1:000000000000:execution:" + sm + ":" + name
}

// An execution ARN is held to its state machine: an ARN pairing a state machine the caller may use with
// another state machine's execution is ExecutionDoesNotExist, so it neither reads nor stops that run.
func TestSFN_ExecutionArnIsBoundToItsStateMachine(t *testing.T) {
	h, _ := sfnPassRoleHandler(t, true, nil, sfnExecution("payroll-run", "payroll"))
	alice := iam.Claims{Sub: "alice"}
	for _, op := range []string{"DescribeExecution", "GetExecutionHistory", "StopExecution"} {
		w := sfnCall(h, alice, op, map[string]any{"executionArn": sfnExecArn("mine", "payroll-run")})
		if w.Code != 400 || !strings.Contains(w.Body.String(), "ExecutionDoesNotExist") {
			t.Errorf("%s with another state machine's execution under an ARN for 'mine': %d %s, want ExecutionDoesNotExist", op, w.Code, w.Body.String())
		}
	}
	if w := sfnCall(h, alice, "DescribeExecution", map[string]any{"executionArn": sfnExecArn("payroll", "payroll-run")}); w.Code != 200 {
		t.Errorf("DescribeExecution under the execution's own ARN: %d %s, want 200", w.Code, w.Body.String())
	}
}

// A User's data-plane Deny on a state machine holds at the Step Functions front door, as at every other.
func TestSFN_UserDataPlaneDenyHolds(t *testing.T) {
	deny := policyFor("alice",
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"states:*"}, Resources: []string{"*"}},
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"states:StartExecution", "states:DescribeExecution"}, Resources: []string{"StateMachine::payroll"}})
	h, _ := sfnPassRoleHandler(t, true, deny, sfnExecution("payroll-run", "payroll"))
	alice := iam.Claims{Sub: "alice"}
	if w := sfnCall(h, alice, "StartExecution", map[string]any{"stateMachineArn": "arn:aws:states:us-east-1:000000000000:stateMachine:payroll"}); w.Code != 403 {
		t.Errorf("StartExecution denied to the User: %d %s, want 403", w.Code, w.Body.String())
	}
	if w := sfnCall(h, alice, "DescribeExecution", map[string]any{"executionArn": sfnExecArn("payroll", "payroll-run")}); w.Code != 403 {
		t.Errorf("DescribeExecution denied to the User: %d %s, want 403", w.Code, w.Body.String())
	}
}
