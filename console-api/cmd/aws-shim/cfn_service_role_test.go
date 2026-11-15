package main

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
)

const (
	cfnRoleArn      = "arn:aws:iam::000000000000:role/cfn-deployer"
	cfnRoleGroup    = "openinfra:cfn-deployer-group"
	cfnRoleUpdateTm = "Description: v2\nResources:\n  Key:\n    Type: AWS::KMS::Key\n    Properties: { Description: k2 }\n"
)

func serviceRoleDoorway(t *testing.T) (*cfnDoorway, *fakeAPI) {
	t.Helper()
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0003")
	h.roles = fakeRoles{
		"cfn-deployer": {trust: []string{"Service::" + cfnServicePrincipal}, groups: []string{cfnRoleGroup}},
		"not-for-cfn":  {trust: []string{"alice"}, groups: []string{"openinfra:other"}},
	}
	return h, fa
}

// actedAsRole reports whether an identity impersonated since the n-th was the service role's.
func actedAsRole(fa *fakeAPI, n int) bool {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	for _, c := range fa.callers[n:] {
		if strings.Contains(c, cfnServiceRoleSession) && strings.HasSuffix(c, "|"+cfnRoleGroup) {
			return true
		}
	}
	return false
}

func callerCount(fa *fakeAPI) int {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return len(fa.callers)
}

// A stack created with a RoleARN acts as the role, keeps it (DescribeStacks shows it), and a later update
// that names none acts as it too, as on AWS.
func TestCFN_ServiceRoleActsForTheStack(t *testing.T) {
	h, fa := serviceRoleDoorway(t)
	n := callerCount(fa)
	if code, body := cfnCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {deletedTmpl},
		"RoleARN": {cfnRoleArn}}); code != 200 {
		t.Fatalf("CreateStack: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	if !actedAsRole(fa, n) {
		t.Fatalf("the create did not act as the service role: %v", fa.callers[n:])
	}
	if _, d, raw := describeByRef(t, h, "app"); len(d.Stacks) != 1 || !strings.Contains(raw, "<RoleARN>"+cfnRoleArn+"</RoleARN>") {
		t.Fatalf("DescribeStacks does not show the stack's role: %s", raw)
	}
	n = callerCount(fa)
	if code, body := cfnCall(t, h, url.Values{"Action": {"UpdateStack"}, "StackName": {"app"}, "TemplateBody": {cfnRoleUpdateTm}}); code != 200 {
		t.Fatalf("UpdateStack: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	if !actedAsRole(fa, n) {
		t.Fatalf("an update naming no role did not act as the stack's role: %v", fa.callers[n:])
	}
	if _, _, raw := describeByRef(t, h, "app"); !strings.Contains(raw, "<RoleARN>"+cfnRoleArn+"</RoleARN>") {
		t.Fatalf("the update dropped the stack's role: %s", raw)
	}
}

// A change set created with a RoleARN is executed as that role.
func TestCFN_ServiceRoleChangeSet(t *testing.T) {
	h, fa := serviceRoleDoorway(t)
	if code, body := cfnCall(t, h, url.Values{"Action": {"CreateChangeSet"}, "StackName": {"cs-app"}, "ChangeSetName": {"one"},
		"ChangeSetType": {"CREATE"}, "TemplateBody": {deletedTmpl}, "RoleARN": {cfnRoleArn}}); code != 200 {
		t.Fatalf("CreateChangeSet: %d %s", code, body)
	}
	if cs, err := h.getChangeSet(context.Background(), "cs-app", "one"); err != nil || cs.RoleARN != cfnRoleArn {
		t.Fatalf("the change set does not keep its role: %+v %v", cs, err)
	}
	n := callerCount(fa)
	if code, body := cfnCall(t, h, url.Values{"Action": {"ExecuteChangeSet"}, "StackName": {"cs-app"}, "ChangeSetName": {"one"}}); code != 200 {
		t.Fatalf("ExecuteChangeSet: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	if !actedAsRole(fa, n) {
		t.Fatalf("the change set was not executed as its role: %v", fa.callers[n:])
	}
}

// A RoleARN CloudFormation can't use, a caller without iam:PassRole, or another account's role is refused
// as AWS refuses it, and nothing is created.
func TestCFN_ServiceRoleRefusals(t *testing.T) {
	for _, c := range []struct {
		name, arn, code string
		noPassRole      bool
	}{
		{"a role that does not trust CloudFormation", "arn:aws:iam::000000000000:role/not-for-cfn", "ValidationError", false},
		{"a role that does not exist", "arn:aws:iam::000000000000:role/nobody", "ValidationError", false},
		{"not a role ARN", "arn:aws:iam::000000000000:user/cfn-deployer", "ValidationError", false},
		{"another account's role", "arn:aws:iam::444455556666:role/cfn-deployer", "AccessDenied", false},
		{"a caller without iam:PassRole", cfnRoleArn, "AccessDenied", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := serviceRoleDoorway(t)
			if c.noPassRole {
				h.cs = csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return !strings.HasPrefix(a.Verb, passRoleVerb) })
			}
			code, body := cfnCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"refused"}, "TemplateBody": {deletedTmpl},
				"RoleARN": {c.arn}})
			if code < 400 || !strings.Contains(body, "<Code>"+c.code+"</Code>") {
				t.Fatalf("want %s, got %d %s", c.code, code, body)
			}
			h.ops.drain(10 * time.Second)
			if _, found, _ := h.applierForIdentityMust(t).GetStack(context.Background(), "refused"); found {
				t.Fatal("a refused CreateStack created the stack")
			}
		})
	}
}

// A stack step on something the shim keeps (a queue) is decided as that front door decides it: for a
// principal IAM policy decides (enforce), its policy alone — an assumed role allowed sqs:* creates the queue
// though the coarse RBAC question says no, and one not allowed it is refused; otherwise the RBAC question
// still gates, as before.
func TestCFN_StackStepIsTheFrontDoorsDecision(t *testing.T) {
	ctx := context.Background()
	h, _ := cfnServeDoorway(t)
	h.cs = csWithSAR(false) // the coarse RBAC question says no
	role := iam.Claims{Sub: "assumed-role/" + ecrTestRole + "/AWSCloudFormation", AssumedRole: ecrTestRole}
	ap, err := h.applierForIn(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	// The platform's IAM_AUTHZ mode (read when the evaluator is built): enforce, or legacy.
	world := func(enforce bool, stmts ...policyengine.Statement) *dataplaneauthz.Checker {
		mode := "legacy"
		if enforce {
			mode = "enforce"
		}
		t.Setenv(iamauthz.EnvMode, mode)
		return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
			return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{Name: "role-access",
				AppliesTo: []string{"Role::" + ecrTestRole}, Statements: stmts}}}, nil
		}, time.Minute)
	}
	step := func() bool {
		ok, _ := h.callerAllowed(ctx, ap, "sqs:CreateQueue", "Queue", "q", "create", "openinfra.dev", "applications", h.authzNS, "q")
		return ok
	}
	h.authz = world(false, dpAllow([]string{"sqs:*"}, "*"))
	if step() {
		t.Fatal("legacy: the RBAC question must still gate the step")
	}
	h.authz = world(true, dpAllow([]string{"sqs:*"}, "*"))
	if !step() {
		t.Fatal("enforce: the role's IAM policy allows sqs:CreateQueue, and it alone decides")
	}
	h.authz = world(true, dpAllow([]string{"sqs:ListQueues"}, "*"))
	if step() {
		t.Fatal("enforce: a role not allowed sqs:CreateQueue must be refused")
	}
}
