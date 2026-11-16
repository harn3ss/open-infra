package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
)

// As on AWS, executing a change set is cloudformation:ExecuteChangeSet on the stack, with no dependent
// action: a role allowed ExecuteChangeSet (and not UpdateStack) executes an UPDATE change set, and a role
// allowed UpdateStack (and not ExecuteChangeSet) is refused it, with AWS's error naming ExecuteChangeSet.
func TestCFN_ExecuteUpdateChangeSetIsExecuteChangeSet(t *testing.T) {
	t.Setenv(iamauthz.EnvMode, "enforce")
	role := iam.Claims{Sub: "assumed-role/" + ecrTestRole + "/deploy", AssumedRole: ecrTestRole}
	allow := func(actions ...string) *dataplaneauthz.Checker {
		return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
			return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{Name: "deploy",
				AppliesTo: []string{"Role::" + ecrTestRole}, Statements: []policyengine.Statement{dpAllow(actions, "*")}}}}, nil
		}, time.Minute)
	}

	for _, c := range []struct {
		name    string
		actions []string
		denied  bool
	}{
		{"ExecuteChangeSet alone", []string{"cloudformation:ExecuteChangeSet"}, false},
		{"UpdateStack without ExecuteChangeSet", []string{"cloudformation:UpdateStack"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := cfnServeDoorway(t)
			if err := h.putChangeSet(context.Background(), &changeSet{StackName: "app", Name: "cs1", TemplateBody: secretTmpl, Type: "UPDATE"}); err != nil {
				t.Fatal(err)
			}
			h.cs = csWithSAR(false) // the coarse RBAC question says no: IAM policy alone decides
			h.authz = allow(c.actions...)
			w := serveWith(h, formOp(url.Values{"Action": {"ExecuteChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}}), role)
			b := w.Body.String()
			switch {
			case c.denied && (w.Code != http.StatusForbidden || !strings.Contains(b, "cloudformation:ExecuteChangeSet")):
				t.Fatalf("want AccessDenied naming cloudformation:ExecuteChangeSet, got %d %s", w.Code, b)
			case !c.denied && strings.Contains(b, "AccessDenied"):
				t.Fatalf("a role allowed ExecuteChangeSet must not be refused: %d %s", w.Code, b)
			}
			h.ops.drain(10 * time.Second)
		})
	}
}

// DescribeChangeSet reports a Modify's Replacement and the properties it changes as AWS does: Scope, and a
// Detail for each property with its RequiresRecreation.
func TestCFN_DescribeChangeSetReportsReplacement(t *testing.T) {
	h, _ := cfnServeDoorway(t)
	if err := h.putChangeSet(context.Background(), &changeSet{StackName: "app", Name: "cs1", TemplateBody: secretTmpl, Type: "UPDATE",
		Changes: []cfn.Change{{LogicalID: "Task", Type: "AWS::ECS::TaskDefinition", Name: "arn:aws:ecs:us-east-1:111122223333:task-definition/web:1",
			Action: cfn.Modify, Replacement: "True", Folded: true,
			Details: []cfn.PropertyChange{{Name: "ExecutionRoleArn", RequiresRecreation: "Always"}}}}}); err != nil {
		t.Fatal(err)
	}
	w := cfnServe(h, url.Values{"Action": {"DescribeChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}})
	b := w.Body.String()
	for _, want := range []string{"<Action>Modify</Action>", "<Replacement>True</Replacement>", "<Scope><member>Properties</member></Scope>",
		"<Target><Attribute>Properties</Attribute><Name>ExecutionRoleArn</Name><RequiresRecreation>Always</RequiresRecreation></Target>",
		"<Evaluation>Static</Evaluation><ChangeSource>DirectModification</ChangeSource>"} {
		if !strings.Contains(b, want) {
			t.Errorf("DescribeChangeSet lacks %s: %s", want, b)
		}
	}
}
