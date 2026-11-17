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

// Executing a change set reports what the change set showed: the plan's summary, with what only the change
// set knows (an update AWS would replace, which open-infra makes in place), each once.
func TestCFN_ExecuteReportsTheChangeSetsCaveats(t *testing.T) {
	plan := "accepted but not emulated as on AWS (2): Svc: a | Task: b"
	got := withChangeSetCaveats(plan, []cfn.Change{
		{LogicalID: "Task", Action: cfn.Modify, Caveats: []string{"b", "changing Cpu replaces it on AWS"}},
		{LogicalID: "Old", Action: cfn.Remove, Caveats: []string{"gone"}},
	})
	if got != "accepted but not emulated as on AWS (3): Svc: a | Task: b | Task: changing Cpu replaces it on AWS" {
		t.Fatalf("got %q", got)
	}
	if got := withChangeSetCaveats("", nil); got != "" {
		t.Fatalf("nothing to report: %q", got)
	}
	if got := withChangeSetCaveats("", []cfn.Change{{LogicalID: "Task", Action: cfn.Modify, Caveats: []string{"x"}}}); got != "accepted but not emulated as on AWS (1): Task: x" {
		t.Fatalf("only the change set's: %q", got)
	}
}
