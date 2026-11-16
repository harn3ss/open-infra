package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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
