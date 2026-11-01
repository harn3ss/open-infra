package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const passRoleDef = `{"StartAt":"A","States":{"A":{"Type":"Pass","End":true}}}`

// sfnPassRoleHandler is a Step Functions front door whose RBAC allows the state-machine verbs, and
// `passrole` on roles only when canPass says so. It records every passrole SubjectAccessReview.
func sfnPassRoleHandler(t *testing.T, canPass bool, authz *dataplaneauthz.Checker, seed ...runtime.Object) (*sfnHandler, *[]authzv1.ResourceAttributes) {
	t.Helper()
	var asked []authzv1.ResourceAttributes
	cs := csWithSARFunc(func(a *authzv1.ResourceAttributes) bool {
		if a.Verb == passRoleVerb {
			asked = append(asked, *a)
			return canPass && a.Group == "iam.openinfra.dev" && a.Resource == "roles"
		}
		return a.Group == "openinfra.dev"
	})
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrStateMachines: "StateMachineList", gvrExecutions: "ExecutionList"}, seed...)
	h := newSFNHandler(cs, dyn, testMinter(t), fakeRoles{"runner": {trust: []string{"alice"}}}, authz,
		"open-infra-aws-shim", "000000000000", "us-east-1", nil)
	h.rolesNS = "open-infra-console"
	return h, &asked
}

func sfnCall(h *sfnHandler, claims iam.Claims, op string, body map[string]any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b)))
	r.Header.Set("X-Amz-Target", "AWSStepFunctions."+op)
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-1")
	return w
}

func createBody(role string) map[string]any {
	b := map[string]any{"name": "sm1", "definition": passRoleDef}
	if role != "" {
		b["roleArn"] = "arn:aws:iam::000000000000:role/" + role
	}
	return b
}

func stateMachineExists(t *testing.T, h *sfnHandler, name string) bool {
	t.Helper()
	_, err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).Get(context.Background(), name, metav1.GetOptions{})
	return err == nil
}

// A User may give a state machine an execution role only with `passrole` on that Role (AWS's
// iam:PassRole on CreateStateMachine); without it nothing is created.
func TestSFN_CreateStateMachineRequiresPassRole(t *testing.T) {
	alice := iam.Claims{Sub: "alice", Groups: []string{"openinfra:powerusers"}}

	h, asked := sfnPassRoleHandler(t, false, nil)
	if w := sfnCall(h, alice, "CreateStateMachine", createBody("runner")); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "iam:PassRole") {
		t.Fatalf("without passrole: %d %s, want 403 naming iam:PassRole", w.Code, w.Body.String())
	}
	if stateMachineExists(t, h, "sm1") {
		t.Fatalf("a refused CreateStateMachine must create nothing")
	}
	if len(*asked) != 1 || (*asked)[0].Namespace != "open-infra-console" || (*asked)[0].Name != "runner" {
		t.Fatalf("passrole SAR = %+v, want one on open-infra-console/runner", *asked)
	}

	h, _ = sfnPassRoleHandler(t, true, nil)
	if w := sfnCall(h, alice, "CreateStateMachine", createBody("runner")); w.Code != http.StatusOK {
		t.Fatalf("with passrole: %d %s", w.Code, w.Body.String())
	}
	if !stateMachineExists(t, h, "sm1") {
		t.Fatalf("an allowed CreateStateMachine must create the state machine")
	}

	// No execution role: nothing to pass, no passrole check.
	h, asked = sfnPassRoleHandler(t, false, nil)
	if w := sfnCall(h, alice, "CreateStateMachine", createBody("")); w.Code != http.StatusOK {
		t.Fatalf("no roleArn: %d %s", w.Code, w.Body.String())
	}
	if len(*asked) != 0 {
		t.Fatalf("no roleArn must not ask for passrole: %+v", *asked)
	}
}

func TestSFN_UpdateStateMachineRoleRequiresPassRole(t *testing.T) {
	existing := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "StateMachine",
		"metadata": map[string]any{"name": "sm1", "namespace": "open-infra-aws-shim"},
		"spec":     map[string]any{"definition": passRoleDef, "type": "Standard"},
	}}
	alice := iam.Claims{Sub: "alice", Groups: []string{"openinfra:powerusers"}}
	h, _ := sfnPassRoleHandler(t, false, nil, existing)
	w := sfnCall(h, alice, "UpdateStateMachine", map[string]any{
		"stateMachineArn": "arn:aws:states:us-east-1:000000000000:stateMachine:sm1",
		"roleArn":         "arn:aws:iam::000000000000:role/runner",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("UpdateStateMachine adding a role without passrole: %d %s, want 403", w.Code, w.Body.String())
	}
	u, err := h.dyn.Resource(gvrStateMachines).Namespace(h.ns).Get(context.Background(), "sm1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if role, _, _ := unstructured.NestedString(u.Object, "spec", "roleArn"); role != "" {
		t.Fatalf("a refused update must not set the role (got %q)", role)
	}
}

// An assumed role passes a Role only when its own policies allow iam:PassRole on it (default deny).
func TestSFN_AssumedRolePassRoleIsItsPolicy(t *testing.T) {
	checker := func(actions ...string) *dataplaneauthz.Checker {
		stmts := []policyengine.Statement{{Effect: policyengine.Allow, Actions: []string{"states:*"}, Resources: []string{"*"}}}
		if len(actions) > 0 {
			stmts = append(stmts, policyengine.Statement{Effect: policyengine.Allow, Actions: actions, Resources: []string{"Role::runner"}})
		}
		return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
			return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{Name: "deployer", AppliesTo: []string{"Role::deployer"}, Statements: stmts}}}, nil
		}, time.Minute)
	}
	session := iam.Claims{Sub: "assumed-role/deployer/s", Groups: []string{"openinfra:users"}, AssumedRole: "deployer"}

	h, _ := sfnPassRoleHandler(t, true, checker())
	if w := sfnCall(h, session, "CreateStateMachine", createBody("runner")); w.Code != http.StatusForbidden {
		t.Fatalf("role without iam:PassRole: %d %s, want 403", w.Code, w.Body.String())
	}
	h, _ = sfnPassRoleHandler(t, true, checker("iam:PassRole"))
	if w := sfnCall(h, session, "CreateStateMachine", createBody("runner")); w.Code != http.StatusOK {
		t.Fatalf("role with iam:PassRole on Role::runner: %d %s", w.Code, w.Body.String())
	}
}
