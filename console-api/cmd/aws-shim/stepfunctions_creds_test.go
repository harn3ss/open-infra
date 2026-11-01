package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// StartExecution on a machine with a role stores the minted session in a Secret OWNED by the new
// Execution (controller owner reference with its UID) — the statemachine controller hands the session
// only to that Execution, so another Execution naming this Secret gets nothing.
func TestSFN_ExecutionCredsAreOwnedByTheirExecution(t *testing.T) {
	sm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "StateMachine",
		"metadata": map[string]any{"name": "sm1", "namespace": "open-infra-aws-shim"},
		"spec":     map[string]any{"definition": passRoleDef, "type": "Standard", "roleArn": "runner"},
	}}
	h, _ := sfnPassRoleHandler(t, true, nil, sm)
	// The API server sets the UID on create; the fake does not, so do it here.
	h.dyn.(*dynamicfake.FakeDynamicClient).PrependReactor("create", "executions", func(a k8stesting.Action) (bool, runtime.Object, error) {
		a.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured).SetUID(types.UID("uid-exec-1"))
		return false, nil, nil
	})
	alice := iam.Claims{Sub: "alice", Groups: []string{"openinfra:powerusers"}}
	w := sfnCall(h, alice, "StartExecution", map[string]any{
		"stateMachineArn": "arn:aws:states:us-east-1:000000000000:stateMachine:sm1", "name": "run1"})
	if w.Code != http.StatusOK {
		t.Fatalf("StartExecution: %d %s", w.Code, w.Body.String())
	}
	ctx := context.Background()
	ex, err := h.dyn.Resource(gvrExecutions).Namespace(h.ns).Get(ctx, "run1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if name, _, _ := unstructured.NestedString(ex.Object, "spec", "credentialsSecret"); name != "run1-creds" {
		t.Fatalf("spec.credentialsSecret = %q", name)
	}
	sec, err := h.cs.CoreV1().Secrets(h.ns).Get(ctx, "run1-creds", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("credentials Secret: %v", err)
	}
	if len(sec.OwnerReferences) != 1 {
		t.Fatalf("owner references = %+v", sec.OwnerReferences)
	}
	o := sec.OwnerReferences[0]
	if o.Kind != "Execution" || o.Name != "run1" || o.UID != "uid-exec-1" || o.Controller == nil || !*o.Controller {
		t.Fatalf("owner reference = %+v, want the Execution run1 (uid-exec-1) as controller", o)
	}
	if len(sec.Data["accessKeyId"]) == 0 || len(sec.Data["sessionToken"]) == 0 {
		t.Fatalf("the Secret must carry the session")
	}
}

// A role the caller is not trusted by creates nothing: no Execution, no Secret.
func TestSFN_UntrustedExecutionRoleCreatesNothing(t *testing.T) {
	sm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "StateMachine",
		"metadata": map[string]any{"name": "sm1", "namespace": "open-infra-aws-shim"},
		"spec":     map[string]any{"definition": passRoleDef, "type": "Standard", "roleArn": "runner"},
	}}
	h, _ := sfnPassRoleHandler(t, true, nil, sm)
	bob := iam.Claims{Sub: "bob", Groups: []string{"openinfra:powerusers"}}
	if w := sfnCall(h, bob, "StartExecution", map[string]any{
		"stateMachineArn": "arn:aws:states:us-east-1:000000000000:stateMachine:sm1", "name": "run2"}); w.Code != http.StatusForbidden {
		t.Fatalf("untrusted caller: %d %s, want 403", w.Code, w.Body.String())
	}
	ctx := context.Background()
	if _, err := h.dyn.Resource(gvrExecutions).Namespace(h.ns).Get(ctx, "run2", metav1.GetOptions{}); err == nil {
		t.Fatal("no Execution may be created")
	}
	if _, err := h.cs.CoreV1().Secrets(h.ns).Get(ctx, "run2-creds", metav1.GetOptions{}); err == nil {
		t.Fatal("no Secret may be created")
	}
}
