package main

// Each account's state machines and executions are its own: a member account's StateMachines, Executions
// and execution credentials are kept in its home namespace (the management account's in the Step
// Functions namespace, exactly where they always were), the same state-machine name lives in both
// accounts independently, each account lists only its own, every ARN carries the caller's account, a
// member's execution role is a role of its own account, and its execution's session acts in it.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const sfnTestNS = "open-infra-aws-shim"

func sfnAccountsHandler(t *testing.T) *sfnHandler {
	t.Helper()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrStateMachines: "StateMachineList", gvrExecutions: "ExecutionList"})
	dyn.PrependReactor("create", "executions", func(a k8stesting.Action) (bool, runtime.Object, error) {
		u := a.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		u.SetUID(types.UID("uid-" + u.GetNamespace() + "-" + u.GetName())) // the API server sets it; the fake does not
		return false, nil, nil
	})
	// The management account's runner is trusted by its alice; the member account's own runner (in its home)
	// by its bob. "mgmtonly" is a role of the management account alone.
	roles := fakeRolesIn{
		fakeRoles: fakeRoles{"runner": {trust: []string{"alice"}}, "mgmtonly": {trust: []string{"*"}}},
		in:        fakeRoles{memberHome + "/runner": {trust: []string{"bob"}}},
	}
	h := newSFNHandler(csWithSAR(true), dyn, testMinter(t), roles, doorAccountsAuthz(t),
		sfnTestNS, awsidentity.Current().AccountID, "us-east-1", discardLogger())
	h.rolesNS = "open-infra-console"
	return h
}

func sfnCallAs(t *testing.T, h *sfnHandler, c doorCaller, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b))).WithContext(c.ctx)
	r.Header.Set("X-Amz-Target", "AWSStepFunctions."+op)
	w := httptest.NewRecorder()
	h.serve(w, r, c.claims, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func sfnDef(result string) string {
	return `{"StartAt":"A","States":{"A":{"Type":"Pass","Result":"` + result + `","End":true}}}`
}

func TestSFNAccounts_StateMachinesAreEachAccountsOwn(t *testing.T) {
	h := sfnAccountsHandler(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtAcct := awsidentity.Current().AccountID
	mgmtArn := "arn:aws:states:us-east-1:" + mgmtAcct + ":stateMachine:sm1"
	memberArn := "arn:aws:states:us-east-1:" + testMember + ":stateMachine:sm1"

	if code, out := sfnCallAs(t, h, mgmt, "CreateStateMachine", map[string]any{"name": "sm1", "definition": sfnDef("mgmt"),
		"roleArn": "arn:aws:iam::" + mgmtAcct + ":role/runner"}); code != http.StatusOK || out["stateMachineArn"] != mgmtArn {
		t.Fatalf("management create: %d %v", code, out)
	}
	if code, out := sfnCallAs(t, h, member, "CreateStateMachine", map[string]any{"name": "sm1", "definition": sfnDef("member"),
		"roleArn": "arn:aws:iam::" + testMember + ":role/runner"}); code != http.StatusOK || out["stateMachineArn"] != memberArn {
		t.Fatalf("member create of the same name: %d %v", code, out)
	}
	ctx := context.Background()
	if _, err := h.dyn.Resource(gvrStateMachines).Namespace(memberHome).Get(ctx, "sm1", metav1.GetOptions{}); err != nil {
		t.Fatalf("the member's state machine is kept in its home: %v", err)
	}
	if u, err := h.dyn.Resource(gvrStateMachines).Namespace(sfnTestNS).Get(ctx, "sm1", metav1.GetOptions{}); err != nil ||
		!strings.Contains(u.Object["spec"].(map[string]any)["definition"].(string), "mgmt") {
		t.Fatalf("the management account's state machine is where it always was: %v", err)
	}

	defOf := func(out map[string]any) string { s, _ := out["definition"].(string); return s }
	if _, out := sfnCallAs(t, h, member, "DescribeStateMachine", map[string]any{"stateMachineArn": memberArn}); !strings.Contains(defOf(out), "member") ||
		out["roleArn"] != "arn:aws:iam::"+testMember+":role/runner" {
		t.Errorf("the member describes its own state machine: %v", out)
	}
	if _, out := sfnCallAs(t, h, mgmt, "DescribeStateMachine", map[string]any{"stateMachineArn": mgmtArn}); !strings.Contains(defOf(out), "mgmt") ||
		out["roleArn"] != "arn:aws:iam::"+mgmtAcct+":role/runner" {
		t.Errorf("the management account describes its own state machine: %v", out)
	}
	// The management account's ARN never resolves for the member — neither to the management account's
	// state machine nor to the member's own of the same name.
	if _, out := sfnCallAs(t, h, member, "DescribeStateMachine", map[string]any{"stateMachineArn": mgmtArn}); jsonErrType(out) != "StateMachineDoesNotExist" {
		t.Errorf("another account's state-machine ARN must not resolve for a member: %v", out)
	}
	if code, _ := sfnCallAs(t, h, member, "DeleteStateMachine", map[string]any{"stateMachineArn": mgmtArn}); code != http.StatusOK {
		t.Fatalf("delete of another account's ARN is a no-op: %d", code)
	}
	if _, err := h.dyn.Resource(gvrStateMachines).Namespace(sfnTestNS).Get(ctx, "sm1", metav1.GetOptions{}); err != nil {
		t.Fatal("the management account's state machine survives the member's delete")
	}
	if _, err := h.dyn.Resource(gvrStateMachines).Namespace(memberHome).Get(ctx, "sm1", metav1.GetOptions{}); err != nil {
		t.Fatal("the member's own state machine is not deleted by another account's ARN")
	}

	arns := func(out map[string]any) []string {
		var s []string
		for _, it := range out["stateMachines"].([]any) {
			s = append(s, it.(map[string]any)["stateMachineArn"].(string))
		}
		return s
	}
	if _, out := sfnCallAs(t, h, member, "ListStateMachines", map[string]any{}); strings.Join(arns(out), ",") != memberArn {
		t.Errorf("the member lists its own state machines alone: %v", out)
	}
	if _, out := sfnCallAs(t, h, mgmt, "ListStateMachines", map[string]any{}); strings.Join(arns(out), ",") != mgmtArn {
		t.Errorf("the management account lists its own state machines alone: %v", out)
	}
}

// A member account's execution role is a role of its own account: another account's role ARN is refused
// as AWS refuses a cross-account iam:PassRole, and a role only the management account has does not exist
// for it. Nothing is created.
func TestSFNAccounts_ExecutionRoleIsTheMembersOwn(t *testing.T) {
	h := sfnAccountsHandler(t)
	member := memberDoorCaller()
	mgmtAcct := awsidentity.Current().AccountID
	code, out := sfnCallAs(t, h, member, "CreateStateMachine", map[string]any{"name": "x", "definition": sfnDef("x"),
		"roleArn": "arn:aws:iam::" + mgmtAcct + ":role/runner"})
	if code != http.StatusForbidden || jsonErrType(out) != "AccessDeniedException" || !strings.Contains(out["message"].(string), "Cross-account pass role") {
		t.Errorf("another account's role: %d %v", code, out)
	}
	if code, out := sfnCallAs(t, h, member, "CreateStateMachine", map[string]any{"name": "x", "definition": sfnDef("x"),
		"roleArn": "arn:aws:iam::" + testMember + ":role/mgmtonly"}); code != http.StatusBadRequest || jsonErrType(out) != "InvalidArn" {
		t.Errorf("a role the member account does not have: %d %v", code, out)
	}
	if l, _ := h.dyn.Resource(gvrStateMachines).Namespace(memberHome).List(context.Background(), metav1.ListOptions{}); len(l.Items) != 0 {
		t.Errorf("a refused create made %d state machines", len(l.Items))
	}
}

// A member account's execution, its credentials Secret and its role session are its own: kept in its home,
// the session acting in the member account as its role there, the execution's ARN naming it; neither
// account lists or reaches the other's executions.
func TestSFNAccounts_ExecutionsAreEachAccountsOwn(t *testing.T) {
	h := sfnAccountsHandler(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtAcct := awsidentity.Current().AccountID
	for _, c := range []struct {
		caller doorCaller
		acct   string
	}{{mgmt, mgmtAcct}, {member, testMember}} {
		if code, out := sfnCallAs(t, h, c.caller, "CreateStateMachine", map[string]any{"name": "sm1", "definition": sfnDef(c.acct),
			"roleArn": "runner"}); code != http.StatusOK {
			t.Fatalf("create in %s: %d %v", c.acct, code, out)
		}
	}
	code, out := sfnCallAs(t, h, member, "StartExecution", map[string]any{
		"stateMachineArn": "arn:aws:states:us-east-1:" + testMember + ":stateMachine:sm1", "name": "run1"})
	memberExec := "arn:aws:states:us-east-1:" + testMember + ":execution:sm1:run1"
	if code != http.StatusOK || out["executionArn"] != memberExec {
		t.Fatalf("member start: %d %v", code, out)
	}
	if code, out := sfnCallAs(t, h, mgmt, "StartExecution", map[string]any{
		"stateMachineArn": "arn:aws:states:us-east-1:" + mgmtAcct + ":stateMachine:sm1", "name": "run1"}); code != http.StatusOK ||
		out["executionArn"] != "arn:aws:states:us-east-1:"+mgmtAcct+":execution:sm1:run1" {
		t.Fatalf("management start of the same name: %d %v", code, out)
	}

	ctx := context.Background()
	ex, err := h.dyn.Resource(gvrExecutions).Namespace(memberHome).Get(ctx, "run1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the member's execution is kept in its home: %v", err)
	}
	if ns, _, _ := unstructured.NestedString(ex.Object, "spec", "credentialsNamespace"); ns != memberHome {
		t.Errorf("the member's credentials namespace is %q, want its home", ns)
	}
	sec, err := h.cs.CoreV1().Secrets(memberHome).Get(ctx, "run1-creds", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the member's execution credentials are beside its execution: %v", err)
	}
	if o := sec.OwnerReferences; len(o) != 1 || o[0].UID != ex.GetUID() {
		t.Errorf("the member's Secret is owned by its execution: %+v", o)
	}
	sess, ok := h.minter.Verify(string(sec.Data["accessKeyId"]), string(sec.Data["sessionToken"]))
	if !ok || sess.Account != testMember || sess.Namespace != memberHome || sess.RoleName != "runner" {
		t.Errorf("the member's execution session acts in its account as its role: %+v %v", sess, ok)
	}
	msec, err := h.cs.CoreV1().Secrets(sfnTestNS).Get(ctx, "run1-creds", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the management account's execution credentials are where they always were: %v", err)
	}
	if ms, ok := h.minter.Verify(string(msec.Data["accessKeyId"]), string(msec.Data["sessionToken"])); !ok || ms.Account != "" || ms.Namespace != "" {
		t.Errorf("the management account's execution session is unchanged: %+v %v", ms, ok)
	}

	execArns := func(out map[string]any) []string {
		var s []string
		for _, it := range out["executions"].([]any) {
			s = append(s, it.(map[string]any)["executionArn"].(string))
		}
		return s
	}
	if _, out := sfnCallAs(t, h, member, "ListExecutions", map[string]any{}); strings.Join(execArns(out), ",") != memberExec {
		t.Errorf("the member lists its own executions alone: %v", out)
	}
	if _, out := sfnCallAs(t, h, mgmt, "ListExecutions", map[string]any{}); strings.Join(execArns(out), ",") != "arn:aws:states:us-east-1:"+mgmtAcct+":execution:sm1:run1" {
		t.Errorf("the management account lists its own executions alone: %v", out)
	}
	if _, out := sfnCallAs(t, h, member, "ListExecutions", map[string]any{
		"stateMachineArn": "arn:aws:states:us-east-1:" + mgmtAcct + ":stateMachine:sm1"}); len(execArns(out)) != 0 {
		t.Errorf("the management account's state machine has no executions for the member: %v", out)
	}
	if _, out := sfnCallAs(t, h, member, "DescribeExecution", map[string]any{"executionArn": memberExec}); out["executionArn"] != memberExec ||
		out["stateMachineArn"] != "arn:aws:states:us-east-1:"+testMember+":stateMachine:sm1" {
		t.Errorf("the member describes its own execution: %v", out)
	}
	if _, out := sfnCallAs(t, h, member, "DescribeExecution", map[string]any{
		"executionArn": "arn:aws:states:us-east-1:" + mgmtAcct + ":execution:sm1:run1"}); jsonErrType(out) != "ExecutionDoesNotExist" {
		t.Errorf("another account's execution ARN must not resolve for a member: %v", out)
	}
	if _, out := sfnCallAs(t, h, member, "StopExecution", map[string]any{
		"executionArn": "arn:aws:states:us-east-1:" + mgmtAcct + ":execution:sm1:run1"}); jsonErrType(out) != "ExecutionDoesNotExist" {
		t.Errorf("a member must not stop another account's execution: %v", out)
	}
	if u, _ := h.dyn.Resource(gvrExecutions).Namespace(sfnTestNS).Get(ctx, "run1", metav1.GetOptions{}); u != nil {
		if stop, _, _ := unstructured.NestedBool(u.Object, "status", "stopRequested"); stop {
			t.Error("the management account's execution was asked to stop by a member")
		}
	}
}

// A member account's execution runs under its own role only if the role's trust names the caller: the
// member's bob is trusted by its runner, the management account's alice is not.
func TestSFNAccounts_MemberRoleTrustDecides(t *testing.T) {
	h := sfnAccountsHandler(t)
	h.roles = fakeRolesIn{fakeRoles: fakeRoles{}, in: fakeRoles{memberHome + "/runner": {trust: []string{"carol"}}}}
	member := memberDoorCaller()
	if code, out := sfnCallAs(t, h, member, "CreateStateMachine", map[string]any{"name": "sm1", "definition": sfnDef("m"), "roleArn": "runner"}); code != http.StatusOK {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, out := sfnCallAs(t, h, member, "StartExecution", map[string]any{
		"stateMachineArn": "arn:aws:states:us-east-1:" + testMember + ":stateMachine:sm1", "name": "r"}); code != http.StatusForbidden {
		t.Errorf("a role whose trust does not name the caller: %d %v", code, out)
	}
	h.roles = fakeRolesIn{fakeRoles: fakeRoles{}, in: fakeRoles{memberHome + "/runner": {trust: []string{"arn:aws:iam::" + testMember + ":root"}}}}
	if code, out := sfnCallAs(t, h, member, "StartExecution", map[string]any{
		"stateMachineArn": "arn:aws:states:us-east-1:" + testMember + ":stateMachine:sm1", "name": "r"}); code != http.StatusOK {
		t.Errorf("a role trusting its own account's root admits the account's principal: %d %v", code, out)
	}
}

// A member account's Task invokes its own account's functions: a Lambda ARN of another account is refused
// (never run as the member's function of the same name); its own account's ARN translates as before, and
// the management account's definitions translate exactly as they always did.
func TestSFNAccounts_TasksInvokeTheAccountsOwnFunctions(t *testing.T) {
	mgmtAcct := awsidentity.Current().AccountID
	task := func(res string) string {
		return `{"StartAt":"T","States":{"T":{"Type":"Task","Resource":"` + res + `","End":true}}}`
	}
	invoke := func(fn string) string {
		return `{"StartAt":"T","States":{"T":{"Type":"Task","Resource":"arn:aws:states:::lambda:invoke","Parameters":{"FunctionName":"` + fn + `"},"End":true}}}`
	}
	nested := `{"StartAt":"P","States":{"P":{"Type":"Parallel","End":true,"Branches":[{"StartAt":"T","States":{"T":{"Type":"Task","Resource":"arn:aws:lambda:us-east-1:` + mgmtAcct + `:function:orders","End":true}}}]}}}`
	for _, def := range []string{task("arn:aws:lambda:us-east-1:" + mgmtAcct + ":function:orders"), invoke("arn:aws:lambda:us-east-1:" + mgmtAcct + ":function:orders"), nested} {
		if _, err := validateAndTranslateDefinitionIn(def, testMember); err == nil || !strings.Contains(err.Error(), "another account") {
			t.Errorf("a member's Task naming another account's function: %v\n%s", err, def)
		}
		if out, err := validateAndTranslateDefinitionIn(def, ""); err != nil || !strings.Contains(out, "function:orders") {
			t.Errorf("the management account's definition translates as before: %v %s", err, out)
		}
	}
	for _, def := range []string{task("arn:aws:lambda:us-east-1:" + testMember + ":function:orders"), invoke("orders"), task("function:orders")} {
		if out, err := validateAndTranslateDefinitionIn(def, testMember); err != nil || !strings.Contains(out, `"function:orders"`) {
			t.Errorf("a member's own function: %v %s", err, out)
		}
	}
	h := sfnAccountsHandler(t)
	if code, out := sfnCallAs(t, h, memberDoorCaller(), "CreateStateMachine", map[string]any{"name": "x",
		"definition": task("arn:aws:lambda:us-east-1:" + mgmtAcct + ":function:orders")}); code != http.StatusBadRequest || jsonErrType(out) != "InvalidDefinition" {
		t.Errorf("CreateStateMachine of a member naming another account's function: %d %v", code, out)
	}
}

func TestSFNAccounts_DoorIsAccountScoped(t *testing.T) {
	if !accountScopedServices["states"] {
		t.Fatal("states must be registered as account-scoped")
	}
}
