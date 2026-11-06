package main

// SSM Run Command keeps each account's instances and commands apart, against a real Postgres store
// (OPENINFRA_TEST_PG_URI; see cfn_services_pg_test.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type rcAccountsFixture struct {
	ssm *ssmHandler
	vmc *vmCommandsHandler
	st  *ssmStore
}

func newRCAccountsFixture(t *testing.T) *rcAccountsFixture {
	t.Helper()
	db := freshPGDB(t)
	st := &ssmStore{db: db}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	memberVM := inNS(ec2Obj("VirtualMachine", "s-web", map[string]any{"os": "ubuntu-24.04", "instanceRole": "s-role"},
		map[string]any{"instanceId": memberWebID, "powerState": "Running"}, nil), memberHome)
	devVM := inNS(ec2Obj("VirtualMachine", "s-dev", map[string]any{"os": "ubuntu-24.04", "instanceRole": "s-role"},
		map[string]any{"instanceId": "i-0bbbbbbbbbbbbbbb2", "powerState": "Running"}, nil), "team-a-dev")
	ec2H, dyn := ec2Fixture(t, []runtime.Object{ec2Web(), memberVM, devVM}...)
	agentActions := []policyengine.Statement{dpAllow([]string{"ssm:UpdateInstanceInformation", "ec2messages:*"}, "*")}
	all := []policyengine.Statement{dpAllow([]string{"*"}, "*")}
	// The instance role's policy in each account: the management account's s-role, and the member
	// account's own s-role in its home (team-a/s-role).
	authz := checkerInMode(t, "enforce",
		dataplaneauthz.PolicyDoc{Name: "mgmt-agent", AppliesTo: []string{"Role::s-role"}, Statements: agentActions},
		dataplaneauthz.PolicyDoc{Name: "member-agent", AppliesTo: []string{"Role::" + memberHome + "/s-role"}, Statements: agentActions},
		dataplaneauthz.PolicyDoc{Name: "alice-all", AppliesTo: []string{"User::alice"}, Statements: all},
		dataplaneauthz.PolicyDoc{Name: "bob-all", AppliesTo: []string{"User::" + memberHome + "/bob"}, Statements: all})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := &commandBus{}
	ssmH := newSSMHandler(csWithSAR(true), "authz", "123456789012", "us-east-1", nil, st, logger)
	ssmH.authz, ssmH.ec2, ssmH.bus = authz, ec2H, bus
	ec2H.door.authz = authz
	dir := testDirectory()
	dir.Observe(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a-dev", Labels: map[string]string{accounts.LabelAccountID: testMember}}})
	vmc := &vmCommandsHandler{
		resolver: fakeSAResolver{byToken: map[string]saIdentity{
			"tok-mgmt":      {role: "s-role", namespace: ec2TestNS, vmName: "s-web"},
			"tok-member":    {role: "s-role", namespace: memberHome, vmName: "s-web"},
			"tok-dev":       {role: "s-role", namespace: "team-a-dev", vmName: "s-dev"},
			"tok-suspended": {role: "s-role", namespace: "team-b", vmName: "s-web"},
			"tok-unlabeled": {role: "s-role", namespace: "tenant-b", vmName: "s-web"},
		}},
		trust: fakeTrust{vmRoles: map[string]bool{ec2TestNS + "/s-role": true, memberHome + "/s-role": true, "team-a-dev/s-role": true,
			"team-b/s-role": true, "tenant-b/s-role": true}},
		store: st, dyn: dyn, authz: authz, home: ec2TestNS, namespaces: map[string]bool{ec2TestNS: true}, accounts: dir, bus: bus,
		maxWait: 3 * time.Second, recheck: 50 * time.Millisecond, cacheTTL: time.Minute, logger: logger,
	}
	return &rcAccountsFixture{ssm: ssmH, vmc: vmc, st: st}
}

// call is an SSM call acting in ctx's account, marked account-scoped as the router marks the "ssm" door's.
func (f *rcAccountsFixture) call(t *testing.T, ctx context.Context, claims iam.Claims, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "http://shim/", bytes.NewReader(b)).WithContext(inAccountScope(ctx))
	r.Header.Set("X-Amz-Target", "AmazonSSM."+op)
	w := httptest.NewRecorder()
	f.ssm.serve(w, r, claims, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *rcAccountsFixture) agent(t *testing.T, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "https://shim"+path, rd)
	r.Header.Set("Authorization", token)
	w := httptest.NewRecorder()
	f.vmc.serve(w, r, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func fmtAny(v any) string { s, _ := v.(string); return s }

func commandIDs(out map[string]any, key string) []string {
	var ids []string
	l, _ := out[key].([]any)
	for _, c := range l {
		m, _ := c.(map[string]any)
		ids = append(ids, m["CommandId"].(string))
	}
	return ids
}

// A member account's instance (its VM in its home) is its own managed instance: its agent registers and acts
// in the member account, the member account's commands reach it and no other account's, and each account's
// commands, invocations and managed instances are listed for it alone.
func TestServicesPG_SSMRunCommandAccounts(t *testing.T) {
	if !accountScopedServices["ssm"] {
		t.Fatal("Run Command and Parameter Store keep each account's apart, so the ssm door is listed as account-scoped")
	}
	f := newRCAccountsFixture(t)
	member, mgmt := memberCtx(), context.Background()

	// The agent channel: the management account's stack namespace and the member account's home are managed;
	// a member account's other namespace, an unlabeled tenant namespace and a suspended account are not.
	for _, c := range []struct {
		token string
		want  int
	}{{"tok-mgmt", 200}, {"tok-member", 200}, {"tok-dev", 404}, {"tok-unlabeled", 404}, {"tok-suspended", 403}} {
		if code, out := f.agent(t, c.token, "GET", "/v1/vm-commands?wait=0&platformName=Ubuntu", nil); code != c.want {
			t.Errorf("agent poll with %s = %d %v, want %d", c.token, code, out, c.want)
		}
	}
	var ns string
	if err := f.st.db.QueryRow(`SELECT namespace FROM ssm_managed_instances WHERE instance_id=$1`, memberWebID).Scan(&ns); err != nil || ns != memberHome {
		t.Fatalf("the member account's instance registers from its home: %q %v", ns, err)
	}

	// Each account's managed instances are its own.
	_, out := f.call(t, member, ec2Bob, "DescribeInstanceInformation", map[string]any{})
	if l, _ := out["InstanceInformationList"].([]any); len(l) != 1 || l[0].(map[string]any)["InstanceId"] != memberWebID {
		t.Errorf("the member account's managed instances = %v", out)
	}
	_, out = f.call(t, mgmt, ec2Alice, "DescribeInstanceInformation", map[string]any{})
	if l, _ := out["InstanceInformationList"].([]any); len(l) != 1 || l[0].(map[string]any)["InstanceId"] != rcWeb {
		t.Errorf("the management account's managed instances = %v", out)
	}

	// Neither account sends a command to the other's instance.
	if code, out := f.call(t, member, ec2Bob, "SendCommand", sendBody(rcWeb)); code != 400 || errType(out) != "InvalidInstanceId" ||
		!strings.Contains(fmtAny(out["message"]), testMember) {
		t.Errorf("member SendCommand to the management account's instance = %d %v", code, out)
	}
	if code, out := f.call(t, mgmt, ec2Alice, "SendCommand", sendBody(memberWebID)); code != 400 || errType(out) != "InvalidInstanceId" {
		t.Errorf("management SendCommand to the member account's instance = %d %v", code, out)
	}

	// Each sends to its own.
	code, out := f.call(t, member, ec2Bob, "SendCommand", sendBody(memberWebID))
	if code != 200 {
		t.Fatalf("member SendCommand = %d %v", code, out)
	}
	memberCmd := out["Command"].(map[string]any)["CommandId"].(string)
	code, out = f.call(t, mgmt, ec2Alice, "SendCommand", sendBody(rcWeb))
	if code != 200 {
		t.Fatalf("management SendCommand = %d %v", code, out)
	}
	mgmtCmd := out["Command"].(map[string]any)["CommandId"].(string)
	var acct string
	if err := f.st.db.QueryRow(`SELECT account FROM ssm_commands WHERE command_id=$1`, memberCmd).Scan(&acct); err != nil || acct != testMember {
		t.Errorf("the member account's command records its account: %q %v", acct, err)
	}
	if err := f.st.db.QueryRow(`SELECT account FROM ssm_commands WHERE command_id=$1`, mgmtCmd).Scan(&acct); err != nil || acct != "" {
		t.Errorf("the management account's command is recorded as it always was: %q %v", acct, err)
	}

	// Each agent receives its own account's command alone.
	if _, out := f.agent(t, "tok-member", "GET", "/v1/vm-commands?wait=0", nil); len(commandIDs(out, "Commands")) != 1 || commandIDs(out, "Commands")[0] != memberCmd {
		t.Fatalf("the member account's agent = %v", out)
	}
	if _, out := f.agent(t, "tok-mgmt", "GET", "/v1/vm-commands?wait=0", nil); len(commandIDs(out, "Commands")) != 1 || commandIDs(out, "Commands")[0] != mgmtCmd {
		t.Fatalf("the management account's agent = %v", out)
	}
	if code, _ := f.agent(t, "tok-member", "POST", "/v1/vm-commands/"+mgmtCmd, map[string]any{"Status": "Success"}); code != 409 {
		t.Errorf("the member account's agent reports the management account's command = %d, want 409", code)
	}
	if code, _ := f.agent(t, "tok-member", "POST", "/v1/vm-commands/"+memberCmd, map[string]any{"Status": "Success", "StandardOutputContent": "member\n"}); code != 200 {
		t.Fatalf("the member account's agent's report = %d", code)
	}

	// The member account reads its own command's output; the management account's command is none of its.
	if code, out := f.call(t, member, ec2Bob, "GetCommandInvocation", map[string]any{"CommandId": memberCmd, "InstanceId": memberWebID}); code != 200 ||
		out["Status"] != "Success" || out["StandardOutputContent"] != "member\n" {
		t.Errorf("member GetCommandInvocation = %d %v", code, out)
	}
	if code, out := f.call(t, member, ec2Bob, "GetCommandInvocation", map[string]any{"CommandId": mgmtCmd, "InstanceId": rcWeb}); code != 400 || errType(out) != "InvocationDoesNotExist" {
		t.Errorf("member GetCommandInvocation of the management account's command = %d %v", code, out)
	}
	if code, out := f.call(t, mgmt, ec2Alice, "GetCommandInvocation", map[string]any{"CommandId": memberCmd, "InstanceId": memberWebID}); code != 400 || errType(out) != "InvocationDoesNotExist" {
		t.Errorf("management GetCommandInvocation of the member account's command = %d %v", code, out)
	}
	for _, op := range []string{"ListCommands", "ListCommandInvocations"} {
		if code, out := f.call(t, member, ec2Bob, op, map[string]any{"CommandId": mgmtCmd}); code != 400 || errType(out) != "InvalidCommandId" {
			t.Errorf("member %s of the management account's command = %d %v", op, code, out)
		}
	}
	if _, out := f.call(t, member, ec2Bob, "ListCommands", map[string]any{}); len(commandIDs(out, "Commands")) != 1 || commandIDs(out, "Commands")[0] != memberCmd {
		t.Errorf("member ListCommands = %v", out)
	}
	if _, out := f.call(t, mgmt, ec2Alice, "ListCommands", map[string]any{}); len(commandIDs(out, "Commands")) != 1 || commandIDs(out, "Commands")[0] != mgmtCmd {
		t.Errorf("management ListCommands = %v", out)
	}
	if _, out := f.call(t, member, ec2Bob, "ListCommandInvocations", map[string]any{}); len(commandIDs(out, "CommandInvocations")) != 1 ||
		commandIDs(out, "CommandInvocations")[0] != memberCmd {
		t.Errorf("member ListCommandInvocations = %v", out)
	}
}

// The member account's agent acts in its own account: its role is the member account's (team-a/s-role) and
// is decided there, so a policy on the management account's role of that name does not reach it.
func TestServicesPG_SSMRunCommandAgentActsInItsAccount(t *testing.T) {
	f := newRCAccountsFixture(t)
	a, status, msg := f.vmc.identify(context.Background(), "tok-member")
	if status != 0 {
		t.Fatalf("identify the member account's agent: %d %s", status, msg)
	}
	if a.claims.Account != testMember || a.account != testMember || a.accountHome != memberHome || a.claims.AssumedRole != memberHome+"/s-role" {
		t.Fatalf("the member account's agent = %+v", a)
	}
	ctx := a.actingIn(context.Background())
	if callerAccount(ctx) != testMember || !accountScoped(ctx) || accountNamespace(ctx, ec2TestNS) != memberHome {
		t.Errorf("the member account's agent acts in its account: %q %v %q", callerAccount(ctx), accountScoped(ctx), accountNamespace(ctx, ec2TestNS))
	}
	// Without the member account's role policy, its agent is refused, though the management account's s-role may.
	f.vmc.authz = checkerInMode(t, "enforce", dataplaneauthz.PolicyDoc{Name: "mgmt-agent", AppliesTo: []string{"Role::s-role"},
		Statements: []policyengine.Statement{dpAllow([]string{"ssm:UpdateInstanceInformation", "ec2messages:*"}, "*")}})
	if code, _ := f.agent(t, "tok-member", "GET", "/v1/vm-commands?wait=0", nil); code != 403 {
		t.Errorf("the member account's agent with no policy of its own = %d, want 403", code)
	}
	if code, _ := f.agent(t, "tok-mgmt", "GET", "/v1/vm-commands?wait=0", nil); code != 200 {
		t.Errorf("the management account's agent = %d", code)
	}
}
