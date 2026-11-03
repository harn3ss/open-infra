package main

// SSM Run Command (#347 item 22) against a real Postgres store (OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go): SendCommand, the agent channel's long-poll and report, GetCommandInvocation,
// ListCommandInvocations, ListCommands and DescribeInstanceInformation, and every refusal.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	rcWeb   = "i-0123456789abcdef0"
	rcTwo   = "i-22222222222222222"
	rcOther = "i-11111111111111111"
)

type rcFixture struct {
	ssm *ssmHandler
	vmc *vmCommandsHandler
	st  *ssmStore
}

func newRCFixture(t *testing.T) *rcFixture {
	t.Helper()
	db := freshPGDB(t)
	st := &ssmStore{db: db}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	vm := func(name, id, role, os string) runtime.Object {
		return ec2Obj("VirtualMachine", name, map[string]any{"os": os, "instanceRole": role}, map[string]any{"instanceId": id, "powerState": "Running"}, nil)
	}
	ec2H, dyn := ec2Fixture(t, ec2Web(), vm("s-two", rcTwo, "s-role", "ubuntu-24.04"), vm("s-other", rcOther, "s-norole", "ubuntu-24.04"))
	authz := dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{
			{AppliesTo: []string{"Role::s-role"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"ssm:UpdateInstanceInformation", "ec2messages:*"}, Resources: []string{"*"}}}},
			{AppliesTo: []string{"User::tester"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"ssm:*"}, Resources: []string{"*"}},
				{Effect: policyengine.Deny, Actions: []string{"ssm:SendCommand"}, Resources: []string{"Instance::" + rcWeb}},
				{Effect: policyengine.Deny, Actions: []string{"ssm:GetCommandInvocation"}, Resources: []string{"*"}}}},
			{AppliesTo: []string{"User::nodoc"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"ssm:*"}, Resources: []string{"*"}},
				{Effect: policyengine.Deny, Actions: []string{"ssm:SendCommand"}, Resources: []string{"Document::AWS-RunShellScript"}}}},
		}}, nil
	}, time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := &commandBus{}
	ssmH := newSSMHandler(csWithSAR(true), "authz", "123456789012", "us-east-1", nil, st, logger)
	ssmH.authz, ssmH.ec2, ssmH.bus = authz, ec2H, bus
	ec2H.door.authz = authz
	vmc := &vmCommandsHandler{
		resolver: fakeSAResolver{byToken: map[string]saIdentity{
			"tok-web":       {role: "s-role", namespace: ec2TestNS, vmName: "s-web"},
			"tok-two":       {role: "s-role", namespace: ec2TestNS, vmName: "s-two"},
			"tok-other":     {role: "s-norole", namespace: ec2TestNS, vmName: "s-other"},
			"tok-norole":    {namespace: ec2TestNS, vmName: "s-two"},
			"tok-elsewhere": {role: "s-role", namespace: "tenant-b", vmName: "s-web"},
		}},
		trust: fakeTrust{vmRoles: map[string]bool{ec2TestNS + "/s-role": true, ec2TestNS + "/s-norole": true}},
		store: st, dyn: dyn, authz: authz, home: ec2TestNS, namespaces: map[string]bool{ec2TestNS: true}, bus: bus,
		maxWait: 3 * time.Second, recheck: 50 * time.Millisecond, cacheTTL: time.Minute, logger: logger,
	}
	return &rcFixture{ssm: ssmH, vmc: vmc, st: st}
}

func (f *rcFixture) call(t *testing.T, claims iam.Claims, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "http://shim/", strings.NewReader(string(b)))
	r.Header.Set("X-Amz-Target", "AmazonSSM."+op)
	w := httptest.NewRecorder()
	f.ssm.serve(w, r, claims, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// agent makes an agent request (GET poll, or POST a report) with a token.
func (f *rcFixture) agent(t *testing.T, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	r := httptest.NewRequest(method, "https://shim"+path, rd)
	if token != "" {
		r.Header.Set("Authorization", token)
	}
	w := httptest.NewRecorder()
	f.vmc.serve(w, r, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func errType(out map[string]any) string { s, _ := out["__type"].(string); return s }

func sendBody(ids ...string) map[string]any {
	return map[string]any{"DocumentName": "AWS-RunShellScript", "InstanceIds": ids, "Parameters": map[string]any{"commands": []any{"echo hello"}}}
}

func TestServicesPG_SSMRunCommand(t *testing.T) {
	f := newRCFixture(t)
	alice := ec2Alice

	// An instance whose agent never registered is not a valid target.
	if code, out := f.call(t, alice, "SendCommand", sendBody(rcWeb)); code != 400 || errType(out) != "InvalidInstanceId" {
		t.Fatalf("SendCommand to an unregistered instance = %d %v", code, out)
	}
	// The agent channel's refusals: no token, an unknown token, a VM with no role, another namespace,
	// and a role that does not allow the SSM agent's actions.
	for _, c := range []struct {
		token string
		want  int
	}{{"", 401}, {"forged", 401}, {"tok-norole", 403}, {"tok-elsewhere", 404}, {"tok-other", 403}} {
		if code, _ := f.agent(t, c.token, "GET", "/v1/vm-commands?wait=0", nil); code != c.want {
			t.Errorf("agent poll with %q = %d, want %d", c.token, code, c.want)
		}
	}
	// The managed agents register.
	for _, tok := range []string{"tok-web", "tok-two"} {
		if code, out := f.agent(t, tok, "GET", "/v1/vm-commands?wait=0&platformName=Ubuntu&platformVersion=24.04", nil); code != 200 || len(out["Commands"].([]any)) != 0 {
			t.Fatalf("%s's first poll = %d %v", tok, code, out)
		}
	}
	code, out := f.call(t, alice, "DescribeInstanceInformation", map[string]any{})
	list, _ := out["InstanceInformationList"].([]any)
	if code != 200 || len(list) != 2 || list[0].(map[string]any)["InstanceId"] != rcWeb || list[0].(map[string]any)["PingStatus"] != "Online" ||
		list[0].(map[string]any)["PlatformName"] != "Ubuntu" {
		t.Fatalf("DescribeInstanceInformation = %d %v", code, out)
	}
	if _, out := f.call(t, alice, "DescribeInstanceInformation", map[string]any{"Filters": []any{map[string]any{"Key": "tag:Name", "Values": []any{"web"}}}}); len(out["InstanceInformationList"].([]any)) != 1 {
		t.Errorf("tag:Name=web selects one instance: %v", out)
	}

	// SendCommand's refusals.
	for name, c := range map[string]struct {
		claims iam.Claims
		body   map[string]any
		want   string
	}{
		"another document":           {alice, map[string]any{"DocumentName": "AWS-ConfigureDocker", "InstanceIds": []any{rcWeb}, "Parameters": map[string]any{"commands": []any{"x"}}}, "InvalidDocument"},
		"no commands":                {alice, map[string]any{"DocumentName": "AWS-RunShellScript", "InstanceIds": []any{rcWeb}}, "InvalidParameters"},
		"an unknown parameter":       {alice, map[string]any{"DocumentName": "AWS-RunShellScript", "InstanceIds": []any{rcWeb}, "Parameters": map[string]any{"commands": []any{"x"}, "sudo": []any{"yes"}}}, "InvalidParameters"},
		"S3 output":                  {alice, map[string]any{"DocumentName": "AWS-RunShellScript", "InstanceIds": []any{rcWeb}, "Parameters": map[string]any{"commands": []any{"x"}}, "OutputS3BucketName": "logs"}, "InvalidParameters"},
		"an instance it can't run":   {alice, sendBody(rcOther), "InvalidInstanceId"},
		"a malformed id":             {alice, sendBody("s-web"), "InvalidInstanceId"},
		"denied on the instance":     {iam.Claims{Sub: "tester"}, sendBody(rcWeb), "AccessDeniedException"},
		"denied on the document":     {iam.Claims{Sub: "nodoc"}, sendBody(rcWeb), "AccessDeniedException"},
		"an assumed role, no policy": {iam.Claims{Sub: "assumed-role/x/y", AssumedRole: "x"}, sendBody(rcWeb), "AccessDeniedException"},
	} {
		if code, out := f.call(t, c.claims, "SendCommand", c.body); code != 400 || errType(out) != c.want {
			t.Errorf("%s: SendCommand = %d %v, want %s", name, code, out, c.want)
		}
	}
	// A User needs RBAC update on the VM itself.
	f.ssm.cs = csWithSARFunc(func(a *authzv1.ResourceAttributes) bool {
		return !(a.Verb == "update" && a.Resource == "virtualmachines")
	})
	if code, out := f.call(t, alice, "SendCommand", sendBody(rcWeb)); code != 400 || errType(out) != "AccessDeniedException" {
		t.Errorf("SendCommand without update on the VM = %d %v", code, out)
	}
	f.ssm.cs = csWithSAR(true)

	// A waiting poll wakes when the command is sent.
	type polled struct {
		code int
		out  map[string]any
	}
	got := make(chan polled, 1)
	go func() {
		c, o := f.agent(t, "tok-web", "GET", "/v1/vm-commands?wait=3", nil)
		got <- polled{c, o}
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	code, out = f.call(t, alice, "SendCommand", map[string]any{"DocumentName": "arn:aws:ssm:us-east-1::document/AWS-RunShellScript",
		"Targets": []any{map[string]any{"Key": "tag:Name", "Values": []any{"web"}}}, "Comment": "deploy",
		"Parameters": map[string]any{"commands": []any{"echo hello", "echo oops >&2"}, "executionTimeout": []any{"120"}}})
	if code != 200 {
		t.Fatalf("SendCommand = %d %v", code, out)
	}
	cmd := out["Command"].(map[string]any)
	cid := cmd["CommandId"].(string)
	if cmd["Status"] != "Pending" || cmd["TargetCount"].(float64) != 1 || cmd["InstanceIds"].([]any)[0] != rcWeb {
		t.Fatalf("the sent command = %v", cmd)
	}
	p := <-got
	cmds, _ := p.out["Commands"].([]any)
	if p.code != 200 || len(cmds) != 1 || cmds[0].(map[string]any)["CommandId"] != cid || time.Since(start) > 2*time.Second {
		t.Fatalf("the waiting poll = %d %v after %v", p.code, p.out, time.Since(start))
	}
	params := cmds[0].(map[string]any)["Parameters"].(map[string]any)
	if params["executionTimeout"].([]any)[0] != "120" || len(params["commands"].([]any)) != 2 {
		t.Errorf("the delivered parameters = %v", params)
	}
	// Delivered once: the next poll has nothing.
	if _, out := f.agent(t, "tok-web", "GET", "/v1/vm-commands?wait=0", nil); len(out["Commands"].([]any)) != 0 {
		t.Errorf("a command is delivered once: %v", out)
	}
	if _, out := f.call(t, alice, "GetCommandInvocation", map[string]any{"CommandId": cid, "InstanceId": rcWeb}); out["Status"] != "InProgress" {
		t.Errorf("a delivered invocation is InProgress: %v", out)
	}
	// Another instance's agent cannot report it; the instance's own can, once.
	report := map[string]any{"Status": "Success", "ResponseCode": 0, "StandardOutputContent": "hello\n" + strings.Repeat("x", 30000), "StandardErrorContent": "oops\n"}
	if code, _ := f.agent(t, "tok-two", "POST", "/v1/vm-commands/"+cid, report); code != 409 {
		t.Errorf("another instance's report = %d, want 409", code)
	}
	if code, _ := f.agent(t, "tok-web", "POST", "/v1/vm-commands/"+cid, map[string]any{"Status": "Bogus"}); code != 400 {
		t.Errorf("a report with a bad status = %d", code)
	}
	if code, out := f.agent(t, "tok-web", "POST", "/v1/vm-commands/"+cid, report); code != 200 {
		t.Fatalf("the instance's report = %d %v", code, out)
	}
	if code, _ := f.agent(t, "tok-web", "POST", "/v1/vm-commands/"+cid, report); code != 409 {
		t.Errorf("a second report = %d, want 409", code)
	}
	code, out = f.call(t, alice, "GetCommandInvocation", map[string]any{"CommandId": cid, "InstanceId": rcWeb})
	if code != 200 || out["Status"] != "Success" || out["ResponseCode"].(float64) != 0 || out["StandardErrorContent"] != "oops\n" ||
		len([]rune(out["StandardOutputContent"].(string))) != ssmOutputCap || !strings.HasPrefix(out["StandardOutputContent"].(string), "hello") ||
		out["ExecutionEndDateTime"] == "" || out["PluginName"] != "aws:runShellScript" {
		t.Fatalf("GetCommandInvocation = %d %v", code, out)
	}
	// The output is readable only with ssm:GetCommandInvocation, and only for an instance the caller sees.
	if code, out := f.call(t, iam.Claims{Sub: "tester"}, "GetCommandInvocation", map[string]any{"CommandId": cid, "InstanceId": rcWeb}); code != 400 || errType(out) != "AccessDeniedException" {
		t.Errorf("GetCommandInvocation denied = %d %v", code, out)
	}
	if code, out := f.call(t, alice, "GetCommandInvocation", map[string]any{"CommandId": cid, "InstanceId": rcTwo}); code != 400 || errType(out) != "InvocationDoesNotExist" {
		t.Errorf("an invocation that does not exist = %d %v", code, out)
	}
	code, out = f.call(t, alice, "ListCommandInvocations", map[string]any{"CommandId": cid, "Details": true})
	inv := out["CommandInvocations"].([]any)
	if o, _ := inv[0].(map[string]any)["CommandPlugins"].([]any)[0].(map[string]any)["Output"].(string); code != 200 || len(inv) != 1 || !strings.HasPrefix(o, "hello") || len([]rune(o)) != 2500 {
		t.Errorf("ListCommandInvocations = %d %v", code, out)
	}
	code, out = f.call(t, alice, "ListCommands", map[string]any{"InstanceId": rcWeb})
	cl := out["Commands"].([]any)
	if code != 200 || len(cl) != 1 || cl[0].(map[string]any)["Status"] != "Success" || cl[0].(map[string]any)["Comment"] != "deploy" {
		t.Errorf("ListCommands = %d %v", code, out)
	}
	if code, out := f.call(t, alice, "ListCommands", map[string]any{"CommandId": "no-such-command"}); code != 400 || errType(out) != "InvalidCommandId" {
		t.Errorf("ListCommands of an unknown command = %d %v", code, out)
	}

	// An invocation its agent never takes times out (DeliveryTimedOut) after the command's TimeoutSeconds.
	code, out = f.call(t, alice, "SendCommand", map[string]any{"DocumentName": "AWS-RunShellScript", "InstanceIds": []any{rcTwo}, "TimeoutSeconds": 30,
		"Parameters": map[string]any{"commands": []any{"true"}}})
	if code != 200 {
		t.Fatalf("SendCommand = %d %v", code, out)
	}
	late := out["Command"].(map[string]any)["CommandId"].(string)
	if _, err := f.st.db.Exec(`UPDATE ssm_commands SET expires_at = now() - interval '1 second' WHERE command_id=$1`, late); err != nil {
		t.Fatal(err)
	}
	if _, out := f.call(t, alice, "GetCommandInvocation", map[string]any{"CommandId": late, "InstanceId": rcTwo}); out["Status"] != "TimedOut" || out["StatusDetails"] != "DeliveryTimedOut" {
		t.Errorf("an undelivered invocation past its timeout = %v", out)
	}
	if _, out := f.agent(t, "tok-two", "GET", "/v1/vm-commands?wait=0", nil); len(out["Commands"].([]any)) != 0 {
		t.Errorf("a timed-out command is not delivered: %v", out)
	}
}

// The agent channel answers only over TLS, whatever VM_CREDS_ALLOW_PLAINTEXT says.
func TestVMCommands_PlaintextRefused(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	for _, allow := range []bool{false, true} {
		w := httptest.NewRecorder()
		plaintextVMCredsGuard(next, allow).ServeHTTP(w, httptest.NewRequest("GET", "http://shim/v1/vm-commands", nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("plaintext /v1/vm-commands (allow=%v) = %d, want 404", allow, w.Code)
		}
		w = httptest.NewRecorder()
		plaintextVMCredsGuard(next, allow).ServeHTTP(w, httptest.NewRequest("POST", "http://shim/v1/vm-commands/x", nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("plaintext report (allow=%v) = %d, want 404", allow, w.Code)
		}
	}
	// The router answers 404 while the channel is off.
	rt := newTestRouter(map[string]awsService{})
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, httptest.NewRequest("GET", "https://shim/v1/vm-commands", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("the channel while off = %d, want 404", w.Code)
	}
}
