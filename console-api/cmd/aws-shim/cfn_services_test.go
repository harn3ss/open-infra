package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
)

// memOwners is an in-memory serviceOwnerStore: the cfn_service_resources table without Postgres (specs
// round-trip through JSON, as through its jsonb column).
type memOwners struct {
	mu sync.Mutex
	m  map[string]memOwner
}

type memOwner struct {
	stack, ns string
	spec      []byte
}

func newMemOwners() *memOwners { return &memOwners{m: map[string]memOwner{}} }

func (o *memOwners) get(_ context.Context, kind, name string) (string, map[string]any, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, ok := o.m[kind+"/"+name]
	if !ok {
		return "", nil, false, nil
	}
	spec := map[string]any{}
	_ = json.Unmarshal(r.spec, &spec)
	return r.stack, spec, true, nil
}

func (o *memOwners) put(_ context.Context, kind, name, stack, ns string, spec map[string]any) error {
	b, _ := json.Marshal(spec)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[kind+"/"+name] = memOwner{stack: stack, ns: ns, spec: b}
	return nil
}

func (o *memOwners) del(_ context.Context, kind, name string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.m, kind+"/"+name)
	return nil
}

func (o *memOwners) stacks() map[string]string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := map[string]string{}
	for k, r := range o.m {
		out[k] = r.stack
	}
	return out
}

// fakeFront is an in-memory AWS front door: it records each call (op, body, the in-process context's
// CloudFormation hints) and answers from a handler.
type fakeFront struct {
	mu     sync.Mutex
	calls  []fakeCall
	handle func(op string, body map[string]any) (int, map[string]any)
}

type fakeCall struct {
	op      string
	body    map[string]any
	fixed   string            // the ARN a CreateSecret was given by the CloudFormation front door
	targets map[string]string // the namespaces a PutTargets was given
	claims  iam.Claims
}

func (f *fakeFront) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, _ string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	body := map[string]any{}
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &body)
	c := fakeCall{op: op, body: body, claims: claims}
	c.fixed, _ = r.Context().Value(cfnSecretARNKey{}).(string)
	c.targets, _ = r.Context().Value(cfnTargetNamespaceKey{}).(map[string]string)
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	status, out := f.handle(op, body)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeFront) authFailure(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(403) }

func (f *fakeFront) ops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.op)
	}
	return out
}

func (f *fakeFront) last(op string) *fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].op == op {
			c := f.calls[i]
			return &c
		}
	}
	return nil
}

func notFound(code string) (int, map[string]any) {
	return 400, map[string]any{"__type": code, "message": "not found"}
}

// fakeSecrets is a Secrets Manager holding names -> value.
func fakeSecrets(preexisting ...string) *fakeFront {
	have := map[string]string{}
	for _, n := range preexisting {
		have[n] = "arn:aws:secretsmanager:r:a:secret:" + n + "-zzzzzz"
	}
	return &fakeFront{handle: func(op string, b map[string]any) (int, map[string]any) {
		id, _ := b["SecretId"].(string)
		switch op {
		case "DescribeSecret":
			if arn, ok := have[id]; ok {
				return 200, map[string]any{"Name": id, "ARN": arn}
			}
			return notFound("ResourceNotFoundException")
		case "GetRandomPassword":
			return 200, map[string]any{"RandomPassword": "generated-pw"}
		case "CreateSecret":
			n := b["Name"].(string)
			if _, ok := have[n]; ok {
				return 400, map[string]any{"__type": "ResourceExistsException"}
			}
			have[n] = "arn:fixed"
			return 200, map[string]any{"Name": n}
		case "DeleteSecret":
			if _, ok := have[id]; !ok {
				return notFound("ResourceNotFoundException")
			}
			delete(have, id)
			return 200, map[string]any{}
		}
		return 200, map[string]any{}
	}}
}

// fakeEvents is an EventBridge holding rules and their targets.
func fakeEvents() *fakeFront {
	rules := map[string]bool{}
	targets := map[string]map[string]bool{}
	return &fakeFront{handle: func(op string, b map[string]any) (int, map[string]any) {
		name, _ := b["Name"].(string)
		rule, _ := b["Rule"].(string)
		switch op {
		case "DescribeRule":
			if rules[name] {
				return 200, map[string]any{"Name": name, "Arn": "arn:rule/" + name, "State": "ENABLED"}
			}
			return notFound("ResourceNotFoundException")
		case "PutRule":
			rules[name] = true
			return 200, map[string]any{}
		case "ListTargetsByRule":
			var out []any
			for id := range targets[rule] {
				out = append(out, map[string]any{"Id": id})
			}
			return 200, map[string]any{"Targets": out}
		case "PutTargets":
			if targets[rule] == nil {
				targets[rule] = map[string]bool{}
			}
			for _, t := range b["Targets"].([]any) {
				targets[rule][t.(map[string]any)["Id"].(string)] = true
			}
			return 200, map[string]any{}
		case "RemoveTargets":
			for _, id := range b["Ids"].([]any) {
				delete(targets[rule], id.(string))
			}
			return 200, map[string]any{}
		case "DeleteRule":
			if len(targets[name]) > 0 {
				return 400, map[string]any{"__type": "ValidationException", "message": "rule has targets"}
			}
			delete(rules, name)
			return 200, map[string]any{}
		}
		return 200, map[string]any{}
	}}
}

const svcStack = `
Resources:
  Db: { Type: AWS::SecretsManager::Secret, Properties: { Name: app-db, Description: db, SecretString: %VALUE% } }
  Gen:
    Type: AWS::SecretsManager::Secret
    Properties: { GenerateSecretString: { SecretStringTemplate: '{"user":"app"}', GenerateStringKey: password } }
  Tick:
    Type: AWS::Events::Rule
    Properties: { ScheduleExpression: "rate(5 minutes)", Targets: [ { Id: fn, Arn: "arn:aws:lambda:r:a:function:job", Input: '{"x":1}' } ] }
`

func svcTestApplier(t *testing.T, sm, eb *fakeFront) (*memOwners, *impersonatingApplier) {
	t.Helper()
	h, ap := cfnTestDoorway(t, "")
	owners := newMemOwners()
	h.services = &cfnServices{owners: owners, doors: map[string]awsService{"secretsmanager": sm, "events": eb}}
	ap.svc, ap.door, ap.user = h.services, h, "dev"
	ap.claims = &iam.Claims{Sub: "dev"}
	return owners, ap
}

func svcOpts() cfn.DeployOptions {
	return cfn.DeployOptions{StackName: "app", Namespace: "default", Wait: true, Timeout: 5 * time.Second,
		Caps: cfn.Capabilities{SecretsManagerAPI: true, EventsAPI: true}}
}

// A stack's service resources are created through their front doors as the caller, kept in sync on update,
// and removed with the stack — their ownership records (cfn_service_resources) with them.
func TestCFNServices_CreateUpdateDelete(t *testing.T) {
	sm, eb := fakeSecrets(), fakeEvents()
	owners, ap := svcTestApplier(t, sm, eb)
	ctx := context.Background()
	tmpl := func(v string) []byte { return []byte(strings.Replace(svcStack, "%VALUE%", v, 1)) }

	rec, err := cfn.Deploy(ctx, tmpl("one"), svcOpts(), ap)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("status %s", rec.Status)
	}
	c := sm.last("CreateSecret")
	if c == nil || c.claims.Sub != "dev" {
		t.Fatalf("CreateSecret not made as the caller: %+v", c)
	}
	// The generated secret is the template with the generated password in its key.
	var gen *fakeCall
	for i := range sm.calls {
		if sm.calls[i].op == "CreateSecret" && sm.calls[i].body["Name"] != "app-db" {
			gen = &sm.calls[i]
		}
	}
	if gen == nil || gen.body["SecretString"] != `{"password":"generated-pw","user":"app"}` {
		t.Fatalf("generated secret value = %+v", gen)
	}
	db := sm.calls[0]
	for _, cc := range sm.calls {
		if cc.op == "CreateSecret" && cc.body["Name"] == "app-db" {
			db = cc
		}
	}
	if !strings.HasPrefix(db.fixed, "arn:aws:secretsmanager:") || !strings.Contains(db.fixed, ":secret:app-db-") {
		t.Fatalf("CreateSecret was not given the stack's ARN: %q", db.fixed)
	}
	if pt := eb.last("PutTargets"); pt == nil || pt.body["Targets"].([]any)[0].(map[string]any)["Input"] != `{"x":1}` {
		t.Fatalf("PutTargets = %+v", pt)
	}
	// The ownership record of each resource names the stack.
	if st := owners.stacks(); len(st) != 3 || st[cfn.KindSecretsManagerSecret+"/app-db"] != "app" {
		t.Fatalf("ownership records = %v, want the stack's 3 resources", st)
	}

	// An update: a new value is a new version; nothing else changed is left alone.
	n := len(sm.calls)
	if _, err := cfn.Update(ctx, tmpl("two"), svcOpts(), ap); err != nil {
		t.Fatalf("update: %v", err)
	}
	var after []string
	for _, cc := range sm.calls[n:] {
		after = append(after, cc.op)
	}
	if !strings.Contains(strings.Join(after, ","), "PutSecretValue") || strings.Contains(strings.Join(after, ","), "UpdateSecret") || strings.Contains(strings.Join(after, ","), "GetRandomPassword") {
		t.Fatalf("update calls = %v, want a PutSecretValue and no UpdateSecret or regenerated value", after)
	}
	if p := sm.last("PutSecretValue"); p.body["SecretString"] != "two" {
		t.Fatalf("PutSecretValue = %v", p.body)
	}

	if _, err := cfn.Destroy(ctx, svcOpts(), ap); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if d := sm.last("DeleteSecret"); d == nil || d.body["ForceDeleteWithoutRecovery"] != true {
		t.Fatalf("DeleteSecret = %+v", d)
	}
	ops := strings.Join(eb.ops(), ",")
	if i, j := strings.LastIndex(ops, "RemoveTargets"), strings.LastIndex(ops, "DeleteRule"); i < 0 || j < i {
		t.Fatalf("rule teardown = %s, want its targets removed and then the rule deleted", ops)
	}
	if st := owners.stacks(); len(st) != 0 {
		t.Fatalf("ownership records left behind: %v", st)
	}
}

// A secret of the same name that no stack created is not taken over, as AWS refuses a name that is taken.
func TestCFNServices_RefusesAnExistingResourceNoStackCreated(t *testing.T) {
	sm, eb := fakeSecrets("app-db"), fakeEvents()
	_, ap := svcTestApplier(t, sm, eb)
	_, err := cfn.Deploy(context.Background(), []byte(strings.Replace(svcStack, "%VALUE%", "x", 1)), svcOpts(), ap)
	if err == nil || !strings.Contains(err.Error(), "already exists and no stack created it") {
		t.Fatalf("want a refusal, got %v", err)
	}
	for _, c := range sm.calls {
		if c.op == "PutSecretValue" || c.op == "UpdateSecret" {
			t.Fatalf("the existing secret was written: %s", c.op)
		}
	}
}

// Without service stores (an applier with none), or without the kind's front door, the resource refuses
// rather than going anywhere else.
func TestCFNServices_NoStoresRefuses(t *testing.T) {
	m := []byte("apiVersion: " + cfn.ServiceAPIVersion + "\nkind: SecretsManagerSecret\nmetadata: {name: x}\nspec: {}\n")
	_, ap := cfnTestDoorway(t, "")
	if err := ap.Apply(context.Background(), m); err == nil {
		t.Fatal("want a refusal with no service stores")
	}
	_, ap = svcTestApplier(t, fakeSecrets(), fakeEvents())
	delete(ap.svc.doors, "secretsmanager")
	if err := ap.Apply(context.Background(), m); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("want a refusal with no Secrets Manager front door, got %v", err)
	}
}

// A front door's refusal of the caller is the engine's Unauthorized, so the stack reports access denied.
func TestCFNServices_FrontDoorDenialIsUnauthorized(t *testing.T) {
	sm := &fakeFront{handle: func(op string, _ map[string]any) (int, map[string]any) {
		if op == "DescribeSecret" {
			return notFound("ResourceNotFoundException")
		}
		return 403, map[string]any{"__type": "AccessDeniedException", "message": "not allowed"}
	}}
	_, ap := svcTestApplier(t, sm, fakeEvents())
	m := []byte("apiVersion: " + cfn.ServiceAPIVersion + "\nkind: SecretsManagerSecret\nmetadata: {name: x}\nspec: {secretString: v}\n")
	if err := ap.Apply(context.Background(), m); !cfn.IsUnauthorized(err) {
		t.Fatalf("want an Unauthorized error, got %v", err)
	}
}

// An in-stack Function target is put with the stack's namespace, and EventBridge authorizes it there.
func TestCFNServices_InStackFunctionTargetNamespace(t *testing.T) {
	eb := fakeEvents()
	c := svcCtx{s: &cfnServices{doors: map[string]awsService{"events": eb}}, ns: "open-infra-cfn"}
	spec := map[string]any{"targets": []any{map[string]any{"id": "fn", "function": "app-job"}}}
	if err := (ruleKind{}).put(context.Background(), c, "tick", spec); err != nil {
		t.Fatal(err)
	}
	pt := eb.last("PutTargets")
	if pt == nil || pt.targets["fn"] != "open-infra-cfn" || !strings.HasSuffix(pt.body["Targets"].([]any)[0].(map[string]any)["Arn"].(string), ":function:app-job") {
		t.Fatalf("PutTargets = %+v", pt)
	}

	var askedNS string
	h := &ebHandler{cs: csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { askedNS = a.Namespace; return true }), fnNS: "default"}
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	if reason, ok := h.authorizeTarget(context.Background(), req, iam.Claims{Sub: "dev"}, "lambda", "arn:aws:lambda:::function:app-job", "open-infra-cfn"); !ok {
		t.Fatalf("refused: %s", reason)
	}
	if askedNS != "open-infra-cfn" {
		t.Fatalf("authorized in %q, want the stack's namespace", askedNS)
	}
}
