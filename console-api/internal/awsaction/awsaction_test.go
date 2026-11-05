package awsaction

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"sigs.k8s.io/yaml"
)

const platformDir = "../../../platform"

// platformKind is one claim kind (an XRD's claim) or CRD kind in the platform's own API groups, with
// its spec's top-level fields.
type platformKind struct {
	group, kind, plural string
	fields              map[string]bool
	file                string
}

// platformKinds reads every XRD and CRD under platform/ in the openinfra API groups.
func platformKinds(t *testing.T) map[string]platformKind {
	t.Helper()
	out := map[string]platformKind{}
	err := filepath.WalkDir(platformDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, doc := range regexp.MustCompile(`(?m)^---\s*$`).Split(string(raw), -1) {
			var o struct {
				Kind string `json:"kind"`
				Spec struct {
					Group      string                         `json:"group"`
					Names      struct{ Kind, Plural string }  `json:"names"`
					ClaimNames *struct{ Kind, Plural string } `json:"claimNames"`
					Versions   []struct {
						Schema struct {
							OpenAPIV3Schema struct {
								Properties map[string]struct {
									Properties map[string]any `json:"properties"`
								} `json:"properties"`
							} `json:"openAPIV3Schema"`
						} `json:"schema"`
					} `json:"versions"`
				} `json:"spec"`
			}
			if yaml.Unmarshal([]byte(doc), &o) != nil {
				continue
			}
			if o.Kind != "CompositeResourceDefinition" && o.Kind != "CustomResourceDefinition" {
				continue
			}
			if o.Spec.Group != groupPlatform && o.Spec.Group != groupIAM {
				continue
			}
			kind, plural := o.Spec.Names.Kind, o.Spec.Names.Plural
			if o.Kind == "CompositeResourceDefinition" {
				if o.Spec.ClaimNames == nil {
					continue
				}
				kind, plural = o.Spec.ClaimNames.Kind, o.Spec.ClaimNames.Plural
			}
			fields := map[string]bool{}
			for _, v := range o.Spec.Versions {
				for f := range v.Schema.OpenAPIV3Schema.Properties["spec"].Properties {
					fields[f] = true
				}
			}
			out[kind] = platformKind{group: o.Spec.Group, kind: kind, plural: plural, fields: fields, file: p}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 40 {
		t.Fatalf("read only %d platform kinds — the walk is broken", len(out))
	}
	return out
}

// Every claim kind and platform CRD kind is in the table, under its own group and plural, and the table
// has no row for a kind that no longer exists. A new kind fails here until it is mapped.
func TestEveryPlatformKindIsMapped(t *testing.T) {
	kinds := platformKinds(t)
	for k, pk := range kinds {
		e, ok := Lookup(k)
		if !ok {
			t.Errorf("kind %s (%s) has no row: map it to its AWS analog, or to openinfra: if it has none", k, pk.file)
			continue
		}
		if e.Group != pk.group || e.Resource != pk.plural {
			t.Errorf("%s: row says %s/%s, the API says %s/%s", k, e.Group, e.Resource, pk.group, pk.plural)
		}
	}
	for _, k := range Kinds() {
		if _, ok := kinds[k]; !ok {
			t.Errorf("row %s names no XRD or CRD under platform/", k)
		}
	}
}

// The fields a row reads from a spec (its physical name, per-field actions, roles it passes, what its
// variants test) exist in that kind's schema, so a renamed field can't silently drop a check.
func TestRowFieldsExistInTheSchema(t *testing.T) {
	kinds := platformKinds(t)
	variantFields := map[string][]string{"Application": {"database", "image"}, "Queue": {"fanout"}}
	// Fields the one-plane IAM model adds (Groups become policy containers); mapped ahead of the schema.
	pending := map[string]bool{"Group.policies": true}
	for _, k := range Kinds() {
		e, _ := Lookup(k)
		pk := kinds[k]
		var fields []string
		if e.NameField != "" {
			fields = append(fields, e.NameField)
		}
		for f := range e.FieldActions {
			fields = append(fields, f)
		}
		fields = append(fields, e.PassRoleFields...)
		fields = append(fields, variantFields[k]...)
		for _, m := range regexp.MustCompile(`\{spec\.([A-Za-z0-9]+)\}`).FindAllStringSubmatch(e.ARN, -1) {
			fields = append(fields, m[1])
		}
		for _, f := range fields {
			if !pk.fields[f] && !pending[k+"."+f] {
				t.Errorf("%s: spec.%s is not in its schema (%s)", k, f, pk.file)
			}
		}
	}
}

func documentedActions(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open("testdata/aws-actions.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out[l] = true
		}
	}
	return out
}

// allActions is every action the table can produce, by kind.
func allActions() map[string][]string {
	out := map[string][]string{}
	var walk func(k string, e *Entry)
	walk = func(k string, e *Entry) {
		for _, v := range Verbs {
			if a := e.Actions[v]; a != "" {
				out[k] = append(out[k], a)
			}
		}
		for _, r := range e.FieldActions {
			out[k] = append(out[k], r.Actions...)
			for _, as := range r.ByValue {
				out[k] = append(out[k], as...)
			}
		}
		if len(e.PassRoleFields) > 0 {
			out[k] = append(out[k], "iam:PassRole")
		}
		for _, vr := range e.Variants {
			walk(k, vr.Entry)
		}
	}
	for _, k := range Kinds() {
		walk(k, byKind[k])
	}
	return out
}

var actionRe = regexp.MustCompile(`^[a-z0-9-]+:[A-Za-z][A-Za-z0-9]*$`)

// Every action an AWS-prefixed row maps to is one AWS documents (the curated list); the openinfra
// prefixes are ours, and each verb has one.
func TestActionsAreAWSDocumented(t *testing.T) {
	doc := documentedActions(t)
	for k, acts := range allActions() {
		for _, a := range acts {
			if !actionRe.MatchString(a) {
				t.Errorf("%s: %q is not an IAM action", k, a)
				continue
			}
			svc, _, _ := strings.Cut(a, ":")
			if svc == "openinfra" || svc == OperatorPrefix {
				continue
			}
			if !doc[a] {
				t.Errorf("%s: %s is not in testdata/aws-actions.txt (AWS's Service Authorization Reference)", k, a)
			}
		}
	}
	for _, k := range Kinds() {
		e, _ := Lookup(k)
		for _, v := range Verbs {
			if _, ok := e.Action(v); !ok {
				t.Errorf("%s: no action for %s", k, v)
			}
		}
		if svc, _, _ := strings.Cut(e.Actions[Create], ":"); svc != e.Service {
			t.Errorf("%s: create is %s, outside its service %s", k, e.Actions[Create], e.Service)
		}
	}
}

// A row's AWS analog agrees with the CloudFormation engine's own mapping (probe/registry/cfn-types.json),
// where the engine names this kind for a CloudFormation type.
func TestCfnTypesAgreeWithTheEngine(t *testing.T) {
	raw, err := os.ReadFile("../../../probe/registry/cfn-types.json")
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Types map[string]struct {
			Kind string `json:"kind"`
		} `json:"types"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	// The engine names a kind's facets "Kind(facet)" (Application(database) is the RDS instance an
	// Application's database block is), so a kind's types are its own and its facets'.
	byEngineKind := map[string][]string{}
	for typ, v := range reg.Types {
		k, _, _ := strings.Cut(v.Kind, "(")
		byEngineKind[strings.TrimSpace(k)] = append(byEngineKind[strings.TrimSpace(k)], typ)
	}
	for _, k := range Kinds() {
		types, named := byEngineKind[k]
		if !named {
			continue
		}
		e, _ := Lookup(k)
		got := []string{e.CfnType}
		for _, vr := range e.Variants {
			got = append(got, vr.Entry.CfnType)
		}
		for _, c := range got {
			found := false
			for _, t2 := range types {
				if t2 == c {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: row's %s is not among the engine's types for it %v", k, c, types)
			}
		}
	}
}

func TestARNShapes(t *testing.T) {
	s := Scope{Account: "123456789012", Region: "eu-west-1"}
	cases := []struct {
		kind, name string
		spec       map[string]any
		want       string
	}{
		{"Bucket", "b", nil, "arn:aws:s3:::b"},
		{"Bucket", "claim", map[string]any{"bucketName": "physical"}, "arn:aws:s3:::physical"},
		{"Table", "t", map[string]any{"tableName": "orders"}, "arn:aws:dynamodb:eu-west-1:123456789012:table/orders"},
		{"Function", "f", nil, "arn:aws:lambda:eu-west-1:123456789012:function:f"},
		{"User", "alice", nil, "arn:aws:iam::123456789012:user/alice"},
		{"Role", "app", nil, "arn:aws:iam::123456789012:role/app"},
		{"Policy", "p", nil, "arn:aws:iam::123456789012:policy/p"},
		{"Queue", "q", nil, "arn:aws:sqs:eu-west-1:123456789012:q"},
		{"StaticSite", "d", nil, "arn:aws:cloudfront::123456789012:distribution/d"},
		{"HttpApi", "a", nil, "arn:aws:apigateway:eu-west-1::/apis/a"},
		{"VmImage", "i", nil, "arn:aws:ec2:eu-west-1::image/i"},
		{"VirtualMachine", "vm", nil, "arn:aws:ec2:eu-west-1:123456789012:instance/vm"},
		{"Parameter", "p", map[string]any{"path": "/app/db/url"}, "arn:aws:ssm:eu-west-1:123456789012:parameter/app/db/url"},
		{"Parameter", "flat", nil, "arn:aws:ssm:eu-west-1:123456789012:parameter/flat"},
		{"EncryptionKey", "k", nil, "arn:aws:kms:eu-west-1:123456789012:key/k"},
		{"Destruction", "d", map[string]any{"encryptionKey": "k"}, "arn:aws:kms:eu-west-1:123456789012:key/k"},
		{"StateMachine", "sm", nil, "arn:aws:states:eu-west-1:123456789012:stateMachine:sm"},
		{"Execution", "run1", map[string]any{"stateMachineRef": "sm"}, "arn:aws:states:eu-west-1:123456789012:execution:sm:run1"},
		{"Execution", "run1", map[string]any{"stateMachineRef": map[string]any{"name": "sm"}}, "arn:aws:states:eu-west-1:123456789012:execution:sm:run1"},
		{"GraphQLApi", "g", nil, "arn:aws:appsync:eu-west-1:123456789012:apis/g"},
		{"DataFlow", "df", nil, "arn:aws:openinfra:eu-west-1:123456789012:dataflow/df"},
		{"Grant", "g1", map[string]any{"subject": "alice"}, "arn:aws:iam::123456789012:user/alice"},
	}
	for _, c := range cases {
		e, ok := Lookup(c.kind)
		if !ok {
			t.Fatalf("no row %s", c.kind)
		}
		if got := e.ARNFor(s, c.name, c.spec); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.kind, c.name, got, c.want)
		}
	}
	asg, _ := Lookup("AutoScalingGroup")
	a1, a2 := asg.ARNFor(s, "web", nil), asg.ARNFor(s, "web", nil)
	if a1 != a2 || !regexp.MustCompile(`^arn:aws:autoscaling:eu-west-1:123456789012:autoScalingGroup:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:autoScalingGroupName/web$`).MatchString(a1) {
		t.Errorf("auto scaling group ARN %s (stable: %v)", a1, a1 == a2)
	}
	if asg.ARNFor(Scope{Account: "999999999999"}, "web", nil) == a1 {
		t.Error("another account's group has the same ARN")
	}
	if got := (Scope{Account: "1", Partition: "aws-us-gov"}).partition(); got != "aws-us-gov" {
		t.Error(got)
	}
}

func TestForKind(t *testing.T) {
	for _, c := range []struct{ kind, verb, name, wantAction, wantARN string }{
		{"Bucket", "create", "b", "s3:CreateBucket", "arn:aws:s3:::b"},
		{"Bucket", "list", "", "s3:ListAllMyBuckets", "*"},
		{"Bucket", "watch", "", "s3:ListAllMyBuckets", "*"},
		{"Table", "patch", "t", "dynamodb:UpdateTable", "arn:aws:dynamodb:us-east-1:111111111111:table/t"},
		{"Table", "deletecollection", "", "dynamodb:DeleteTable", "*"},
		{"VirtualMachine", "get", "vm", "ec2:DescribeInstances", "*"}, // EC2 Describe* has no resource-level permission
		{"VirtualMachine", "create", "vm", "ec2:RunInstances", "arn:aws:ec2:us-east-1:111111111111:instance/vm"},
		{"Function", "get", "f", "lambda:GetFunction", "arn:aws:lambda:us-east-1:111111111111:function:f"},
		{"User", "delete", "u", "iam:DeleteUser", "arn:aws:iam::111111111111:user/u"},
		{"DataFlow", "create", "x", "openinfra:CreateDataFlow", "arn:aws:openinfra:us-east-1:111111111111:dataflow/x"},
		{"DataClassification", "list", "", "openinfra:ListDataClassifications", "*"},
	} {
		a, arn, ok := ForKind(c.kind, c.verb, c.name, "111111111111")
		if !ok || a != c.wantAction || arn != c.wantARN {
			t.Errorf("%s %s %s: %s %s %v, want %s %s", c.kind, c.verb, c.name, a, arn, ok, c.wantAction, c.wantARN)
		}
	}
	for _, c := range [][2]string{{"Nope", "get"}, {"Bucket", "escalate"}, {"Bucket", "impersonate"}, {"Bucket", ""}} {
		if _, _, ok := ForKind(c[0], c[1], "x", "1"); ok {
			t.Errorf("%v: ok, want refused", c)
		}
	}
}

func reqs(t *testing.T, s Scope, kind, verb, name string, spec, old map[string]any) []string {
	t.Helper()
	rs, ok := s.ForObject(kind, verb, name, spec, old)
	if !ok {
		t.Fatalf("%s %s: refused", kind, verb)
	}
	var out []string
	for _, r := range rs {
		out = append(out, r.Action+" "+r.ARN)
	}
	sort.Strings(out)
	return out
}

func eq(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s:\n got %q\nwant %q", what, got, want)
	}
}

func TestForObject(t *testing.T) {
	s := Scope{Account: "222222222222"}
	fn := "arn:aws:lambda:us-east-1:222222222222:function:f"
	eq(t, "a Function's code and memory change", reqs(t, s, "Function", "update", "f",
		map[string]any{"image": "new", "memory": "1Gi"}, map[string]any{"image": "old", "memory": "512Mi"}),
		"lambda:UpdateFunctionCode "+fn, "lambda:UpdateFunctionConfiguration "+fn)
	eq(t, "a metadata-only change is the kind's update", reqs(t, s, "Function", "update", "f",
		map[string]any{"image": "x"}, map[string]any{"image": "x"}), "lambda:UpdateFunctionConfiguration "+fn)
	vm := "arn:aws:ec2:us-east-1:222222222222:instance/vm"
	eq(t, "stopping a VM", reqs(t, s, "VirtualMachine", "update", "vm", map[string]any{"running": false}, map[string]any{"running": true}),
		"ec2:StopInstances "+vm)
	eq(t, "starting a VM", reqs(t, s, "VirtualMachine", "update", "vm", map[string]any{"running": true}, map[string]any{"running": false}),
		"ec2:StartInstances "+vm)
	sm := "arn:aws:states:us-east-1:222222222222:stateMachine:sm"
	eq(t, "creating a state machine passes its role", reqs(t, s, "StateMachine", "create", "sm",
		map[string]any{"roleArn": "arn:aws:iam::222222222222:role/exec"}, nil),
		"states:CreateStateMachine "+sm, "iam:PassRole arn:aws:iam::222222222222:role/exec")
	eq(t, "a role named by name is in the caller's account", reqs(t, s, "Application", "create", "web",
		map[string]any{"image": "nginx", "assumeRole": "app"}, nil),
		"ecs:CreateService arn:aws:ecs:us-east-1:222222222222:service/default/web", "iam:PassRole arn:aws:iam::222222222222:role/app")
	eq(t, "an Application with an image and a database is both", reqs(t, s, "Application", "create", "web",
		map[string]any{"image": "nginx", "database": map[string]any{"engine": "postgres"}}, nil),
		"ecs:CreateService arn:aws:ecs:us-east-1:222222222222:service/default/web", "rds:CreateDBInstance arn:aws:rds:us-east-1:222222222222:db:web")
	eq(t, "a database-only Application is an RDS instance", reqs(t, s, "Application", "delete", "db1",
		map[string]any{"database": map[string]any{"engine": "postgres"}}, nil),
		"rds:DeleteDBInstance arn:aws:rds:us-east-1:222222222222:db:db1")
	eq(t, "a fanout Queue is an SNS topic", reqs(t, s, "Queue", "create", "events", map[string]any{"fanout": true}, nil),
		"sns:CreateTopic arn:aws:sns:us-east-1:222222222222:events")
	eq(t, "a security group's ingress change authorizes and revokes", reqs(t, s, "SecurityGroup", "update", "sg",
		map[string]any{"ingress": []any{"a"}}, map[string]any{"ingress": []any{"b"}}),
		"ec2:AuthorizeSecurityGroupIngress arn:aws:ec2:us-east-1:222222222222:security-group/sg",
		"ec2:RevokeSecurityGroupIngress arn:aws:ec2:us-east-1:222222222222:security-group/sg")
	eq(t, "a bucket field S3 has no single action for takes PutBucketPolicy", reqs(t, s, "Bucket", "update", "b",
		map[string]any{"somethingNew": 1}, map[string]any{}), "s3:PutBucketPolicy arn:aws:s3:::b")
	if _, ok := s.ForObject("Nope", "get", "x", nil, nil); ok {
		t.Error("an unknown kind was answered")
	}
	if _, ok := s.ForObject("Bucket", "bind", "x", nil, nil); ok {
		t.Error("an unmappable verb was answered")
	}
}

func TestForKubernetes(t *testing.T) {
	const acct = "333333333333"
	for _, c := range []struct{ verb, group, resource, ns, name, wantAction, wantARN string }{
		{"create", "openinfra.dev", "buckets", "team", "b", "s3:CreateBucket", "arn:aws:s3:::b"},
		{"get", "openinfra.dev", "functions/status", "team", "f", "lambda:GetFunction", "arn:aws:lambda:us-east-1:" + acct + ":function:f"},
		{"list", "iam.openinfra.dev", "users", "open-infra-console", "", "iam:ListUsers", "*"},
		{"patch", "iam.openinfra.dev", "roles", "open-infra-console", "r", "iam:UpdateRole", "arn:aws:iam::" + acct + ":role/r"},
		{"get", "openinfra.dev", "xbuckets", "", "b-x1", "openinfra-operator:GetXBucket", "arn:aws:openinfra-operator:us-east-1:" + acct + ":xbuckets/b-x1"},
		{"list", "", "pods", "team", "", "openinfra-operator:ListPods", "*"},
		{"get", "", "pods/log", "team", "p", "openinfra-operator:GetPodLog", "arn:aws:openinfra-operator:us-east-1:" + acct + ":pods/team/p"},
		{"create", "", "pods/exec", "team", "p", "openinfra-operator:CreatePodExec", "arn:aws:openinfra-operator:us-east-1:" + acct + ":pods/team/p"},
		{"get", "", "secrets", "team", "s", "openinfra-operator:GetSecret", "arn:aws:openinfra-operator:us-east-1:" + acct + ":secrets/team/s"},
		{"get", "", "nodes", "", "n1", "openinfra-operator:GetNode", "arn:aws:openinfra-operator:us-east-1:" + acct + ":nodes/n1"},
		{"delete", "kubevirt.io", "virtualmachineinstances", "team", "v", "openinfra-operator:DeleteVirtualmachineinstance", "arn:aws:openinfra-operator:us-east-1:" + acct + ":virtualmachineinstances/team/v"},
		{"list", "apps", "deployments", "team", "", "openinfra-operator:ListDeployments", "*"},
	} {
		a, arn, ok := ForKubernetes(c.verb, c.group, c.resource, c.ns, c.name, acct)
		if !ok || a != c.wantAction || arn != c.wantARN {
			t.Errorf("%s %s/%s %s/%s: %q %q %v, want %q %q", c.verb, c.group, c.resource, c.ns, c.name, a, arn, ok, c.wantAction, c.wantARN)
		}
	}
	for _, c := range [][3]string{
		{"get", "openinfra.dev", "newkinds"},       // an openinfra kind the table doesn't know: deny until mapped
		{"get", "iam.openinfra.dev", "accesskeys"}, // likewise
		{"escalate", "rbac.authorization.k8s.io", "clusterroles"},
		{"impersonate", "", "users"},
		{"get", "", ""},
	} {
		if _, _, ok := ForKubernetes(c[0], c[1], c[2], "ns", "x", acct); ok {
			t.Errorf("%v: answered, want refused", c)
		}
	}
	// Every claim's own resource answers with its kind's create action.
	for _, k := range Kinds() {
		e, _ := Lookup(k)
		if a, _, ok := ForKubernetes("create", e.Group, e.Resource, "ns", "x", acct); !ok || a != e.Actions[Create] {
			t.Errorf("%s: %s/%s create → %s %v", k, e.Group, e.Resource, a, ok)
		}
	}
}

func TestRouteRegistry(t *testing.T) {
	reg := NewRegistry()
	allow := map[string]bool{"s3:ListBucket arn:aws:s3:::open": true}
	authz := func(r *http.Request, action, arn string) (bool, string) {
		return allow[action+" "+arn], "no policy allows it"
	}
	r := chi.NewRouter()
	r.Route("/api", func(api chi.Router) {
		api.With(reg.Authorize(Route{Method: "GET", Path: "/api/buckets/{bucket}/objects", Action: "s3:ListBucket",
			ARN: func(r *http.Request) string { return "arn:aws:s3:::" + chi.URLParam(r, "bucket") }}, authz)).
			Get("/buckets/{bucket}/objects", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		api.Post("/auth/login", func(w http.ResponseWriter, _ *http.Request) {})
		api.Get("/unregistered", func(w http.ResponseWriter, _ *http.Request) {})
	})
	for path, want := range map[string]int{"/api/buckets/open/objects": 200, "/api/buckets/closed/objects": 403} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
		if want == 403 && (!strings.Contains(w.Body.String(), `"code":"AccessDenied"`) ||
			!strings.Contains(w.Body.String(), "s3:ListBucket on resource: arn:aws:s3:::closed")) {
			t.Errorf("denial body %s", w.Body)
		}
	}
	reg.Public("POST", "/api/auth/login", "sign-in")
	if got := reg.Uncovered(r); len(got) != 1 || got[0] != "GET /api/unregistered" {
		t.Errorf("uncovered %v", got)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("MustCover did not fail on an unregistered route")
			}
		}()
		reg.MustCover(r)
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a route registered twice was accepted")
			}
		}()
		reg.Add(Route{Method: "GET", Path: "/api/buckets/{bucket}/objects", Action: "s3:ListBucket"})
	}()
	if _, ok := reg.Lookup("get", "/api/buckets/{bucket}/objects"); !ok || len(reg.Routes()) != 1 {
		t.Error("lookup")
	}
}
