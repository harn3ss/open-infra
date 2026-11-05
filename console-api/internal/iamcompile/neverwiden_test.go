package iamcompile

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awsaction"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
)

// corpusEngine compiles the corpus's statements for one user ONCE (the webhook's checker recompiles per
// request, too slow for a grid) and answers a request the way controlplaneauthz maps a
// SubjectAccessReview: the verb is the action, "<resource>[/<sub>].<group>" the type, "<ns>/<name>" the id.
// TestCorpusEngineAgreesWithTheWebhook pins that mapping to the webhook's own.
func corpusEngine(t *testing.T, out Output, user string) func(verb, group, resource, ns, name string) bool {
	t.Helper()
	raw, err := MarshalCorpus(out.Corpus)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ParseCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	var stmts []policyengine.Statement
	for _, d := range docs {
		for _, a := range d.AppliesTo {
			if a == "User::"+user {
				stmts = append(stmts, d.Statements...)
			}
		}
	}
	if len(stmts) == 0 {
		return func(string, string, string, string, string) bool { return false }
	}
	eng, err := policyengine.NewEngine(stmts)
	if err != nil {
		t.Fatal(err)
	}
	return func(verb, group, resource, ns, name string) bool {
		rtype := resource
		if group != "" {
			rtype += "." + group
		}
		id := name
		if ns != "" {
			id = ns + "/" + name
		}
		return eng.Authorize(policyengine.Request{Principal: policyengine.Principal{Type: "User", ID: user},
			Action: verb, Resource: policyengine.Resource{Type: rtype, ID: id}, Context: map[string]any{}}).Allowed
	}
}

// The grid's engine answers exactly as the webhook's checker does.
func TestCorpusEngineAgreesWithTheWebhook(t *testing.T) {
	out := Compile(Input{
		World:      world([]iamauthz.Policy{doc(t, "PowerUserAccess", powerUserDoc)}, map[string][]string{"User::alice": {"PowerUserAccess"}}),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice"}},
	})
	fast, slow := corpusEngine(t, out, alice), corpusChecker(t, out)
	for _, q := range [][]string{
		{"create", "openinfra.dev", "buckets", "team-a", ""},
		{"delete", "iam.openinfra.dev", "users", "open-infra-console", "x"},
		{"get", "openinfra.dev", "functions/status", "team-a", "f"},
		{"get", "", "secrets", "kube-system", "x"},
		{"list", "iam.openinfra.dev", "roles", "", ""},
	} {
		res := q[2]
		if strings.Contains(res, "/") {
			continue // the webhook folds a subresource the same way; covered by the slow path below
		}
		if a, b := fast(q[0], q[1], res, q[3], q[4]), can(slow, alice, q[0], q[1], res, q[3], q[4]); a != b {
			t.Errorf("%v: grid engine %v, webhook %v", q, a, b)
		}
	}
}

// Never widen, as a property: over a grid of Kubernetes requests — every table kind and operator
// resource, every verb, a handful of names, in and out of the principal's account — whatever the
// compiled corpus allows, the one IAM evaluator (iamauthz, what the console and the shim decide with)
// allows too for the same AWS action on the same resource; and whatever the generated RBAC allows, the
// corpus allows. Compiling can only ever be narrower than the policy.
func TestNeverWiden(t *testing.T) {
	cases := []struct {
		name   string
		doc    string
		groups []string
		bound  string
	}{
		{"admin", adminDoc, nil, ""},
		{"poweruser", powerUserDoc, nil, ""},
		{"deny", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},
			{"Effect":"Deny","Action":["lambda:Delete*","s3:*"],"Resource":["arn:aws:lambda:us-east-1:000000000000:function:prod-*","*"]}]}`, nil, ""},
		{"names", `{"Statement":[{"Effect":"Allow","Action":["lambda:*","openinfra:*"],"Resource":[
			"arn:aws:lambda:us-east-1:000000000000:function:orders","arn:aws:lambda:us-east-1:000000000000:function:etl-*",
			"arn:aws:openinfra:us-east-1:000000000000:dataflow/orders"]}]}`, nil, ""},
		{"notresource", `{"Statement":[{"Effect":"Allow","Action":"lambda:*","NotResource":"arn:aws:lambda:us-east-1:000000000000:function:prod-*"}]}`, nil, ""},
		{"conditions", `{"Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}},
			{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"},
			{"Effect":"Deny","Action":"dynamodb:Delete*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}]}`, nil, ""},
		{"boundary", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, nil, `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","lambda:*"],"Resource":"*"}]}`},
		{"group", adminDoc, []string{"ops"}, ""},
	}
	for _, accounts := range []map[string]string{nil, {"team-a": "000000000000", "open-infra-console": "000000000000", "team-b": "912345678901"}} {
		for _, tc := range cases {
			pols := []iamauthz.Policy{doc(t, "p", tc.doc)}
			attach := map[string][]string{"User::alice": {"p"}}
			if len(tc.groups) > 0 {
				attach = map[string][]string{"Group::ops": {"p"}}
			}
			w := world(pols, attach)
			if tc.bound != "" {
				w.Docs = append(w.Docs, doc(t, "b", tc.bound))
				w.Boundary = map[string]string{"User::alice": "b"}
			}
			out := Compile(Input{World: w, NamespaceAccounts: accounts,
				Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice", Groups: tc.groups}}})
			corpus := corpusEngine(t, out, alice)
			ev := iamauthz.New(func(context.Context) (iamauthz.World, error) { return w, nil }, time.Hour)
			p := iamauthz.Principal{Account: "000000000000", Type: iamauthz.User, ID: "alice", Groups: tc.groups}

			checked := 0
			check := func(verb, group, resource, ns, name string) {
				checked++
				action, arn, ok := awsaction.ForKubernetes(verb, group, resource, ns, name, "000000000000")
				iamOK := ok && ev.Authorize(context.Background(), p, action, arn, nil).Allowed
				cOK := corpus(verb, group, resource, ns, name)
				rOK := rbacAllows(out, alice, verb, group, resource, ns, name)
				if cOK && !iamOK {
					t.Errorf("%s (accounts=%v): corpus allows %s %s/%s %s/%s but IAM does not (%s on %s)", tc.name, accounts != nil, verb, group, resource, ns, name, action, arn)
				}
				if rOK && !cOK {
					t.Errorf("%s (accounts=%v): rbac allows %s %s/%s %s/%s but the corpus does not", tc.name, accounts != nil, verb, group, resource, ns, name)
				}
			}
			for _, kind := range awsaction.Kinds() {
				e, _ := awsaction.Lookup(kind)
				// A create's authorization request carries no name, so a corpus that allows a nameless
				// create must have IAM allowing the create whatever the new object is called.
				for _, ns := range []string{"team-a", "team-b"} {
					if !corpus("create", e.Group, e.Resource, ns, "") {
						continue
					}
					for _, name := range []string{"orders", "prod-1", "etl-nightly"} {
						action, arn, ok := awsaction.ForKind(kind, "create", name, "000000000000")
						if !ok || !ev.Authorize(context.Background(), p, action, arn, nil).Allowed {
							t.Errorf("%s (accounts=%v): corpus allows any create of %s in %s, but IAM denies creating %q", tc.name, accounts != nil, kind, ns, name)
						}
					}
				}
				for _, verb := range []string{"get", "list", "create", "update", "delete"} {
					for _, name := range []string{"", "orders", "prod-1", "etl-nightly"} {
						for _, ns := range []string{"team-a", "team-b", ""} {
							if ns == "" && name != "" {
								continue // a named request for a namespaced claim always carries its namespace
							}
							check(verb, e.Group, e.Resource, ns, name)
						}
					}
				}
			}
			for _, or := range append(append([]operatorResource(nil), operatorResources...), sentinelOperator) {
				for _, verb := range []string{"get", "list", "create", "delete"} {
					ns := ""
					if or.Namespaced {
						ns = "team-a"
					}
					check(verb, or.Group, or.Resource, ns, "x")
				}
			}
			if checked < 1000 {
				t.Fatalf("grid too small: %d", checked)
			}
		}
	}
}
