package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

func dp(appliesTo []any, stmts ...map[string]any) map[string]any {
	l := make([]any, len(stmts))
	for i, s := range stmts {
		l[i] = s
	}
	m := map[string]any{"statements": l}
	if appliesTo != nil {
		m["appliesTo"] = appliesTo
	}
	return m
}

func fixtureWorld() World {
	s3read := map[string]any{"effect": "Allow", "actions": []any{"s3:GetObject"}, "resources": []any{"Bucket::assets"}}
	ddbDeny := map[string]any{"effect": "Deny", "actions": []any{"dynamodb:DeleteTable"}, "resources": []any{"*"},
		"ipConditions": []any{map[string]any{"key": "sourceIp", "cidr": "10.0.0.0/8", "negate": true}}}
	return World{
		Home: "open-infra-console",
		Policies: []Obj{
			{Kind: "Policy", Namespace: "stack-ns", Name: "app-access", Spec: map[string]any{"dataPlane": dp([]any{"Role::app"}, s3read, ddbDeny)}},
			{Kind: "Policy", Namespace: "stack-ns", Name: "everyone", Spec: map[string]any{"dataPlane": dp([]any{"*"}, s3read)}},
			{Kind: "Policy", Namespace: "stack-ns", Name: strings.Repeat("x", 60), Spec: map[string]any{"dataPlane": dp([]any{"Role::app"}, s3read)}},
			{Kind: "Policy", Namespace: "open-infra-console", Name: "mirror-tables", Spec: map[string]any{"dataPlane": dp([]any{"Group::mirror-readers"}, s3read)}},
			{Kind: "Policy", Namespace: "open-infra-console", Name: "ops-k8s", Spec: map[string]any{"controlPlane": map[string]any{"statements": []any{}}}},
			{Kind: "Policy", Namespace: "open-infra-console", Name: "administrator-access",
				Labels:      map[string]string{"openinfra.dev/managed-policy": "true"},
				Annotations: map[string]string{"openinfra.dev/aws-equivalent": "AdministratorAccess"},
				Spec:        map[string]any{"statements": []any{}, "dataPlane": dp(nil, s3read)}},
			{Kind: "Policy", Namespace: "open-infra-console", Name: "aws-readonlyaccess",
				Labels: map[string]string{"openinfra.dev/managed-policy": "true"}, Spec: map[string]any{"document": map[string]any{}}},
		},
		Groups: []Obj{
			{Kind: "Group", Namespace: "open-infra-console", Name: "builders", Spec: map[string]any{"clusterRole": "open-infra-poweruser"}},
			{Kind: "Group", Namespace: "open-infra-console", Name: "readers", Spec: map[string]any{"clusterRole": "open-infra-readonly"}},
			{Kind: "Group", Namespace: "open-infra-console", Name: "custom", Spec: map[string]any{"clusterRole": "some-hand-written-role"}},
		},
		Users: []Obj{
			{Kind: "User", Namespace: "open-infra-console", Name: "alice", Spec: map[string]any{"groups": []any{"admins"}, "policies": []any{"administrator-access"}}},
		},
		Roles: []Obj{
			{Kind: "Role", Namespace: "stack-ns", Name: "app", Spec: map[string]any{"policies": []any{"aws-amazonssmmanagedinstancecore"}}},
		},
		Bindings: []Binding{
			{Name: "open-infra-admins", ClusterRole: "open-infra-console", Group: "admins"},
			{Name: "open-infra-readers", ClusterRole: "open-infra-readonly", Group: "readers"},
			{Name: "openinfra-pass-role-admins", ClusterRole: "openinfra-pass-role", Group: "admins"},
			{Name: "ecr-pusher-group", ClusterRole: "ecr-pusher", Group: "ecr-pushers"},
			{Name: "ecr-runtime-puller-group", ClusterRole: "ecr-runtime-puller", Group: "node-pullers"},
			{Name: "mirror-reader-binding", ClusterRole: "some-mirror-role", Group: "mirror-readers"},
		},
	}
}

func changeFor(p Plan, kind, ns, name string) (Change, bool) {
	for _, c := range p.Changes {
		if c.Kind == kind && c.Namespace == ns && c.Name == name {
			return c, true
		}
	}
	return Change{}, false
}

func TestBuild_MigratesAdditively(t *testing.T) {
	p := Build(fixtureWorld(), false)

	// A native policy gains a document that imports back to its statements, and its principal gains it.
	c, ok := changeFor(p, "Policy", "stack-ns", "app-access")
	if !ok {
		t.Fatalf("app-access not migrated: %+v", p)
	}
	if _, drop := c.Patch["dataPlane"]; drop {
		t.Fatal("a dry migration must not remove dataPlane")
	}
	doc, _ := json.Marshal(c.Patch["document"])
	got, unsupported, err := policyengine.ImportAWS(string(doc))
	want := statementsFromSpec(dp(nil,
		map[string]any{"effect": "Allow", "actions": []any{"s3:GetObject"}, "resources": []any{"Bucket::assets"}},
		map[string]any{"effect": "Deny", "actions": []any{"dynamodb:DeleteTable"}, "resources": []any{"*"},
			"ipConditions": []any{map[string]any{"key": "sourceIp", "cidr": "10.0.0.0/8", "negate": true}}})["statements"])
	if err != nil || len(unsupported) > 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("the document does not import back to the policy's statements:\n got  %+v\n want %+v\n %s", got, want, doc)
	}
	r, ok := changeFor(p, "Role", "stack-ns", "app")
	if !ok || fmt.Sprint(r.Patch["policies"]) != "[aws-amazonssmmanagedinstancecore app-access]" {
		t.Fatalf("the role must keep its policies and gain app-access: %+v", r)
	}

	// Tiers become managed policies; built-in groups become containers; superseded bindings are noted.
	checks := map[string]string{
		"builders": "[aws-poweruseraccess]", "readers": "[aws-readonlyaccess]",
		"admins": "[aws-administratoraccess]", "ecr-pushers": "[aws-amazonec2containerregistrypoweruser]",
		"node-pullers": "[aws-amazonec2containerregistrypullonly]", "mirror-readers": "[mirror-tables]",
	}
	for g, want := range checks {
		c, ok := changeFor(p, "Group", "open-infra-console", g)
		if !ok || fmt.Sprint(c.Patch["policies"]) != want {
			t.Errorf("group %s: %+v, want policies %s", g, c, want)
		}
		if _, drop := c.Patch["clusterRole"]; drop {
			t.Errorf("group %s: a dry migration must keep clusterRole", g)
		}
	}
	for g, create := range map[string]bool{"admins": true, "ecr-pushers": true, "node-pullers": true, "mirror-readers": true, "builders": false, "readers": false} {
		if c, _ := changeFor(p, "Group", "open-infra-console", g); c.Create != create {
			t.Errorf("group %s: create=%v, want %v", g, c.Create, create)
		}
	}

	// A deprecated alias gains its AWS managed equivalent beside it.
	u, ok := changeFor(p, "User", "open-infra-console", "alice")
	if !ok || fmt.Sprint(u.Patch["policies"]) != "[administrator-access aws-administratoraccess]" {
		t.Fatalf("alice: %+v", u)
	}

	// Kept and noted, never guessed.
	all := strings.Join(append(append([]string{}, p.Kept...), p.Notes...), "\n")
	for _, want := range []string{"Policy open-infra-console/ops-k8s: its controlPlane", "custom: its clusterRole some-hand-written-role",
		`applies to "*"`, "does not fit a Role's spec.policies", "openinfra-pass-role-admins (openinfra-pass-role → openinfra:admins) is carried by AdministratorAccess"} {
		if !strings.Contains(all, want) {
			t.Errorf("kept/notes lack %q:\n%s", want, all)
		}
	}
	for _, c := range p.Changes {
		if c.Name == "administrator-access" || c.Name == "aws-readonlyaccess" {
			t.Errorf("the shipped library must not be rewritten: %+v", c)
		}
	}
}

func TestBuild_DropLegacyRemovesOnlyWhatWasReplaced(t *testing.T) {
	p := Build(fixtureWorld(), true)
	if c, _ := changeFor(p, "Policy", "stack-ns", "app-access"); c.Patch["dataPlane"] != nil || !hasKey(c.Patch, "dataPlane") {
		t.Fatalf("app-access's dataPlane is fully replaced and must be removed: %+v", c)
	}
	if c, _ := changeFor(p, "Policy", "stack-ns", "everyone"); hasKey(c.Patch, "dataPlane") {
		t.Fatalf("a policy whose appliesTo has no AWS form keeps its dataPlane: %+v", c)
	}
	if c, _ := changeFor(p, "Group", "open-infra-console", "builders"); !hasKey(c.Patch, "clusterRole") || c.Patch["clusterRole"] != nil {
		t.Fatalf("a mapped tier is removed by --drop-legacy: %+v", c)
	}
	if _, ok := changeFor(p, "Group", "open-infra-console", "custom"); ok {
		t.Fatal("an unmapped tier must be left alone")
	}
}

func hasKey(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// parseList reads kubectl's list JSON.
func TestParseList(t *testing.T) {
	objs, err := parseList([]byte(`{"items":[{"metadata":{"name":"p","namespace":"n","labels":{"a":"b"}},"spec":{"x":1}}]}`), "Policy")
	if err != nil || len(objs) != 1 || objs[0].Name != "p" || objs[0].Labels["a"] != "b" || objs[0].Kind != "Policy" {
		t.Fatalf("%+v %v", objs, err)
	}
}
