package cfn

import (
	"context"
	"strings"
	"testing"
)

// A change set says whether a Modify replaces the resource, as AWS's does, from AWS's update type of each
// property that changes: a task definition whose ExecutionRoleArn changes is replaced (every property but
// Tags is Immutable), one whose Tags alone change is not, and a key whose Description changes (Mutable) is not.
func TestChangeSet_ReplacementIsAWSUpdateType(t *testing.T) {
	base := `
Resources:
  Key: { Type: AWS::KMS::Key, Properties: { Description: a } }
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: web
      ExecutionRoleArn: arn:aws:iam::111122223333:role/old-role
      ContainerDefinitions: [{ Name: web, Image: nginx, PortMappings: [{ ContainerPort: 80 }] }]
      Tags: [{ Key: team, Value: a }]
  Service:
    Type: AWS::ECS::Service
    Properties: { ServiceName: web, TaskDefinition: !Ref Task, DesiredCount: 1 }
`
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), []byte(base), deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	for _, c := range []struct {
		name, from, to, id, replacement, prop, recreation string
	}{
		{"an Immutable property", "role/old-role", "role/new-role", "Task", "True", "ExecutionRoleArn", "Always"},
		{"Tags alone", "Value: a }]", "Value: b }]", "Task", "False", "Tags", "Never"},
		{"a Mutable property", "Description: a", "Description: b", "Key", "False", "Description", "Never"},
	} {
		t.Run(c.name, func(t *testing.T) {
			next := replaceOnce(t, base, c.from, c.to)
			cs, _, _, err := BuildChangeSet(context.Background(), []byte(next), deployOpts(), f)
			if err != nil {
				t.Fatal(err)
			}
			ch, ok := foldedChange(cs, c.id)
			if !ok || ch.Action != Modify {
				t.Fatalf("%s: want a Modify, got %+v (all %+v)", c.id, ch, cs.Changes)
			}
			if ch.Replacement != c.replacement || len(ch.Details) != 1 || ch.Details[0].Name != c.prop || ch.Details[0].RequiresRecreation != c.recreation {
				t.Fatalf("%s: Replacement %q Details %+v; want %s, %s %s", c.id, ch.Replacement, ch.Details, c.replacement, c.prop, c.recreation)
			}
		})
	}
}

func TestReplacementOf_Conditional(t *testing.T) {
	updateTypesBackup := updateTypes["AWS::Example::Thing"]
	defer func() { updateTypes["AWS::Example::Thing"] = updateTypesBackup }()
	updateTypes["AWS::Example::Thing"] = map[string]string{"Size": "Conditional", "Name": "Immutable"}
	if r, d := replacementOf("AWS::Example::Thing", map[string]any{"Size": 1}, map[string]any{"Size": 2}); r != "Conditional" || d[0].RequiresRecreation != "Conditionally" {
		t.Errorf("a Conditional property: %s %+v", r, d)
	}
	if r, _ := replacementOf("AWS::Example::Thing", map[string]any{"Size": 1, "Name": "a"}, map[string]any{"Size": 2, "Name": "b"}); r != "True" {
		t.Errorf("an Immutable property wins: %s", r)
	}
	if r, d := replacementOf("AWS::Example::Thing", map[string]any{"Size": 1}, map[string]any{"Size": 1}); r != "False" || len(d) != 0 {
		t.Errorf("no change: %s %+v", r, d)
	}
}

func replaceOnce(t *testing.T, s, from, to string) string {
	t.Helper()
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("%q not in the template", from)
	}
	return s[:i] + to + s[i+len(from):]
}
