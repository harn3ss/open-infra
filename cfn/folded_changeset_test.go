package cfn

import (
	"context"
	"testing"
)

// A stack with resources that provision nothing of their own: an internet gateway and its attachment (part
// of the VPC), a wait condition handle (part of nothing), next to a key and the VPC, which do.
const foldedBase = `
Parameters:
  Env: { Type: String, Default: dev }
Resources:
  Key: { Type: AWS::KMS::Key, Properties: { Description: a } }
  Vpc: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  Igw:
    Type: AWS::EC2::InternetGateway
    Properties: { Tags: [ { Key: env, Value: !Ref Env } ] }
  Attach: { Type: AWS::EC2::VPCGatewayAttachment, Properties: { VpcId: !Ref Vpc, InternetGatewayId: !Ref Igw } }
  Handle: { Type: AWS::CloudFormation::WaitConditionHandle }
`

func deployFolded(t *testing.T) *fakeApplier {
	t.Helper()
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), []byte(foldedBase), deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return f
}

func foldedChange(cs *ChangeSet, id string) (Change, bool) {
	for _, c := range cs.Changes {
		if c.LogicalID == id {
			return c, true
		}
	}
	return Change{}, false
}

// A change set lists what changes of the resources that provision nothing, with their AWS types, as AWS
// does: an added handle is an Add, a removed one a Remove, a gateway whose (resolved) properties change a
// Modify — and an unchanged one is not listed.
func TestChangeSet_ListsFoldedResources(t *testing.T) {
	f := deployFolded(t)
	next := `
Parameters:
  Env: { Type: String, Default: dev }
Resources:
  Key: { Type: AWS::KMS::Key, Properties: { Description: a } }
  Vpc: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  Igw:
    Type: AWS::EC2::InternetGateway
    Properties: { Tags: [ { Key: env, Value: !Ref Env } ] }
  Attach: { Type: AWS::EC2::VPCGatewayAttachment, Properties: { VpcId: !Ref Vpc, InternetGatewayId: !Ref Igw } }
  Handle2: { Type: AWS::CloudFormation::WaitConditionHandle }
`
	opts := deployOpts()
	opts.Params = map[string]string{"Env": "prod"} // the gateway's tag resolves differently
	cs, _, _, err := BuildChangeSet(context.Background(), []byte(next), opts, f)
	if err != nil {
		t.Fatalf("changeset: %v", err)
	}
	want := map[string]struct {
		action ChangeAction
		typ    string
	}{
		"Handle2": {Add, "AWS::CloudFormation::WaitConditionHandle"},
		"Handle":  {Remove, "AWS::CloudFormation::WaitConditionHandle"},
		"Igw":     {Modify, "AWS::EC2::InternetGateway"},
	}
	for id, w := range want {
		c, ok := foldedChange(cs, id)
		if !ok {
			t.Errorf("%s is not in the change set: %+v", id, cs.Changes)
			continue
		}
		if c.Action != w.action || c.Type != w.typ || !c.Folded {
			t.Errorf("%s = %+v, want %s of %s, folded", id, c, w.action, w.typ)
		}
	}
	if c, ok := foldedChange(cs, "Attach"); ok && c.Folded {
		t.Errorf("an unchanged attachment is listed: %+v", c)
	}
	if c, ok := foldedChange(cs, "Igw"); ok && c.Name == "" {
		t.Errorf("a modified gateway has no physical id: %+v", c)
	}
}

// The same template with the same parameters lists nothing: an unchanged folded resource is no change.
func TestChangeSet_UnchangedFoldedResourcesAreNoChange(t *testing.T) {
	f := deployFolded(t)
	cs, _, _, err := BuildChangeSet(context.Background(), []byte(foldedBase), deployOpts(), f)
	if err != nil {
		t.Fatalf("changeset: %v", err)
	}
	if cs.hasChanges() {
		t.Fatalf("re-applying the same template shows changes: %+v", cs.Changes)
	}
}

// A create's change set lists every resource as an Add, the ones that provision nothing included.
func TestChangeSet_CreateListsFoldedResources(t *testing.T) {
	cs, _, _, err := BuildChangeSet(context.Background(), []byte(foldedBase), deployOpts(), &fakeApplier{})
	if err != nil {
		t.Fatalf("changeset: %v", err)
	}
	for _, id := range []string{"Igw", "Attach", "Handle"} {
		if c, ok := foldedChange(cs, id); !ok || c.Action != Add || !c.Folded {
			t.Errorf("%s = %+v (listed %v), want a folded Add", id, c, ok)
		}
	}
}

// An update that changes only resources that provision nothing is an update, as on AWS: the stack records
// the new template and parameters and the resources' events, and ends UPDATE_COMPLETE — with nothing
// applied or deleted, since nothing of theirs exists to apply.
func TestUpdate_FoldedOnlyChangeIsRecorded(t *testing.T) {
	f := deployFolded(t)
	f.applied, f.deleted = nil, nil
	next := `
Parameters:
  Env: { Type: String, Default: dev }
Resources:
  Key: { Type: AWS::KMS::Key, Properties: { Description: a } }
  Vpc: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  Igw:
    Type: AWS::EC2::InternetGateway
    Properties: { Tags: [ { Key: env, Value: !Ref Env } ] }
  Attach: { Type: AWS::EC2::VPCGatewayAttachment, Properties: { VpcId: !Ref Vpc, InternetGatewayId: !Ref Igw } }
  Handle2: { Type: AWS::CloudFormation::WaitConditionHandle }
`
	opts := deployOpts()
	opts.Params = map[string]string{"Env": "prod"}
	rec, err := Update(context.Background(), []byte(next), opts, f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("status = %s, want UPDATE_COMPLETE", rec.Status)
	}
	if rec.Template != next {
		t.Error("the stack did not record the new template")
	}
	if rec.Parameters["Env"] != "prod" {
		t.Errorf("the stack did not record the new parameters: %v", rec.Parameters)
	}
	if got := f.appliedNonCM(); len(got) != 0 {
		t.Errorf("an update of folded resources applied %v", got)
	}
	if len(f.deleted) != 0 {
		t.Errorf("an update of folded resources deleted %v", f.deleted)
	}
	has := func(id, status string) bool {
		for _, e := range rec.Events {
			if e.LogicalID == id && e.Status == status {
				return true
			}
		}
		return false
	}
	for _, w := range [][2]string{
		{"Handle2", "CREATE_IN_PROGRESS"}, {"Handle2", "CREATE_COMPLETE"},
		{"Igw", "UPDATE_IN_PROGRESS"}, {"Igw", "UPDATE_COMPLETE"},
		{"Handle", "DELETE_IN_PROGRESS"}, {"Handle", "DELETE_COMPLETE"},
		{"s", "UPDATE_COMPLETE"},
	} {
		if !has(w[0], w[1]) {
			t.Errorf("no %s event for %s", w[1], w[0])
		}
	}
	for _, e := range rec.Events {
		if e.LogicalID == "Handle2" && e.Type != "AWS::CloudFormation::WaitConditionHandle" {
			t.Errorf("Handle2's event has type %q", e.Type)
		}
	}
	// The next change set compares against what was recorded: nothing left to change.
	cs, _, _, err := BuildChangeSet(context.Background(), []byte(next), opts, f)
	if err != nil {
		t.Fatalf("changeset after: %v", err)
	}
	if cs.hasChanges() {
		t.Errorf("the recorded update still shows changes: %+v", cs.Changes)
	}
}

// Removing a folded resource next to a provisioned one: the provisioned one is deleted, the folded one only
// gets its events — no delete of an object that does not exist.
func TestUpdate_FoldedRemovalDeletesNothingOfItsOwn(t *testing.T) {
	f := deployFolded(t)
	f.applied, f.deleted = nil, nil
	next := `
Parameters:
  Env: { Type: String, Default: dev }
Resources:
  Vpc: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  Igw:
    Type: AWS::EC2::InternetGateway
    Properties: { Tags: [ { Key: env, Value: !Ref Env } ] }
  Attach: { Type: AWS::EC2::VPCGatewayAttachment, Properties: { VpcId: !Ref Vpc, InternetGatewayId: !Ref Igw } }
`
	rec, err := Update(context.Background(), []byte(next), deployOpts(), f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "EncryptionKey/s-key" {
		t.Errorf("deleted %v, want only the key", f.deleted)
	}
	var sawHandle bool
	for _, e := range rec.Events {
		if e.LogicalID == "Handle" && e.Status == "DELETE_COMPLETE" {
			sawHandle = true
		}
	}
	if !sawHandle {
		t.Error("the removed handle has no DELETE_COMPLETE event")
	}
}
