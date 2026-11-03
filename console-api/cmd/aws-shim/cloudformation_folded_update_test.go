package main

import (
	"context"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
)

// A folded resource an update changed has events of its own, which the engine records. Its creation
// before them still follows its carriers; one the update created has no history before its own create.
func TestWithFoldedEvents_OwnEventsTakeOverFromTheFirst(t *testing.T) {
	folded := []cfn.FoldedResource{
		{LogicalID: "Mount", Type: "AWS::EC2::VolumeAttachment", PhysicalID: "net-Mount-ABC", Carriers: []string{"Data", "Web"}},
		{LogicalID: "Route2", Type: "AWS::EC2::Route", PhysicalID: "rtb-1|10.1.0.0/16", Carriers: []string{"Web"}},
	}
	chrono := []cfn.StackEvent{
		{EventID: "s1", LogicalID: "net", Type: cfn.StackTypeName, Status: "CREATE_IN_PROGRESS", Timestamp: "t1"},
		{EventID: "d1", LogicalID: "Data", Status: "CREATE_IN_PROGRESS", Timestamp: "t2"},
		{EventID: "w1", LogicalID: "Web", Status: "CREATE_IN_PROGRESS", Timestamp: "t3"},
		{EventID: "d2", LogicalID: "Data", Status: "CREATE_COMPLETE", Timestamp: "t4"},
		{EventID: "w2", LogicalID: "Web", Status: "CREATE_COMPLETE", Timestamp: "t5"},
		{EventID: "s2", LogicalID: "net", Type: cfn.StackTypeName, Status: "CREATE_COMPLETE", Timestamp: "t6"},
		// An update that changed Mount and added Route2, neither of which provisions anything.
		{EventID: "u1", LogicalID: "net", Type: cfn.StackTypeName, Status: "UPDATE_IN_PROGRESS", Timestamp: "t7"},
		{EventID: "m1", LogicalID: "Mount", Type: "AWS::EC2::VolumeAttachment", Status: "UPDATE_IN_PROGRESS", Timestamp: "t8"},
		{EventID: "m2", LogicalID: "Mount", Type: "AWS::EC2::VolumeAttachment", Status: "UPDATE_COMPLETE", Timestamp: "t8"},
		{EventID: "r1", LogicalID: "Route2", Type: "AWS::EC2::Route", Status: "CREATE_IN_PROGRESS", Timestamp: "t8"},
		{EventID: "r2", LogicalID: "Route2", Type: "AWS::EC2::Route", Status: "CREATE_COMPLETE", Timestamp: "t8"},
		{EventID: "u2", LogicalID: "net", Type: cfn.StackTypeName, Status: "UPDATE_COMPLETE", Timestamp: "t9"},
	}
	newest := make([]cfn.StackEvent, 0, len(chrono))
	for i := len(chrono) - 1; i >= 0; i-- {
		newest = append(newest, chrono[i])
	}
	out := withFoldedEvents(newest, folded, "net")
	var seq []string
	for i := len(out) - 1; i >= 0; i-- {
		seq = append(seq, out[i].LogicalID+":"+out[i].Status+"@"+out[i].Timestamp)
	}
	want := "net:CREATE_IN_PROGRESS@t1 Data:CREATE_IN_PROGRESS@t2 Mount:CREATE_IN_PROGRESS@t2 Web:CREATE_IN_PROGRESS@t3 " +
		"Data:CREATE_COMPLETE@t4 Web:CREATE_COMPLETE@t5 Mount:CREATE_COMPLETE@t5 net:CREATE_COMPLETE@t6 " +
		"net:UPDATE_IN_PROGRESS@t7 Mount:UPDATE_IN_PROGRESS@t8 Mount:UPDATE_COMPLETE@t8 Route2:CREATE_IN_PROGRESS@t8 Route2:CREATE_COMPLETE@t8 net:UPDATE_COMPLETE@t9"
	if got := strings.Join(seq, " "); got != want {
		t.Fatalf("events (oldest first):\n got %s\nwant %s", got, want)
	}
}

// After an update, a resource it removed is no longer the stack's: it is not listed, though its
// DELETE_COMPLETE event stays in the history. A rolled-back create still lists what it deleted, as AWS does.
func TestProvisionedRows_ResourceAnUpdateRemovedIsNotListed(t *testing.T) {
	h, _ := cfnTestDoorway(t, "192.0.2.10")
	events := []cfn.StackEvent{
		{EventID: "k1", LogicalID: "Key", Type: "AWS::KMS::Key", Status: "CREATE_COMPLETE", Timestamp: "t1"},
		{EventID: "g1", LogicalID: "Gone", Type: "AWS::KMS::Key", Status: "CREATE_COMPLETE", Timestamp: "t1"},
		{EventID: "h1", LogicalID: "Handle", Type: "AWS::CloudFormation::WaitConditionHandle", Status: "DELETE_COMPLETE", Timestamp: "t2"},
		{EventID: "g2", LogicalID: "Gone", Type: "AWS::KMS::Key", Status: "DELETE_COMPLETE", Timestamp: "t2"},
	}
	rec := &cfn.StackRecord{Name: "s", Status: "UPDATE_COMPLETE", Events: events,
		Resources: []cfn.StackResource{{LogicalID: "Key", Kind: "EncryptionKey", Name: "s-key", Type: "AWS::KMS::Key", Status: "CREATE_COMPLETE"}}}
	listed := map[string]string{}
	for _, r := range h.provisionedResourceRows(context.Background(), rec) {
		listed[r.logicalID] = r.status
	}
	if _, ok := listed["Gone"]; ok {
		t.Errorf("a resource the update removed is listed: %v", listed)
	}
	if _, ok := listed["Handle"]; ok {
		t.Errorf("a folded resource the update removed is listed: %v", listed)
	}
	if listed["Key"] != "CREATE_COMPLETE" {
		t.Errorf("the stack's key: %v", listed)
	}
	rec.Status, rec.Resources = "ROLLBACK_COMPLETE", nil
	listed = map[string]string{}
	for _, r := range h.provisionedResourceRows(context.Background(), rec) {
		listed[r.logicalID] = r.status
	}
	if listed["Gone"] != "DELETE_COMPLETE" {
		t.Errorf("a rolled-back create lists what it deleted: %v", listed)
	}
}

// A change set whose only change is to a resource that provisions nothing is a change, as on AWS: it is
// AVAILABLE, not "didn't contain changes", and lists the resource by its type and physical id.
func TestChangeSet_FoldedOnlyChangeIsAChange(t *testing.T) {
	cs := &changeSet{Type: "UPDATE", Changes: []cfn.Change{
		{LogicalID: "Key", Kind: "EncryptionKey", Type: "AWS::KMS::Key", Name: "s-key", Action: cfn.Unchanged},
		{LogicalID: "Igw", Type: "AWS::EC2::InternetGateway", Name: "igw-0abc", Action: cfn.Modify, Folded: true},
	}}
	if st := changeSetStatus(cs); st != "CREATE_COMPLETE" {
		t.Fatalf("status = %s, want CREATE_COMPLETE", st)
	}
	if ex := changeSetExecutionStatus(cs); ex != "AVAILABLE" {
		t.Fatalf("execution status = %s, want AVAILABLE", ex)
	}
	got := changeSetResourceChanges(cs.Changes)
	if len(got) != 1 || got[0].LogicalID != "Igw" || got[0].Type != "AWS::EC2::InternetGateway" || got[0].Name != "igw-0abc" {
		t.Fatalf("listed changes: %+v", got)
	}
}
