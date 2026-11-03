package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// #350 Y: a deleted stack is kept, as AWS keeps one for 90 days, under the StackId of its own instance.

var aliceClaims = iam.Claims{Sub: "alice", Groups: []string{"openinfra:powerusers", "openinfra:users"}}

const deletedTmpl = "Description: kept after delete\nResources:\n  Key:\n    Type: AWS::KMS::Key\n    Properties: { Description: k }\nOutputs:\n  Id: { Value: !Ref AWS::StackId }\n"

type stackSummariesXML struct {
	Members []struct {
		StackID      string `xml:"StackId"`
		StackName    string `xml:"StackName"`
		StackStatus  string `xml:"StackStatus"`
		DeletionTime string `xml:"DeletionTime"`
		CreationTime string `xml:"CreationTime"`
		Description  string `xml:"TemplateDescription"`
	} `xml:"ListStacksResult>StackSummaries>member"`
}

type describedXML struct {
	Stacks []struct {
		StackID      string `xml:"StackId"`
		StackStatus  string `xml:"StackStatus"`
		DeletionTime string `xml:"DeletionTime"`
		Outputs      []struct {
			OutputKey   string `xml:"OutputKey"`
			OutputValue string `xml:"OutputValue"`
		} `xml:"Outputs>member"`
	} `xml:"DescribeStacksResult>Stacks>member"`
}

func cfnCall(t *testing.T, h *cfnDoorway, form url.Values) (int, string) {
	t.Helper()
	w := serveWith(h, formOp(form), aliceClaims)
	return w.Code, w.Body.String()
}

func createdStackID(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		StackID string `xml:"CreateStackResult>StackId"`
	}
	if err := xml.Unmarshal([]byte(body), &out); err != nil || out.StackID == "" {
		t.Fatalf("CreateStack answered no StackId: %v %s", err, body)
	}
	return out.StackID
}

func describeByRef(t *testing.T, h *cfnDoorway, ref string) (int, describedXML, string) {
	t.Helper()
	code, body := cfnCall(t, h, url.Values{"Action": {"DescribeStacks"}, "StackName": {ref}})
	var d describedXML
	_ = xml.Unmarshal([]byte(body), &d)
	return code, d, body
}

func listStacks(t *testing.T, h *cfnDoorway, filter ...string) stackSummariesXML {
	t.Helper()
	form := url.Values{"Action": {"ListStacks"}}
	for i, f := range filter {
		form.Set("StackStatusFilter.member."+string(rune('1'+i)), f)
	}
	code, body := cfnCall(t, h, form)
	if code != 200 {
		t.Fatalf("ListStacks: %d %s", code, body)
	}
	var s stackSummariesXML
	if err := xml.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCFNDeleted_KeptUnderItsOwnStackIDAndReCreatedWithANewOne(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")

	code, body := cfnCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {deletedTmpl}})
	if code != 200 {
		t.Fatalf("CreateStack: %d %s", code, body)
	}
	first := createdStackID(t, body)
	h.ops.drain(10 * time.Second)
	if want := "arn:aws:cloudformation:us-east-1:000000000000:stack/app/"; !strings.HasPrefix(first, want) || first == h.stackID("app") {
		t.Fatalf("a new stack's StackId = %s, want its own (not the derived %s)", first, h.stackID("app"))
	}
	// AWS::StackId is the stack's own StackId.
	if _, d, raw := describeByRef(t, h, "app"); len(d.Stacks) != 1 || d.Stacks[0].StackID != first ||
		len(d.Stacks[0].Outputs) != 1 || d.Stacks[0].Outputs[0].OutputValue != first {
		t.Fatalf("DescribeStacks app: %s", raw)
	}

	if code, body := cfnCall(t, h, url.Values{"Action": {"DeleteStack"}, "StackName": {"app"}}); code != 200 {
		t.Fatalf("DeleteStack: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)

	// By name, a deleted stack is gone; by its StackId it is DELETE_COMPLETE, with its DeletionTime.
	if code, _, raw := describeByRef(t, h, "app"); code != 400 || !strings.Contains(raw, "does not exist") {
		t.Fatalf("DescribeStacks of a deleted stack by name: %d %s", code, raw)
	}
	code, d, raw := describeByRef(t, h, first)
	if code != 200 || len(d.Stacks) != 1 || d.Stacks[0].StackStatus != "DELETE_COMPLETE" || d.Stacks[0].DeletionTime == "" || d.Stacks[0].StackID != first {
		t.Fatalf("DescribeStacks of a deleted stack by its StackId: %d %s", code, raw)
	}
	if len(d.Stacks[0].Outputs) != 0 {
		t.Fatalf("a deleted stack has no outputs: %s", raw)
	}
	// Its events, through the delete.
	code, evs := cfnCall(t, h, url.Values{"Action": {"DescribeStackEvents"}, "StackName": {first}})
	if code != 200 || !strings.Contains(evs, "<ResourceStatus>DELETE_COMPLETE</ResourceStatus>") || !strings.Contains(evs, "<ResourceStatus>CREATE_COMPLETE</ResourceStatus>") {
		t.Fatalf("DescribeStackEvents of the deleted stack: %d %s", code, evs)
	}
	// Its resources, each DELETE_COMPLETE; its template.
	code, res := cfnCall(t, h, url.Values{"Action": {"DescribeStackResources"}, "StackName": {first}})
	if code != 200 || !strings.Contains(res, "<LogicalResourceId>Key</LogicalResourceId>") || !strings.Contains(res, "<ResourceStatus>DELETE_COMPLETE</ResourceStatus>") {
		t.Fatalf("DescribeStackResources of the deleted stack: %d %s", code, res)
	}
	code, tb := cfnCall(t, h, url.Values{"Action": {"GetTemplate"}, "StackName": {first}})
	if code != 200 || !strings.Contains(tb, "kept after delete") {
		t.Fatalf("GetTemplate of the deleted stack: %d %s", code, tb)
	}
	// ListStacks lists it.
	l := listStacks(t, h)
	if len(l.Members) != 1 || l.Members[0].StackID != first || l.Members[0].StackStatus != "DELETE_COMPLETE" || l.Members[0].DeletionTime == "" ||
		l.Members[0].CreationTime == "" || l.Members[0].Description != "kept after delete" {
		t.Fatalf("ListStacks after the delete: %+v", l.Members)
	}

	// Re-created under the same name: a new StackId; the deleted one stays known by its own.
	code, body = cfnCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {deletedTmpl}})
	if code != 200 {
		t.Fatalf("re-CreateStack: %d %s", code, body)
	}
	second := createdStackID(t, body)
	h.ops.drain(10 * time.Second)
	if second == first {
		t.Fatalf("a re-created stack got the deleted stack's StackId %s", first)
	}
	if _, d, raw := describeByRef(t, h, "app"); len(d.Stacks) != 1 || d.Stacks[0].StackID != second || d.Stacks[0].StackStatus != "CREATE_COMPLETE" ||
		d.Stacks[0].Outputs[0].OutputValue != second {
		t.Fatalf("by name, the stack in use: %s", raw)
	}
	if _, d, raw := describeByRef(t, h, first); len(d.Stacks) != 1 || d.Stacks[0].StackStatus != "DELETE_COMPLETE" {
		t.Fatalf("by its StackId, the deleted stack: %s", raw)
	}
	if _, d, raw := describeByRef(t, h, second); len(d.Stacks) != 1 || d.Stacks[0].StackStatus != "CREATE_COMPLETE" {
		t.Fatalf("by its StackId, the live stack: %s", raw)
	}
	// Every-stack DescribeStacks lists only the live one, as on AWS.
	if _, body := cfnCall(t, h, url.Values{"Action": {"DescribeStacks"}}); strings.Contains(body, first) || !strings.Contains(body, second) {
		t.Fatalf("DescribeStacks of every stack: %s", body)
	}
	if l := listStacks(t, h, "DELETE_COMPLETE"); len(l.Members) != 1 || l.Members[0].StackID != first {
		t.Fatalf("ListStacks DELETE_COMPLETE: %+v", l.Members)
	}
	if l := listStacks(t, h, "CREATE_COMPLETE"); len(l.Members) != 1 || l.Members[0].StackID != second {
		t.Fatalf("ListStacks CREATE_COMPLETE: %+v", l.Members)
	}

	// The deleted stack's StackId never acts on the stack now using its name: a delete is AWS's no-op,
	// an update does not find it.
	if code, body := cfnCall(t, h, url.Values{"Action": {"DeleteStack"}, "StackName": {first}}); code != 200 {
		t.Fatalf("DeleteStack of a deleted StackId: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	if rec, _ := recordIn(t, fa, "app"); rec == nil || rec.StackID != second || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("deleting by the deleted stack's StackId touched the live stack: %+v", rec)
	}
	if code, body := cfnCall(t, h, url.Values{"Action": {"UpdateStack"}, "StackName": {first}, "TemplateBody": {deletedTmpl}}); code != 400 || !strings.Contains(body, "does not exist") {
		t.Fatalf("UpdateStack by a deleted StackId: %d %s", code, body)
	}
}

// A stack from before StackIds were per instance keeps its derived StackId — named by it, or by any ARN
// of its name, as before — and once deleted is kept under it.
func TestCFNDeleted_LegacyStackKeepsItsDerivedStackID(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	seedStack(fa, cfn.StackRecord{Name: "old", Status: "CREATE_COMPLETE", Template: deletedTmpl, CreatedAt: "2026-01-01T00:00:00Z"}, nil)
	derived := h.stackID("old")
	for _, ref := range []string{"old", derived, "arn:aws:cloudformation:us-east-1:000000000000:stack/old/some-earlier-form"} {
		if code, d, raw := describeByRef(t, h, ref); code != 200 || len(d.Stacks) != 1 || d.Stacks[0].StackID != derived {
			t.Fatalf("DescribeStacks %s of a legacy stack: %d %s", ref, code, raw)
		}
	}
	if code, body := cfnCall(t, h, url.Values{"Action": {"DeleteStack"}, "StackName": {derived}}); code != 200 {
		t.Fatalf("DeleteStack by the derived StackId: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	if rec, _ := recordIn(t, fa, "old"); rec != nil {
		t.Fatalf("the legacy stack was not deleted: %+v", rec)
	}
	if code, d, raw := describeByRef(t, h, derived); code != 200 || d.Stacks[0].StackStatus != "DELETE_COMPLETE" {
		t.Fatalf("the deleted legacy stack by its derived StackId: %d %s", code, raw)
	}
}

// Deleted stacks are removed 90 days after their delete.
func TestCFNDeleted_PrunedAfterRetention(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	keep := func(name, deletedAt string) {
		rec := cfn.StackRecord{Name: name, Namespace: opsNS, StackID: h.newStackID(name), Status: "DELETE_COMPLETE", DeletedAt: deletedAt}
		data, _ := json.Marshal(rec)
		fa.put("secrets", shimNS, deletedRecordName(name, rec.StackID), map[string]any{"apiVersion": "v1", "kind": "Secret",
			"metadata": map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": cfnDeletedManagedBy, "cfn.openinfra.dev/stack": name}},
			"data":     map[string]any{"stack.json": base64.StdEncoding.EncodeToString(data)}})
	}
	now := time.Now().UTC()
	keep("recent", now.Add(-89*24*time.Hour).Format(time.RFC3339))
	keep("expired", now.Add(-91*24*time.Hour).Format(time.RFC3339))
	h.pruneDeleted(t.Context(), now)
	var names []string
	for _, rec := range h.deletedStacks(t.Context(), "") {
		names = append(names, rec.Name)
	}
	if strings.Join(names, ",") != "recent" {
		t.Fatalf("after pruning, kept %v; want only the stack deleted within 90 days", names)
	}
}

// The kept record holds no applied spec of the deleted stack's resources (what a NoEcho value may have
// fed), only each resource's identity and last status.
func TestCFNDeleted_KeptRecordIsCompact(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	before := &cfn.StackRecord{Name: "s", Namespace: opsNS, StackID: h.newStackID("s"), Status: "DELETE_IN_PROGRESS",
		Template: deletedTmpl, Resources: []cfn.StackResource{{LogicalID: "Key", Type: "AWS::KMS::Key", Kind: "EncryptionKey", Name: "s-key",
			Spec: map[string]any{"description": "fed-by-a-secret"}}},
		Outputs: []cfn.StackOutput{{OutputKey: "Id", OutputValue: "x", ExportName: "s-id"}}}
	h.keepDeleted(t.Context(), before, nil)
	o := fa.get("secrets", shimNS, deletedRecordName("s", before.StackID))
	if o == nil {
		t.Fatal("no kept record")
	}
	rec, ok := shimRecords.stackRecord(&unstructured.Unstructured{Object: o})
	if !ok || rec.Status != "DELETE_COMPLETE" || rec.DeletedAt == "" || len(rec.Resources) != 1 || rec.Resources[0].Spec != nil ||
		len(rec.Outputs) != 0 || rec.Resources[0].Status != "DELETE_COMPLETE" {
		t.Fatalf("kept record: %+v", rec)
	}
	if n := len(rec.Events); n == 0 || rec.Events[n-1].Status != "DELETE_COMPLETE" || rec.Events[n-1].Type != cfn.StackTypeName {
		t.Fatalf("a resumed delete's kept record ends with the stack's DELETE_COMPLETE: %+v", rec.Events)
	}
	if _, ok := awsidentity.StackIDName(rec.StackID); !ok {
		t.Fatalf("kept StackId %q", rec.StackID)
	}
}
