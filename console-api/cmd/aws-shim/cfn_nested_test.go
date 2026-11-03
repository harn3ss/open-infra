package main

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// #350 Y: a nested stack is a stack of its own through the front door, created from its child template in
// the shim's S3, and deleted with its parent.

// templateObjects serves GET /<bucket>/<key> from a map, as S3 would serve a template object.
func templateObjects(t *testing.T, objects map[string]string) *minio.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := objects[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code><Message>no</Message></Error>`))
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("ETag", `"e"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "text/yaml")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	mc, err := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4("a", "b", ""), Region: "us-east-1", BucketLookup: minio.BucketLookupPath})
	if err != nil {
		t.Fatal(err)
	}
	return mc
}

const nestedChild = `
Parameters:
  Env: { Type: String }
Resources:
  Inner:
    Type: AWS::KMS::Key
    Properties: { Description: !Sub "inner-${Env}" }
Outputs:
  KeyName: { Value: !Sub "child-${Env}" }
`

const nestedParent = `
Parameters:
  Env: { Type: String, Default: prod }
Resources:
  Network:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub "https://s3.amazonaws.com/templates/${Env}/child.yaml"
      Parameters: { Env: !Ref Env }
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: !GetAtt Network.Outputs.KeyName }
Outputs:
  FromChild: { Value: !GetAtt Network.Outputs.KeyName }
`

type listedStacksXML struct {
	Members []struct {
		StackID     string `xml:"StackId"`
		StackName   string `xml:"StackName"`
		StackStatus string `xml:"StackStatus"`
		ParentID    string `xml:"ParentId"`
		RootID      string `xml:"RootId"`
	} `xml:"ListStacksResult>StackSummaries>member"`
}

func nestedDoorway(t *testing.T) (*cfnDoorway, *fakeAPI) {
	t.Helper()
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	h.s3 = &s3Handler{mc: templateObjects(t, map[string]string{
		"templates/prod/child.yaml": nestedChild,
		"templates/bad/child.yaml":  "Resources:\n  Gone: { Type: AWS::Nope::Thing }\n",
	}), cs: csWithSAR(true), authzNS: "default", logger: discardLogger()}
	return h, fa
}

func TestCFNNested_ChildIsAStackOfItsOwnAndGoesWithItsParent(t *testing.T) {
	h, fa := nestedDoorway(t)
	code, body := cfnCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {nestedParent}})
	if code != 200 {
		t.Fatalf("CreateStack: %d %s", code, body)
	}
	parentID := createdStackID(t, body)
	h.ops.drain(10 * time.Second)

	parent, _ := recordIn(t, fa, "app")
	if parent == nil || parent.Status != "CREATE_COMPLETE" {
		t.Fatalf("parent: %+v", parent)
	}
	childName := ""
	for _, r := range parent.Resources {
		if r.LogicalID == "Network" {
			childName = r.Name
		}
	}
	child, _ := recordIn(t, fa, childName)
	if childName == "" || child == nil || child.Status != "CREATE_COMPLETE" || child.ParentID != parentID || child.RootID != parentID {
		t.Fatalf("child %q: %+v", childName, child)
	}
	if !strings.HasPrefix(childName, "app-network-") {
		t.Fatalf("child stack name %q", childName)
	}

	// The parent's resources and Outputs read the child's Outputs; its resource's physical id is the child.
	_, d, raw := describeByRef(t, h, "app")
	if len(d.Stacks) != 1 || len(d.Stacks[0].Outputs) != 1 || d.Stacks[0].Outputs[0].OutputValue != "child-prod" {
		t.Fatalf("parent outputs: %s", raw)
	}
	_, res := cfnCall(t, h, url.Values{"Action": {"DescribeStackResources"}, "StackName": {"app"}, "LogicalResourceId": {"Network"}})
	if !strings.Contains(res, "<PhysicalResourceId>"+child.StackID+"</PhysicalResourceId>") || !strings.Contains(res, "<ResourceType>AWS::CloudFormation::Stack</ResourceType>") {
		t.Fatalf("the parent's nested stack resource: %s", res)
	}
	// The child is listed and described with its parent and root.
	_, cd := cfnCall(t, h, url.Values{"Action": {"DescribeStacks"}, "StackName": {childName}})
	if !strings.Contains(cd, "<ParentId>"+parentID+"</ParentId>") || !strings.Contains(cd, "<RootId>"+parentID+"</RootId>") {
		t.Fatalf("DescribeStacks of the child: %s", cd)
	}
	var l listedStacksXML
	_, lb := cfnCall(t, h, url.Values{"Action": {"ListStacks"}})
	_ = xml.Unmarshal([]byte(lb), &l)
	if len(l.Members) != 2 {
		t.Fatalf("ListStacks: %s", lb)
	}

	// The child is deleted with its parent, not on its own; its termination protection is its root's.
	if code, body := cfnCall(t, h, url.Values{"Action": {"DeleteStack"}, "StackName": {childName}}); code != 400 || !strings.Contains(body, "nested stack") {
		t.Fatalf("DeleteStack of the child on its own: %d %s", code, body)
	}
	if code, body := cfnCall(t, h, url.Values{"Action": {"UpdateTerminationProtection"}, "StackName": {childName}, "EnableTerminationProtection": {"true"}}); code != 400 || !strings.Contains(body, "nested stack") {
		t.Fatalf("UpdateTerminationProtection of the child: %d %s", code, body)
	}
	if code, body := cfnCall(t, h, url.Values{"Action": {"DeleteStack"}, "StackName": {"app"}}); code != 200 {
		t.Fatalf("DeleteStack of the parent: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	if p, _ := recordIn(t, fa, "app"); p != nil {
		t.Fatalf("parent not deleted: %+v", p)
	}
	if c, _ := recordIn(t, fa, childName); c != nil {
		t.Fatalf("child not deleted with its parent: %+v", c)
	}
	l = listedStacksXML{}
	_, lb = cfnCall(t, h, url.Values{"Action": {"ListStacks"}, "StackStatusFilter.member.1": {"DELETE_COMPLETE"}})
	_ = xml.Unmarshal([]byte(lb), &l)
	if len(l.Members) != 2 {
		t.Fatalf("both stacks are kept as deleted stacks: %s", lb)
	}
	for _, m := range l.Members {
		if m.StackName == childName && m.ParentID != parentID {
			t.Fatalf("the deleted child keeps its parent: %+v", m)
		}
	}
}

// A child that fails rolls its parent back, and the parent's rollback deletes it.
func TestCFNNested_ChildFailureRollsBackItsParent(t *testing.T) {
	h, fa := nestedDoorway(t)
	tmpl := strings.Replace(nestedParent, "${Env}/child.yaml", "bad/child.yaml", 1)
	if code, body := cfnCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {tmpl}}); code != 200 {
		t.Fatalf("CreateStack: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	parent, _ := recordIn(t, fa, "app")
	if parent == nil || parent.Status != "ROLLBACK_COMPLETE" || !strings.Contains(parent.Message, "Embedded stack") {
		t.Fatalf("parent after its nested stack failed: %+v", parent)
	}
	var l listedStacksXML
	_, lb := cfnCall(t, h, url.Values{"Action": {"ListStacks"}})
	_ = xml.Unmarshal([]byte(lb), &l)
	for _, m := range l.Members {
		if m.StackName != "app" && m.StackStatus != "DELETE_COMPLETE" {
			t.Fatalf("a failed child must not be left in use: %s", lb)
		}
	}
}
