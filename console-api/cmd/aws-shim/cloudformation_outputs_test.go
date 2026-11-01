package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// #347: DescribeStacks returns the stack Outputs the engine evaluated at *_COMPLETE; Exports are a
// namespace registry (ListExports, Fn::ImportValue) with AWS's collision / in-use rules. Addresses are
// RFC 5737 documentation ranges.

// cfnTestDoorway builds a doorway + caller applier over one fake dynamic client (the shim's record client
// and the caller's resource client are the same fake here). lanIP, when set, is the status.lanIp every
// VirtualMachine reports (what the VM composition surfaces once MetalLB assigns the address).
func cfnTestDoorway(t *testing.T, lanIP string) (*cfnDoorway, *impersonatingApplier) {
	t.Helper()
	gvrs := map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "configmaps"}:                              "ConfigMapList",
		{Group: "openinfra.dev", Version: "v1", Resource: "virtualmachines"}: "VirtualMachineList",
		{Group: "openinfra.dev", Version: "v1", Resource: "securitygroups"}:  "SecurityGroupList",
		{Group: "openinfra.dev", Version: "v1", Resource: "encryptionkeys"}:  "EncryptionKeyList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrs)
	// The fake tracker's server-side apply only patches an EXISTING object; make it create-or-replace,
	// like the API server does for the doorway's applies.
	dyn.PrependReactor("patch", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pa := a.(k8stesting.PatchAction)
		if pa.GetPatchType() != types.ApplyPatchType {
			return false, nil, nil
		}
		obj := &unstructured.Unstructured{}
		if err := json.Unmarshal(pa.GetPatch(), &obj.Object); err != nil {
			return true, nil, err
		}
		obj.SetName(pa.GetName())
		obj.SetNamespace(pa.GetNamespace())
		tr := dyn.Tracker()
		if _, err := tr.Get(pa.GetResource(), pa.GetNamespace(), pa.GetName()); err != nil {
			return true, obj, tr.Create(pa.GetResource(), obj, pa.GetNamespace())
		}
		return true, obj, tr.Update(pa.GetResource(), obj, pa.GetNamespace())
	})
	if lanIP != "" {
		// An applied VM reads back with the LAN IP its controller would set. One that was never applied is
		// absent (the engine checks before applying that no other stack owns the name).
		dyn.PrependReactor("get", "virtualmachines", func(a k8stesting.Action) (bool, runtime.Object, error) {
			ga := a.(k8stesting.GetAction)
			o, err := dyn.Tracker().Get(ga.GetResource(), ga.GetNamespace(), ga.GetName())
			if err != nil {
				return true, nil, err
			}
			u := o.(*unstructured.Unstructured).DeepCopy()
			_ = unstructured.SetNestedField(u.Object, lanIP, "status", "lanIp")
			return true, u, nil
		})
	}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Version: "v1"}, {Group: "openinfra.dev", Version: "v1"}})
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, meta.RESTScopeNamespace)
	for _, k := range []string{"VirtualMachine", "SecurityGroup", "EncryptionKey"} {
		mapper.Add(schema.GroupVersionKind{Group: "openinfra.dev", Version: "v1", Kind: k}, meta.RESTScopeNamespace)
	}
	h := &cfnDoorway{shimDyn: dyn, mapper: mapper, ns: "default", account: "000000000000", region: "us-east-1",
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)), cs: csWithSAR(true), authzNS: "default"}
	return h, &impersonatingApplier{caller: dyn, shim: dyn, mapper: mapper, ns: "default"}
}

// cfnPost runs one doorway action with form values and returns the recorder.
func cfnPost(t *testing.T, h *cfnDoorway, ap *impersonatingApplier, form url.Values, run func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	rr := httptest.NewRecorder()
	run(rr, req)
	return rr
}

type describeStacksXML struct {
	XMLName xml.Name `xml:"DescribeStacksResponse"`
	Stacks  []struct {
		StackName   string `xml:"StackName"`
		StackStatus string `xml:"StackStatus"`
		Outputs     []struct {
			OutputKey   string `xml:"OutputKey"`
			OutputValue string `xml:"OutputValue"`
			Description string `xml:"Description"`
			ExportName  string `xml:"ExportName"`
		} `xml:"Outputs>member"`
	} `xml:"DescribeStacksResult>Stacks>member"`
}

const outputsWebTmpl = `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  Assoc:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !GetAtt WebEip.AllocationId, InstanceId: !Ref Web }
Outputs:
  WebAddress:
    Description: the web server's address
    Value: !Ref WebEip
    Export: { Name: !Sub "${AWS::StackName}-WebAddress" }
  WebUrl:
    Value: !Sub "http://${WebEip.PublicIp}/"
  WebPrivateIp:
    Value: !GetAtt Web.PrivateIp
`

// End to end through the doorway's own applier: the engine deploys, resolves the Elastic IP Outputs from
// the VM's status.lanIp (read as the caller), persists them on the stack record, and DescribeStacks
// returns them in the AWS shape. An unresolvable Output is omitted (recorded, never faked).
func TestCFNDoorway_DescribeStacksReturnsOutputs(t *testing.T) {
	h, ap := cfnTestDoorway(t, "192.0.2.40")
	opts := h.optsFor("web", nil, stackExports{})
	opts.Wait = false // the fake has no controllers to mark resources Ready
	rec, err := cfn.Deploy(context.Background(), []byte(outputsWebTmpl), opts, ap)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(rec.OutputsOmitted) != 1 || rec.OutputsOmitted[0].OutputKey != "WebPrivateIp" {
		t.Fatalf("only the unresolvable PrivateIp Output is omitted, got %+v", rec.OutputsOmitted)
	}

	rr := cfnPost(t, h, ap, url.Values{"StackName": {"web"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStacks(w, r, ap, "req-1") })
	if rr.Code != http.StatusOK {
		t.Fatalf("DescribeStacks: %d %s", rr.Code, rr.Body.String())
	}
	var got describeStacksXML
	if err := xml.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("DescribeStacks XML: %v\n%s", err, rr.Body.String())
	}
	if len(got.Stacks) != 1 || got.Stacks[0].StackStatus != "CREATE_COMPLETE" {
		t.Fatalf("want one CREATE_COMPLETE stack: %+v", got)
	}
	outs := got.Stacks[0].Outputs
	if len(outs) != 2 {
		t.Fatalf("want the 2 resolvable Outputs (PrivateIp omitted), got %+v", outs)
	}
	byKey := map[string]int{}
	for i, o := range outs {
		byKey[o.OutputKey] = i
	}
	wa := outs[byKey["WebAddress"]]
	if wa.OutputValue != "192.0.2.40" || wa.Description != "the web server's address" || wa.ExportName != "web-WebAddress" {
		t.Errorf("WebAddress Output wrong: %+v", wa)
	}
	if u := outs[byKey["WebUrl"]]; u.OutputValue != "http://192.0.2.40/" || u.ExportName != "" {
		t.Errorf("WebUrl Output wrong: %+v", u)
	}
	if strings.Contains(rr.Body.String(), "WebPrivateIp") {
		t.Errorf("an omitted Output must not appear in DescribeStacks:\n%s", rr.Body.String())
	}
}

// Exports: ListExports lists them; another stack exporting the same name is refused (AWS's rule), and a
// stack whose export another stack imports can't be deleted. Fn::ImportValue resolves against them.
func TestCFNDoorway_ExportsRegistry(t *testing.T) {
	h, ap := cfnTestDoorway(t, "")
	ctx := context.Background()
	for _, rec := range []*cfn.StackRecord{
		{Name: "net", Namespace: "default", Status: "CREATE_COMPLETE",
			Outputs: []cfn.StackOutput{{OutputKey: "Address", OutputValue: "192.0.2.60", ExportName: "net-Address"}, {OutputKey: "Plain", OutputValue: "x"}}},
		{Name: "app", Namespace: "default", Status: "CREATE_COMPLETE", Imports: []string{"net-Address"}},
	} {
		if err := ap.putRecord(ctx, rec); err != nil {
			t.Fatalf("seed record: %v", err)
		}
	}

	// ListExports: only Outputs with an ExportName.
	rr := cfnPost(t, h, ap, url.Values{}, func(w http.ResponseWriter, r *http.Request) { h.listExports(w, r, "req-2") })
	body := rr.Body.String()
	if !strings.Contains(body, "<Name>net-Address</Name><Value>192.0.2.60</Value>") || strings.Contains(body, "Plain") || !strings.Contains(body, "stack/net/") {
		t.Fatalf("ListExports must list net-Address (exported by net) and nothing else:\n%s", body)
	}

	// A template importing the export validates (Fn::ImportValue resolves against the registry).
	imp := `
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: !ImportValue net-Address }
`
	rr = cfnPost(t, h, ap, url.Values{"TemplateBody": {imp}}, func(w http.ResponseWriter, r *http.Request) { h.validateTemplate(w, r, "req-3") })
	if rr.Code != http.StatusOK {
		t.Fatalf("Fn::ImportValue of a registered export must validate: %d %s", rr.Code, rr.Body.String())
	}

	// Another stack exporting the same name is refused before anything is created.
	dup := `
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: k }
Outputs:
  Address: { Value: 192.0.2.61, Export: { Name: net-Address } }
`
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"other"}, "TemplateBody": {dup}}, func(w http.ResponseWriter, r *http.Request) { h.createStack(w, r, ap, "req-4") })
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "Export with name net-Address is already exported by stack net") {
		t.Fatalf("a duplicate export name must be refused: %d %s", rr.Code, rr.Body.String())
	}
	if _, found, _ := ap.GetStack(ctx, "other"); found {
		t.Fatal("a refused CreateStack must create nothing (not even the record)")
	}

	// net's export is imported by app: deleting net is refused.
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"net"}}, func(w http.ResponseWriter, r *http.Request) { h.deleteStack(w, r, ap, "req-5") })
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "Export net-Address cannot be deleted as it is in use by app") {
		t.Fatalf("deleting a stack whose export is imported must be refused: %d %s", rr.Code, rr.Body.String())
	}
	// …and so is an update of net that drops the export.
	noExport := `
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: k }
`
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"net"}, "TemplateBody": {noExport}}, func(w http.ResponseWriter, r *http.Request) { h.updateStack(w, r, ap, "req-6") })
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "in use by app") {
		t.Fatalf("an update dropping an imported export must be refused: %d %s", rr.Code, rr.Body.String())
	}
}

// The registry excludes the stack being evaluated (a stack can't import its own export) and carries only
// completed stacks' Outputs; outputsXML renders nothing for a stack without Outputs.
func TestCFNDoorway_ExportsFromAndOutputsXML(t *testing.T) {
	recs := []*cfn.StackRecord{
		{Name: "a", Outputs: []cfn.StackOutput{{OutputKey: "K", OutputValue: "v", ExportName: "a-K"}}},
		{Name: "b", Outputs: []cfn.StackOutput{{OutputKey: "K", OutputValue: "w", ExportName: "b-K"}}},
	}
	ex := exportsFrom(recs, "a")
	if _, self := ex.values["a-K"]; self || ex.values["b-K"] != "w" || ex.owners["b-K"] != "b" {
		t.Fatalf("exports must exclude the evaluated stack: %+v", ex)
	}
	if got := outputsXML(&cfn.StackRecord{Name: "x"}); got != "" {
		t.Fatalf("no Outputs -> no <Outputs> member, got %q", got)
	}
	got := outputsXML(&cfn.StackRecord{Outputs: []cfn.StackOutput{{OutputKey: "U", OutputValue: "a<b&c"}}})
	if got != "<Outputs><member><OutputKey>U</OutputKey><OutputValue>a&lt;b&amp;c</OutputValue></member></Outputs>" {
		t.Fatalf("Outputs XML must be escaped and omit empty Description/ExportName, got %s", got)
	}
}

// GetStatus reads a live object's .status through the CALLER client (cfn.StatusReader), found=false when
// the object is absent.
func TestImpersonatingApplier_GetStatus(t *testing.T) {
	_, ap := cfnTestDoorway(t, "192.0.2.70")
	var _ cfn.StatusReader = ap
	if err := ap.Apply(context.Background(), []byte("apiVersion: openinfra.dev/v1\nkind: VirtualMachine\nmetadata: {name: web, namespace: default}\nspec: {os: ubuntu-24.04}\n")); err != nil {
		t.Fatal(err)
	}
	st, found, err := ap.GetStatus(context.Background(), "openinfra.dev/v1", "VirtualMachine", "web")
	if err != nil || !found || st["lanIp"] != "192.0.2.70" {
		t.Fatalf("GetStatus = %v, %v, %v", st, found, err)
	}
	_, ap2 := cfnTestDoorway(t, "")
	if _, found, err := ap2.GetStatus(context.Background(), "openinfra.dev/v1", "VirtualMachine", "absent"); err != nil || found {
		t.Fatalf("an absent object must be found=false, got found=%v err=%v", found, err)
	}
}
