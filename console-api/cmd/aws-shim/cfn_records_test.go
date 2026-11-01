package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
)

// A NoEcho value fed into resources every way a template can (Ref, Sub, Join, Select of Split, Base64)
// is in the stack's resolved properties — so the whole record is kept where the NoEcho values are, in
// Secrets in the shim's namespace. No ConfigMap anywhere holds it (plain or base64), and no response —
// DescribeStacks, DescribeStackResources, ListStacks, GetTemplate — returns it.
const noEchoIntoResourcesTmpl = `
Parameters:
  DbPassword: { Type: String, NoEcho: true }
Resources:
  KeyRef:
    Type: AWS::KMS::Key
    Properties: { Description: !Ref DbPassword }
  KeySub:
    Type: AWS::KMS::Key
    Properties: { Description: !Sub "postgres://app:${DbPassword}@db" }
  KeyJoin:
    Type: AWS::KMS::Key
    Properties: { Description: !Join [ ":", [ user, !Ref DbPassword ] ] }
  KeySelect:
    Type: AWS::KMS::Key
    Properties: { Description: !Select [ 1, !Split [ "|", !Sub "x|${DbPassword}|y" ] ] }
  KeyB64:
    Type: AWS::KMS::Key
    Properties: { Description: !Base64 { Ref: DbPassword } }
`

func TestCFN_NoEchoInResourcesStaysInSecrets(t *testing.T) {
	const secret = "n0echo-Pa55word"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0007")
	h.noecho = &noEchoSecrets{cs: h.cs.(*fake.Clientset), ns: shimNS}

	call := func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		w := serveWith(h, formOp(form), testUser)
		h.ops.drain(10 * time.Second)
		return w
	}
	if w := call(url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {noEchoIntoResourcesTmpl},
		"Parameters.member.1.ParameterKey": {"DbPassword"}, "Parameters.member.1.ParameterValue": {secret}}); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	rec, _ := recordIn(t, fa, "app")
	if rec == nil || rec.Status != "CREATE_COMPLETE" || len(rec.Resources) != 5 {
		t.Fatalf("want CREATE_COMPLETE with 5 resources: %+v", rec)
	}
	// The resolved properties do carry the value (that is why the record is a Secret) ...
	blob, _ := json.Marshal(rec.Resources)
	if !strings.Contains(string(blob), secret) || !strings.Contains(string(blob), b64) {
		t.Fatalf("the test template must feed the value into resource properties: %s", blob)
	}
	// ... and no ConfigMap holds it.
	fa.mu.Lock()
	for k, o := range fa.objs {
		if !strings.HasPrefix(k, "configmaps/") {
			continue
		}
		if b, _ := json.Marshal(o); strings.Contains(string(b), secret) || strings.Contains(string(b), b64) {
			fa.mu.Unlock()
			t.Fatalf("a NoEcho-derived value is in ConfigMap %s", k)
		}
	}
	fa.mu.Unlock()
	if fa.get("configmaps", opsNS, "cfn-stack-app") != nil {
		t.Fatal("the stack record must not be a ConfigMap")
	}
	for _, form := range []url.Values{
		{"Action": {"DescribeStacks"}, "StackName": {"app"}},
		{"Action": {"DescribeStacks"}},
		{"Action": {"DescribeStackResources"}, "StackName": {"app"}},
		{"Action": {"ListStacks"}},
		{"Action": {"GetTemplate"}, "StackName": {"app"}},
	} {
		w := call(form)
		if w.Code != http.StatusOK {
			t.Fatalf("%v: %d %s", form, w.Code, w.Body.String())
		}
		if b := w.Body.String(); strings.Contains(b, secret) || strings.Contains(b, b64) {
			t.Fatalf("%v returned the NoEcho value: %s", form, b)
		}
	}
}

// Records an earlier front door kept as ConfigMaps in the stack namespace are moved to the record store
// (labels, data and operation annotations kept) and the ConfigMaps removed; a stack another front door is
// still running is left until that front door settles it; a record moved before is not copied again.
func TestCFN_LegacyConfigMapRecordsMoved(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0008")
	ctx := context.Background()
	legacyCM := func(name string, labels map[string]any, ann map[string]any, data map[string]string) {
		md := map[string]any{"labels": labels}
		if ann != nil {
			md["annotations"] = ann
		}
		d := map[string]any{}
		for k, v := range data {
			d[k] = v
		}
		fa.put("configmaps", opsNS, name, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": md, "data": d})
	}
	stackJSON := func(rec cfn.StackRecord) string {
		rec.Namespace = opsNS
		b, _ := json.Marshal(rec)
		return string(b)
	}
	stackLabels := func(s string) map[string]any {
		return map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": s}
	}
	legacyCM("cfn-stack-settled", stackLabels("settled"), nil, map[string]string{"stack.json": stackJSON(cfn.StackRecord{Name: "settled",
		Status: "CREATE_COMPLETE", Resources: []cfn.StackResource{{LogicalID: "K", Kind: "EncryptionKey", Name: "k",
			Spec: map[string]any{"description": "derived-secret"}}}})})
	legacyCM("cfn-changeset-settled.cs1", map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/changeset": "settled"}, nil,
		map[string]string{"changeset.json": `{"stackName":"settled","name":"cs1","type":"UPDATE"}`})
	legacyCM("cfn-drift-settled", map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/drift": "settled"},
		map[string]any{"cfn.openinfra.dev/detection-id": "d1"}, map[string]string{"drift.json": `{"InSync":true}`, "detectionId": "d1", "stack": "settled"})
	fresh := map[string]any{annOpOwner: "aws-shim-old/0001", annOpRenewed: time.Now().UTC().Format(time.RFC3339Nano), annOpLease: "60", annOpAction: "UpdateStack"}
	legacyCM("cfn-stack-running", stackLabels("running"), fresh, map[string]string{"stack.json": stackJSON(cfn.StackRecord{Name: "running", Status: "UPDATE_IN_PROGRESS"})})
	stale := staleLease("aws-shim-old/0001", "CreateStack", alice)
	legacyCM("cfn-stack-orphan", stackLabels("orphan"), stale, map[string]string{"stack.json": stackJSON(cfn.StackRecord{Name: "orphan", Status: "CREATE_IN_PROGRESS"})})
	// Moved before (its ConfigMap's delete did not happen): the moved record is kept as it is.
	seedStack(fa, cfn.StackRecord{Name: "moved", Status: "UPDATE_COMPLETE"}, nil)
	legacyCM("cfn-stack-moved", stackLabels("moved"), nil, map[string]string{"stack.json": stackJSON(cfn.StackRecord{Name: "moved", Status: "CREATE_COMPLETE"})})
	legacyCM("unrelated", map[string]any{"app.kubernetes.io/managed-by": "cfn"}, nil, map[string]string{"x": "y"})

	h.migrateLegacyRecords(ctx)

	for _, name := range []string{"cfn-stack-settled", "cfn-changeset-settled.cs1", "cfn-drift-settled", "cfn-stack-orphan", "cfn-stack-moved"} {
		if fa.get("configmaps", opsNS, name) != nil {
			t.Errorf("%s must be moved off its ConfigMap", name)
		}
		if fa.get("secrets", shimNS, name) == nil {
			t.Errorf("%s must be in the record store", name)
		}
	}
	if fa.get("configmaps", opsNS, "cfn-stack-running") == nil || fa.get("secrets", shimNS, "cfn-stack-running") != nil {
		t.Error("a stack another front door is running is left where it is until it settles")
	}
	if fa.get("configmaps", opsNS, "unrelated") == nil {
		t.Error("a ConfigMap that is not a record is not touched")
	}
	rec, ann := recordIn(t, fa, "settled")
	if rec == nil || rec.Status != "CREATE_COMPLETE" || rec.Resources[0].Spec["description"] != "derived-secret" {
		t.Fatalf("the moved record keeps its content: %+v", rec)
	}
	if hasOpAnnotations(ann) {
		t.Fatalf("no lease appears from nowhere: %v", ann)
	}
	if _, ann := recordIn(t, fa, "orphan"); ann[annOpCaller] != callerJSON(alice) || ann[annOpOwner] != "aws-shim-old/0001" {
		t.Fatalf("a moved record keeps its operation annotations (recovery needs the caller): %v", ann)
	}
	if rec, _ := recordIn(t, fa, "moved"); rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("a record moved before is kept, not overwritten from its old ConfigMap: %+v", rec)
	}
	sec := &unstructured.Unstructured{Object: fa.get("secrets", shimNS, "cfn-drift-settled")}
	if shimRecords.value(sec, "detectionId") != "d1" || sec.GetAnnotations()["cfn.openinfra.dev/detection-id"] != "d1" {
		t.Fatalf("the drift record keeps its data and annotation: %v", sec.Object)
	}
	if cs, err := h.getChangeSet(ctx, "settled", "cs1"); err != nil || cs.Type != "UPDATE" {
		t.Fatalf("the moved change set is found: %v %+v", err, cs)
	}
	ap, _ := h.applierForIdentity(alice.User, alice.Groups)
	if rec, found, err := ap.GetStack(ctx, "settled"); err != nil || !found || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("the engine reads the moved record: %v %v %+v", err, found, rec)
	}
}
