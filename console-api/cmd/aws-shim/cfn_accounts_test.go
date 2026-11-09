package main

// Each account's CloudFormation stacks are its own (cfn_accounts.go): a member account's stack keeps its
// resources in its home, its records under its own names, and a StackId naming its account; the management
// account's stacks are exactly what they were, and neither account lists, reads or changes the other's.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// bobClaims is the member account's bob, as the router authenticates him.
var bobClaims = iam.Claims{Sub: "bob", Account: testMember}

// memberCFNCall calls the CloudFormation front door as the member account's bob, as the router does: the
// request carries the member account's identity and home, and is marked account-scoped.
func memberCFNCall(t *testing.T, h *cfnDoorway, form url.Values) (int, string) {
	t.Helper()
	w := serveWith(h, formOp(form).WithContext(inAccountScope(memberCtx())), bobClaims)
	return w.Code, w.Body.String()
}

// objNames are the names of the fake API's objects of resource res in namespace ns, sorted. (A stack's
// AWS::KMS::Key, with no KMS API, is a kind: EncryptionKey, which the test doorway's mapper resolves to the
// resource "encryptionkeies".)
func (f *fakeAPI) objNames(res, ns string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.objs {
		if strings.HasPrefix(k, res+"/"+ns+"/") {
			out = append(out, strings.TrimPrefix(k, res+"/"+ns+"/"))
		}
	}
	sort.Strings(out)
	return out
}

// recordOf decodes a stored record object's stack.json.
func storedRecord(t *testing.T, o map[string]any) *cfn.StackRecord {
	t.Helper()
	if o == nil {
		return nil
	}
	rec, ok := shimRecords.stackRecord(&unstructured.Unstructured{Object: o})
	if !ok {
		t.Fatalf("record unreadable: %v", o)
	}
	return rec
}

func listedStacks(t *testing.T, body string) stackSummariesXML {
	t.Helper()
	var s stackSummariesXML
	if err := xml.Unmarshal([]byte(body), &s); err != nil {
		t.Fatalf("ListStacks: %v %s", err, body)
	}
	return s
}

func TestCFNAccounts_EachAccountKeepsItsOwnStacks(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim/0001")
	h.noecho = &noEchoSecrets{cs: k8sfake.NewSimpleClientset(), ns: shimNS}

	// The management account's stack, made before any member account's, exactly as it always was.
	code, body := cfnCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {deletedTmpl}})
	if code != 200 {
		t.Fatalf("management CreateStack: %d %s", code, body)
	}
	mgmtID := createdStackID(t, body)
	h.ops.drain(10 * time.Second)
	if !strings.HasPrefix(mgmtID, "arn:aws:cloudformation:us-east-1:000000000000:stack/app/") {
		t.Fatalf("the management account's StackId: %s", mgmtID)
	}
	mgmtRecord := fa.get("secrets", shimNS, "cfn-stack-app")
	mgmtKeys := fa.objNames("encryptionkeies", opsNS)
	if mgmtRecord == nil || len(mgmtKeys) == 0 {
		t.Fatalf("the management account's stack: record %v, keys %v", mgmtRecord != nil, mgmtKeys)
	}
	if _, labelled := mgmtRecord["metadata"].(map[string]any)["labels"].(map[string]any)[labelRecordAccount]; labelled {
		t.Fatal("the management account's record must carry no account label")
	}

	// The member account makes a stack of the same name: its own.
	h.authz = doorAccountsAuthz(t)
	code, body = memberCFNCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {deletedTmpl}})
	if code != 200 {
		t.Fatalf("member CreateStack of a name the management account has: %d %s", code, body)
	}
	memberID := createdStackID(t, body)
	h.ops.drain(10 * time.Second)
	if !strings.HasPrefix(memberID, "arn:aws:cloudformation:us-east-1:"+testMember+":stack/app/") {
		t.Fatalf("a member account's StackId names its account: %s", memberID)
	}
	mrec := storedRecord(t, fa.get("secrets", shimNS, testMember+"-cfn-stack-app"))
	if mrec == nil || mrec.Status != "CREATE_COMPLETE" || mrec.Namespace != memberHome || mrec.StackID != memberID {
		t.Fatalf("the member account's record, kept under its own name: %+v", mrec)
	}
	if l := (&unstructured.Unstructured{Object: fa.get("secrets", shimNS, testMember+"-cfn-stack-app")}).GetLabels(); l[labelRecordAccount] != testMember {
		t.Fatalf("the member account's record is labelled with its account: %v", l)
	}
	if keys := fa.objNames("encryptionkeies", memberHome); len(keys) == 0 {
		t.Fatal("the member account's stack resources are in its home")
	}
	if got := fa.objNames("encryptionkeies", opsNS); !reflect.DeepEqual(got, mgmtKeys) {
		t.Fatalf("the management account's namespace changed: %v, was %v", got, mgmtKeys)
	}
	if got := fa.get("secrets", shimNS, "cfn-stack-app"); !reflect.DeepEqual(got, mgmtRecord) {
		t.Fatal("the management account's record changed when a member account made a stack of its name")
	}
	if c := fa.created[testMember+"-cfn-stack-app"][annOpCaller]; !strings.Contains(c.(string), `"account":"`+testMember+`"`) ||
		!strings.Contains(c.(string), "openinfra:"+testMember+":bob") {
		t.Fatalf("the member account's operation records its caller and account: %v", c)
	}

	// Each account describes and lists its own stack alone.
	describe := func(call func(*testing.T, *cfnDoorway, url.Values) (int, string), ref string) (int, describedXML, string) {
		code, body := call(t, h, url.Values{"Action": {"DescribeStacks"}, "StackName": {ref}})
		var d describedXML
		_ = xml.Unmarshal([]byte(body), &d)
		return code, d, body
	}
	if code, d, raw := describe(memberCFNCall, "app"); code != 200 || len(d.Stacks) != 1 || d.Stacks[0].StackID != memberID ||
		len(d.Stacks[0].Outputs) != 1 || d.Stacks[0].Outputs[0].OutputValue != memberID {
		t.Fatalf("member DescribeStacks app: %d %s", code, raw)
	}
	if code, d, raw := describe(cfnCall, "app"); code != 200 || len(d.Stacks) != 1 || d.Stacks[0].StackID != mgmtID {
		t.Fatalf("management DescribeStacks app: %d %s", code, raw)
	}
	if code, _, raw := describe(memberCFNCall, mgmtID); code != 400 || !strings.Contains(raw, "does not exist") {
		t.Fatalf("a member account names the management account's StackId: %d %s", code, raw)
	}
	if code, _, raw := describe(cfnCall, memberID); code != 400 || !strings.Contains(raw, "does not exist") {
		t.Fatalf("the management account names a member account's StackId: %d %s", code, raw)
	}
	for who, call := range map[string]func(*testing.T, *cfnDoorway, url.Values) (int, string){"member": memberCFNCall, "management": cfnCall} {
		want := map[string]string{"member": memberID, "management": mgmtID}[who]
		_, body := call(t, h, url.Values{"Action": {"ListStacks"}})
		s := listedStacks(t, body)
		if len(s.Members) != 1 || s.Members[0].StackID != want {
			t.Fatalf("%s ListStacks lists its own stack alone: %s", who, body)
		}
		_, body = call(t, h, url.Values{"Action": {"DescribeStacks"}})
		var d describedXML
		_ = xml.Unmarshal([]byte(body), &d)
		if len(d.Stacks) != 1 || d.Stacks[0].StackID != want {
			t.Fatalf("%s DescribeStacks (every stack) lists its own alone: %s", who, body)
		}
	}

	// A change set: its ARN names its account, its record and NoEcho values are its account's own.
	csTmpl := "Parameters:\n  Pw: { Type: String, NoEcho: true }\nResources:\n  Key:\n    Type: AWS::KMS::Key\n    Properties: { Description: k2 }\n"
	csForm := func() url.Values {
		return url.Values{"Action": {"CreateChangeSet"}, "StackName": {"app"}, "ChangeSetName": {"cs1"}, "TemplateBody": {csTmpl},
			"Parameters.member.1.ParameterKey": {"Pw"}}
	}
	mf := csForm()
	mf.Set("Parameters.member.1.ParameterValue", "member-secret")
	code, body = memberCFNCall(t, h, mf)
	if code != 200 || !strings.Contains(body, "arn:aws:cloudformation:us-east-1:"+testMember+":changeSet/cs1/") {
		t.Fatalf("member CreateChangeSet: %d %s", code, body)
	}
	gf := csForm()
	gf.Set("Parameters.member.1.ParameterValue", "mgmt-secret")
	if code, body = cfnCall(t, h, gf); code != 200 || !strings.Contains(body, "arn:aws:cloudformation:us-east-1:000000000000:changeSet/cs1/") {
		t.Fatalf("management CreateChangeSet: %d %s", code, body)
	}
	if fa.get("secrets", shimNS, testMember+"-cfn-changeset-app.cs1") == nil || fa.get("secrets", shimNS, "cfn-changeset-app.cs1") == nil {
		t.Fatalf("each account's change set is its own record: %v", fa.objNames("secrets", shimNS))
	}
	memberCtx := inAccountScope(memberCtx())
	if v, _ := h.noecho.get(memberCtx, changeSetCMName("app", "cs1")); v["Pw"] != "member-secret" {
		t.Fatalf("the member account's NoEcho value: %v", v)
	}
	if v, _ := h.noecho.get(context.Background(), changeSetCMName("app", "cs1")); v["Pw"] != "mgmt-secret" {
		t.Fatalf("the management account's NoEcho value: %v", v)
	}

	// The member account deletes its stack: the management account's stack, records and values stay.
	if code, body := memberCFNCall(t, h, url.Values{"Action": {"DeleteStack"}, "StackName": {"app"}}); code != 200 {
		t.Fatalf("member DeleteStack: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	if fa.get("secrets", shimNS, testMember+"-cfn-stack-app") != nil || len(fa.objNames("encryptionkeies", memberHome)) != 0 {
		t.Fatal("the member account's stack was not deleted")
	}
	if got := fa.objNames("encryptionkeies", opsNS); !reflect.DeepEqual(got, mgmtKeys) {
		t.Fatalf("a member account's delete touched the management account's namespace: %v", got)
	}
	if fa.get("secrets", shimNS, "cfn-stack-app") == nil || fa.get("secrets", shimNS, "cfn-changeset-app.cs1") == nil {
		t.Fatal("a member account's delete removed the management account's records")
	}
	if v, _ := h.noecho.get(context.Background(), changeSetCMName("app", "cs1")); v["Pw"] != "mgmt-secret" {
		t.Fatalf("a member account's delete removed the management account's NoEcho values: %v", v)
	}
	if v, _ := h.noecho.get(memberCtx, changeSetCMName("app", "cs1")); len(v) != 0 {
		t.Fatalf("the member account's NoEcho values outlived its stack: %v", v)
	}
	_, body = memberCFNCall(t, h, url.Values{"Action": {"ListStacks"}})
	if s := listedStacks(t, body); len(s.Members) != 1 || s.Members[0].StackID != memberID || s.Members[0].StackStatus != "DELETE_COMPLETE" {
		t.Fatalf("the member account lists its deleted stack: %s", body)
	}
	if code, d, raw := describe(memberCFNCall, memberID); code != 200 || len(d.Stacks) != 1 || d.Stacks[0].StackStatus != "DELETE_COMPLETE" {
		t.Fatalf("the member account describes its deleted stack by its StackId: %d %s", code, raw)
	}
	_, body = cfnCall(t, h, url.Values{"Action": {"ListStacks"}})
	if s := listedStacks(t, body); len(s.Members) != 1 || s.Members[0].StackID != mgmtID || s.Members[0].StackStatus != "CREATE_COMPLETE" {
		t.Fatalf("the management account lists its own stack alone, never a member account's deleted one: %s", body)
	}
	if code, _, raw := describe(cfnCall, memberID); code != 400 {
		t.Fatalf("the management account read a member account's deleted stack: %d %s", code, raw)
	}

	// The member account re-creates its stack: a new one, while the management account's is untouched.
	if code, body = memberCFNCall(t, h, url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {deletedTmpl}}); code != 200 {
		t.Fatalf("member re-CreateStack: %d %s", code, body)
	}
	h.ops.drain(10 * time.Second)
	if again := createdStackID(t, body); again == memberID || !strings.Contains(again, ":"+testMember+":") {
		t.Fatalf("the re-created stack's StackId: %s", again)
	}
}

// A member account without a home namespace has nowhere to keep stacks: refused before anything is written.
func TestCFNAccounts_MemberWithoutHomeRefused(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim/0001")
	h.authz = doorAccountsAuthz(t)
	ctx := inAccountScope(withAccount(context.Background(), testMember, ""))
	w := serveWith(h, formOp(url.Values{"Action": {"CreateStack"}, "StackName": {"app"}, "TemplateBody": {deletedTmpl}}).WithContext(ctx), bobClaims)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a member account with no home: %d %s", w.Code, w.Body.String())
	}
	// Its stacks would have no namespace: an applier for it reaches none.
	ap, err := h.applierForIn(ctx, bobClaims)
	if err != nil || !strings.Contains(ap.ns, "no-home") {
		t.Fatalf("a member account with no home gets a namespace that names none: %v %+v", err, ap)
	}
	if names := fa.objNames("secrets", shimNS); len(names) != 0 {
		t.Fatalf("nothing is written: %v", names)
	}
}

// seedMemberStack writes a member account's stack record as its stack operation would have left it: under
// the member account's record name and label.
func seedMemberStack(fa *fakeAPI, rec cfn.StackRecord, ann map[string]any) {
	data, _ := json.Marshal(rec)
	md := map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": rec.Name,
		labelRecordAccount: testMember}}
	if ann != nil {
		md["annotations"] = ann
	}
	fa.put("secrets", shimNS, testMember+"-cfn-stack-"+rec.Name, map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": md, "data": map[string]any{"stack.json": base64.StdEncoding.EncodeToString(data)}})
}

func memberStackID(name string) string {
	return "arn:aws:cloudformation:us-east-1:" + testMember + ":stack/" + name + "/0b1c2d3e-0000-4000-8000-000000000001"
}

// An interrupted member-account stack operation is recovered in the member account: under its recorded
// caller (of that account), in its home, its own record settled — the management account's stack of the
// same name, in progress too, is recovered in its own account, each by its own caller.
func TestCFNAccounts_RecoveryActsInTheStacksAccount(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	h.accounts = testDirectory()
	bob := &recordedCaller{User: "openinfra:" + testMember + ":bob", Account: testMember}
	vol := dataVolRes
	seedMemberStack(fa, cfn.StackRecord{Name: "app", Namespace: memberHome, StackID: memberStackID("app"), Status: "CREATE_IN_PROGRESS",
		UpdatedAt: "2026-10-31T09:00:00Z", Resources: []cfn.StackResource{vol}}, staleLease("aws-shim-old/0001", "CreateStack", bob))
	fa.put("volumes", memberHome, "data", map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "Volume",
		"metadata": map[string]any{"labels": map[string]any{"cfn.openinfra.dev/stack": "app", "app.kubernetes.io/managed-by": "cfn"}},
		"spec":     map[string]any{"size": "10Gi"}})
	seedStack(fa, cfn.StackRecord{Name: "app", Status: "CREATE_IN_PROGRESS", UpdatedAt: "2026-10-31T09:00:00Z",
		Resources: []cfn.StackResource{vol}}, staleLease("aws-shim-old/0001", "CreateStack", alice))
	liveObject(fa, "volumes", "Volume", "data", "app", map[string]any{"size": "10Gi"})

	h.recoverOrphans(context.Background())
	h.ops.drain(10 * time.Second)

	mrec := storedRecord(t, fa.get("secrets", shimNS, testMember+"-cfn-stack-app"))
	if mrec == nil || mrec.Status != "ROLLBACK_COMPLETE" || !strings.Contains(mrec.Message, "interrupted") {
		t.Fatalf("the member account's interrupted create is rolled back in its account: %+v", mrec)
	}
	if fa.get("volumes", memberHome, "data") != nil {
		t.Error("the member account's resource (in its home) was not rolled back")
	}
	grec, _ := recordIn(t, fa, "app")
	if grec == nil || grec.Status != "ROLLBACK_COMPLETE" || fa.get("volumes", opsNS, "data") != nil {
		t.Fatalf("the management account's interrupted create is rolled back in its own account: %+v", grec)
	}
	callers := strings.Join(fa.callerLog(), " ")
	if !strings.Contains(callers, "openinfra:"+testMember+":bob|") || !strings.Contains(callers, alice.User+"|") {
		t.Fatalf("each stack is rolled back as its own account's recorded caller: %v", fa.callerLog())
	}
}

// A member account's record never runs under a caller of another account, nor in another account than its
// StackId names: the first is settled without any authority, the second left alone.
func TestCFNAccounts_RecoveryNeverCrossesAccounts(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	h.accounts = testDirectory()
	// A member account's record whose recorded caller is the management account's alice.
	seedMemberStack(fa, cfn.StackRecord{Name: "borrowed", Namespace: memberHome, StackID: memberStackID("borrowed"), Status: "CREATE_IN_PROGRESS",
		UpdatedAt: "2026-10-31T09:00:00Z", Resources: []cfn.StackResource{dataVolRes}}, staleLease("aws-shim-old/0001", "CreateStack", alice))
	// A member account's record whose StackId names the management account.
	seedMemberStack(fa, cfn.StackRecord{Name: "misfiled", Namespace: memberHome,
		StackID: "arn:aws:cloudformation:us-east-1:000000000000:stack/misfiled/0b1c2d3e-0000-4000-8000-000000000002", Status: "CREATE_IN_PROGRESS",
		UpdatedAt: "2026-10-31T09:00:00Z"}, staleLease("aws-shim-old/0001", "CreateStack", &recordedCaller{User: "openinfra:" + testMember + ":bob", Account: testMember}))

	h.recoverOrphans(context.Background())
	h.ops.drain(10 * time.Second)

	if rec := storedRecord(t, fa.get("secrets", shimNS, testMember+"-cfn-stack-borrowed")); rec == nil || rec.Status != "ROLLBACK_FAILED" {
		t.Fatalf("a record carrying another account's caller is settled without authority: %+v", rec)
	}
	if rec := storedRecord(t, fa.get("secrets", shimNS, testMember+"-cfn-stack-misfiled")); rec == nil || rec.Status != "CREATE_IN_PROGRESS" {
		t.Fatalf("a record whose StackId names another account is left alone: %+v", rec)
	}
	if callers := fa.callerLog(); len(callers) != 0 {
		t.Fatalf("no recovery ran under any caller: %v", callers)
	}
}

// An asynchronous member-account operation acts in its account from start to finish: the record it seeds,
// the lease it holds and releases, the resources it creates — all its account's.
func TestCFNAccounts_AsyncOperationKeepsItsAccount(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim/0001")
	h.authz = doorAccountsAuthz(t)
	r := formOp(url.Values{"StackName": {"svc"}, "TemplateBody": {deletedTmpl}}).WithContext(inAccountScope(memberCtx()))
	_ = r.ParseForm()
	ap, err := h.applierForIn(r.Context(), bobClaims)
	if err != nil {
		t.Fatal(err)
	}
	if ap.ns != memberHome || ap.account != testMember || ap.records.account != testMember {
		t.Fatalf("the member account's applier: ns %s account %s records %s", ap.ns, ap.account, ap.records.account)
	}
	w := httptest.NewRecorder()
	h.createStack(w, r, ap, "req")
	if w.Code != 200 {
		t.Fatalf("CreateStack: %d %s", w.Code, w.Body.String())
	}
	if !h.ops.isLive(testMember+":svc") && fa.get("secrets", shimNS, testMember+"-cfn-stack-svc") == nil {
		t.Fatal("the operation is tracked under the member account's key")
	}
	h.ops.drain(10 * time.Second)
	rec, _, _ := (&impersonatingApplier{records: ap.records}).GetStack(context.Background(), "svc")
	o := fa.get("secrets", shimNS, testMember+"-cfn-stack-svc")
	if rec == nil || rec.Status != "CREATE_COMPLETE" || o == nil || hasOpAnnotations(anyStringMap((&unstructured.Unstructured{Object: o}).GetAnnotations())) {
		t.Fatalf("the operation settles the member account's record and releases its lease: %+v", rec)
	}
	if fa.get("secrets", shimNS, "cfn-stack-svc") != nil || len(fa.objNames("encryptionkeies", opsNS)) != 0 {
		t.Fatal("the member account's operation wrote into the management account")
	}
	if len(fa.objNames("encryptionkeies", memberHome)) == 0 {
		t.Fatal("the member account's resources are in its home")
	}
}

func anyStringMap(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// The record store's account view: a member account's records are named and labelled its own, read back by
// their names within the account, and listed only to it; the management account's listing never includes
// them, and a member account's never another account's.
func TestCFNAccounts_RecordStoreKeepsAccountsApart(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{secretGVR: "SecretList"})
	ctx := context.Background()
	mgmt := recordStore{dyn: dyn, ns: shimNS, secret: true}
	member := mgmt
	member.account = testMember
	other := mgmt
	other.account = "923456789012"
	labels := map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": "app"}
	for _, st := range []recordStore{mgmt, member, other} {
		obj := st.object("cfn-stack-app", labels, nil, map[string]string{"stack.json": `{"name":"app","status":"` + st.account + `"}`})
		if _, err := st.client().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := mgmt.rawClient().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var stored []string
	for _, u := range raw.Items {
		stored = append(stored, u.GetName())
	}
	sort.Strings(stored)
	if want := []string{testMember + "-cfn-stack-app", "923456789012-cfn-stack-app", "cfn-stack-app"}; !reflect.DeepEqual(stored, want) {
		t.Fatalf("stored names: %v, want %v", stored, want)
	}
	for name, st := range map[string]recordStore{"management": mgmt, "member": member, "other member": other} {
		u, err := st.client().Get(ctx, "cfn-stack-app", metav1.GetOptions{})
		if err != nil || u.GetName() != "cfn-stack-app" || st.value(u, "stack.json") != `{"name":"app","status":"`+st.account+`"}` {
			t.Fatalf("%s reads its own record by its name: %v %v", name, err, u)
		}
		list, err := st.client().List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
		if err != nil || len(list.Items) != 1 || list.Items[0].GetName() != "cfn-stack-app" ||
			st.value(&list.Items[0], "stack.json") != `{"name":"app","status":"`+st.account+`"}` {
			t.Fatalf("%s lists its own record alone: %v %+v", name, err, list)
		}
	}
	// A member account cannot reach the management account's record (nor another's) by any name.
	if _, err := member.client().Get(ctx, "../cfn-stack-app", metav1.GetOptions{}); err == nil {
		t.Fatal("a member account's name reached a record that is not its own")
	}
	if err := member.client().Delete(ctx, "cfn-stack-app", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgmt.client().Get(ctx, "cfn-stack-app", metav1.GetOptions{}); err != nil {
		t.Fatal("a member account's delete removed the management account's record")
	}
	if _, err := other.client().Get(ctx, "cfn-stack-app", metav1.GetOptions{}); err != nil {
		t.Fatal("a member account's delete removed another member's record")
	}
}

// A stack reads a TemplateURL from a bucket its account may read, as on AWS: a member account's stack its
// own account's bucket, never another account's that no bucket policy opens to it; the management
// account's caller keeps the S3 gate it always had on its own buckets.
func TestCFNAccounts_TemplateURLIsReadInTheBucketsAccount(t *testing.T) {
	s3h, _, _ := s3AccountsFixture(t)
	h := &cfnDoorway{s3: s3h, authz: doorAccountsAuthz(t)}
	member := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(inAccountScope(memberCtx()))
	if denied, reason := h.s3ReadDenied(member, s3Bob, "team-data", "templates/app.yaml"); denied {
		t.Fatalf("a member account's stack reads a template from its own bucket: %s", reason)
	}
	if denied, _ := h.s3ReadDenied(member, s3Bob, "mgmt-data", "templates/app.yaml"); !denied {
		t.Fatal("a member account's stack read a template from another account's bucket with no bucket policy")
	}
	mgmt := httptest.NewRequest(http.MethodPost, "/", nil)
	if denied, reason := h.s3ReadDenied(mgmt, s3Alice, "mgmt-data", "templates/app.yaml"); denied {
		t.Fatalf("the management account reads a template from its own bucket: %s", reason)
	}
	if denied, _ := h.s3ReadDenied(mgmt, s3Alice, "team-data", "templates/app.yaml"); !denied {
		t.Fatal("the management account read a template from a member account's bucket with no bucket policy")
	}
}

// A deploy reads its Lambda packages (and nested stacks' templates) after its request, on a context of its
// own: the caller is still decided as its account's principal there. A member account's stack reads its
// package from its own bucket, as the S3 API lets the same caller, and still not another account's (#419).
func TestCFNAccounts_ADeploysOwnContextKeepsTheCallersAccount(t *testing.T) {
	s3h, _, _ := s3AccountsFixture(t)
	h := &cfnDoorway{s3: s3h, authz: doorAccountsAuthz(t)}
	req := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(inAccountScope(memberCtx()))
	bare, cancel := context.WithTimeout(context.Background(), time.Minute) // as cfn's resolvePackage makes it
	defer cancel()
	r := onBehalfOf(bare, req, s3Bob)
	if denied, reason := h.s3ReadDenied(r, s3Bob, "team-data", "packages/fn.zip"); denied {
		t.Fatalf("a member account's deploy reads its package from its own bucket: %s", reason)
	}
	if denied, _ := h.s3ReadDenied(r, s3Bob, "mgmt-data", "packages/fn.zip"); !denied {
		t.Fatal("a member account's deploy read a package from another account's bucket with no bucket policy")
	}
	// What the deploy did before: the request cloned onto the bare context loses the caller's account,
	// and the caller is decided as no principal (the refusal #419 reported).
	if denied, _ := h.s3ReadDenied(withCallerClaims(req.Clone(bare), s3Bob), s3Bob, "team-data", "packages/fn.zip"); !denied {
		t.Fatal("the request without its account was allowed: this test no longer shows what onBehalfOf adds")
	}
	if p := principalOf(r.Context(), s3Bob); p.ID != memberHome+"/bob" {
		t.Errorf("the deploy's principal is %q, want the member account's bob", p.ID)
	}
	// The management account's caller is unchanged.
	mgmt := onBehalfOf(bare, httptest.NewRequest(http.MethodPost, "/", nil), s3Alice)
	if denied, reason := h.s3ReadDenied(mgmt, s3Alice, "mgmt-data", "packages/fn.zip"); denied {
		t.Fatalf("the management account's deploy reads its own bucket: %s", reason)
	}
}
