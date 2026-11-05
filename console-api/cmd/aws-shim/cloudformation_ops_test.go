package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// #347: a stack operation interrupted by a front-door restart is failed and rolled back by the next front
// door (under the operation's recorded caller) instead of staying *_IN_PROGRESS forever.

// fakeAPI is a small API server for these tests: objects carry resourceVersions, a merge patch that names
// a resourceVersion is a precondition (409 on mismatch), and server-side apply leaves annotations it does
// not set alone (they belong to another field manager — the lease's). Every object but a ConfigMap or a
// Secret reports status.ready (its controller "reconciled" it). Errors can be injected for merge patches.
type fakeAPI struct {
	mu          sync.Mutex
	rv          int
	objs        map[string]map[string]any // resource/namespace/name -> object
	failPatches bool                      // merge patches fail (cluster unreachable for the lease)
	created     map[string]map[string]any // record (ConfigMap or Secret) name -> annotations it was CREATED with
	callers     []string                  // identities a caller client was built for
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{objs: map[string]map[string]any{}, created: map[string]map[string]any{}}
}

func fkey(res, ns, name string) string { return res + "/" + ns + "/" + name }

func jsonCopy(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func (f *fakeAPI) store(res, ns, name string, obj map[string]any) {
	f.rv++
	md, _ := obj["metadata"].(map[string]any)
	if md == nil {
		md = map[string]any{}
		obj["metadata"] = md
	}
	md["name"], md["namespace"], md["resourceVersion"] = name, ns, strconv.Itoa(f.rv)
	if res != "configmaps" && res != "secrets" {
		obj["status"] = map[string]any{"ready": true}
	}
	f.objs[fkey(res, ns, name)] = obj
}

func (f *fakeAPI) react(a k8stesting.Action) (bool, runtime.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	res, ns := a.GetResource().Resource, a.GetNamespace()
	gr := a.GetResource().GroupResource()
	// Dispatch on the verb: the action interfaces overlap (a PatchAction is also a GetAction).
	switch a.GetVerb() {
	case "get":
		act := a.(k8stesting.GetAction)
		o, ok := f.objs[fkey(res, ns, act.GetName())]
		if !ok {
			return true, nil, apierrors.NewNotFound(gr, act.GetName())
		}
		return true, &unstructured.Unstructured{Object: jsonCopy(o)}, nil
	case "list":
		list := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": "v1", "kind": "List"}}
		for k, o := range f.objs {
			if strings.HasPrefix(k, res+"/"+ns+"/") {
				list.Items = append(list.Items, unstructured.Unstructured{Object: jsonCopy(o)})
			}
		}
		return true, list, nil
	case "create":
		u := a.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		if _, ok := f.objs[fkey(res, ns, u.GetName())]; ok {
			return true, nil, apierrors.NewAlreadyExists(gr, u.GetName())
		}
		obj := jsonCopy(u.Object)
		if res == "configmaps" || res == "secrets" {
			f.created[u.GetName()] = jsonCopy(u.GetAnnotations())
		}
		f.store(res, ns, u.GetName(), obj)
		return true, &unstructured.Unstructured{Object: jsonCopy(obj)}, nil
	case "delete":
		act := a.(k8stesting.DeleteAction)
		if _, ok := f.objs[fkey(res, ns, act.GetName())]; !ok {
			return true, nil, apierrors.NewNotFound(gr, act.GetName())
		}
		delete(f.objs, fkey(res, ns, act.GetName()))
		return true, nil, nil
	case "patch":
		act := a.(k8stesting.PatchAction)
		k := fkey(res, ns, act.GetName())
		var patch map[string]any
		if err := json.Unmarshal(act.GetPatch(), &patch); err != nil {
			return true, nil, err
		}
		existing, exists := f.objs[k]
		switch act.GetPatchType() {
		case types.ApplyPatchType: // create-or-update; annotations this apply doesn't set survive
			if exists {
				if ann, ok := existing["metadata"].(map[string]any)["annotations"]; ok {
					md, _ := patch["metadata"].(map[string]any)
					if _, set := md["annotations"]; !set {
						md["annotations"] = ann
					}
				}
			}
			f.store(res, ns, act.GetName(), patch)
			return true, &unstructured.Unstructured{Object: jsonCopy(patch)}, nil
		case types.MergePatchType: // annotations only; never creates; resourceVersion = precondition
			if !exists {
				return true, nil, apierrors.NewNotFound(gr, act.GetName())
			}
			if f.failPatches {
				return true, nil, apierrors.NewInternalError(io.ErrUnexpectedEOF)
			}
			pmd, _ := patch["metadata"].(map[string]any)
			emd := existing["metadata"].(map[string]any)
			if rv, ok := pmd["resourceVersion"].(string); ok && rv != emd["resourceVersion"] {
				return true, nil, apierrors.NewConflict(gr, act.GetName(), io.EOF)
			}
			ann, _ := emd["annotations"].(map[string]any)
			if ann == nil {
				ann = map[string]any{}
			}
			pann, _ := pmd["annotations"].(map[string]any)
			for ak, av := range pann {
				if av == nil {
					delete(ann, ak)
				} else {
					ann[ak] = av
				}
			}
			emd["annotations"] = ann
			f.store(res, ns, act.GetName(), existing)
			return true, &unstructured.Unstructured{Object: jsonCopy(existing)}, nil
		}
	}
	return true, nil, nil
}

// get returns a copy of an object (nil if absent).
func (f *fakeAPI) get(res, ns, name string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.objs[fkey(res, ns, name)]; ok {
		return jsonCopy(o)
	}
	return nil
}

func (f *fakeAPI) put(res, ns, name string, obj map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store(res, ns, name, jsonCopy(obj))
}

func (f *fakeAPI) setFailPatches(v bool) {
	f.mu.Lock()
	f.failPatches = v
	f.mu.Unlock()
}

func (f *fakeAPI) callerLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.callers...)
}

const opsNS = "open-infra-cfn"

// shimNS is the shim's own namespace, where the front door keeps its records (Secrets).
const shimNS = "open-infra-aws-shim"

// shimRecords is the record store the test doorways use: Secrets in shimNS, as in a cluster.
var shimRecords = recordStore{ns: shimNS, secret: true}

// The doorway's applier reads labels, so recovery's rollback deletes only this stack's objects.
var _ cfn.LabelReader = (*impersonatingApplier)(nil)

// opsDoorway is a doorway (one "front door" process, identified by owner) over a shared fakeAPI.
func opsDoorway(t *testing.T, fa *fakeAPI, owner string) *cfnDoorway {
	t.Helper()
	gvrs := map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "configmaps"}:                             "ConfigMapList",
		{Version: "v1", Resource: "secrets"}:                                "SecretList",
		{Group: "openinfra.dev", Version: "v1", Resource: "volumes"}:        "VolumeList",
		{Group: "openinfra.dev", Version: "v1", Resource: "encryptionkeys"}: "EncryptionKeyList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrs)
	dyn.PrependReactor("*", "*", fa.react)
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Version: "v1"}, {Group: "openinfra.dev", Version: "v1"}})
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, meta.RESTScopeNamespace)
	for _, k := range []string{"Volume", "EncryptionKey"} {
		mapper.Add(schema.GroupVersionKind{Group: "openinfra.dev", Version: "v1", Kind: k}, meta.RESTScopeNamespace)
	}
	h := &cfnDoorway{shimDyn: dyn, mapper: mapper, ns: opsNS, account: "000000000000", region: "us-east-1",
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)), cs: csWithSAR(true), authzNS: "default", recNS: shimNS}
	h.ops.owner = owner
	h.callerDyn = func(user string, groups []string) (dynamic.Interface, error) {
		fa.mu.Lock()
		fa.callers = append(fa.callers, user+"|"+strings.Join(groups, ","))
		fa.mu.Unlock()
		return dyn, nil
	}
	t.Cleanup(func() {
		if !h.ops.drain(10 * time.Second) {
			t.Errorf("stack operations still running at test end: %v", h.ops.running())
		}
	})
	return h
}

var alice = &recordedCaller{User: "openinfra:alice", Groups: []string{"openinfra:powerusers", "openinfra:users"}}

func callerJSON(c *recordedCaller) string {
	b, _ := json.Marshal(c)
	return string(b)
}

// seedStack writes a stack record as a front door would have left it, with the given operation
// annotations (nil = a record from before leases).
func seedStack(fa *fakeAPI, rec cfn.StackRecord, ann map[string]any) {
	rec.Namespace = opsNS
	data, _ := json.Marshal(rec)
	md := map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": rec.Name}}
	if ann != nil {
		md["annotations"] = ann
	}
	fa.put("secrets", shimNS, "cfn-stack-"+rec.Name, map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": md, "data": map[string]any{"stack.json": base64.StdEncoding.EncodeToString(data)}})
}

// staleLease is the annotations a front door that stopped 5 minutes ago left behind.
func staleLease(owner, action string, c *recordedCaller) map[string]any {
	ann := map[string]any{annOpOwner: owner, annOpRenewed: time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339Nano),
		annOpLease: "60", annOpAction: action}
	if c != nil {
		ann[annOpCaller] = callerJSON(c)
	}
	return ann
}

// liveObject seeds a stack resource object labeled for stack.
func liveObject(fa *fakeAPI, res, kind, name, stack string, spec map[string]any) {
	fa.put(res, opsNS, name, map[string]any{"apiVersion": "openinfra.dev/v1", "kind": kind,
		"metadata": map[string]any{"labels": map[string]any{"cfn.openinfra.dev/stack": stack, "app.kubernetes.io/managed-by": "cfn"}},
		"spec":     spec})
}

func recordIn(t *testing.T, fa *fakeAPI, stack string) (*cfn.StackRecord, map[string]any) {
	t.Helper()
	o := fa.get("secrets", shimNS, "cfn-stack-"+stack)
	if o == nil {
		return nil, nil
	}
	u := &unstructured.Unstructured{Object: o}
	rec, ok := shimRecords.stackRecord(u)
	if !ok {
		t.Fatalf("record %s unreadable: %v", stack, o)
	}
	ann := map[string]any{}
	for k, v := range u.GetAnnotations() {
		ann[k] = v
	}
	return rec, ann
}

func hasOpAnnotations(ann map[string]any) bool {
	for _, k := range opAnnotations {
		if _, ok := ann[k]; ok {
			return true
		}
	}
	return false
}

var (
	sharedKeyRes = cfn.StackResource{LogicalID: "Data/ebs-default", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey",
		Name: "ebs-default", DeletionPolicy: "Retain", Spec: map[string]any{"rotationDays": float64(365)}}
	dataVolRes = cfn.StackResource{LogicalID: "Data", APIVersion: "openinfra.dev/v1", Kind: "Volume", Name: "data",
		Spec: map[string]any{"size": "10Gi", "encryptionKey": "ebs-default"}}
)

// The observed failure: CreateStack running when the front door was replaced — the record says
// CREATE_IN_PROGRESS, a Volume and the shared default EncryptionKey exist, and the owner's lease stopped
// being renewed. The next front door rolls the create back under the RECORDED caller, keeps the Retain key,
// and settles ROLLBACK_COMPLETE naming the interruption.
func TestCFNRecovery_InterruptedCreate_RolledBack(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	seedStack(fa, cfn.StackRecord{Name: "app", Status: "CREATE_IN_PROGRESS", UpdatedAt: "2026-10-31T09:00:00Z",
		Resources: []cfn.StackResource{sharedKeyRes, dataVolRes}}, staleLease("aws-shim-old/0001", "CreateStack", alice))
	liveObject(fa, "encryptionkeys", "EncryptionKey", "ebs-default", "app", map[string]any{"rotationDays": 365})
	liveObject(fa, "volumes", "Volume", "data", "app", map[string]any{"size": "10Gi"})

	h.recoverOrphans(context.Background())
	h.ops.drain(5 * time.Second)

	rec, ann := recordIn(t, fa, "app")
	if rec == nil || rec.Status != "ROLLBACK_COMPLETE" {
		t.Fatalf("want ROLLBACK_COMPLETE, got %+v", rec)
	}
	for _, want := range []string{"CreateStack was interrupted before it finished", "aws-shim-old/0001", "stopped renewing its lease"} {
		if !strings.Contains(rec.Message, want) {
			t.Errorf("StackStatusReason must name the interruption (%q): %q", want, rec.Message)
		}
	}
	if fa.get("volumes", opsNS, "data") != nil {
		t.Error("the Volume the interrupted create made must be rolled back")
	}
	if fa.get("encryptionkeys", opsNS, "ebs-default") == nil {
		t.Error("the shared default EncryptionKey (DeletionPolicy Retain) must survive the rollback")
	}
	if got := fa.callerLog(); len(got) != 1 || got[0] != "openinfra:alice|openinfra:powerusers,openinfra:users" {
		t.Errorf("the rollback must run as the operation's recorded caller, impersonated: %v", got)
	}
	if hasOpAnnotations(ann) {
		t.Errorf("a settled record carries no operation lease: %v", ann)
	}
	// DescribeStacks reports it with the reason.
	ap, _ := h.applierForIdentity(alice.User, alice.Groups)
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"app"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStacks(w, r, ap, "req") })
	if !strings.Contains(rr.Body.String(), "<StackStatus>ROLLBACK_COMPLETE</StackStatus><StackStatusReason>CreateStack was interrupted") {
		t.Errorf("DescribeStacks must show ROLLBACK_COMPLETE + the reason:\n%s", rr.Body.String())
	}
	// AWS: a ROLLBACK_COMPLETE stack can't be updated (only deleted).
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"app"}, "TemplateBody": {"Resources: {}"}}, func(w http.ResponseWriter, r *http.Request) { h.updateStack(w, r, ap, "req") })
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "is in ROLLBACK_COMPLETE state and can not be updated") {
		t.Errorf("UpdateStack on ROLLBACK_COMPLETE must be refused: %d %s", rr.Code, rr.Body.String())
	}
}

// An interrupted update is rolled back to the recorded prior stack: the add is deleted, the modified
// spec restored, UPDATE_ROLLBACK_COMPLETE.
func TestCFNRecovery_InterruptedUpdate_PriorStackRestored(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	extra := cfn.StackResource{LogicalID: "Extra", APIVersion: "openinfra.dev/v1", Kind: "Volume", Name: "extra", Spec: map[string]any{"size": "5Gi"}}
	seedStack(fa, cfn.StackRecord{Name: "app", Status: "UPDATE_IN_PROGRESS", UpdatedAt: "2026-10-31T09:00:00Z",
		Resources: []cfn.StackResource{dataVolRes}, Pending: []cfn.StackResource{extra},
		Outputs: []cfn.StackOutput{{OutputKey: "Disk", OutputValue: "data"}}}, staleLease("aws-shim-old/0001", "UpdateStack", alice))
	liveObject(fa, "volumes", "Volume", "data", "app", map[string]any{"size": "20Gi"}) // modified by the update
	liveObject(fa, "volumes", "Volume", "extra", "app", map[string]any{"size": "5Gi"}) // added by the update

	h.recoverOrphans(context.Background())
	h.ops.drain(5 * time.Second)

	rec, ann := recordIn(t, fa, "app")
	if rec == nil || rec.Status != "UPDATE_ROLLBACK_COMPLETE" || len(rec.Pending) != 0 {
		t.Fatalf("want UPDATE_ROLLBACK_COMPLETE with no Pending, got %+v", rec)
	}
	if !strings.Contains(rec.Message, "UpdateStack was interrupted before it finished") {
		t.Errorf("reason must name the interruption: %q", rec.Message)
	}
	if fa.get("volumes", opsNS, "extra") != nil {
		t.Error("the update's add must be deleted")
	}
	data := fa.get("volumes", opsNS, "data")
	if data == nil || data["spec"].(map[string]any)["size"] != "10Gi" {
		t.Errorf("the prior spec must be restored: %v", data)
	}
	if len(rec.Resources) != 1 || rec.Resources[0].Name != "data" || len(rec.Outputs) != 1 {
		t.Errorf("the record must be the prior stack (resources + outputs): %+v", rec)
	}
	if hasOpAnnotations(ann) {
		t.Errorf("a settled record carries no operation lease: %v", ann)
	}
}

// An interrupted delete is resumed to completion: the record is gone, the Retain key kept.
func TestCFNRecovery_InterruptedDelete_Completed(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	seedStack(fa, cfn.StackRecord{Name: "app", Status: "DELETE_IN_PROGRESS", UpdatedAt: "2026-10-31T09:00:00Z",
		Resources: []cfn.StackResource{sharedKeyRes, dataVolRes}}, staleLease("aws-shim-old/0001", "DeleteStack", alice))
	liveObject(fa, "encryptionkeys", "EncryptionKey", "ebs-default", "app", map[string]any{"rotationDays": 365})
	liveObject(fa, "volumes", "Volume", "data", "app", map[string]any{"size": "10Gi"})

	h.recoverOrphans(context.Background())
	h.ops.drain(5 * time.Second)

	if rec, _ := recordIn(t, fa, "app"); rec != nil {
		t.Fatalf("the resumed delete must remove the stack record, got %+v", rec)
	}
	if fa.get("volumes", opsNS, "data") != nil {
		t.Error("the Volume must be deleted")
	}
	if fa.get("encryptionkeys", opsNS, "ebs-default") == nil {
		t.Error("the Retain key survives the delete")
	}
}

// Ownership: a record whose owner is alive (fresh lease), one whose operation is live in THIS process, and
// a pre-lease record that might still be running in an old front door are all left alone.
func TestCFNRecovery_LiveOwnersNotTouched(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	fresh := map[string]any{annOpOwner: "aws-shim-other/0003", annOpRenewed: time.Now().Add(-5 * time.Second).UTC().Format(time.RFC3339Nano),
		annOpLease: "60", annOpAction: "CreateStack", annOpCaller: callerJSON(alice)}
	seedStack(fa, cfn.StackRecord{Name: "elsewhere", Status: "CREATE_IN_PROGRESS", Resources: []cfn.StackResource{dataVolRes}}, fresh)
	seedStack(fa, cfn.StackRecord{Name: "mine", Status: "CREATE_IN_PROGRESS", Resources: []cfn.StackResource{dataVolRes}},
		staleLease("aws-shim-new/0002", "CreateStack", alice))
	seedStack(fa, cfn.StackRecord{Name: "legacy", Status: "UPDATE_IN_PROGRESS", UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Resources: []cfn.StackResource{dataVolRes}}, nil)
	liveObject(fa, "volumes", "Volume", "data", "elsewhere", map[string]any{"size": "10Gi"})
	if err := h.ops.begin("mine"); err != nil { // a live operation in this process
		t.Fatal(err)
	}

	h.recoverOrphans(context.Background())
	h.ops.end("mine")
	h.ops.drain(5 * time.Second)

	for stack, want := range map[string]string{"elsewhere": "CREATE_IN_PROGRESS", "mine": "CREATE_IN_PROGRESS", "legacy": "UPDATE_IN_PROGRESS"} {
		if rec, _ := recordIn(t, fa, stack); rec == nil || rec.Status != want {
			t.Errorf("%s must be untouched (%s), got %+v", stack, want, rec)
		}
	}
	if _, ann := recordIn(t, fa, "elsewhere"); ann[annOpOwner] != "aws-shim-other/0003" {
		t.Errorf("a live owner's lease must not be taken: %v", ann)
	}
	if fa.get("volumes", opsNS, "data") == nil || len(fa.callerLog()) != 0 {
		t.Error("nothing may be rolled back for a live operation")
	}
}

// This process's OWN operation that ended without settling the record (it ran out of time) is recovered at
// once — no need to wait out its lease.
func TestCFNRecovery_OwnEndedOperationRecoveredAtOnce(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	ann := map[string]any{annOpOwner: "aws-shim-new/0002", annOpRenewed: time.Now().UTC().Format(time.RFC3339Nano),
		annOpLease: "60", annOpAction: "CreateStack", annOpCaller: callerJSON(alice)}
	seedStack(fa, cfn.StackRecord{Name: "app", Status: "CREATE_IN_PROGRESS", Resources: []cfn.StackResource{dataVolRes}}, ann)
	liveObject(fa, "volumes", "Volume", "data", "app", map[string]any{"size": "10Gi"})

	h.recoverOrphans(context.Background())
	h.ops.drain(5 * time.Second)

	if rec, _ := recordIn(t, fa, "app"); rec == nil || rec.Status != "ROLLBACK_COMPLETE" || !strings.Contains(rec.Message, "ran out of time") {
		t.Fatalf("want ROLLBACK_COMPLETE (ran out of time), got %+v", rec)
	}
	if fa.get("volumes", opsNS, "data") != nil {
		t.Error("the Volume must be rolled back")
	}
}

// A record with no usable recorded caller — written before callers were recorded, or naming an identity
// this front door could not have minted — is never rolled back under any other authority: it settles
// ROLLBACK_FAILED with its resources kept, and the caller's own DeleteStack removes them. One that recorded
// nothing to undo is simply ROLLBACK_COMPLETE.
func TestCFNRecovery_NoRecordedCaller_SettledNotRolledBack(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	seedStack(fa, cfn.StackRecord{Name: "legacy", Status: "CREATE_IN_PROGRESS", UpdatedAt: old,
		Resources: []cfn.StackResource{sharedKeyRes, dataVolRes}}, nil)
	seedStack(fa, cfn.StackRecord{Name: "empty", Status: "CREATE_IN_PROGRESS", UpdatedAt: old}, nil)
	forged := &recordedCaller{User: "openinfra:mallory", Groups: []string{"system:masters"}}
	seedStack(fa, cfn.StackRecord{Name: "forged", Status: "CREATE_IN_PROGRESS", UpdatedAt: old,
		Resources: []cfn.StackResource{{LogicalID: "Other", APIVersion: "openinfra.dev/v1", Kind: "Volume", Name: "other"}}},
		staleLease("aws-shim-old/0001", "CreateStack", forged))
	liveObject(fa, "encryptionkeys", "EncryptionKey", "ebs-default", "legacy", map[string]any{"rotationDays": 365})
	liveObject(fa, "volumes", "Volume", "data", "legacy", map[string]any{"size": "10Gi"})
	liveObject(fa, "volumes", "Volume", "other", "forged", map[string]any{"size": "1Gi"})

	h.recoverOrphans(context.Background())
	h.ops.drain(5 * time.Second)

	rec, _ := recordIn(t, fa, "legacy")
	if rec == nil || rec.Status != "ROLLBACK_FAILED" || !strings.Contains(rec.Message, "caller was not recorded") ||
		!strings.Contains(rec.Message, "DeleteStack") || len(rec.Resources) != 2 {
		t.Fatalf("want ROLLBACK_FAILED keeping its resources, pointing at DeleteStack, got %+v", rec)
	}
	if rec, _ := recordIn(t, fa, "empty"); rec == nil || rec.Status != "ROLLBACK_COMPLETE" {
		t.Fatalf("a create that recorded nothing is simply ROLLBACK_COMPLETE, got %+v", rec)
	}
	if rec, _ := recordIn(t, fa, "forged"); rec == nil || rec.Status != "ROLLBACK_FAILED" {
		t.Fatalf("a recorded identity the front door could not have minted is refused, got %+v", rec)
	}
	if fa.get("volumes", opsNS, "data") == nil || fa.get("volumes", opsNS, "other") == nil || len(fa.callerLog()) != 0 {
		t.Fatal("nothing may be deleted, and no identity impersonated, without the operation's recorded caller")
	}

	// The caller's own DeleteStack (their authority) removes what the interrupted create made.
	ap, _ := h.applierForIdentity(alice.User, alice.Groups)
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"legacy"}}, func(w http.ResponseWriter, r *http.Request) { h.deleteStack(w, r, ap, "req") })
	if rr.Code != http.StatusOK {
		t.Fatalf("DeleteStack: %d %s", rr.Code, rr.Body.String())
	}
	h.ops.drain(5 * time.Second)
	if rec, _ := recordIn(t, fa, "legacy"); rec != nil || fa.get("volumes", opsNS, "data") != nil {
		t.Fatalf("DeleteStack must remove the stack and its Volume: rec=%+v", rec)
	}
	if fa.get("encryptionkeys", opsNS, "ebs-default") == nil {
		t.Fatal("the Retain key survives DeleteStack")
	}
}

// Two front doors racing to recover the same orphan: the conditional claim lets exactly one run it.
func TestCFNRecovery_ClaimIsExclusive(t *testing.T) {
	fa := newFakeAPI()
	a := opsDoorway(t, fa, "aws-shim-a/000a")
	b := opsDoorway(t, fa, "aws-shim-b/000b")
	seedStack(fa, cfn.StackRecord{Name: "app", Status: "CREATE_IN_PROGRESS", Resources: []cfn.StackResource{dataVolRes}},
		staleLease("aws-shim-old/0001", "CreateStack", alice))
	liveObject(fa, "volumes", "Volume", "data", "app", map[string]any{"size": "10Gi"})

	var wg sync.WaitGroup
	for _, h := range []*cfnDoorway{a, b} {
		wg.Add(1)
		go func(h *cfnDoorway) { defer wg.Done(); h.recoverOrphans(context.Background()) }(h)
	}
	wg.Wait()
	a.ops.drain(5 * time.Second)
	b.ops.drain(5 * time.Second)

	if got := fa.callerLog(); len(got) != 1 {
		t.Fatalf("exactly one front door may run the recovery, ran %d: %v", len(got), got)
	}
	if rec, _ := recordIn(t, fa, "app"); rec == nil || rec.Status != "ROLLBACK_COMPLETE" {
		t.Fatalf("want ROLLBACK_COMPLETE, got %+v", rec)
	}

	// The claim is a conditional patch: a stale resourceVersion is a Conflict.
	seedStack(fa, cfn.StackRecord{Name: "other", Status: "CREATE_COMPLETE"}, nil)
	if err := a.patchLease(context.Background(), "other", "1", a.leaseAnnotations("UpdateStack", alice)); !apierrors.IsConflict(err) {
		t.Fatalf("a claim against a stale resourceVersion must Conflict, got %v", err)
	}
}

// The running operation renews its lease; the engine's own record writes (server-side apply) leave it in
// place; once stopped, renewals stop; a settled record's lease is released.
func TestCFNLease_RenewedWhileRunningAndReleased(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	h.ops.refresh = 20 * time.Millisecond
	ctx := context.Background()
	if err := h.seedRecord(ctx, &cfn.StackRecord{Name: "app", Namespace: opsNS, Status: "CREATE_IN_PROGRESS"}, "CreateStack", alice); err != nil {
		t.Fatal(err)
	}
	_, ann0 := recordIn(t, fa, "app")
	if ann0[annOpOwner] != "aws-shim-new/0002" || ann0[annOpCaller] != callerJSON(alice) || ann0[annOpAction] != "CreateStack" {
		t.Fatalf("the seeded record must carry the owner, the caller and the action: %v", ann0)
	}
	opCtx, stop := h.holdLease("app")
	time.Sleep(120 * time.Millisecond)
	// The engine writes the record (SSA, its own field manager) mid-operation: the lease survives it.
	rs := h.recs()
	sa := &impersonatingApplier{shim: h.shimDyn, mapper: h.mapper, ns: opsNS, records: &rs}
	if err := sa.putRecord(ctx, &cfn.StackRecord{Name: "app", Namespace: opsNS, Status: "CREATE_IN_PROGRESS",
		Resources: []cfn.StackResource{dataVolRes}}); err != nil {
		t.Fatal(err)
	}
	_, ann1 := recordIn(t, fa, "app")
	t0, _ := time.Parse(time.RFC3339Nano, ann0[annOpRenewed].(string))
	t1, _ := time.Parse(time.RFC3339Nano, ann1[annOpRenewed].(string))
	if !t1.After(t0) || ann1[annOpOwner] != "aws-shim-new/0002" || ann1[annOpCaller] != callerJSON(alice) {
		t.Fatalf("the lease must be renewed while running and survive the engine's record write: before %v after %v", ann0, ann1)
	}
	if lost := stop(); lost || opCtx.Err() == nil {
		t.Fatalf("stop: lost=%v ctxErr=%v (stop ends the operation's context, lease not lost)", lost, opCtx.Err())
	}
	_, ann2 := recordIn(t, fa, "app")
	time.Sleep(80 * time.Millisecond)
	if _, ann3 := recordIn(t, fa, "app"); ann3[annOpRenewed] != ann2[annOpRenewed] {
		t.Fatalf("renewals must stop with the operation: %v then %v", ann2[annOpRenewed], ann3[annOpRenewed])
	}
	// Still in progress → the lease is kept (recovery needs the recorded caller); settled → released.
	h.releaseLease(ctx, "app")
	if _, ann := recordIn(t, fa, "app"); ann[annOpOwner] == nil {
		t.Fatal("an in-progress record keeps its lease and caller for recovery")
	}
	_ = sa.putRecord(ctx, &cfn.StackRecord{Name: "app", Namespace: opsNS, Status: "CREATE_COMPLETE"})
	h.releaseLease(ctx, "app")
	if _, ann := recordIn(t, fa, "app"); hasOpAnnotations(ann) {
		t.Fatalf("a settled record's lease is released: %v", ann)
	}
}

// Fencing: an operation whose record was claimed by another owner, or that cannot renew within its
// deadline, has its context cancelled — it stops before anyone else can take the stack over.
func TestCFNLease_FencedWhenLostOrUnrenewable(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	h.ops.refresh, h.ops.lease = 10*time.Millisecond, 60*time.Millisecond
	ctx := context.Background()

	_ = h.seedRecord(ctx, &cfn.StackRecord{Name: "taken", Namespace: opsNS, Status: "CREATE_IN_PROGRESS"}, "CreateStack", alice)
	opCtx, stop := h.holdLease("taken")
	if err := h.patchLease(ctx, "taken", "", map[string]any{annOpOwner: "aws-shim-other/0003"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-opCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("an operation whose lease was taken must be stopped")
	}
	if !stop() {
		t.Fatal("stop must report the lease lost")
	}

	_ = h.seedRecord(ctx, &cfn.StackRecord{Name: "cutoff", Namespace: opsNS, Status: "CREATE_IN_PROGRESS"}, "CreateStack", alice)
	fa.setFailPatches(true)
	start := time.Now()
	opCtx, stop = h.holdLease("cutoff")
	select {
	case <-opCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("an operation that cannot renew its lease must fence itself")
	}
	// It rides out transient failures until its renew deadline (two refreshes inside the lease, so it is
	// stopped before another front door can see the lease stale), then reports the lease lost.
	if elapsed := time.Since(start); elapsed < h.ops.renewDeadline() {
		t.Fatalf("it must tolerate failed renewals until its deadline (%v), fenced after %v", h.ops.renewDeadline(), elapsed)
	}
	if !stop() {
		t.Fatal("stop must report the lease lost")
	}
	if h.ops.renewDeadline() > h.ops.leaseFor()-2*h.ops.refreshEvery() {
		t.Fatalf("the renew deadline must sit two refreshes inside the lease: %v vs %v", h.ops.renewDeadline(), h.ops.leaseFor())
	}
	fa.setFailPatches(false)
}

// A CreateStack runs as an owned operation: the record is created already carrying the lease and the
// caller, and is released when the stack settles.
func TestCFNDoorway_CreateStackIsOwnedThenReleased(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	ap, _ := h.applierForIdentity(alice.User, alice.Groups)
	tmpl := "Resources:\n  Key:\n    Type: AWS::KMS::Key\n    Properties: { Description: k }\n"
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"app"}, "TemplateBody": {tmpl}}, func(w http.ResponseWriter, r *http.Request) { h.createStack(w, r, ap, "req") })
	if rr.Code != http.StatusOK {
		t.Fatalf("CreateStack: %d %s", rr.Code, rr.Body.String())
	}
	h.ops.drain(10 * time.Second)
	created := fa.created["cfn-stack-app"]
	if created[annOpOwner] != "aws-shim-new/0002" || created[annOpCaller] != callerJSON(alice) || created[annOpAction] != "CreateStack" {
		t.Fatalf("the record must be created owned by the operation, with its caller: %v", created)
	}
	rec, ann := recordIn(t, fa, "app")
	if rec == nil || rec.Status != "CREATE_COMPLETE" || hasOpAnnotations(ann) {
		t.Fatalf("want CREATE_COMPLETE with the lease released: %+v %v", rec, ann)
	}
	// A second create of the same name is refused.
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"app"}, "TemplateBody": {tmpl}}, func(w http.ResponseWriter, r *http.Request) { h.createStack(w, r, ap, "req") })
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "AlreadyExistsException") {
		t.Fatalf("a duplicate CreateStack must be refused: %d %s", rr.Code, rr.Body.String())
	}
}

// A stack with an operation in progress (live or awaiting recovery) refuses UpdateStack and DeleteStack
// the AWS way; deleting a stack already being deleted is a no-op.
func TestCFNDoorway_InProgressStackRefusesNewOperations(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	ap, _ := h.applierForIdentity(alice.User, alice.Groups)
	fresh := map[string]any{annOpOwner: "aws-shim-other/0003", annOpRenewed: time.Now().UTC().Format(time.RFC3339Nano), annOpLease: "60"}
	seedStack(fa, cfn.StackRecord{Name: "busy", Status: "CREATE_IN_PROGRESS"}, fresh)
	seedStack(fa, cfn.StackRecord{Name: "going", Status: "DELETE_IN_PROGRESS"}, fresh)
	tmpl := "Resources:\n  Key:\n    Type: AWS::KMS::Key\n    Properties: { Description: k }\n"

	rr := cfnPost(t, h, ap, url.Values{"StackName": {"busy"}, "TemplateBody": {tmpl}}, func(w http.ResponseWriter, r *http.Request) { h.updateStack(w, r, ap, "req") })
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "is in CREATE_IN_PROGRESS state and can not be updated") {
		t.Errorf("UpdateStack on an in-progress stack: %d %s", rr.Code, rr.Body.String())
	}
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"busy"}}, func(w http.ResponseWriter, r *http.Request) { h.deleteStack(w, r, ap, "req") })
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "cannot be deleted while in status CREATE_IN_PROGRESS") {
		t.Errorf("DeleteStack on an in-progress create: %d %s", rr.Code, rr.Body.String())
	}
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"going"}}, func(w http.ResponseWriter, r *http.Request) { h.deleteStack(w, r, ap, "req") })
	if rr.Code != http.StatusOK {
		t.Errorf("DeleteStack on a stack being deleted is a no-op success: %d %s", rr.Code, rr.Body.String())
	}
	if rec, ann := recordIn(t, fa, "busy"); rec.Status != "CREATE_IN_PROGRESS" || ann[annOpOwner] != "aws-shim-other/0003" {
		t.Errorf("a refused operation changes nothing: %+v %v", rec, ann)
	}
}

// Once terminating (SIGTERM), the front door accepts no new stack operation — 503 ServiceUnavailable,
// which SDKs retry — writes nothing, and starts no recovery.
func TestCFNDoorway_ShutdownRefusesNewOperations(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	ap, _ := h.applierForIdentity(alice.User, alice.Groups)
	seedStack(fa, cfn.StackRecord{Name: "existing", Status: "CREATE_COMPLETE"}, nil)
	seedStack(fa, cfn.StackRecord{Name: "orphan", Status: "CREATE_IN_PROGRESS"}, staleLease("aws-shim-old/0001", "CreateStack", alice))
	h.ops.shutdown()
	tmpl := "Resources:\n  Key:\n    Type: AWS::KMS::Key\n    Properties: { Description: k }\n"

	for name, run := range map[string]func(http.ResponseWriter, *http.Request){
		"CreateStack": func(w http.ResponseWriter, r *http.Request) { h.createStack(w, r, ap, "req") },
		"UpdateStack": func(w http.ResponseWriter, r *http.Request) { h.updateStack(w, r, ap, "req") },
		"DeleteStack": func(w http.ResponseWriter, r *http.Request) { h.deleteStack(w, r, ap, "req") },
	} {
		stack := "existing"
		if name == "CreateStack" {
			stack = "new"
		}
		rr := cfnPost(t, h, ap, url.Values{"StackName": {stack}, "TemplateBody": {tmpl}}, run)
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "ServiceUnavailable") {
			t.Errorf("%s while terminating must be 503 ServiceUnavailable: %d %s", name, rr.Code, rr.Body.String())
		}
	}
	if rec, _ := recordIn(t, fa, "new"); rec != nil {
		t.Error("a refused CreateStack writes nothing")
	}
	if rec, ann := recordIn(t, fa, "existing"); rec.Status != "CREATE_COMPLETE" || hasOpAnnotations(ann) {
		t.Errorf("a refused operation changes nothing: %+v %v", rec, ann)
	}
	h.recoverOrphans(context.Background())
	if rec, _ := recordIn(t, fa, "orphan"); rec.Status != "CREATE_IN_PROGRESS" {
		t.Error("a terminating front door starts no recovery (the next one does)")
	}
}

// recordedCaller.usable accepts exactly the shape iam.Identity mints.
func TestRecordedCallerUsable(t *testing.T) {
	for _, tc := range []struct {
		c    *recordedCaller
		want bool
	}{
		{alice, true},
		{&recordedCaller{User: "openinfra:svc"}, true},
		{nil, false},
		{&recordedCaller{}, false},
		{&recordedCaller{User: "openinfra:"}, false},
		{&recordedCaller{User: "system:admin", Groups: []string{"openinfra:admins"}}, false},
		{&recordedCaller{User: "openinfra:x", Groups: []string{"system:masters"}}, false},
		{&recordedCaller{User: "openinfra:x", Groups: []string{"openinfra:users,system:masters"}}, false},
	} {
		if got := tc.c.usable(); got != tc.want {
			t.Errorf("usable(%+v) = %v, want %v", tc.c, got, tc.want)
		}
	}
}

// A create of a just-deleted stack's name waits out the delete's bookkeeping (its record is gone, its
// operation is still live) instead of answering AlreadyExists; it never waits while the stack exists.
func TestCFNBeginCreate_WaitsForAFinishingDelete(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim-new/0002")
	ap, _ := h.applierForIdentity(alice.User, alice.Groups)
	prev := createAfterDeleteWait
	createAfterDeleteWait = 5 * time.Second
	defer func() { createAfterDeleteWait = prev }()

	// The delete's record is gone; its operation ends a moment later.
	if err := h.ops.begin("gone"); err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(400 * time.Millisecond); h.ops.end("gone") }()
	start := time.Now()
	if err := h.beginCreate(context.Background(), ap, "gone"); err != nil {
		t.Fatalf("a create after a completed delete must wait for its operation, got %v", err)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Error("beginCreate must have waited for the delete's operation to end")
	}
	h.ops.end("gone")

	// A stack of that name exists (a live operation on it): refused at once, as AlreadyExists is.
	seedStack(fa, cfn.StackRecord{Name: "here", Status: "UPDATE_IN_PROGRESS"}, nil)
	if err := h.ops.begin("here"); err != nil {
		t.Fatal(err)
	}
	defer h.ops.end("here")
	start = time.Now()
	if err := h.beginCreate(context.Background(), ap, "here"); !errors.Is(err, errCFNStackBusy) {
		t.Fatalf("an existing stack's name must be refused, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("beginCreate must not wait while the stack exists")
	}
}
