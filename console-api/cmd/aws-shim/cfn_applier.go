// The CloudFormation doorway's live cluster Applier.
//
// This is the seam that makes a stack operation run under the CALLER's authority, not the shim's —
// the way AWS CloudFormation provisions with the calling principal's own IAM permissions (its default),
// never CloudFormation's service permissions. Every RESOURCE operation goes through a client-go dynamic
// client that IMPERSONATES the caller (Impersonate-User: openinfra:<sub> + their groups), so the API
// server's RBAC and the Cedar admission webhook bound the whole stack to exactly what the caller may do.
// A caller who cannot create a resource is denied by the API server itself — the confused-deputy blast
// radius #175 warns about is structurally impossible here.
//
// The ONE exception is the stack record (cfn-stack-<name>): that is the doorway's internal bookkeeping
// (the analog of AWS's service-side stack metadata, which is not a customer resource created under
// customer credentials). It is written with the shim's own ServiceAccount, because it is not part of the
// user's stack. The engine writes it as a ConfigMap; the applier keeps it in its record store — for the
// CloudFormation front door a Secret in the shim's namespace (cfn_records.go). Resource ops = caller;
// record ops = shim.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/csaupgrade"
	"sigs.k8s.io/yaml"
)

const cfnFieldManager = "cfn-doorway"

// impersonatingApplier implements cfn.Applier. `caller` is a dynamic client impersonating the request's
// principal (authority for every resource op); `shim` is the shim SA's own client, used ONLY for the
// stack-record ConfigMap. `mapper` resolves apiVersion+Kind -> GVR (+ namespaced scope).
type impersonatingApplier struct {
	caller dynamic.Interface
	shim   dynamic.Interface
	mapper meta.RESTMapper
	ns     string
	// user/groups are the identity `caller` impersonates — recorded on a stack record while an operation
	// runs, so an operation interrupted by a front-door restart is rolled back under the SAME authority
	// (cloudformation_ops.go). Empty for an applier built without an impersonated identity.
	user   string
	groups []string
	// assumedRole is the kind: Role an sts:AssumeRole caller acts as ("" for a User): recorded with the
	// caller, so a recovery's data-plane checks run for the same principal (cfn_authz.go).
	assumedRole string
	// noecho holds the stack's NoEcho parameter values (cfn_noecho.go); nil keeps none.
	noecho *noEchoSecrets
	// records is where stack records are kept (cfn_records.go); nil = ConfigMaps in ns, via shim.
	records *recordStore
	// claims is the caller's identity as the front door authenticated it, for the data-plane checks on
	// the steps that act with the shim's authority (cfn_authz.go); nil = derived from user/groups.
	claims *iam.Claims
	// svc + door route the service kinds (a stack's queues, topics, parameters, keys — cfn.IsServiceKind)
	// to the shim's own AWS API stores, checked as those front doors check them (cfn_services.go). nil
	// svc = this applier cannot provision them (it refuses).
	svc  *cfnServices
	door *cfnDoorway
}

// recordStore is where this applier keeps stack records.
func (a *impersonatingApplier) recordStore() recordStore {
	if a.records != nil {
		return *a.records
	}
	return recordStore{dyn: a.shim, ns: a.ns}
}

// PutNoEcho makes the applier a cfn.NoEchoStore: a stack's NoEcho values go to a Secret, not its record.
func (a *impersonatingApplier) PutNoEcho(ctx context.Context, stackName string, values map[string]string) error {
	return a.noecho.put(ctx, stackRecordName(stackName), stackName, values)
}

// identity is the caller this applier acts as, in the form recorded on a stack record.
func (a *impersonatingApplier) identity() *recordedCaller {
	return &recordedCaller{User: a.user, Groups: append([]string(nil), a.groups...), AssumedRole: a.callerClaims().AssumedRole}
}

// isStackRecord reports whether a (kind,name) the engine writes is the doorway's own bookkeeping — the
// stack record, which the engine writes as a ConfigMap — shim-owned rather than caller-owned.
func isStackRecord(gvkKind, name string) bool {
	return gvkKind == "ConfigMap" && strings.HasPrefix(name, "cfn-stack-")
}

// gvrFor maps an apiVersion+kind to a namespaced GVR via the RESTMapper.
func (a *impersonatingApplier) gvrFor(apiVersion, kind string) (schema.GroupVersionResource, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, fmt.Errorf("bad apiVersion %q: %w", apiVersion, err)
	}
	m, err := a.mapper.RESTMapping(schema.GroupKind{Group: gv.Group, Kind: kind}, gv.Version)
	if err != nil {
		return schema.GroupVersionResource{}, fmt.Errorf("no REST mapping for %s/%s: %w", apiVersion, kind, err)
	}
	return m.Resource, nil
}

func (a *impersonatingApplier) Apply(ctx context.Context, manifestYAML []byte) error {
	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(manifestYAML, &obj.Object); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	gvk := obj.GroupVersionKind()
	name := obj.GetName()
	if cfn.IsServiceKind(obj.GetAPIVersion(), gvk.Kind) {
		_, err := a.svcPut(ctx, obj, false)
		return err
	}
	if err := a.checkAddressAssociation(ctx, obj); err != nil {
		return err
	}
	if isStackRecord(gvk.Kind, name) {
		data, _, _ := unstructured.NestedStringMap(obj.Object, "data")
		labels := map[string]any{}
		for k, v := range obj.GetLabels() {
			labels[k] = v
		}
		if err := a.recordStore().apply(ctx, name, labels, data); err != nil {
			return fmt.Errorf("write stack record %q: %w", name, err)
		}
		return nil
	}
	ns := obj.GetNamespace()
	if ns == "" {
		ns = a.ns
	}
	gvr, err := a.gvrFor(obj.GetAPIVersion(), gvk.Kind)
	if err != nil {
		return err
	}
	cli := a.caller
	// Server-side apply — the client-go analog of `kubectl apply`, correct for both create and update
	// (fields this manager stops setting are pruned). Force resolves ownership conflicts on re-apply.
	_, err = cli.Resource(gvr).Namespace(ns).Apply(ctx, name, obj, metav1.ApplyOptions{FieldManager: cfnFieldManager, Force: true})
	if err != nil {
		return fmt.Errorf("apply %s/%s %q: %w", obj.GetAPIVersion(), gvk.Kind, name, err)
	}
	return nil
}

// Create makes the object only if none of that kind and name exists (cfn.Creator), under the caller's
// authority: the engine's first apply of a resource, so two operations racing for one name cannot both
// take it. The fields it sets are then handed to the server-side-apply manager Apply uses, so a later
// Apply that stops setting a field prunes it exactly as if the object had been applied. That hand-over is
// retried while controllers update the new object; if it still does not land, the object stands as
// created and only such pruning is lost.
func (a *impersonatingApplier) Create(ctx context.Context, manifestYAML []byte) (bool, error) {
	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(manifestYAML, &obj.Object); err != nil {
		return false, fmt.Errorf("parse manifest: %w", err)
	}
	gvk := obj.GroupVersionKind()
	name := obj.GetName()
	if cfn.IsServiceKind(obj.GetAPIVersion(), gvk.Kind) {
		return a.svcPut(ctx, obj, true)
	}
	if err := a.checkAddressAssociation(ctx, obj); err != nil {
		return false, err
	}
	ns := obj.GetNamespace()
	if ns == "" {
		ns = a.ns
	}
	gvr, err := a.gvrFor(obj.GetAPIVersion(), gvk.Kind)
	if err != nil {
		return false, err
	}
	if isStackRecord(gvk.Kind, name) {
		return false, fmt.Errorf("the stack record %q is written by Apply, never created as a resource", name)
	}
	if err := a.functionNameFree(ctx, gvr, ns, name); err != nil {
		return false, err
	}
	cli := a.caller.Resource(gvr).Namespace(ns)
	created, err := cli.Create(ctx, obj, metav1.CreateOptions{FieldManager: cfnFieldManager})
	if apierrors.IsAlreadyExists(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create %s/%s %q: %w", obj.GetAPIVersion(), gvk.Kind, name, err)
	}
	for i := 0; i < 5 && created != nil; i++ {
		patch, perr := csaupgrade.UpgradeManagedFieldsPatch(created, sets.New(cfnFieldManager), cfnFieldManager)
		if perr != nil || patch == nil {
			break
		}
		if _, perr = cli.Patch(ctx, name, types.JSONPatchType, patch, metav1.PatchOptions{}); perr == nil || !apierrors.IsConflict(perr) {
			break
		}
		if created, perr = cli.Get(ctx, name, metav1.GetOptions{}); perr != nil {
			break
		}
	}
	if gvr == functionClaimGVR && a.door != nil {
		a.door.fns.forget(name) // the next invoke by name finds it here
	}
	return true, nil
}

// functionNameFree refuses a stack's new kind: Function whose name a function in another of the
// namespaces the Lambda API invokes in already has: a function is invoked by name, and a name is unique
// in an account, as on AWS. When those namespaces cannot be read, nothing is refused (the earlier
// behavior: the stack's function is created, and an invoke by name looks where it always did).
func (a *impersonatingApplier) functionNameFree(ctx context.Context, gvr schema.GroupVersionResource, ns, name string) error {
	if gvr != functionClaimGVR || a.door == nil || a.door.fns == nil {
		return nil
	}
	other, err := a.door.fns.elsewhere(ctx, name, ns)
	if err != nil || other == "" {
		return nil
	}
	return fmt.Errorf("Function %s already exists (outside this stack) — a function name is unique, as on AWS, and every invoke by name would reach that one; refusing to create another (give the stack's function another FunctionName)", name)
}

// List returns the objects of a kind in the stack namespace via the CALLER (cfn.Lister) — how the engine
// checks that no other object already has a resource's explicit physical name (a BucketName).
func (a *impersonatingApplier) List(ctx context.Context, apiVersion, kind string) ([]cfn.LiveObject, error) {
	if cfn.IsServiceKind(apiVersion, kind) {
		return nil, nil // a service resource's name is its identity: Create is create-only (no list check)
	}
	gvr, err := a.gvrFor(apiVersion, kind)
	if err != nil {
		return nil, err
	}
	l, err := a.caller.Resource(gvr).Namespace(a.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list %s/%s: %w", apiVersion, kind, err)
	}
	out := make([]cfn.LiveObject, 0, len(l.Items))
	for i := range l.Items {
		spec, _, _ := unstructured.NestedMap(l.Items[i].Object, "spec")
		out = append(out, cfn.LiveObject{Name: l.Items[i].GetName(), Labels: l.Items[i].GetLabels(), Spec: spec})
	}
	return out, nil
}

func (a *impersonatingApplier) Delete(ctx context.Context, apiVersion, kind, name string) error {
	if cfn.IsServiceKind(apiVersion, kind) {
		return a.svcDelete(ctx, kind, name)
	}
	if isStackRecord(kind, name) {
		if err := a.recordStore().client().Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete stack record %q: %w", name, err)
		}
		return nil
	}
	gvr, err := a.gvrFor(apiVersion, kind)
	if err != nil {
		return err
	}
	err = a.caller.Resource(gvr).Namespace(a.ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) { // --ignore-not-found semantics
		return fmt.Errorf("delete %s/%s %q: %w", apiVersion, kind, name, err)
	}
	if gvr == functionClaimGVR && a.door != nil {
		a.door.fns.forget(name)
	}
	return nil
}

// WaitReady polls until the resource reports readiness, accepting EITHER open-infra's status.ready:true
// OR the Crossplane Ready condition — the same dual check the kubectl Applier uses (some kinds set
// status.ready=true while the composite's Ready condition stays "Creating").
func (a *impersonatingApplier) WaitReady(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error {
	if cfn.IsServiceKind(apiVersion, kind) {
		return a.svcWaitReady(ctx, kind, name, timeout)
	}
	gvr, err := a.gvrFor(apiVersion, kind)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	var last string
	for {
		u, gerr := a.caller.Resource(gvr).Namespace(a.ns).Get(ctx, name, metav1.GetOptions{})
		if gerr == nil {
			ready, _, _ := unstructured.NestedBool(u.Object, "status", "ready")
			cond := readyCondition(u.Object)
			last = fmt.Sprintf("ready=%v condition=%q", ready, cond)
			if ready || cond == "True" {
				return nil
			}
		} else {
			last = gerr.Error()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s/%s not ready within %s (last: %s)", kind, name, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// readyCondition returns the status of the status.conditions[type=="Ready"] entry, or "".
func readyCondition(obj map[string]any) string {
	conds, found, _ := unstructured.NestedSlice(obj, "status", "conditions")
	if !found {
		return ""
	}
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t == "Ready" {
			s, _ := m["status"].(string)
			return s
		}
	}
	return ""
}

func (a *impersonatingApplier) WaitGone(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error {
	if cfn.IsServiceKind(apiVersion, kind) {
		return a.svcWaitGone(ctx, kind, name, timeout)
	}
	var cli dynamic.ResourceInterface
	if isStackRecord(kind, name) {
		cli = a.recordStore().client()
	} else {
		gvr, err := a.gvrFor(apiVersion, kind)
		if err != nil {
			return err
		}
		cli = a.caller.Resource(gvr).Namespace(a.ns)
	}
	deadline := time.Now().Add(timeout)
	for {
		_, gerr := cli.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(gerr) {
			return nil // gone
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s/%s still present after %s", kind, name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func (a *impersonatingApplier) GetSpec(ctx context.Context, apiVersion, kind, name string) (map[string]any, bool, error) {
	if cfn.IsServiceKind(apiVersion, kind) {
		return a.svcSpec(ctx, kind, name)
	}
	gvr, err := a.gvrFor(apiVersion, kind)
	if err != nil {
		return nil, false, err
	}
	u, gerr := a.caller.Resource(gvr).Namespace(a.ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(gerr) {
		return nil, false, nil
	}
	if gerr != nil {
		return nil, false, gerr
	}
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	return spec, true, nil
}

// GetStatus reads a live resource's .status via the CALLER (cfn.StatusReader) — how a completing stack
// resolves an Output naming a post-deploy attribute (a VM's status.lanIp for an Elastic IP), under the
// same authority that created the resource.
func (a *impersonatingApplier) GetStatus(ctx context.Context, apiVersion, kind, name string) (map[string]any, bool, error) {
	if cfn.IsServiceKind(apiVersion, kind) {
		_, found, err := a.svcSpec(ctx, kind, name)
		st := map[string]any{"ready": found}
		if found && err == nil && kind == cfn.KindEC2Address {
			st["publicIp"] = a.addressIP(ctx, name) // "" while MetalLB has not assigned it (pending)
		}
		return st, found, err
	}
	gvr, err := a.gvrFor(apiVersion, kind)
	if err != nil {
		return nil, false, err
	}
	u, gerr := a.caller.Resource(gvr).Namespace(a.ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(gerr) {
		return nil, false, nil
	}
	if gerr != nil {
		return nil, false, gerr
	}
	st, _, _ := unstructured.NestedMap(u.Object, "status")
	if st == nil {
		st = map[string]any{}
	}
	return st, true, nil
}

// GetLabels reads a live resource's metadata.labels via the CALLER (cfn.LabelReader) — how recovery checks
// an object carries this stack's label before rolling it back, under the operation's own authority.
func (a *impersonatingApplier) GetLabels(ctx context.Context, apiVersion, kind, name string) (map[string]string, bool, error) {
	if cfn.IsServiceKind(apiVersion, kind) {
		return a.svcLabels(ctx, kind, name)
	}
	var u *unstructured.Unstructured
	var gerr error
	if isStackRecord(kind, name) {
		u, gerr = a.recordStore().client().Get(ctx, name, metav1.GetOptions{})
	} else {
		gvr, err := a.gvrFor(apiVersion, kind)
		if err != nil {
			return nil, false, err
		}
		u, gerr = a.caller.Resource(gvr).Namespace(a.ns).Get(ctx, name, metav1.GetOptions{})
	}
	if apierrors.IsNotFound(gerr) {
		return nil, false, nil
	}
	if gerr != nil {
		return nil, false, gerr
	}
	return u.GetLabels(), true, nil
}

// GetReady reports whether a resource's Ready condition is True (or status.ready), read via the CALLER —
// so a doorway can report a workload's readiness without the shim SA needing read access to the workload.
func (a *impersonatingApplier) GetReady(ctx context.Context, apiVersion, kind, name string) (ready, found bool, err error) {
	if cfn.IsServiceKind(apiVersion, kind) {
		_, found, err := a.svcSpec(ctx, kind, name)
		return found, found, err
	}
	gvr, gerr := a.gvrFor(apiVersion, kind)
	if gerr != nil {
		return false, false, gerr
	}
	u, gerr := a.caller.Resource(gvr).Namespace(a.ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(gerr) {
		return false, false, nil
	}
	if gerr != nil {
		return false, false, gerr
	}
	if rd, ok, _ := unstructured.NestedBool(u.Object, "status", "ready"); ok && rd {
		return true, true, nil
	}
	return readyCondition(u.Object) == "True", true, nil
}

// GetStack reads the doorway's own stack record (shim-owned bookkeeping) from its record store.
func (a *impersonatingApplier) GetStack(ctx context.Context, stackName string) (*cfn.StackRecord, bool, error) {
	st := a.recordStore()
	u, gerr := st.client().Get(ctx, "cfn-stack-"+stackName, metav1.GetOptions{})
	if apierrors.IsNotFound(gerr) {
		return nil, false, nil
	}
	if gerr != nil {
		return nil, false, gerr
	}
	data := st.value(u, "stack.json")
	if strings.TrimSpace(data) == "" {
		return nil, false, nil
	}
	var rec cfn.StackRecord
	if err := json.Unmarshal([]byte(data), &rec); err != nil {
		return nil, false, fmt.Errorf("stack record is corrupt: %w", err)
	}
	return &rec, true, nil
}

var configMapGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}

// putRecord writes/updates a stack record in the record store with the shim client (bookkeeping) — e.g.
// to backstop a terminal status. Server-side apply of labels + data only: the operation-lease annotations
// (cloudformation_ops.go) belong to another field manager and are left as they are.
func (a *impersonatingApplier) putRecord(ctx context.Context, rec *cfn.StackRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return a.recordStore().apply(ctx, "cfn-stack-"+rec.Name,
		map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": rec.Name},
		map[string]string{"stack.json": string(data)})
}

// backstopTerminal sets the record to a terminal status IFF it is still *_IN_PROGRESS — a safety net for
// an async engine run that errored without writing its own terminal record. No-op if already terminal.
func (a *impersonatingApplier) backstopTerminal(ctx context.Context, stackName, status, message string) {
	rec, found, err := a.GetStack(ctx, stackName)
	if err != nil || !found {
		return
	}
	if !strings.HasSuffix(rec.Status, "_IN_PROGRESS") {
		return
	}
	rec.Status = status
	rec.Message = message
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = a.putRecord(ctx, rec)
}
