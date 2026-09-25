// The CloudFormation doorway's live cluster Applier (polyhedron#175).
//
// This is the seam that makes a stack operation run under the CALLER's authority, not the shim's —
// the way AWS CloudFormation provisions with the calling principal's own IAM permissions (its default),
// never CloudFormation's service permissions. Every RESOURCE operation goes through a client-go dynamic
// client that IMPERSONATES the caller (Impersonate-User: openinfra:<sub> + their groups), so the API
// server's RBAC and the Cedar admission webhook bound the whole stack to exactly what the caller may do.
// A caller who cannot create a resource is denied by the API server itself — the confused-deputy blast
// radius #175 warns about is structurally impossible here.
//
// The ONE exception is the stack-record ConfigMap (cfn-stack-<name>): that is the doorway's internal
// bookkeeping (the analog of AWS's service-side stack metadata, which is not a customer resource created
// under customer credentials). It is written with the shim's own ServiceAccount, because it is not part
// of the user's stack and powerusers deliberately cannot create ConfigMaps. Resource ops = caller;
// record ops = shim.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
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
}

// isStackRecord reports whether a (kind,name) is the doorway's own bookkeeping ConfigMap, which is
// shim-owned rather than caller-owned.
func isStackRecord(gvkKind, name string) bool {
	return gvkKind == "ConfigMap" && strings.HasPrefix(name, "cfn-stack-")
}

// clientFor returns the record client (shim) for the stack-record ConfigMap, else the caller client.
func (a *impersonatingApplier) clientFor(kind, name string) dynamic.Interface {
	if isStackRecord(kind, name) {
		return a.shim
	}
	return a.caller
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
	ns := obj.GetNamespace()
	if ns == "" {
		ns = a.ns
	}
	gvr, err := a.gvrFor(obj.GetAPIVersion(), gvk.Kind)
	if err != nil {
		return err
	}
	cli := a.clientFor(gvk.Kind, name)
	// Server-side apply — the client-go analog of `kubectl apply`, correct for both create and update
	// (fields this manager stops setting are pruned). Force resolves ownership conflicts on re-apply.
	_, err = cli.Resource(gvr).Namespace(ns).Apply(ctx, name, obj, metav1.ApplyOptions{FieldManager: cfnFieldManager, Force: true})
	if err != nil {
		return fmt.Errorf("apply %s/%s %q: %w", obj.GetAPIVersion(), gvk.Kind, name, err)
	}
	return nil
}

func (a *impersonatingApplier) Delete(ctx context.Context, apiVersion, kind, name string) error {
	gvr, err := a.gvrFor(apiVersion, kind)
	if err != nil {
		return err
	}
	cli := a.clientFor(kind, name)
	err = cli.Resource(gvr).Namespace(a.ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) { // --ignore-not-found semantics
		return fmt.Errorf("delete %s/%s %q: %w", apiVersion, kind, name, err)
	}
	return nil
}

// WaitReady polls until the resource reports readiness, accepting EITHER open-infra's status.ready:true
// OR the Crossplane Ready condition — the same dual check the kubectl Applier uses (some kinds set
// status.ready=true while the composite's Ready condition stays "Creating").
func (a *impersonatingApplier) WaitReady(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error {
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
	gvr, err := a.gvrFor(apiVersion, kind)
	if err != nil {
		return err
	}
	cli := a.clientFor(kind, name)
	deadline := time.Now().Add(timeout)
	for {
		_, gerr := cli.Resource(gvr).Namespace(a.ns).Get(ctx, name, metav1.GetOptions{})
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

// GetStack reads the doorway's own stack-record ConfigMap (shim-owned bookkeeping) via the shim client.
func (a *impersonatingApplier) GetStack(ctx context.Context, stackName string) (*cfn.StackRecord, bool, error) {
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	u, gerr := a.shim.Resource(gvr).Namespace(a.ns).Get(ctx, "cfn-stack-"+stackName, metav1.GetOptions{})
	if apierrors.IsNotFound(gerr) {
		return nil, false, nil
	}
	if gerr != nil {
		return nil, false, gerr
	}
	data, _, _ := unstructured.NestedString(u.Object, "data", "stack.json")
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

// putRecord writes/updates a stack-record ConfigMap with the shim client (bookkeeping). The doorway uses
// it to seed CREATE_IN_PROGRESS before the async engine run, and to backstop a terminal status.
func (a *impersonatingApplier) putRecord(ctx context.Context, rec *cfn.StackRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	cm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      "cfn-stack-" + rec.Name,
			"namespace": a.ns,
			"labels":    map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": rec.Name},
		},
		"data": map[string]any{"stack.json": string(data)},
	}}
	_, err = a.shim.Resource(configMapGVR).Namespace(a.ns).Apply(ctx, "cfn-stack-"+rec.Name, cm, metav1.ApplyOptions{FieldManager: cfnFieldManager, Force: true})
	return err
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
