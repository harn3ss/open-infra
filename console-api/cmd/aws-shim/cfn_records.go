package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// The CloudFormation front door's own records — stack records (cfn-stack-<stack>), change sets
// (cfn-changeset-<stack>.<name>) and drift results (cfn-drift-<stack>) — are Secrets in the shim's own
// namespace. A stack record holds what the stack was deployed with: its template, parameters and outputs,
// and every resource's resolved properties, which include whatever a NoEcho parameter was fed into. Readers
// and power users may read ConfigMaps in every namespace, so a record kept as a ConfigMap could be read
// around the front door's own checks; Secrets in the shim's namespace are readable only by the shim and
// cluster admins, as the NoEcho values themselves are (cfn_noecho.go).
//
// Records an earlier front door wrote as ConfigMaps in the stack namespace are moved here
// (migrateLegacyRecords): on startup, on every recovery pass, and before each request.

var secretGVR = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

// recordStore is where a front door keeps its records: Secrets in ns (secret, the CloudFormation front
// door), or ConfigMaps (the ECS front door, whose records hold no parameters).
type recordStore struct {
	dyn    dynamic.Interface
	ns     string
	secret bool
	// account is the member account whose records this store holds, kept beside the management account's
	// under names of their own (cfn_accounts.go); "" holds the management account's, as they always were.
	account string
}

// client reads and writes the store's account's records, by their names within the account
// (accountRecords): a listing never returns another account's.
func (s recordStore) client() dynamic.ResourceInterface {
	return accountRecords{ResourceInterface: s.rawClient(), account: s.account}
}

// rawClient is every account's records as stored (work that runs for every account: the recovery pass).
func (s recordStore) rawClient() dynamic.ResourceInterface {
	if s.secret {
		return s.dyn.Resource(secretGVR).Namespace(s.ns)
	}
	return s.dyn.Resource(configMapGVR).Namespace(s.ns)
}

// object builds a record: name, labels, annotations (nil = none) and its data as plain strings.
func (s recordStore) object(name string, labels, annotations map[string]any, data map[string]string) *unstructured.Unstructured {
	md := map[string]any{"name": name, "namespace": s.ns, "labels": labels}
	if annotations != nil {
		md["annotations"] = annotations
	}
	d := map[string]any{}
	for k, v := range data {
		if s.secret {
			d[k] = base64.StdEncoding.EncodeToString([]byte(v))
		} else {
			d[k] = v
		}
	}
	obj := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": md, "data": d}
	if s.secret {
		obj["kind"], obj["type"] = "Secret", "Opaque"
	}
	return &unstructured.Unstructured{Object: obj}
}

// value reads one data key of a record as a plain string ("" when absent or undecodable).
func (s recordStore) value(u *unstructured.Unstructured, key string) string {
	v, _, _ := unstructured.NestedString(u.Object, "data", key)
	if !s.secret {
		return v
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// stackRecord parses a stack record's stack.json.
func (s recordStore) stackRecord(u *unstructured.Unstructured) (*cfn.StackRecord, bool) {
	data := s.value(u, "stack.json")
	if strings.TrimSpace(data) == "" {
		return nil, false
	}
	var rec cfn.StackRecord
	if json.Unmarshal([]byte(data), &rec) != nil {
		return nil, false
	}
	return &rec, true
}

// apply server-side applies a record (create or replace its labels and data; annotations it does not set,
// the operation lease's, are left alone).
func (s recordStore) apply(ctx context.Context, name string, labels map[string]any, data map[string]string) error {
	_, err := s.client().Apply(ctx, name, s.object(name, labels, nil, data), metav1.ApplyOptions{FieldManager: cfnFieldManager, Force: true})
	return err
}

// recs is this front door's record store: Secrets in the shim's namespace when one is configured
// (recNS), else ConfigMaps in the stack namespace.
func (h *cfnDoorway) recs() recordStore {
	if h.recNS != "" {
		return recordStore{dyn: h.shimDyn, ns: h.recNS, secret: true}
	}
	return recordStore{dyn: h.shimDyn, ns: h.ns}
}

// isCFNRecordName reports whether a name is one of the front door's record names.
func isCFNRecordName(name string) bool {
	for _, p := range []string{"cfn-stack-", "cfn-changeset-", "cfn-drift-"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// migrateLegacyRecords moves the records an earlier front door kept as ConfigMaps in the stack namespace
// into the record store. A stack record still in progress under another front door's live lease is left
// for a later pass, once that front door has settled it. Each record is copied first and its ConfigMap
// then deleted only if unchanged since it was read; if it changed meanwhile, the copy is removed and the
// record moved on a later pass. Best effort: what fails is logged and retried.
func (h *cfnDoorway) migrateLegacyRecords(ctx context.Context) {
	st := h.recs()
	if !st.secret {
		return
	}
	legacy := recordStore{dyn: h.shimDyn, ns: h.ns}
	cms := legacy.client()
	list, err := cms.List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			h.logger.Warn("cfn: could not list records kept as ConfigMaps (they are moved on a later pass)", "error", err.Error())
		}
		return
	}
	now := time.Now()
	for i := range list.Items {
		u := &list.Items[i]
		name := u.GetName()
		if !isCFNRecordName(name) {
			continue
		}
		if rec, ok := legacy.stackRecord(u); ok && strings.HasPrefix(name, "cfn-stack-") && inProgress(rec.Status) {
			if l, leased := leaseOf(u); leased && l.owner != h.ops.ownerID() {
				d := l.duration
				if d <= 0 {
					d = h.ops.leaseFor()
				}
				if now.Sub(l.renewed) <= d {
					continue // another front door is running it
				}
			}
		}
		data, _, _ := unstructured.NestedStringMap(u.Object, "data")
		ann := map[string]any{}
		for k, v := range u.GetAnnotations() {
			if strings.HasPrefix(k, "cfn.openinfra.dev/") {
				ann[k] = v
			}
		}
		labels := map[string]any{}
		for k, v := range u.GetLabels() {
			labels[k] = v
		}
		created, cerr := st.client().Create(ctx, st.object(name, labels, ann, data), metav1.CreateOptions{FieldManager: cfnLeaseManager})
		switch {
		case cerr == nil:
		case apierrors.IsAlreadyExists(cerr):
			// Moved before, and the ConfigMap's delete did not happen: the moved record is the one in use.
			created = nil
			h.logger.Warn("cfn: a record kept as a ConfigMap was already moved; removing the ConfigMap", "record", name)
		default:
			h.logger.Warn("cfn: could not move a record kept as a ConfigMap (retried on a later pass)", "record", name, "error", cerr.Error())
			continue
		}
		rv := u.GetResourceVersion()
		derr := cms.Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &rv}})
		switch {
		case derr == nil || apierrors.IsNotFound(derr):
			h.logger.Info("cfn: moved a record from a ConfigMap to the record store", "record", name)
		case apierrors.IsConflict(derr) && created != nil:
			// The ConfigMap changed while it was copied: drop the copy (unless it is in use already) and
			// move the newer record on a later pass.
			crv := created.GetResourceVersion()
			if err := st.client().Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &crv}}); err != nil && !apierrors.IsNotFound(err) {
				h.logger.Warn("cfn: a record changed while it was moved, and its copy could not be removed", "record", name, "error", err.Error())
			}
		default:
			h.logger.Warn("cfn: could not remove a moved record's ConfigMap (retried on a later pass)", "record", name, "error", derr.Error())
		}
	}
}
