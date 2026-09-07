package dataplaneauthz

import (
	"context"

	"github.com/harn3ss/open-infra/policyengine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	policyGVR = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "policies"}
	// The principal kinds that carry a spec.policies managed-attachment list. Role has it today;
	// User gains it (user-xrd.yaml); Group has no such field yet, so it simply contributes nothing.
	roleGVR  = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "roles"}
	userGVR  = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "users"}
	groupGVR = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "groups"}
)

// K8sLoader reads the whole data-plane policy world from the cluster: every kind: Policy's
// spec.dataPlane block (statements + its own appliesTo, name-tagged so it can be attached), plus the
// managed-attachment index — each kind: Role/User/Group's spec.policies. A principal's attached
// Policies confer their dataPlane authority, the same one policy world as the inline appliesTo axis.
//
// It fails CLOSED on any list error (the Checker then denies governed traffic), exactly as before —
// so the shim's ServiceAccount must be granted list on policies AND roles/users/groups in
// iam.openinfra.dev. Policies with no dataPlane block are ignored.
func K8sLoader(dc dynamic.Interface) Loader {
	return func(ctx context.Context) (Snapshot, error) {
		list, err := dc.Resource(policyGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return Snapshot{}, err
		}
		var docs []PolicyDoc
		for i := range list.Items {
			spec, _ := list.Items[i].Object["spec"].(map[string]any)
			dp, _ := spec["dataPlane"].(map[string]any)
			if dp == nil {
				continue
			}
			doc := PolicyDoc{Name: list.Items[i].GetName(), AppliesTo: toStrings(dp["appliesTo"])}
			for _, s := range toSlice(dp["statements"]) {
				sm, _ := s.(map[string]any)
				if sm == nil {
					continue
				}
				doc.Statements = append(doc.Statements, policyengine.Statement{
					Effect:       policyengine.Effect(str(sm["effect"])),
					Actions:      toStrings(sm["actions"]),
					Resources:    toStrings(sm["resources"]),
					Condition:    toStringMap(sm["condition"]),
					IPConditions: toIPConditions(sm["ipConditions"]),
				})
			}
			if len(doc.Statements) > 0 {
				docs = append(docs, doc)
			}
		}

		attach := map[string][]string{}
		boundary := map[string]string{}
		for _, k := range []struct {
			gvr  schema.GroupVersionResource
			kind string
		}{{roleGVR, "Role"}, {userGVR, "User"}, {groupGVR, "Group"}} {
			if err := loadAttachments(ctx, dc, k.gvr, k.kind, attach, boundary); err != nil {
				return Snapshot{}, err // fail closed, unchanged
			}
		}
		return Snapshot{Docs: docs, Attach: attach, Boundary: boundary}, nil
	}
}

// loadAttachments lists one principal kind and records each object's spec.policies under
// "<kind>::<name>" in the attach index, and its spec.permissionBoundary (Role/User) in the boundary
// index. A list error propagates (fail closed). Groups carry no permissionBoundary field, so it is
// simply absent for them.
func loadAttachments(ctx context.Context, dc dynamic.Interface, gvr schema.GroupVersionResource, kind string, attach map[string][]string, boundary map[string]string) error {
	list, err := dc.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for i := range list.Items {
		spec, _ := list.Items[i].Object["spec"].(map[string]any)
		key := kind + "::" + list.Items[i].GetName()
		if names := toStrings(spec["policies"]); len(names) > 0 {
			attach[key] = names
		}
		if pb := str(spec["permissionBoundary"]); pb != "" {
			boundary[key] = pb
		}
	}
	return nil
}

// toIPConditions parses a statement's ipConditions array (the aws:SourceIp-style CIDR conditions the
// AWS importer emits) into policyengine.IPConditions. Entries missing a key or cidr are skipped.
func toIPConditions(v any) []policyengine.IPCondition {
	items, _ := v.([]any)
	var out []policyengine.IPCondition
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		key, cidr := str(m["key"]), str(m["cidr"])
		if key == "" || cidr == "" {
			continue
		}
		neg, _ := m["negate"].(bool)
		out = append(out, policyengine.IPCondition{Key: key, CIDR: cidr, Negate: neg})
	}
	return out
}

func toSlice(v any) []any { s, _ := v.([]any); return s }

func str(v any) string { s, _ := v.(string); return s }

func toStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toStringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		switch x := val.(type) {
		case string:
			out[k] = x
		case bool:
			if x {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		}
	}
	return out
}
