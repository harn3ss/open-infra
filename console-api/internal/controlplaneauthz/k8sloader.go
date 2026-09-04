package controlplaneauthz

import (
	"context"

	"github.com/harn3ss/open-infra/policyengine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var policyGVR = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "policies"}

// K8sLoader lists every kind: Policy in the cluster and extracts its spec.controlPlane block. A
// policy with no controlPlane block is ignored. (The spec.controlPlane XRD field is not yet defined;
// the loader reads it if present — the spike works against fixtures until the field lands.)
func K8sLoader(dc dynamic.Interface) Loader {
	return func(ctx context.Context) ([]PolicyDoc, error) {
		list, err := dc.Resource(policyGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		var docs []PolicyDoc
		for i := range list.Items {
			spec, _ := list.Items[i].Object["spec"].(map[string]any)
			cp, _ := spec["controlPlane"].(map[string]any)
			if cp == nil {
				continue
			}
			doc := PolicyDoc{AppliesTo: toStrings(cp["appliesTo"])}
			for _, s := range toSlice(cp["statements"]) {
				sm, _ := s.(map[string]any)
				if sm == nil {
					continue
				}
				doc.Statements = append(doc.Statements, policyengine.Statement{
					Effect:    policyengine.Effect(str(sm["effect"])),
					Actions:   toStrings(sm["actions"]),
					Resources: toStrings(sm["resources"]),
					Condition: toStringMap(sm["condition"]),
				})
			}
			if len(doc.Statements) > 0 {
				docs = append(docs, doc)
			}
		}
		return docs, nil
	}
}

func toSlice(v any) []any { s, _ := v.([]any); return s }
func str(v any) string    { s, _ := v.(string); return s }

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
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}
