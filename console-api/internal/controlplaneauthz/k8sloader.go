package controlplaneauthz

import (
	"context"
	"fmt"

	"github.com/harn3ss/open-infra/policyengine"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

var (
	policyGVR    = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "policies"}
	configMapGVR = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
)

// Where an optional compiled control-plane corpus bundle lives. Delivering the large generated corpus
// (hundreds of principals) as ONE ConfigMap avoids one Crossplane claim per principal (which backed
// up composition on a bulk apply). Absent = only the kind: Policy grants are used.
const (
	corpusCMNamespace = "open-infra-authz"
	corpusCMName      = "control-plane-corpus"
	corpusCMKey       = "corpus.yaml"
)

// K8sLoader assembles the control-plane corpus from BOTH sources, unioned:
//  1. every kind: Policy's spec.controlPlane block, and
//  2. an optional compiled bundle in the control-plane-corpus ConfigMap.
//
// A read error on either source, or a malformed bundle, fails the load (the Checker then serves its
// last-good snapshot) rather than silently under-granting. A missing ConfigMap is not an error.
func K8sLoader(dc dynamic.Interface) Loader {
	return func(ctx context.Context) ([]PolicyDoc, error) {
		docs, err := loadFromPolicies(ctx, dc)
		if err != nil {
			return nil, err
		}
		bundle, err := loadFromConfigMap(ctx, dc)
		if err != nil {
			return nil, err
		}
		return append(docs, bundle...), nil
	}
}

// loadFromPolicies extracts spec.controlPlane from every kind: Policy. A policy with no controlPlane
// block is ignored.
func loadFromPolicies(ctx context.Context, dc dynamic.Interface) ([]PolicyDoc, error) {
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

// loadFromConfigMap reads the optional control-plane-corpus ConfigMap and parses its bundle.
func loadFromConfigMap(ctx context.Context, dc dynamic.Interface) ([]PolicyDoc, error) {
	cm, err := dc.Resource(configMapGVR).Namespace(corpusCMNamespace).Get(ctx, corpusCMName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil // optional — no bundle configured
	}
	if err != nil {
		return nil, err
	}
	data, _ := cm.Object["data"].(map[string]any)
	raw, _ := data[corpusCMKey].(string)
	if raw == "" {
		return nil, nil
	}
	return parseBundle([]byte(raw))
}

// bundleDoc mirrors one control-plane grant for JSON/YAML decoding of the ConfigMap bundle. It is the
// same shape as a kind: Policy spec.controlPlane block (appliesTo + statements); a `caveats` field is
// accepted (for reviewer notes) and ignored by the loader.
type bundleDoc struct {
	AppliesTo  []string `json:"appliesTo"`
	Caveats    []string `json:"caveats,omitempty"`
	Statements []struct {
		Effect    string            `json:"effect"`
		Actions   []string          `json:"actions"`
		Resources []string          `json:"resources"`
		Condition map[string]string `json:"condition,omitempty"`
	} `json:"statements"`
}

// parseBundle decodes a corpus bundle (a YAML/JSON list of grants) into PolicyDocs. Kept pure so it
// is unit-testable without a cluster.
func parseBundle(raw []byte) ([]PolicyDoc, error) {
	var grants []bundleDoc
	if err := yaml.Unmarshal(raw, &grants); err != nil {
		return nil, fmt.Errorf("control-plane-corpus %s/%s key %q: %w", corpusCMNamespace, corpusCMName, corpusCMKey, err)
	}
	var docs []PolicyDoc
	for _, g := range grants {
		doc := PolicyDoc{AppliesTo: g.AppliesTo}
		for _, s := range g.Statements {
			doc.Statements = append(doc.Statements, policyengine.Statement{
				Effect:    policyengine.Effect(s.Effect),
				Actions:   s.Actions,
				Resources: s.Resources,
				Condition: s.Condition,
			})
		}
		if len(doc.Statements) > 0 {
			docs = append(docs, doc)
		}
	}
	return docs, nil
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
