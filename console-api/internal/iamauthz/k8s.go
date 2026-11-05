package iamauthz

import (
	"context"
	"encoding/json"

	"github.com/harn3ss/open-infra/policyengine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	policyGVR = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "policies"}
	roleGVR   = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "roles"}
	userGVR   = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "users"}
	groupGVR  = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "groups"}
)

// K8sLoader reads the IAM policy world from the cluster with the default home namespace.
func K8sLoader(dc dynamic.Interface) Loader { return K8sLoaderIn(dc, DefaultHomeNamespace) }

// K8sLoaderIn reads the IAM policy world from the cluster: every kind: Policy (its AWS document,
// spec.document, and its native data-plane statements, spec.dataPlane), and each kind: Role / User /
// Group's attachments (spec.policies), inline policies (spec.inlinePolicies), permission boundary
// (spec.permissionBoundary) and canary label. Every principal key and Policy name is canonical
// (QualifiedName). It fails closed on any list error. A document that does not compile is skipped and
// its Policy carries the report (its Allows then grant nothing; a Deny in it is lost only when the whole
// document is malformed, which admission refuses).
func K8sLoaderIn(dc dynamic.Interface, home string) Loader {
	return func(ctx context.Context) (World, error) {
		list, err := dc.Resource(policyGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return World{}, err
		}
		var docs []Policy
		defined := map[string]bool{}
		for i := range list.Items {
			defined[QualifiedName(home, list.Items[i].GetNamespace(), list.Items[i].GetName())] = true
		}
		for i := range list.Items {
			spec, _ := list.Items[i].Object["spec"].(map[string]any)
			ns := list.Items[i].GetNamespace()
			doc := Policy{Name: QualifiedName(home, ns, list.Items[i].GetName()), ARN: str(spec["arn"])}
			if text := documentText(spec["document"]); text != "" {
				stmts, report, err := CompileDocument(text)
				if err != nil {
					doc.Report = append(doc.Report, "document does not compile: "+err.Error())
				} else {
					doc.Statements = append(doc.Statements, stmts...)
					doc.Report = append(doc.Report, report...)
				}
			}
			if dp, _ := spec["dataPlane"].(map[string]any); dp != nil {
				doc.AppliesTo = CanonAppliesTo(home, ns, toStrings(dp["appliesTo"]))
				doc.Statements = append(doc.Statements, StatementsFromSpec(dp["statements"])...)
			}
			if len(doc.Statements) > 0 {
				docs = append(docs, doc)
			}
		}

		w := World{Docs: docs, Attach: map[string][]string{}, Boundary: map[string]string{},
			Inline: map[string][]Policy{}, Enforce: map[string]bool{}}
		for _, k := range []struct {
			gvr  schema.GroupVersionResource
			kind string
		}{{roleGVR, "Role"}, {userGVR, "User"}, {groupGVR, "Group"}} {
			if err := loadPrincipals(ctx, dc, home, k.gvr, k.kind, func(n string) bool { return defined[n] }, &w); err != nil {
				return World{}, err
			}
		}
		if len(w.Inline) == 0 {
			w.Inline = nil
		}
		if len(w.Enforce) == 0 {
			w.Enforce = nil
		}
		return w, nil
	}
}

// documentText is a spec.document as JSON text: a string as written, or an object re-encoded.
func documentText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		b, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(b)
	}
	return ""
}

// unresolvableBoundary stands in for a permission boundary that names a Policy the principal may not
// use. It is never a Policy name, so it compiles to the deny-all ceiling, exactly as a typo'd name does.
const unresolvableBoundary = "\x00unresolvable"

func loadPrincipals(ctx context.Context, dc dynamic.Interface, home string, gvr schema.GroupVersionResource, kind string,
	defined func(string) bool, w *World) error {
	list, err := dc.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for i := range list.Items {
		obj := list.Items[i]
		spec, _ := obj.Object["spec"].(map[string]any)
		ns := obj.GetNamespace()
		if ns == "" {
			ns = home
		}
		key := kind + "::" + QualifiedName(home, ns, obj.GetName())
		var names []string
		for _, ref := range toStrings(spec["policies"]) {
			if n := ResolvePolicyRef(home, ns, ref, defined); n != "" {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			w.Attach[key] = names
		}
		if pb := str(spec["permissionBoundary"]); pb != "" {
			if n := ResolvePolicyRef(home, ns, pb, defined); n != "" {
				w.Boundary[key] = n
			} else {
				w.Boundary[key] = unresolvableBoundary
			}
		}
		for _, it := range toSlice(spec["inlinePolicies"]) {
			m, _ := it.(map[string]any)
			if m == nil {
				continue
			}
			p := Policy{Name: str(m["name"])}
			stmts, report, err := CompileDocument(documentText(m["document"]))
			if err != nil {
				p.Report = []string{"document does not compile: " + err.Error()}
			} else {
				p.Statements, p.Report = stmts, report
			}
			if len(p.Statements) > 0 {
				w.Inline[key] = append(w.Inline[key], p)
			}
		}
		if kind != "Group" && obj.GetLabels()[CanaryLabel] == CanaryEnforce {
			w.Enforce[key] = true
		}
	}
	return nil
}

// StatementsFromSpec parses a native statements array (kind: Policy spec.dataPlane.statements).
func StatementsFromSpec(v any) []policyengine.Statement {
	var out []policyengine.Statement
	for _, s := range toSlice(v) {
		sm, _ := s.(map[string]any)
		if sm == nil {
			continue
		}
		out = append(out, policyengine.Statement{
			Effect:         policyengine.Effect(str(sm["effect"])),
			Actions:        toStrings(sm["actions"]),
			NotActions:     toStrings(sm["notActions"]),
			Resources:      toStrings(sm["resources"]),
			NotResources:   toStrings(sm["notResources"]),
			Condition:      toStringMap(sm["condition"]),
			IPConditions:   ToIPConditions(sm["ipConditions"]),
			LikeConditions: ToLikeConditions(sm["likeConditions"]),
			TimeConditions: ToTimeConditions(sm["timeConditions"]),
		})
	}
	return out
}

// ToIPConditions parses a statement's ipConditions array. Entries missing a key or cidr are skipped.
func ToIPConditions(v any) []policyengine.IPCondition {
	var out []policyengine.IPCondition
	for _, it := range toSlice(v) {
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

// ToLikeConditions parses a statement's likeConditions array. Entries missing a key or pattern are
// skipped.
func ToLikeConditions(v any) []policyengine.LikeCondition {
	var out []policyengine.LikeCondition
	for _, it := range toSlice(v) {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		key, pattern := str(m["key"]), str(m["pattern"])
		if key == "" || pattern == "" {
			continue
		}
		neg, _ := m["negate"].(bool)
		out = append(out, policyengine.LikeCondition{Key: key, Pattern: pattern, Negate: neg})
	}
	return out
}

// ToTimeConditions parses a statement's timeConditions array. Entries missing a key, op, or target are
// skipped.
func ToTimeConditions(v any) []policyengine.TimeCondition {
	var out []policyengine.TimeCondition
	for _, it := range toSlice(v) {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		key, op, target := str(m["key"]), str(m["op"]), str(m["target"])
		if key == "" || op == "" || target == "" {
			continue
		}
		out = append(out, policyengine.TimeCondition{Key: key, Op: op, Target: target})
	}
	return out
}

func toSlice(v any) []any { s, _ := v.([]any); return s }

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
