package cfn

import (
	"context"
	"sort"
)

// TemplateResource is one resource of a deployed stack's template as the stack resolves it.
type TemplateResource struct {
	LogicalID string
	Type      string
	// Ref is the resource's Ref value where the engine derives it without a deployed object (a CloudFront
	// policy's id, an ACM certificate's ARN — resource_attrs.go); "" when it does not resolve that way.
	Ref string
	// Attrs are its Fn::GetAtt attributes that resolve the same way (an origin access identity's
	// S3CanonicalUserId, a distribution's DomainName).
	Attrs map[string]string
	// Properties are its properties with intrinsics resolved as the stack resolved them: an in-stack Ref
	// or Fn::GetAtt that resolves statically is its value; one that does not is left as a placeholder.
	Properties map[string]any
}

// TemplateResources resolves the included resources of the given types in a stack's template, with the
// parameters and exports it was deployed with — the Ref values and properties the stack's own create
// resolved. A front door answers from it for a resource that provisions nothing of its own (it composes
// into another kind, so the stack record keeps no entry for it), such as a CloudFront policy or an ACM
// certificate. A NoEcho parameter's value is not in params, so a property fed by one stays unresolved.
func TemplateResources(data []byte, params, exports map[string]string, stackName string, types ...string) ([]TemplateResource, error) {
	t, err := Parse(data)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, typ := range types {
		want[typ] = true
	}
	r := newResolver(t, resolveParams(t, params), strMapToAny(exports), pseudoParams(stackName))
	r.evalConditions()
	sctx := &stackCtx{template: t, resolver: r, namer: newPhysNamer(stackName, nil)}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, sctx) }
	r.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, sctx) }
	d := &deployedAttrs{ctx: context.Background(), sctx: sctx,
		byID: map[string]StackResource{}, status: map[string]map[string]any{}, missed: map[string]bool{}}
	r.deployed = d.lookup
	ids := make([]string, 0, len(t.Resources))
	for id := range t.Resources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []TemplateResource
	for _, id := range ids {
		res := t.Resources[id]
		if !want[res.Type] || !sctx.included(res) {
			continue
		}
		e := d.env(id, res)
		tr := TemplateResource{LogicalID: id, Type: res.Type, Properties: e.props, Attrs: map[string]string{}}
		if v, ok := resolveResourceAttr(e, ""); ok {
			tr.Ref = v
		}
		for _, a := range AttrNames(res.Type) {
			if v, ok := resolveResourceAttr(e, a); ok {
				tr.Attrs[a] = v
			}
		}
		out = append(out, tr)
	}
	return out, nil
}
