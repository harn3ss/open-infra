// Nested-stack flattening.
//
// An AWS::CloudFormation::Stack references a CHILD template (TemplateURL) + passes it Parameters, and
// the parent reads the child's Outputs via Fn::GetAtt <Stack>.Outputs.<Key>. open-infra has no nested
// sub-stack runtime; instead FlattenNested INLINES each child's resources into the parent as ONE flat
// template (the whole tree becomes one open-infra stack), which then flows through the existing
// plan/deploy/update/destroy/drift machinery unchanged. The parent's Outputs-GetAtt resolves to the
// child's Output expression, inlined.
//
// FAIL-CLOSED is the cardinal rule: anything that cannot be rewritten CORRECTLY refuses (returns an
// error), so a flattened template is never a MIS-WIRED one. v1 handles the common nested-stack shape —
// Parameters passed parent->child, in-child Ref/Fn::GetAtt/DependsOn (prefixed), and child Outputs
// exposed — and refuses what it can't safely rewrite (Fn::Sub in a child, child Conditions/Mappings,
// a nested-nested stack, an intrinsic TemplateURL, an unmappable Ref/GetAtt, an id collision, an
// unbound Parameter). Those refusals are honest ceilings, not silent partials.
package cfn

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// TemplateResolver fetches a nested stack's child template by its TemplateURL. In AWS the URL is an S3
// object; the CLI resolves it to a local file, the aws-shim would fetch it from MinIO. A nil resolver
// means nested stacks are unsupported on this path (they refuse rather than guess).
type TemplateResolver interface {
	Resolve(templateURL string) ([]byte, error)
}

// FlattenNested returns `data` with every AWS::CloudFormation::Stack inlined. A template with no nested
// stack is returned byte-for-byte unchanged (the common case is never touched). See the file header.
func FlattenNested(data []byte, resolve TemplateResolver) ([]byte, error) {
	root, err := parseAny(data)
	if err != nil {
		return nil, err
	}
	m, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template root is not an object")
	}
	resources, _ := m["Resources"].(map[string]any)
	stacks := make([]string, 0)
	for id, rv := range resources {
		if rm, ok := rv.(map[string]any); ok {
			if ty, _ := rm["Type"].(string); ty == "AWS::CloudFormation::Stack" {
				stacks = append(stacks, id)
			}
		}
	}
	if len(stacks) == 0 {
		return data, nil // no nested stacks — return the original bytes untouched
	}
	if resolve == nil {
		return nil, fmt.Errorf("nested stacks (AWS::CloudFormation::Stack: %s) need a template resolver; this deploy path cannot fetch child templates (use the engine path that provides one)", strings.Join(sortedCopy(stacks), ", "))
	}
	sort.Strings(stacks) // deterministic flatten order

	childOutputs := map[string]map[string]any{} // stackID -> outputName -> rewritten Value expression
	for _, s := range stacks {
		sres, _ := resources[s].(map[string]any)
		sprops, _ := sres["Properties"].(map[string]any)
		if err := inlineOneStack(s, sprops, resources, resolve, childOutputs); err != nil {
			return nil, err
		}
		delete(resources, s) // the Stack resource itself is replaced by the inlined children
	}

	// Rewrite the PARENT's Fn::GetAtt <Stack>.Outputs.<Key> references to the child's (inlined) Output
	// expression. Done after all stacks are inlined so a parent can reference any child's outputs.
	rewritten, err := rewriteOutputRefs(m, childOutputs)
	if err != nil {
		return nil, err
	}
	return marshalTemplate(rewritten)
}

// inlineOneStack inlines a single AWS::CloudFormation::Stack `s` into `resources`, recording its exposed
// Outputs in childOutputs[s]. Fail-closed throughout.
func inlineOneStack(s string, sprops, resources map[string]any, resolve TemplateResolver, childOutputs map[string]map[string]any) error {
	tu, ok := sprops["TemplateURL"].(string)
	if !ok || tu == "" {
		return fmt.Errorf("%s: TemplateURL must be a literal string (an intrinsic TemplateURL can't be resolved at flatten time)", s)
	}
	childBytes, err := resolve.Resolve(tu)
	if err != nil {
		return fmt.Errorf("%s: resolving TemplateURL %q: %w", s, tu, err)
	}
	croot, err := parseAny(childBytes)
	if err != nil {
		return fmt.Errorf("%s: child template %q: %w", s, tu, err)
	}
	child, ok := croot.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: child template root is not an object", s)
	}
	// Fail-closed carve-outs — constructs this v1 cannot rewrite correctly.
	if child["Transform"] != nil {
		return fmt.Errorf("%s: child template uses Transform (macro/SAM) — not supported", s)
	}
	if mustMap(child["Conditions"]) != nil && len(mustMap(child["Conditions"])) > 0 {
		return fmt.Errorf("%s: child template uses Conditions — not supported in a nested stack v1 (flatten the child without Conditions)", s)
	}
	if mustMap(child["Mappings"]) != nil && len(mustMap(child["Mappings"])) > 0 {
		return fmt.Errorf("%s: child template uses Mappings — not supported in a nested stack v1", s)
	}
	childRes := mustMap(child["Resources"])
	if len(childRes) == 0 {
		return fmt.Errorf("%s: child template has no Resources", s)
	}
	for rid, rv := range childRes {
		if rm, ok := rv.(map[string]any); ok {
			if ty, _ := rm["Type"].(string); ty == "AWS::CloudFormation::Stack" {
				return fmt.Errorf("%s: child resource %s is itself a nested stack — nested-nested stacks are not supported in v1", s, rid)
			}
		}
	}

	// Bind the child's Parameters: value = the parent's Stack.Properties.Parameters[name], else the
	// child's Default. An unbound Parameter refuses (we won't flatten against an unknown value).
	stackParams := mustMap(sprops["Parameters"])
	params := map[string]any{}
	for pname, pdef := range mustMap(child["Parameters"]) {
		if v, ok := stackParams[pname]; ok {
			params[pname] = v
			continue
		}
		pm := mustMap(pdef)
		if d, ok := pm["Default"]; ok {
			params[pname] = d
			continue
		}
		return fmt.Errorf("%s: child Parameter %q has no value from the parent and no Default", s, pname)
	}

	// Prefix every child resource logical id with the stack id (collision-checked) so in-child refs stay
	// unambiguous in the merged template.
	idMap := map[string]string{}
	for rid := range childRes {
		p := s + rid
		if _, clash := resources[p]; clash {
			return fmt.Errorf("%s: inlining child resource %s collides with existing id %s", s, rid, p)
		}
		idMap[rid] = p
	}
	// Rewrite + merge the child's resources.
	for rid, rv := range childRes {
		rm := mustMap(rv)
		nr, err := rewriteResource(rm, idMap, params)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", s, rid, err)
		}
		resources[idMap[rid]] = nr
	}
	// Record the child's Outputs (rewritten), for the parent's Fn::GetAtt <s>.Outputs.<key>.
	outs := map[string]any{}
	for oname, ov := range mustMap(child["Outputs"]) {
		om := mustMap(ov)
		rv, err := rewriteValue(om["Value"], idMap, params)
		if err != nil {
			return fmt.Errorf("%s: Output %q: %w", s, oname, err)
		}
		outs[oname] = rv
	}
	childOutputs[s] = outs
	return nil
}

// rewriteResource rewrites one child resource's rewritable members (Properties, DependsOn), prefixing
// in-child references. A resource-level Condition refuses (child Conditions are unsupported).
func rewriteResource(rm map[string]any, idMap map[string]string, params map[string]any) (map[string]any, error) {
	if _, has := rm["Condition"]; has {
		return nil, fmt.Errorf("a resource Condition in a nested child is not supported in v1")
	}
	out := map[string]any{}
	for k, v := range rm {
		switch k {
		case "Properties":
			nv, err := rewriteValue(v, idMap, params)
			if err != nil {
				return nil, err
			}
			out[k] = nv
		case "DependsOn":
			dep, err := rewriteDependsOn(v, idMap)
			if err != nil {
				return nil, err
			}
			out[k] = dep
		default:
			out[k] = v // Type, DeletionPolicy, etc. — carried as-is
		}
	}
	return out, nil
}

// rewriteValue deep-walks a property value, rewriting Ref/Fn::GetAtt that target in-child resources
// (prefixed), substituting bound child Parameters, keeping pseudo-parameters, and FAIL-CLOSING on
// anything it cannot map (an unknown Ref/GetAtt, or Fn::Sub which it does not rewrite in v1).
func rewriteValue(v any, idMap map[string]string, params map[string]any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 1 {
			for k, arg := range x {
				switch {
				case k == "Ref":
					name, _ := arg.(string)
					if np, ok := idMap[name]; ok {
						return map[string]any{"Ref": np}, nil
					}
					if pv, ok := params[name]; ok {
						return pv, nil // substitute the parent-supplied Parameter value
					}
					if strings.HasPrefix(name, "AWS::") {
						return x, nil // pseudo-parameter (AWS::Region, AWS::AccountId, …)
					}
					return nil, fmt.Errorf("Ref %q can't be mapped (not a child resource, bound Parameter, or pseudo-parameter)", name)
				case k == "Fn::GetAtt":
					id, rest, ok := splitGetAtt(arg)
					if !ok {
						return nil, fmt.Errorf("malformed Fn::GetAtt %v", arg)
					}
					if np, ok := idMap[id]; ok {
						return map[string]any{"Fn::GetAtt": []any{np, rest}}, nil
					}
					if strings.HasPrefix(id, "AWS::") {
						return x, nil
					}
					return nil, fmt.Errorf("Fn::GetAtt on %q can't be mapped (not a child resource)", id)
				case k == "Fn::Sub":
					return nil, fmt.Errorf("Fn::Sub in a nested child is not supported in v1 (its ${…} references can't be safely rewritten) — author the child without Fn::Sub")
				}
			}
		}
		out := map[string]any{}
		for k, vv := range x {
			nv, err := rewriteValue(vv, idMap, params)
			if err != nil {
				return nil, err
			}
			out[k] = nv
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			nv, err := rewriteValue(e, idMap, params)
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil
	default:
		return v, nil
	}
}

// rewriteDependsOn prefixes each DependsOn entry (which must name an in-child resource).
func rewriteDependsOn(v any, idMap map[string]string) (any, error) {
	one := func(s string) (string, error) {
		if np, ok := idMap[s]; ok {
			return np, nil
		}
		return "", fmt.Errorf("DependsOn %q is not an in-child resource", s)
	}
	switch d := v.(type) {
	case string:
		return one(d)
	case []any:
		out := make([]any, 0, len(d))
		for _, e := range d {
			s, _ := e.(string)
			np, err := one(s)
			if err != nil {
				return nil, err
			}
			out = append(out, np)
		}
		return out, nil
	}
	return nil, fmt.Errorf("malformed DependsOn %v", v)
}

// rewriteOutputRefs replaces every Fn::GetAtt <Stack>.Outputs.<Key> in the (stack-removed) parent with
// the child's inlined Output expression. Fail-closed: a reference to an output that no inlined stack
// exposes refuses.
func rewriteOutputRefs(v any, childOutputs map[string]map[string]any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 1 {
			if arg, ok := x["Fn::GetAtt"]; ok {
				id, rest, ok := splitGetAtt(arg)
				if ok && strings.HasPrefix(rest, "Outputs.") {
					if outs, isStack := childOutputs[id]; isStack {
						key := strings.TrimPrefix(rest, "Outputs.")
						val, has := outs[key]
						if !has {
							return nil, fmt.Errorf("Fn::GetAtt %s.%s: the nested stack exposes no Output %q", id, rest, key)
						}
						return val, nil
					}
				}
			}
		}
		out := map[string]any{}
		for k, vv := range x {
			nv, err := rewriteOutputRefs(vv, childOutputs)
			if err != nil {
				return nil, err
			}
			out[k] = nv
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			nv, err := rewriteOutputRefs(e, childOutputs)
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil
	default:
		return v, nil
	}
}

// splitGetAtt normalizes an Fn::GetAtt argument ([id, attr...] or "id.attr") to (id, attrPath, ok).
func splitGetAtt(arg any) (id, rest string, ok bool) {
	switch a := arg.(type) {
	case []any:
		if len(a) >= 2 {
			id, _ = a[0].(string)
			parts := make([]string, 0, len(a)-1)
			for _, p := range a[1:] {
				parts = append(parts, fmt.Sprint(p))
			}
			return id, strings.Join(parts, "."), id != ""
		}
	case string:
		if i := strings.Index(a, "."); i > 0 {
			return a[:i], a[i+1:], true
		}
	}
	return "", "", false
}

// marshalTemplate renders the flattened template back to bytes. JSON is a valid CloudFormation
// template body, and parseAny decodes JSON directly, so the engine re-parses it unchanged.
func marshalTemplate(m any) ([]byte, error) { return json.Marshal(m) }

func mustMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func sortedCopy(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}
