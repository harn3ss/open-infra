// CloudFormation template ingestion for the open-infra CFN engine (Phase 1).
// Parses a template from JSON or YAML — including the YAML short forms (!Ref, !GetAtt,
// !Sub, …) — into a uniform map[string]any, then into a typed Template. Everything
// downstream (intrinsics, mapping, ordering) works on the normalized structure, so JSON
// and YAML templates are handled identically.
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template is a parsed CloudFormation template (the sections Phase 1 reads).
type Template struct {
	Transform  any                  // presence => a macro/SAM template (unsupported v1)
	Parameters map[string]Parameter // name -> {Type, Default, ...}
	Mappings   map[string]any       // name -> { topKey -> { secondKey -> value } }
	Conditions map[string]any       // name -> a condition intrinsic
	Resources  map[string]Resource  // logical id -> resource
	Outputs    map[string]any       // name -> { Value, ... }
	rawOrder   []string             // resource logical ids in template order (stable output)
}

type Parameter struct {
	Type    string
	Default any
	hasDef  bool
}

type Resource struct {
	Type       string
	Properties map[string]any
	DependsOn  []string
	Condition  string
}

// Parse reads a CloudFormation template from JSON or YAML bytes.
func Parse(data []byte) (*Template, error) {
	root, err := parseAny(data)
	if err != nil {
		return nil, err
	}
	m, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template root is not an object")
	}
	t := &Template{
		Parameters: map[string]Parameter{},
		Mappings:   map[string]any{},
		Conditions: map[string]any{},
		Resources:  map[string]Resource{},
		Outputs:    map[string]any{},
	}
	t.Transform = m["Transform"]
	if mp, ok := m["Mappings"].(map[string]any); ok {
		t.Mappings = mp
	}
	if c, ok := m["Conditions"].(map[string]any); ok {
		t.Conditions = c
	}
	if o, ok := m["Outputs"].(map[string]any); ok {
		t.Outputs = o
	}
	if p, ok := m["Parameters"].(map[string]any); ok {
		for name, pv := range p {
			pm, _ := pv.(map[string]any)
			param := Parameter{}
			if ty, ok := pm["Type"].(string); ok {
				param.Type = ty
			}
			if d, ok := pm["Default"]; ok {
				param.Default, param.hasDef = d, true
			}
			t.Parameters[name] = param
		}
	}
	res, ok := m["Resources"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template has no Resources section")
	}
	for id, rv := range res {
		rm, ok := rv.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("resource %q is not an object", id)
		}
		ty, _ := rm["Type"].(string)
		if ty == "" {
			return nil, fmt.Errorf("resource %q has no Type", id)
		}
		r := Resource{Type: ty}
		if props, ok := rm["Properties"].(map[string]any); ok {
			r.Properties = props
		}
		if cond, ok := rm["Condition"].(string); ok {
			r.Condition = cond
		}
		switch d := rm["DependsOn"].(type) {
		case string:
			r.DependsOn = []string{d}
		case []any:
			for _, e := range d {
				if s, ok := e.(string); ok {
					r.DependsOn = append(r.DependsOn, s)
				}
			}
		}
		t.Resources[id] = r
		t.rawOrder = append(t.rawOrder, id)
	}
	return t, nil
}

// parseAny decodes JSON directly; otherwise decodes YAML (expanding CFN short-form tags)
// into the same map[string]any shape JSON produces.
func parseAny(data []byte) (any, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("invalid JSON template: %w", err)
		}
		return v, nil
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("invalid YAML template: %w", err)
	}
	if len(node.Content) == 0 {
		return nil, fmt.Errorf("empty template")
	}
	return yamlNodeToAny(node.Content[0])
}

// yamlNodeToAny converts a yaml.Node tree to map[string]any/[]any/scalars, rewriting CFN
// short-form tags (!Ref, !GetAtt, !Sub, !Join, !If, …) into their long form so the rest of
// the engine only ever sees the canonical {"Fn::X": …} / {"Ref": …} representation. A
// short-form tag can sit on a scalar (!Ref foo), a sequence (!Join [d, list]) or a mapping,
// so the tag is handled before the node kind.
func yamlNodeToAny(n *yaml.Node) (any, error) {
	if n.Kind == yaml.DocumentNode {
		return yamlNodeToAny(n.Content[0])
	}
	if n.Kind == yaml.AliasNode {
		return yamlNodeToAny(n.Alias)
	}
	if fn := shortFormTag(n.Tag); fn != "" {
		if n.Kind == yaml.ScalarNode {
			return wrapShortForm(fn, n.Value), nil // short-form scalar arg is a raw string
		}
		inner, err := plainNode(n)
		if err != nil {
			return nil, err
		}
		return wrapShortForm(fn, inner), nil
	}
	return plainNode(n)
}

func plainNode(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, err := yamlNodeToAny(n.Content[i])
			if err != nil {
				return nil, err
			}
			v, err := yamlNodeToAny(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m[fmt.Sprint(k)] = v
		}
		return m, nil
	case yaml.SequenceNode:
		arr := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlNodeToAny(c)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	case yaml.ScalarNode:
		return scalarValue(n)
	}
	return nil, fmt.Errorf("unsupported YAML node kind")
}

// shortFormTag maps a YAML custom tag (!Ref, !Sub, …) to its long-form key, or "" if the
// tag is a normal YAML type tag. Standard resolved tags are double-bang (!!map, !!str, !!seq)
// and must NOT be treated as CFN short forms — only single-bang custom tags are.
func shortFormTag(tag string) string {
	if !strings.HasPrefix(tag, "!") || strings.HasPrefix(tag, "!!") {
		return ""
	}
	name := strings.TrimPrefix(tag, "!")
	switch name {
	case "Ref":
		return "Ref"
	case "Condition":
		return "Condition"
	default:
		return "Fn::" + name
	}
}

// wrapShortForm builds the long form. !GetAtt takes a dotted string that becomes a list;
// !Sub / !Ref etc. keep their single argument.
func wrapShortForm(key string, inner any) any {
	if key == "Fn::GetAtt" {
		if s, ok := inner.(string); ok {
			parts := strings.SplitN(s, ".", 2)
			as := make([]any, len(parts)) // []any, so the resolver's []any type switch matches
			for i, p := range parts {
				as[i] = p
			}
			return map[string]any{key: as}
		}
	}
	return map[string]any{key: inner}
}

func scalarValue(n *yaml.Node) (any, error) {
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
