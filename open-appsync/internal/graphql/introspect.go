package graphql

// Introspection: read the type graph back out in the shape __schema / __type mandate.
//
// The whole result is materialized as plain map[string]any / []any so the executor's existing project()
// walks it exactly like any resolver result — introspection is a reader, not a special execution path.
//
// Cycle safety (the one subtlety): a field's type reference to a named type is the SAME shared __Type
// map object as that type's entry in __schema.types (Go maps are references). So the graph has cycles
// (User.posts → [Post] → Post.author → User → …), but project() only descends SELECTED fields, and a
// finite introspection query selects a finite path — plus the hostile-load MaxDepth guard already caps
// selection nesting. No copy is ever made recursively, so building the graph terminates and querying it
// terminates. LIST/NON_NULL wrappers are fresh little maps whose ofType eventually reaches a shared
// named object.

// buildIntrospection materializes one shared __Type object per named type, then the __schema object.
func (s *Schema) buildIntrospection() {
	s.typeObjs = make(map[string]map[string]any, len(s.types))
	// First pass: create the shell objects so refObj can point at them while we fill fields.
	for name, nt := range s.types {
		s.typeObjs[name] = map[string]any{"kind": nt.kind, "name": nt.name}
	}
	// Second pass: fill each object's members (their type refs resolve to the shells from pass one).
	for name, nt := range s.types {
		obj := s.typeObjs[name]
		obj["description"] = nilIfEmpty(nt.description)
		obj["ofType"] = nil // named types never have an ofType

		switch nt.kind {
		case kindObject, kindInterface:
			obj["fields"] = s.fieldObjs(nt.fields)
			obj["interfaces"] = s.refList(nt.interfaces) // [] when none, per spec (non-null list)
		default:
			obj["fields"] = nil
			obj["interfaces"] = nil
		}
		switch nt.kind {
		case kindInputObject:
			obj["inputFields"] = s.inputValueObjs(nt.inputFields)
		default:
			obj["inputFields"] = nil
		}
		switch nt.kind {
		case kindEnum:
			obj["enumValues"] = s.enumValueObjs(nt.enumValues)
		default:
			obj["enumValues"] = nil
		}
		switch nt.kind {
		case kindUnion, kindInterface:
			obj["possibleTypes"] = s.refList(nt.possibleTypes)
		default:
			obj["possibleTypes"] = nil
		}
	}
	s.schemaObj = map[string]any{
		"queryType":        s.rootObj(s.queryType),
		"mutationType":     s.rootObj(s.mutationType),
		"subscriptionType": s.rootObj(s.subscriptionType),
		"types":            s.allTypeObjs(),
		"directives":       standardDirectives(),
		"description":      nil,
	}
}

func (s *Schema) rootObj(name string) any {
	if name == "" {
		return nil
	}
	return s.typeObjs[name]
}

func (s *Schema) allTypeObjs() []any {
	names := s.sortedTypeNames()
	out := make([]any, 0, len(names))
	for _, n := range names {
		out = append(out, s.typeObjs[n])
	}
	return out
}

// refObj turns a (possibly wrapped) type reference into a __Type object. Named → the shared full object
// (so name/kind resolve and, if a client selects deeper, its fields resolve too). LIST/NON_NULL → a
// fresh wrapper whose ofType is the inner ref.
func (s *Schema) refObj(tr typeRef) any {
	switch tr.kind {
	case kindList:
		return map[string]any{"kind": kindList, "name": nil, "ofType": s.refObj(*tr.elem)}
	case kindNonNull:
		return map[string]any{"kind": kindNonNull, "name": nil, "ofType": s.refObj(*tr.elem)}
	default:
		if obj, ok := s.typeObjs[tr.name]; ok {
			return obj
		}
		// A reference to an undeclared type: report it as a bare named shell rather than crash, so an
		// incomplete SDL still introspects (the missing type simply won't appear in `types`).
		return map[string]any{"kind": kindScalar, "name": tr.name, "ofType": nil}
	}
}

func (s *Schema) refList(names []string) []any {
	out := make([]any, 0, len(names))
	for _, n := range names {
		out = append(out, s.refObj(typeRef{name: n}))
	}
	return out
}

func (s *Schema) fieldObjs(fields []fieldDef) []any {
	out := make([]any, 0, len(fields))
	for _, f := range fields {
		out = append(out, map[string]any{
			"name":              f.name,
			"description":       nilIfEmpty(f.description),
			"args":              s.inputValueObjs(f.args),
			"type":              s.refObj(f.typ),
			"isDeprecated":      f.deprecated,
			"deprecationReason": nilIfEmpty(f.deprecationReason),
		})
	}
	return out
}

func (s *Schema) inputValueObjs(ivs []inputValueDef) []any {
	out := make([]any, 0, len(ivs))
	for _, iv := range ivs {
		var def any
		if iv.defaultValue != "" {
			def = iv.defaultValue
		}
		out = append(out, map[string]any{
			"name":         iv.name,
			"description":  nilIfEmpty(iv.description),
			"type":         s.refObj(iv.typ),
			"defaultValue": def,
		})
	}
	return out
}

func (s *Schema) enumValueObjs(vs []enumValueDef) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, map[string]any{
			"name":              v.name,
			"description":       nilIfEmpty(v.description),
			"isDeprecated":      v.deprecated,
			"deprecationReason": nilIfEmpty(v.deprecationReason),
		})
	}
	return out
}

// introspectSchema returns the __schema object (memoized).
func (s *Schema) introspectSchema() map[string]any { return s.schemaObj }

// introspectType returns the __Type object for a name, or nil if there is no such type (which the spec
// requires __type(name:) to report as null).
func (s *Schema) introspectType(name string) any {
	if obj, ok := s.typeObjs[name]; ok {
		return obj
	}
	return nil
}

// standardDirectives reports the three directives every GraphQL schema declares (spec §3.13). @deprecated
// is honored (fields/enum values carry isDeprecated/deprecationReason); execution of @skip/@include is a
// separate rung — they are reported here because the introspection schema mandates the directive list,
// and every conformant schema includes these built-ins.
func standardDirectives() []any {
	boolNonNull := map[string]any{"kind": kindNonNull, "name": nil, "ofType": map[string]any{"kind": kindScalar, "name": "Boolean", "ofType": nil}}
	stringType := map[string]any{"kind": kindScalar, "name": "String", "ofType": nil}
	ifArg := func() []any {
		return []any{map[string]any{"name": "if", "description": nil, "type": boolNonNull, "defaultValue": nil}}
	}
	return []any{
		map[string]any{
			"name": "skip", "description": "Directs the executor to skip this field or fragment when the `if` argument is true.",
			"locations": []any{"FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"}, "args": ifArg(), "isRepeatable": false,
		},
		map[string]any{
			"name": "include", "description": "Directs the executor to include this field or fragment only when the `if` argument is true.",
			"locations": []any{"FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"}, "args": ifArg(), "isRepeatable": false,
		},
		map[string]any{
			"name": "deprecated", "description": "Marks an element of a GraphQL schema as no longer supported.",
			"locations":    []any{"FIELD_DEFINITION", "ENUM_VALUE"},
			"args":         []any{map[string]any{"name": "reason", "description": nil, "type": stringType, "defaultValue": `"No longer supported"`}},
			"isRepeatable": false,
		},
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
