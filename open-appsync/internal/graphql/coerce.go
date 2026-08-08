package graphql

// Variable coercion: validate and normalize the supplied variables against their declared operation
// types BEFORE any resolver runs — check each value against its *wrapped* type (`ID!` rejects null,
// `[Post!]!` rejects a bare null, an enum rejects an off-list value, an input object rejects
// unknown/missing-required fields), apply defaults, and reject with a validation error. The GraphQL spec
// pins these rules, so there is a single right answer.
//
// Custom scalars go through a NEUTRAL validation seam: the core validates *that a scalar validates* by
// consulting a per-scalar-name validator, but knows nothing about any vendor's scalar. Specific rules
// (AWSDateTime format, AWSJSON well-formedness, …) live at the edge as registered ScalarValidators (see
// internal/awsscalars), wired in by the server — not baked into this core. A custom scalar with no
// registered validator passes through unvalidated.

import (
	"fmt"
	"math"
	"strconv"
)

// ScalarValidator validates and may normalize a value for a custom scalar, returning the coerced value
// or an error. Registered per scalar name; keeps the engine core vendor-neutral.
type ScalarValidator func(value any) (any, error)

// coercer coerces values against the type graph, consulting the scalar validators for custom scalars.
type coercer struct {
	schema     *Schema
	validators map[string]ScalarValidator
}

// variables coerces the raw variables against the operation's variable definitions. Only declared
// variables appear in the result; a missing required variable, a type mismatch, or a bad default is a
// validation error.
func (c coercer) variables(defs []variableDef, vars map[string]any) (map[string]any, *GqlError) {
	out := map[string]any{}
	for _, d := range defs {
		raw, provided := vars[d.name]
		if !provided {
			if d.hasDefault {
				cv, err := c.value(evalValue(d.defaultValue, nil), d.typ, "$"+d.name+" (default)")
				if err != nil {
					return nil, err
				}
				out[d.name] = cv
				continue
			}
			if d.typ.kind == kindNonNull {
				return nil, varErr("variable $%s of required type %s was not provided", d.name, typeRefString(d.typ))
			}
			continue // nullable, no default → simply unset
		}
		cv, err := c.value(raw, d.typ, "$"+d.name)
		if err != nil {
			return nil, err
		}
		out[d.name] = cv
	}
	return out, nil
}

// value coerces one value against a (possibly wrapped) type reference.
func (c coercer) value(val any, tr typeRef, path string) (any, *GqlError) {
	switch tr.kind {
	case kindNonNull:
		if val == nil {
			return nil, varErr("%s must not be null (type %s)", path, typeRefString(tr))
		}
		return c.value(val, *tr.elem, path)
	case kindList:
		if val == nil {
			return nil, nil
		}
		if list, ok := val.([]any); ok {
			out := make([]any, len(list))
			for i, e := range list {
				cv, err := c.value(e, *tr.elem, fmt.Sprintf("%s[%d]", path, i))
				if err != nil {
					return nil, err
				}
				out[i] = cv
			}
			return out, nil
		}
		// A single value where a list is expected coerces to a one-element list (spec list input coercion).
		cv, err := c.value(val, *tr.elem, path)
		if err != nil {
			return nil, err
		}
		return []any{cv}, nil
	default:
		return c.named(val, tr.name, path)
	}
}

// named coerces a value against a named type: the built-in scalars by name, then (with a schema) enums,
// input objects, and custom scalars (via a registered validator). A nullable named type accepts null.
func (c coercer) named(val any, name, path string) (any, *GqlError) {
	if val == nil {
		return nil, nil
	}
	switch name {
	case "Int":
		f, ok := toFloat(val)
		if !ok || f != math.Trunc(f) || math.IsInf(f, 0) {
			return nil, varErr("%s expected an Int, got %s", path, jsonKind(val))
		}
		return f, nil
	case "Float":
		f, ok := toFloat(val)
		if !ok {
			return nil, varErr("%s expected a Float, got %s", path, jsonKind(val))
		}
		return f, nil
	case "String":
		s, ok := val.(string)
		if !ok {
			return nil, varErr("%s expected a String, got %s", path, jsonKind(val))
		}
		return s, nil
	case "Boolean":
		b, ok := val.(bool)
		if !ok {
			return nil, varErr("%s expected a Boolean, got %s", path, jsonKind(val))
		}
		return b, nil
	case "ID":
		switch v := val.(type) {
		case string:
			return v, nil
		case float64:
			if v == math.Trunc(v) {
				return strconv.FormatFloat(v, 'f', -1, 64), nil // ID accepts an Int, serialized as a String
			}
		case int:
			return strconv.Itoa(v), nil
		case int64:
			return strconv.FormatInt(v, 10), nil
		}
		return nil, varErr("%s expected an ID (String or Int), got %s", path, jsonKind(val))
	}
	if c.schema != nil {
		if nt := c.schema.types[name]; nt != nil {
			switch nt.kind {
			case kindEnum:
				s, ok := val.(string)
				if !ok {
					return nil, varErr("%s expected a value of enum %s, got %s", path, name, jsonKind(val))
				}
				for _, ev := range nt.enumValues {
					if ev.name == s {
						return s, nil
					}
				}
				return nil, varErr("%s: %q is not a valid value for enum %s", path, s, name)
			case kindInputObject:
				return c.inputObject(val, nt, path)
			case kindScalar:
				// Custom scalar: run its registered validator if one exists (neutral seam); otherwise pass
				// through — value validation is opt-in per scalar, not baked into the core.
				if v, ok := c.validators[name]; ok {
					out, err := v(val)
					if err != nil {
						return nil, varErr("%s: invalid %s: %v", path, name, err)
					}
					return out, nil
				}
			}
		}
	}
	// Unknown type / no schema / unvalidated custom scalar: pass through.
	return val, nil
}

// inputObject coerces a value against an input object type: every field is coerced against its declared
// type, unknown fields are rejected, missing required (NON_NULL, no default) fields are an error, and
// declared defaults are applied for absent fields.
func (c coercer) inputObject(val any, nt *namedType, path string) (any, *GqlError) {
	m, ok := val.(map[string]any)
	if !ok {
		return nil, varErr("%s expected input object %s, got %s", path, nt.name, jsonKind(val))
	}
	declared := map[string]inputValueDef{}
	for _, f := range nt.inputFields {
		declared[f.name] = f
	}
	for k := range m {
		if _, ok := declared[k]; !ok {
			return nil, varErr("%s.%s: unknown field on input object %s", path, k, nt.name)
		}
	}
	out := map[string]any{}
	for _, f := range nt.inputFields {
		fieldPath := path + "." + f.name
		raw, provided := m[f.name]
		if !provided {
			if f.hasDefault {
				cv, err := c.value(evalValue(f.defaultVal, nil), f.typ, fieldPath+" (default)")
				if err != nil {
					return nil, err
				}
				out[f.name] = cv
				continue
			}
			if f.typ.kind == kindNonNull {
				return nil, varErr("%s: required field %q (%s) is missing", path, f.name, typeRefString(f.typ))
			}
			continue
		}
		cv, err := c.value(raw, f.typ, fieldPath)
		if err != nil {
			return nil, err
		}
		out[f.name] = cv
	}
	return out, nil
}

// typeRefString renders a type reference in GraphQL notation (Int, [Post!]!) for error messages.
func typeRefString(tr typeRef) string {
	switch tr.kind {
	case kindNonNull:
		return typeRefString(*tr.elem) + "!"
	case kindList:
		return "[" + typeRefString(*tr.elem) + "]"
	default:
		return tr.name
	}
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	default:
		return 0, false
	}
}

// jsonKind names a value's JSON-ish kind for error messages.
func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "a String"
	case bool:
		return "a Boolean"
	case float64, int, int64:
		return "a number"
	case []any:
		return "a list"
	case map[string]any:
		return "an object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// varErr builds a variable/validation GraphQL error carrying the ValidationError errorType.
func varErr(format string, a ...any) *GqlError {
	return &GqlError{Message: "graphql: " + fmt.Sprintf(format, a...), ErrorType: "ValidationError"}
}
