// Package apigwschema is the shared API Gateway request-validation logic used by BOTH the
// apigw-validator tier (HttpApi v2) and the aws-shim REST API v1 data plane, so a request Model is
// validated identically on both surfaces (#295 — "keep validators/models consistent with the v2
// apigw-validator tier"). It implements the JSON Schema keyword subset API Gateway Models use in
// practice: type, required, properties, items, enum, minimum/maximum, minLength/maxLength, pattern,
// additionalProperties:false. Unsupported keywords are ignored (documented) — never a silent pass of
// something that should fail.
package apigwschema

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// ValidateBody parses body as JSON and validates it against schema (the AWS "validate request body
// against a Model" behavior). An empty schema imposes no constraint. Returns "" when valid, else a
// human-readable reason.
func ValidateBody(schema map[string]any, body []byte) string {
	if len(schema) == 0 {
		return ""
	}
	if len(body) == 0 {
		return "request body is required and must match the model"
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return "request body is not valid JSON"
	}
	return ValidateSchema(schema, v, "body")
}

// ValidateSchema returns "" when v satisfies schema, else a human-readable reason naming the failing
// path.
func ValidateSchema(schema map[string]any, v any, path string) string {
	if t, ok := schema["type"].(string); ok {
		if reason := checkType(t, v, path); reason != "" {
			return reason
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		if !anyEqual(enum, v) {
			return path + " must be one of the allowed values"
		}
	}
	switch val := v.(type) {
	case map[string]any:
		if req, ok := schema["required"].([]any); ok {
			for _, rn := range req {
				if name, ok := rn.(string); ok {
					if _, present := val[name]; !present {
						return path + "." + name + " is required"
					}
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		if addl, ok := schema["additionalProperties"].(bool); ok && !addl && props != nil {
			for k := range val {
				if _, declared := props[k]; !declared {
					return path + "." + k + " is not an allowed property"
				}
			}
		}
		for name, sub := range props {
			if subSchema, ok := sub.(map[string]any); ok {
				if child, present := val[name]; present {
					if reason := ValidateSchema(subSchema, child, path+"."+name); reason != "" {
						return reason
					}
				}
			}
		}
	case []any:
		if items, ok := schema["items"].(map[string]any); ok {
			for i, el := range val {
				if reason := ValidateSchema(items, el, fmt.Sprintf("%s[%d]", path, i)); reason != "" {
					return reason
				}
			}
		}
	case string:
		if reason := checkString(schema, val, path); reason != "" {
			return reason
		}
	case float64:
		if reason := checkNumber(schema, val, path); reason != "" {
			return reason
		}
	}
	return ""
}

func checkType(t string, v any, path string) string {
	ok := false
	switch t {
	case "object":
		_, ok = v.(map[string]any)
	case "array":
		_, ok = v.([]any)
	case "string":
		_, ok = v.(string)
	case "number":
		_, ok = v.(float64)
	case "integer":
		f, isF := v.(float64)
		ok = isF && f == float64(int64(f))
	case "boolean":
		_, ok = v.(bool)
	case "null":
		ok = v == nil
	default:
		ok = true // unknown type keyword — don't reject
	}
	if !ok {
		return path + " must be of type " + t
	}
	return ""
}

func checkString(schema map[string]any, s, path string) string {
	if m, ok := schema["minLength"].(float64); ok && float64(len(s)) < m {
		return fmt.Sprintf("%s must be at least %d characters", path, int(m))
	}
	if m, ok := schema["maxLength"].(float64); ok && float64(len(s)) > m {
		return fmt.Sprintf("%s must be at most %d characters", path, int(m))
	}
	if p, ok := schema["pattern"].(string); ok && p != "" {
		// A malformed pattern is treated as "don't reject" so a bad Model can't wedge every request.
		if matched, err := regexp.MatchString(p, s); err == nil && !matched {
			return path + " does not match the required pattern"
		}
	}
	return ""
}

func checkNumber(schema map[string]any, n float64, path string) string {
	if m, ok := schema["minimum"].(float64); ok && n < m {
		return fmt.Sprintf("%s must be >= %v", path, m)
	}
	if m, ok := schema["maximum"].(float64); ok && n > m {
		return fmt.Sprintf("%s must be <= %v", path, m)
	}
	return ""
}

func anyEqual(list []any, v any) bool {
	for _, item := range list {
		if fmt.Sprintf("%v", item) == fmt.Sprintf("%v", v) {
			return true
		}
	}
	return false
}
