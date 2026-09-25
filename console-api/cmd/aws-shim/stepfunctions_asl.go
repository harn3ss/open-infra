// CreateStateMachine definition validation + Lambda-integration translation for the Step Functions front
// door. The goal is refused-not-faked fidelity: accept an AWS-authored ASL document that the open-infra
// engine can actually run, translating AWS Lambda Task Resources into the engine's function:<name> form,
// and REFUSE (with a clear InvalidDefinition) anything the engine does not implement — rather than storing
// a definition that would fail or silently mis-run at execution time.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// validateAndTranslateDefinition parses an ASL JSON document, rejects unsupported features, translates
// AWS Lambda Task Resources to the engine's function:<name> form, and returns the (possibly rewritten)
// definition as compact JSON.
func validateAndTranslateDefinition(def string) (string, error) {
	if strings.TrimSpace(def) == "" {
		return "", fmt.Errorf("definition is required")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(def), &doc); err != nil {
		return "", fmt.Errorf("definition is not valid JSON: %v", err)
	}
	if _, ok := doc["StartAt"].(string); !ok {
		return "", fmt.Errorf("definition must have a top-level string \"StartAt\"")
	}
	states, ok := doc["States"].(map[string]any)
	if !ok || len(states) == 0 {
		return "", fmt.Errorf("definition must have a non-empty \"States\" object")
	}
	for name, raw := range states {
		st, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("state %q is not an object", name)
		}
		typ, _ := st["Type"].(string)
		switch typ {
		case "":
			return "", fmt.Errorf("state %q has no Type", name)
		case "Parallel", "Map":
			return "", fmt.Errorf("state %q uses Type %q, which is not supported in v1 (no Parallel/Map)", name, typ)
		case "Task":
			if err := translateTaskResource(name, st); err != nil {
				return "", err
			}
		case "Choice", "Wait", "Pass", "Succeed", "Fail":
			// supported as-is
		default:
			return "", fmt.Errorf("state %q uses unknown Type %q", name, typ)
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("could not re-encode definition: %v", err)
	}
	return string(out), nil
}

// translateTaskResource validates and, where needed, rewrites a Task state's Resource in place.
func translateTaskResource(name string, st map[string]any) error {
	res, ok := st["Resource"].(string)
	if !ok || res == "" {
		return fmt.Errorf("Task state %q has no string Resource", name)
	}
	// Callback / sync service-integration patterns are not supported (the engine invokes request/response).
	if strings.HasSuffix(res, ".waitForTaskToken") || strings.HasSuffix(res, ".sync") || strings.HasSuffix(res, ".sync2") {
		return fmt.Errorf("Task state %q uses Resource %q — callback (.waitForTaskToken) and .sync integration patterns are not supported", name, res)
	}

	switch {
	case strings.HasPrefix(res, "function:"), strings.HasPrefix(res, "http://"), strings.HasPrefix(res, "https://"):
		return nil // native engine forms

	case strings.HasPrefix(res, "arn:aws:lambda:"):
		fn := lambdaNameFromArn(res)
		if fn == "" {
			return fmt.Errorf("Task state %q has a Lambda ARN with no function name: %q", name, res)
		}
		st["Resource"] = "function:" + fn
		return nil

	case res == "arn:aws:states:::lambda:invoke":
		// Optimized Lambda integration: the function is named in Parameters.FunctionName and the payload
		// in Parameters.Payload. Rewrite to the engine's function:<name> + fold Payload up to Parameters.
		params, _ := st["Parameters"].(map[string]any)
		fnRef, _ := params["FunctionName"].(string)
		fn := lambdaNameFromArn(fnRef)
		if fn == "" {
			fn = fnRef // may be a bare name
		}
		if fn == "" {
			return fmt.Errorf("Task state %q uses states:::lambda:invoke but Parameters.FunctionName is missing", name)
		}
		st["Resource"] = "function:" + fn
		if payload, has := params["Payload"]; has {
			st["Parameters"] = payload
		} else {
			delete(st, "Parameters")
		}
		return nil

	case strings.HasPrefix(res, "arn:aws:states:::"):
		return fmt.Errorf("Task state %q uses service integration %q — only Lambda/Function Task integrations are supported in v1", name, res)

	default:
		return fmt.Errorf("Task state %q has an unsupported Resource %q (use a Lambda ARN, arn:aws:states:::lambda:invoke, function:<name>, or an http(s):// URL)", name, res)
	}
}
