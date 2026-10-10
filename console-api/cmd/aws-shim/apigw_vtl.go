// API Gateway REST (v1) VTL request/response MAPPING TEMPLATES for the aws-shim (polyhedron#295,
// increment 2). This is the data-plane complement to apigateway_v1.go: for a non-proxy integration
// (type "AWS" = Lambda, or "HTTP") API Gateway transforms the request body through a `requestTemplates`
// VTL template before forwarding, and the response body through a `responseTemplates` template after.
//
// The Velocity engine itself is the SHARED core (github.com/harn3ss/open-infra/vtl) — the exact same
// parser/evaluator open-appsync uses for AppSync resolvers, so the two front doors can never drift on
// VTL semantics. What differs per dialect is the variable binding and the $util helper surface, both
// injected here:
//
//   - $util       — apigwUtil, API Gateway's helper set (escapeJavaScript / urlEncode / urlDecode /
//     base64Encode / base64Decode / parseJson / toJson).
//   - $input      — apigwInput (a vtl.Receiver): $input.body (raw body string), $input.json(path),
//     $input.path(path), $input.params(name) / $input.params().
//   - $context        — a small request-context map (httpMethod / resourcePath / stage / requestId / …).
//   - $stageVariables — the stage's variables.
//
// HONEST SUBSET (documented, not silently partial):
//   - $input.json / $input.path support "$" (whole body) and dotted object paths ("$.a.b") over JSON
//     objects. They do NOT support array indexing, wildcards, or filter expressions. The result is the
//     JSON-encoded string of the selection (as AWS returns), so it splices into a template unquoted.
//   - $input.params(name) resolves from a single pre-merged name→value map (path > query > header);
//     multi-value params and the typed params().path/.querystring/.header sub-maps are not modelled.
//   - $context is a minimal map, not AWS's full $context surface.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	sharedvtl "github.com/harn3ss/open-infra/vtl"
)

// renderMappingTemplate renders an API Gateway mapping template against the request/response body and
// the surrounding bindings. input is the raw body the template maps; params is the pre-merged
// name→value parameter map ($input.params); stageVars are the stage variables ($stageVariables); ctx
// is the $context map.
func renderMappingTemplate(tmpl string, input []byte, params, stageVars map[string]string, ctx map[string]any) (string, error) {
	in := &apigwInput{raw: string(input), params: params}
	if len(input) > 0 {
		_ = json.Unmarshal(input, &in.parsed) // parsed stays nil for a non-JSON body
	}
	sv := make(map[string]any, len(stageVars))
	for k, v := range stageVars {
		sv[k] = v
	}
	if ctx == nil {
		ctx = map[string]any{}
	}
	// NOTE: the shared engine's Render binds its argument to AppSync's single $ctx/$context object;
	// API Gateway templates instead reference several top-level variables, so we bind them explicitly
	// through RenderVars.
	vars := map[string]any{
		"input":          in,
		"context":        ctx,
		"stageVariables": sv,
	}
	return sharedvtl.New(apigwUtil{}).RenderVars(tmpl, vars)
}

// apigwInput backs the $input object. It is a vtl.Receiver: .body is a property, .json/.path/.params
// are methods.
type apigwInput struct {
	raw    string
	parsed any               // body parsed as JSON (nil if the body is empty or not JSON)
	params map[string]string // pre-merged path/query/header params
}

func (in *apigwInput) GetProp(name string) (any, bool) {
	if name == "body" {
		return in.raw, true
	}
	return nil, false
}

func (in *apigwInput) CallMethod(name string, args []any) (any, bool) {
	switch name {
	case "body":
		return in.raw, true
	case "json", "path":
		p := "$"
		if len(args) > 0 {
			if s, ok := args[0].(string); ok {
				p = s
			}
		}
		return in.selectJSON(p), true
	case "params":
		if len(args) == 0 {
			m := make(map[string]any, len(in.params))
			for k, v := range in.params {
				m[k] = v
			}
			return m, true
		}
		key, _ := args[0].(string)
		return in.params[key], true // "" when absent, matching AWS
	}
	return nil, false
}

// selectJSON implements the honest $input.json/$input.path subset: "$" (whole body) and dotted object
// paths ("$.a.b"). It returns the JSON-encoded string of the selection, as AWS does.
func (in *apigwInput) selectJSON(path string) string {
	sel := in.parsed
	p := strings.TrimSpace(path)
	p = strings.TrimPrefix(p, "$")
	p = strings.TrimPrefix(p, ".")
	if p != "" {
		for _, seg := range strings.Split(p, ".") {
			m, ok := sel.(map[string]any)
			if !ok {
				sel = nil
				break
			}
			sel = m[seg]
		}
	}
	b, err := json.Marshal(sel)
	if err != nil {
		return "null"
	}
	return string(b)
}

// apigwUtil is the API Gateway $util surface, injected into the shared engine as vtl.Util.
type apigwUtil struct{}

func (apigwUtil) Invoke(path string, args []any) (any, error, bool) {
	switch path {
	case "escapeJavaScript":
		return escapeJavaScript(agwArgStr(args, 0)), nil, true
	case "urlEncode":
		return url.QueryEscape(agwArgStr(args, 0)), nil, true
	case "urlDecode":
		s, err := url.QueryUnescape(agwArgStr(args, 0))
		if err != nil {
			return agwArgStr(args, 0), nil, true // lenient: hand back the input unchanged
		}
		return s, nil, true
	case "base64Encode":
		return base64.StdEncoding.EncodeToString([]byte(agwArgStr(args, 0))), nil, true
	case "base64Decode":
		b, err := base64.StdEncoding.DecodeString(agwArgStr(args, 0))
		if err != nil {
			return "", nil, true
		}
		return string(b), nil, true
	case "parseJson":
		var v any
		_ = json.Unmarshal([]byte(agwArgStr(args, 0)), &v)
		return v, nil, true
	case "toJson":
		b, err := json.Marshal(agwArg(args, 0))
		if err != nil {
			return "null", nil, true
		}
		return string(b), nil, true
	}
	return nil, nil, false
}

func (apigwUtil) Call(path string, args []any) (any, error) {
	res, err, ok := apigwUtil{}.Invoke(path, args)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("apigw $util: unknown method %q", path)
	}
	return res, nil
}

// escapeJavaScript escapes a string so it embeds safely inside a JSON/JS string literal (the common
// use is "$util.escapeJavaScript($input.body)"). It escapes the JSON control characters and leaves
// everything else intact.
func escapeJavaScript(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func agwArg(args []any, i int) any {
	if i < len(args) {
		return args[i]
	}
	return nil
}

func agwArgStr(args []any, i int) string {
	v := agwArg(args, i)
	if s, ok := v.(string); ok {
		return s
	}
	return toStr(v)
}

// pickMappingTemplate selects the template for a content-type from a requestTemplates/responseTemplates
// map, falling back to application/json then AWS's $default key. ok=false means "no template matched"
// → the caller passes the body through unchanged.
func pickMappingTemplate(tmpls map[string]string, contentType string) (string, bool) {
	if len(tmpls) == 0 {
		return "", false
	}
	ct := contentType
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct != "" {
		for k, v := range tmpls {
			if strings.ToLower(strings.TrimSpace(k)) == ct {
				return v, true
			}
		}
	}
	if v, ok := tmpls["application/json"]; ok {
		return v, true
	}
	if v, ok := tmpls["$default"]; ok {
		return v, true
	}
	return "", false
}
