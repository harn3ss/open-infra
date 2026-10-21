// API Gateway REST API (v1) pure logic for the aws-shim: management-path -> op
// dispatch (restJson1 over /restapis/...), and resource-tree route matching for the data plane.
// Side-effect-free so the contract is unit-testable. Reuses the v2 matchTemplate + buildProxyEvent.
package main

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/apigwschema"
)

// restV1Op is a parsed REST v1 management request.
type restV1Op struct {
	Op         string
	APIID      string
	ResourceID string
	HTTPMethod string
	StatusCode string // PutIntegrationResponse / PutMethodResponse
	Name       string // model name (GetModel) or request-validator id (GetRequestValidator)
}

// restV1OpFromRequest maps a /restapis/... path + method to an op. REST v1 paths:
//
//	/restapis                                                         POST CreateRestApi / GET GetRestApis
//	/restapis/{id}                                                    GET GetRestApi / DELETE DeleteRestApi
//	/restapis/{id}/resources                                          GET GetResources
//	/restapis/{id}/resources/{parentId}                               POST CreateResource (child of parent)
//	/restapis/{id}/resources/{resourceId}/methods/{httpMethod}        PUT PutMethod
//	/restapis/{id}/resources/{resourceId}/methods/{httpMethod}/integration  PUT PutIntegration
//	/restapis/{id}/resources/{resourceId}/methods/{httpMethod}/integration/responses/{statusCode}  PUT PutIntegrationResponse
//	/restapis/{id}/resources/{resourceId}/methods/{httpMethod}/responses/{statusCode}  PUT PutMethodResponse
//	/restapis/{id}/deployments                                        POST CreateDeployment
//	/restapis/{id}/stages                                             POST CreateStage / GET GetStages
//	/restapis/{id}/authorizers                                        POST CreateAuthorizer
//	/restapis/{id}/models                                             POST CreateModel / GET GetModels
//	/restapis/{id}/models/{modelName}                                 GET GetModel
//	/restapis/{id}/requestvalidators                                  POST CreateRequestValidator / GET GetRequestValidators
//	/restapis/{id}/requestvalidators/{validatorId}                    GET GetRequestValidator
func restV1OpFromRequest(r *http.Request) (restV1Op, bool) {
	segs := splitPath(r.URL.Path)
	if len(segs) < 1 || segs[0] != "restapis" {
		return restV1Op{}, false
	}
	switch len(segs) {
	case 1: // /restapis
		switch r.Method {
		case http.MethodPost:
			return restV1Op{Op: "CreateRestApi"}, true
		case http.MethodGet:
			return restV1Op{Op: "GetRestApis"}, true
		}
	case 2: // /restapis/{id}
		switch r.Method {
		case http.MethodGet:
			return restV1Op{Op: "GetRestApi", APIID: segs[1]}, true
		case http.MethodDelete:
			return restV1Op{Op: "DeleteRestApi", APIID: segs[1]}, true
		}
	case 3: // /restapis/{id}/<sub>
		switch segs[2] {
		case "resources":
			if r.Method == http.MethodGet {
				return restV1Op{Op: "GetResources", APIID: segs[1]}, true
			}
		case "deployments":
			if r.Method == http.MethodPost {
				return restV1Op{Op: "CreateDeployment", APIID: segs[1]}, true
			}
		case "stages":
			if r.Method == http.MethodPost {
				return restV1Op{Op: "CreateStage", APIID: segs[1]}, true
			}
			if r.Method == http.MethodGet {
				return restV1Op{Op: "GetStages", APIID: segs[1]}, true
			}
		case "authorizers":
			if r.Method == http.MethodPost {
				return restV1Op{Op: "CreateAuthorizer", APIID: segs[1]}, true
			}
		case "models":
			if r.Method == http.MethodPost {
				return restV1Op{Op: "CreateModel", APIID: segs[1]}, true
			}
			if r.Method == http.MethodGet {
				return restV1Op{Op: "GetModels", APIID: segs[1]}, true
			}
		case "requestvalidators":
			if r.Method == http.MethodPost {
				return restV1Op{Op: "CreateRequestValidator", APIID: segs[1]}, true
			}
			if r.Method == http.MethodGet {
				return restV1Op{Op: "GetRequestValidators", APIID: segs[1]}, true
			}
		}
	case 4: // /restapis/{id}/<sub>/<name>
		switch segs[2] {
		case "resources":
			if r.Method == http.MethodPost {
				return restV1Op{Op: "CreateResource", APIID: segs[1], ResourceID: segs[3]}, true
			}
		case "models":
			if r.Method == http.MethodGet {
				return restV1Op{Op: "GetModel", APIID: segs[1], Name: segs[3]}, true
			}
		case "requestvalidators":
			if r.Method == http.MethodGet {
				return restV1Op{Op: "GetRequestValidator", APIID: segs[1], Name: segs[3]}, true
			}
		}
	case 6: // /restapis/{id}/resources/{resourceId}/methods/{httpMethod}
		if segs[2] == "resources" && segs[4] == "methods" && r.Method == http.MethodPut {
			return restV1Op{Op: "PutMethod", APIID: segs[1], ResourceID: segs[3], HTTPMethod: strings.ToUpper(segs[5])}, true
		}
	case 7: // /restapis/{id}/resources/{resourceId}/methods/{httpMethod}/integration
		if segs[2] == "resources" && segs[4] == "methods" && segs[6] == "integration" && r.Method == http.MethodPut {
			return restV1Op{Op: "PutIntegration", APIID: segs[1], ResourceID: segs[3], HTTPMethod: strings.ToUpper(segs[5])}, true
		}
	case 8: // /restapis/{id}/resources/{resourceId}/methods/{httpMethod}/responses/{statusCode}
		if segs[2] == "resources" && segs[4] == "methods" && segs[6] == "responses" && r.Method == http.MethodPut {
			return restV1Op{Op: "PutMethodResponse", APIID: segs[1], ResourceID: segs[3], HTTPMethod: strings.ToUpper(segs[5]), StatusCode: segs[7]}, true
		}
	case 9: // /restapis/{id}/resources/{resourceId}/methods/{httpMethod}/integration/responses/{statusCode}
		if segs[2] == "resources" && segs[4] == "methods" && segs[6] == "integration" && segs[7] == "responses" && r.Method == http.MethodPut {
			return restV1Op{Op: "PutIntegrationResponse", APIID: segs[1], ResourceID: segs[3], HTTPMethod: strings.ToUpper(segs[5]), StatusCode: segs[8]}, true
		}
	}
	return restV1Op{}, false
}

// childFullPath computes a child resource's full path from its parent's full path + the new pathPart.
func childFullPath(parentFull, pathPart string) string {
	if parentFull == "/" || parentFull == "" {
		return "/" + pathPart
	}
	return parentFull + "/" + pathPart
}

// matchRestRoute picks the best resource+method for (method, path) from a deployment snapshot, with the
// same precedence as v2 (more static segments, then non-greedy, then an exact method over ANY). It
// returns the matched integration, the matched method (carrying auth + request-validation config), the
// extracted path parameters, and ok.
func matchRestRoute(snap restSnapshot, method, path string) (integ restIntegration, matched restMethod, params map[string]string, ok bool) {
	// index integrations + resources by id for lookup
	resByID := map[string]restResource{}
	for _, r := range snap.Resources {
		resByID[r.ID] = r
	}
	integByKey := map[string]restIntegration{} // resourceID+"\x00"+httpMethod
	for _, i := range snap.Integrations {
		integByKey[i.ResourceID+"\x00"+i.HTTPMethod] = i
	}
	actual := splitPath(path)
	best := -1
	for _, m := range snap.Methods {
		if m.HTTPMethod != method && m.HTTPMethod != "ANY" {
			continue
		}
		res, rok := resByID[m.ResourceID]
		if !rok {
			continue
		}
		p, static, greedy, mtch := matchTemplate(splitPath(res.FullPath), actual)
		if !mtch {
			continue
		}
		score := static * 1000
		if !greedy {
			score += 100
		}
		if m.HTTPMethod != "ANY" {
			score += 10
		}
		if score <= best {
			continue
		}
		i, iok := integByKey[m.ResourceID+"\x00"+m.HTTPMethod]
		if !iok {
			continue // a method with no integration can't be served
		}
		best, integ, matched, params, ok = score, i, m, p, true
	}
	return integ, matched, params, ok
}

// validateRestRequest applies a method's request validator (AWS "request validation") to an incoming
// request, returning an AWS-faithful 400 reason when the request is invalid. ok=true means the request
// may proceed to the integration. It mirrors AWS precedence (parameters first, then body) and AWS's
// faithful quirks: a required parameter counts as missing when absent OR blank, and body validation is
// SKIPPED (the request passes) when no request model matches the request's content type.
//
// A method with no validator, or one referencing a validator absent from the deployed snapshot, imposes
// no constraint — request validation is additive, so an unattached/missing validator means "no
// validation", exactly as before the feature (never a silent 403/500).
func validateRestRequest(snap restSnapshot, m restMethod, contentType string, query url.Values, header http.Header, pathParams map[string]string, body []byte) (reason string, ok bool) {
	if m.RequestValidatorID == "" {
		return "", true
	}
	var v *restRequestValidator
	for i := range snap.Validators {
		if snap.Validators[i].ID == m.RequestValidatorID {
			v = &snap.Validators[i]
			break
		}
	}
	if v == nil {
		return "", true
	}
	// 1) parameters — existence only (not type/format), blank counts as missing; report short names.
	if v.ValidateRequestParameters {
		var missing []string
		for name, required := range m.RequestParameters {
			if required && !requestParamPresent(name, query, header, pathParams) {
				missing = append(missing, shortParamName(name))
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return "Missing required request parameters: [" + strings.Join(missing, ", ") + "]", false
		}
	}
	// 2) body — against the model mapped to the request's content type (skip when none matches).
	if v.ValidateRequestBody {
		if schema := resolveRequestModelSchema(snap, m, contentType); schema != nil {
			if apigwschema.ValidateBody(schema, body) != "" {
				return "Invalid request body", false
			}
		}
	}
	return "", true
}

// requestParamPresent reports whether an AWS method.request.(querystring|header|path).<name> parameter
// is present and non-blank. An unknown parameter location is treated as present (don't block on a shape
// we don't model).
func requestParamPresent(name string, query url.Values, header http.Header, pathParams map[string]string) bool {
	switch {
	case strings.HasPrefix(name, "method.request.querystring."):
		return query.Get(strings.TrimPrefix(name, "method.request.querystring.")) != ""
	case strings.HasPrefix(name, "method.request.header."):
		return header.Get(strings.TrimPrefix(name, "method.request.header.")) != ""
	case strings.HasPrefix(name, "method.request.path."):
		p := strings.TrimPrefix(name, "method.request.path.")
		return pathParams[p] != ""
	}
	return true
}

// shortParamName reduces a method.request.* expression to the bare parameter name AWS reports in the
// "Missing required request parameters: [...]" message (e.g. method.request.querystring.petType →
// petType).
func shortParamName(name string) string {
	for _, pfx := range []string{"method.request.querystring.", "method.request.header.", "method.request.path."} {
		if strings.HasPrefix(name, pfx) {
			return strings.TrimPrefix(name, pfx)
		}
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// resolveRequestModelSchema finds the JSON Schema to validate the body against: the model mapped to the
// request's content type, falling back to the application/json mapping. Returns nil (→ skip validation)
// when no model is mapped for the content type — AWS's documented behavior ("if no matching content
// type is found, request validation is not performed").
func resolveRequestModelSchema(snap restSnapshot, m restMethod, contentType string) map[string]any {
	if len(m.RequestModels) == 0 {
		return nil
	}
	// Exact content-type match only (after normalizing charset params). AWS does not fall back to a
	// different content type's model: "if no matching content type is found, request validation is not
	// performed". An absent/blank Content-Type defaults to application/json (handled in normalize).
	name := m.RequestModels[normalizeContentType(contentType)]
	if name == "" {
		return nil
	}
	for _, md := range snap.Models {
		if md.Name == name {
			return md.Schema
		}
	}
	return nil
}

// normalizeContentType strips any parameters (";charset=…") and lowercases, defaulting an empty header
// to application/json (REST APIs treat a bodied request with no content type as JSON).
func normalizeContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return "application/json"
	}
	return ct
}

// boolMap coerces a decoded JSON object into map[string]bool (requestParameters / responseParameters).
func boolMap(v any) map[string]bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k, val := range m {
		b, _ := val.(bool)
		out[k] = b
	}
	return out
}
