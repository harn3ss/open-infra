// API Gateway REST API (v1) pure logic for the aws-shim: management-path -> op
// dispatch (restJson1 over /restapis/...), and resource-tree route matching for the data plane.
// Side-effect-free so the contract is unit-testable. Reuses the v2 matchTemplate + buildProxyEvent.
package main

import (
	"net/http"
	"strings"
)

// restV1Op is a parsed REST v1 management request.
type restV1Op struct {
	Op         string
	APIID      string
	ResourceID string
	HTTPMethod string
	StatusCode string // PutIntegrationResponse
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
//	/restapis/{id}/deployments                                        POST CreateDeployment
//	/restapis/{id}/stages                                             POST CreateStage / GET GetStages
//	/restapis/{id}/authorizers                                        POST CreateAuthorizer
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
		}
	case 4: // /restapis/{id}/resources/{parentId}
		if segs[2] == "resources" && r.Method == http.MethodPost {
			return restV1Op{Op: "CreateResource", APIID: segs[1], ResourceID: segs[3]}, true
		}
	case 6: // /restapis/{id}/resources/{resourceId}/methods/{httpMethod}
		if segs[2] == "resources" && segs[4] == "methods" && r.Method == http.MethodPut {
			return restV1Op{Op: "PutMethod", APIID: segs[1], ResourceID: segs[3], HTTPMethod: strings.ToUpper(segs[5])}, true
		}
	case 7: // /restapis/{id}/resources/{resourceId}/methods/{httpMethod}/integration
		if segs[2] == "resources" && segs[4] == "methods" && segs[6] == "integration" && r.Method == http.MethodPut {
			return restV1Op{Op: "PutIntegration", APIID: segs[1], ResourceID: segs[3], HTTPMethod: strings.ToUpper(segs[5])}, true
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
// returns the matched integration, the extracted path parameters, the method's auth, and ok.
func matchRestRoute(snap restSnapshot, method, path string) (integ restIntegration, params map[string]string, authType, authorizerID string, ok bool) {
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
		p, static, greedy, matched := matchTemplate(splitPath(res.FullPath), actual)
		if !matched {
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
		best, integ, params, authType, authorizerID, ok = score, i, p, m.AuthorizationType, m.AuthorizerID, true
	}
	return integ, params, authType, authorizerID, ok
}
