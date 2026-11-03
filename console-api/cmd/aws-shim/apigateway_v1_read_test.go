package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
)

func TestRestV1OpFromRequest_Reads(t *testing.T) {
	for _, c := range []struct{ method, path, op, api, res, httpMethod, name string }{
		{"GET", "/restapis/abc/resources/r1/methods/get", "GetMethod", "abc", "r1", "GET", ""},
		{"GET", "/restapis/abc/deployments", "GetDeployments", "abc", "", "", ""},
		{"GET", "/restapis/abc/deployments/d1", "GetDeployment", "abc", "", "", "d1"},
		{"GET", "/restapis/abc/authorizers", "GetAuthorizers", "abc", "", "", ""},
		{"GET", "/restapis/abc/authorizers/a1", "GetAuthorizer", "abc", "", "", "a1"},
	} {
		v, ok := restV1OpFromRequest(httptest.NewRequest(c.method, "http://apigw"+c.path, nil))
		if !ok || v.Op != c.op || v.APIID != c.api || v.ResourceID != c.res || v.HTTPMethod != c.httpMethod || v.Name != c.name {
			t.Errorf("%s %s = %+v %v, want %s", c.method, c.path, v, ok, c.op)
		}
	}
	if _, ok := restV1OpFromRequest(httptest.NewRequest("DELETE", "http://apigw/restapis/abc/deployments/d1", nil)); ok {
		t.Error("DeleteDeployment is not served")
	}
}

// restV1Call sends one REST v1 management request and decodes the JSON answer.
func restV1Call(t *testing.T, h *apigwV1Handler, claims iam.Claims, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "http://apigw"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.serve(w, req, claims, "r-1")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A REST API's methods, deployments and authorizers read back as PutMethod, CreateDeployment and
// CreateAuthorizer wrote them; an id that does not exist is NotFound; a caller without get (or under a
// Deny of the operation) is refused.
func TestServicesPG_RestV1ReadsMethodsDeploymentsAuthorizers(t *testing.T) {
	db := freshPGDB(t)
	st := &apigwV1Store{db: db}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := newAPIGWV1Handler(csWithSAR(true), "default", "default", "svc.cluster.local", "http://shim/cognito", st, nil, discardLogger())
	u := iam.Claims{Sub: "u"}
	code, api := restV1Call(t, h, u, "POST", "/restapis", `{"name":"orders"}`)
	if code != http.StatusCreated {
		t.Fatalf("CreateRestApi = %d %v", code, api)
	}
	id, root := api["id"].(string), api["rootResourceId"].(string)
	_, res := restV1Call(t, h, u, "POST", "/restapis/"+id+"/resources/"+root, `{"pathPart":"items"}`)
	rid := res["id"].(string)
	code, az := restV1Call(t, h, u, "POST", "/restapis/"+id+"/authorizers",
		`{"name":"pool","type":"COGNITO_USER_POOLS","providerARNs":["arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_abc"],"identitySource":"method.request.header.Authorization"}`)
	if code != http.StatusCreated {
		t.Fatalf("CreateAuthorizer = %d %v", code, az)
	}
	azID := az["id"].(string)
	if code, out := restV1Call(t, h, u, "PUT", "/restapis/"+id+"/resources/"+rid+"/methods/GET",
		`{"authorizationType":"COGNITO_USER_POOLS","authorizerId":"`+azID+`","requestParameters":{"method.request.querystring.q":true}}`); code != http.StatusCreated {
		t.Fatalf("PutMethod = %d %v", code, out)
	}
	if code, out := restV1Call(t, h, u, "PUT", "/restapis/"+id+"/resources/"+rid+"/methods/GET/integration",
		`{"type":"MOCK","requestTemplates":{"application/json":"{\"statusCode\":200}"}}`); code != http.StatusCreated {
		t.Fatalf("PutIntegration = %d %v", code, out)
	}
	if code, out := restV1Call(t, h, u, "PUT", "/restapis/"+id+"/resources/"+rid+"/methods/GET/responses/200",
		`{"responseModels":{"application/json":"Empty"}}`); code != http.StatusCreated {
		t.Fatalf("PutMethodResponse = %d %v", code, out)
	}
	code, dep := restV1Call(t, h, u, "POST", "/restapis/"+id+"/deployments", `{"stageName":"prod"}`)
	if code != http.StatusCreated {
		t.Fatalf("CreateDeployment = %d %v", code, dep)
	}
	depID := dep["id"].(string)

	// GetMethod: the method, its integration and its method responses.
	code, m := restV1Call(t, h, u, "GET", "/restapis/"+id+"/resources/"+rid+"/methods/GET", "")
	if code != http.StatusOK || m["httpMethod"] != "GET" || m["authorizationType"] != "COGNITO_USER_POOLS" || m["authorizerId"] != azID {
		t.Fatalf("GetMethod = %d %v", code, m)
	}
	if mi, _ := m["methodIntegration"].(map[string]any); mi == nil || mi["type"] != "MOCK" || mi["requestTemplates"] == nil {
		t.Errorf("methodIntegration = %v", m["methodIntegration"])
	}
	if mr, _ := m["methodResponses"].(map[string]any); mr == nil || mr["200"].(map[string]any)["statusCode"] != "200" {
		t.Errorf("methodResponses = %v", m["methodResponses"])
	}
	if rp, _ := m["requestParameters"].(map[string]any); rp["method.request.querystring.q"] != true {
		t.Errorf("requestParameters = %v", m["requestParameters"])
	}

	// GetDeployments / GetDeployment.
	code, deps := restV1Call(t, h, u, "GET", "/restapis/"+id+"/deployments", "")
	items, _ := deps["item"].([]any)
	if code != http.StatusOK || len(items) != 1 || items[0].(map[string]any)["id"] != depID {
		t.Errorf("GetDeployments = %d %v", code, deps)
	}
	if code, d := restV1Call(t, h, u, "GET", "/restapis/"+id+"/deployments/"+depID, ""); code != http.StatusOK || d["id"] != depID || d["createdDate"] == nil {
		t.Errorf("GetDeployment = %d %v", code, d)
	}

	// GetAuthorizers / GetAuthorizer: the providerARNs it was created with.
	code, azs := restV1Call(t, h, u, "GET", "/restapis/"+id+"/authorizers", "")
	items, _ = azs["item"].([]any)
	if code != http.StatusOK || len(items) != 1 {
		t.Fatalf("GetAuthorizers = %d %v", code, azs)
	}
	code, a := restV1Call(t, h, u, "GET", "/restapis/"+id+"/authorizers/"+azID, "")
	if arns, _ := a["providerARNs"].([]any); code != http.StatusOK || a["type"] != "COGNITO_USER_POOLS" || a["name"] != "pool" ||
		len(arns) != 1 || arns[0] != "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_abc" ||
		a["identitySource"] != "method.request.header.Authorization" {
		t.Errorf("GetAuthorizer = %d %v", code, a)
	}

	// Not found.
	for _, p := range []string{
		"/restapis/" + id + "/resources/" + rid + "/methods/POST",
		"/restapis/" + id + "/resources/nope/methods/GET",
		"/restapis/" + id + "/deployments/nope",
		"/restapis/" + id + "/authorizers/nope",
		"/restapis/nope/deployments",
		"/restapis/nope/authorizers",
	} {
		if code, out := restV1Call(t, h, u, "GET", p, ""); code != http.StatusNotFound {
			t.Errorf("GET %s = %d %v, want 404", p, code, out)
		}
	}

	// Denied: no get on the coarse gate; a Deny of the operation on the API.
	denied := newAPIGWV1Handler(csWithSARFunc(func(a *authzv1.ResourceAttributes) bool { return a.Verb != "get" }), "default", "default", "svc.cluster.local", "", st, nil, discardLogger())
	h.authz = userPolicy(dpAllow([]string{"apigateway:*"}, "*"), dpDeny([]string{"apigateway:GetMethod", "apigateway:GetDeployment",
		"apigateway:GetDeployments", "apigateway:GetAuthorizer", "apigateway:GetAuthorizers"}, "Api::"+id))
	for _, p := range []string{
		"/restapis/" + id + "/resources/" + rid + "/methods/GET",
		"/restapis/" + id + "/deployments",
		"/restapis/" + id + "/deployments/" + depID,
		"/restapis/" + id + "/authorizers",
		"/restapis/" + id + "/authorizers/" + azID,
	} {
		if code, _ := restV1Call(t, denied, u, "GET", p, ""); code != http.StatusForbidden {
			t.Errorf("GET %s without get = %d", p, code)
		}
		if code, _ := restV1Call(t, h, testUser, "GET", p, ""); code != http.StatusForbidden {
			t.Errorf("GET %s under a Deny = %d", p, code)
		}
	}
}
