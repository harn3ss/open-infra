package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

func cognitoCall(t *testing.T, h *cognitoHandler, claims iam.Claims, op, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://cognito/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService."+op)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	w := httptest.NewRecorder()
	h.serve(w, req, claims, "r-1")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A pool's app clients read back (DescribeUserPoolClient, a paged ListUserPoolClients); a client of
// another pool, or one that does not exist, is not found; a caller without get on the pool is refused.
func TestServicesPG_CognitoUserPoolClients(t *testing.T) {
	st := &cognitoStore{db: freshPGDB(t)}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	h := newCognitoHandler(csWithSAR(true), "default", "000000000000", "us-east-1", "http://shim", st, signer, discardLogger())
	u := iam.Claims{Sub: "u"}
	pool := func(name string) string {
		code, out := cognitoCall(t, h, u, "CreateUserPool", `{"PoolName":"`+name+`"}`)
		if code != http.StatusOK {
			t.Fatalf("CreateUserPool = %d %v", code, out)
		}
		return out["UserPool"].(map[string]any)["Id"].(string)
	}
	client := func(pool, name string) string {
		code, out := cognitoCall(t, h, u, "CreateUserPoolClient", `{"UserPoolId":"`+pool+`","ClientName":"`+name+`","ExplicitAuthFlows":["ALLOW_USER_PASSWORD_AUTH"]}`)
		if code != http.StatusOK {
			t.Fatalf("CreateUserPoolClient = %d %v", code, out)
		}
		return out["UserPoolClient"].(map[string]any)["ClientId"].(string)
	}
	p1, p2 := pool("one"), pool("two")
	web, mobile, other := client(p1, "web"), client(p1, "mobile"), client(p2, "other")

	code, out := cognitoCall(t, h, u, "DescribeUserPoolClient", `{"UserPoolId":"`+p1+`","ClientId":"`+web+`"}`)
	c, _ := out["UserPoolClient"].(map[string]any)
	if code != http.StatusOK || c["ClientName"] != "web" || c["UserPoolId"] != p1 || c["CreationDate"] == nil {
		t.Fatalf("DescribeUserPoolClient = %d %v", code, out)
	}
	if flows, _ := c["ExplicitAuthFlows"].([]any); len(flows) != 1 || flows[0] != "ALLOW_USER_PASSWORD_AUTH" {
		t.Errorf("ExplicitAuthFlows = %v", c["ExplicitAuthFlows"])
	}
	if _, has := c["ClientSecret"]; has {
		t.Error("a client secret was answered")
	}

	// ListUserPoolClients pages one at a time, and lists only the pool's own clients.
	var names []string
	token := ""
	for i := 0; i < 5; i++ {
		body := `{"UserPoolId":"` + p1 + `","MaxResults":1`
		if token != "" {
			body += `,"NextToken":"` + token + `"`
		}
		code, out := cognitoCall(t, h, u, "ListUserPoolClients", body+"}")
		if code != http.StatusOK {
			t.Fatalf("ListUserPoolClients = %d %v", code, out)
		}
		for _, it := range out["UserPoolClients"].([]any) {
			names = append(names, it.(map[string]any)["ClientId"].(string))
		}
		token, _ = out["NextToken"].(string)
		if token == "" {
			break
		}
	}
	if len(names) != 2 || !contains(names, web) || !contains(names, mobile) {
		t.Errorf("listed %v, want the pool's two clients", names)
	}

	// Not found: a client of another pool, a missing client, a missing pool.
	for _, body := range []string{
		`{"UserPoolId":"` + p1 + `","ClientId":"` + other + `"}`,
		`{"UserPoolId":"` + p1 + `","ClientId":"nope"}`,
		`{"UserPoolId":"us-east-1_nope","ClientId":"` + web + `"}`,
	} {
		if code, out := cognitoCall(t, h, u, "DescribeUserPoolClient", body); code != http.StatusBadRequest || out["__type"] != "ResourceNotFoundException" {
			t.Errorf("DescribeUserPoolClient %s = %d %v", body, code, out)
		}
	}
	if code, out := cognitoCall(t, h, u, "ListUserPoolClients", `{"UserPoolId":"us-east-1_nope"}`); code != http.StatusBadRequest || out["__type"] != "ResourceNotFoundException" {
		t.Errorf("ListUserPoolClients of a missing pool = %d %v", code, out)
	}

	// Denied: no get on the coarse gate; a Deny of the operation on the pool.
	deny := newCognitoHandler(csWithSAR(false), "default", "000000000000", "us-east-1", "http://shim", st, signer, discardLogger())
	h.authz = userPolicy(dpAllow([]string{"cognito-idp:*"}, "*"), dpDeny([]string{"cognito-idp:DescribeUserPoolClient", "cognito-idp:ListUserPoolClients"}, "UserPool::"+p1))
	for _, op := range []string{"DescribeUserPoolClient", "ListUserPoolClients"} {
		body := `{"UserPoolId":"` + p1 + `","ClientId":"` + web + `"}`
		if code, out := cognitoCall(t, deny, u, op, body); code != http.StatusForbidden {
			t.Errorf("%s without get = %d %v", op, code, out)
		}
		if code, out := cognitoCall(t, h, testUser, op, body); code != http.StatusForbidden {
			t.Errorf("%s under a Deny = %d %v", op, code, out)
		}
	}
	if code, _ := cognitoCall(t, h, testUser, "DescribeUserPoolClient", `{"UserPoolId":"`+p2+`","ClientId":"`+other+`"}`); code != http.StatusOK {
		t.Errorf("DescribeUserPoolClient of a pool the Deny does not name = %d", code)
	}
}
