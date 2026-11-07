package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// unsignedSpy is a front door as the router sees it: it records each request the router hands it as
// authenticated (serve), which an unsigned request must never be.
type unsignedSpy struct{ served []string }

func (s *unsignedSpy) serve(w http.ResponseWriter, r *http.Request, _ iam.Claims, _ string) {
	s.served = append(s.served, r.Method+" "+r.URL.Path)
	w.WriteHeader(http.StatusOK)
}
func (s *unsignedSpy) authFailure(w http.ResponseWriter, _ *http.Request, _ string) {
	w.WriteHeader(http.StatusForbidden)
}

// unsignedAPIGW is API Gateway as the router sees it: the real invoke-target parser, its management API
// (serve) and its data plane (serveInvoke), each recorded.
type unsignedAPIGW struct {
	unsignedSpy
	invoked []string
}

func (g *unsignedAPIGW) invokeTarget(r *http.Request) (string, string, bool) {
	return (&apigwHandler{}).invokeTarget(r)
}
func (g *unsignedAPIGW) serveInvoke(w http.ResponseWriter, _ *http.Request, apiID, path, _ string) {
	g.invoked = append(g.invoked, apiID+" "+path)
	w.WriteHeader(http.StatusNotFound)
}

// The two doors that take unsigned requests keep their administration on the signed side, as AWS's do:
// Cognito's end-user operations (SignUp, InitiateAuth …) run anonymously, and every administrative one —
// a pool, its clients, an Admin* user operation — is refused there with NotAuthorizedException and changes
// nothing; API Gateway's invoke path reaches a deployed API's routes, never its management API, whatever
// path it names. No other front door is handed an unsigned request at all.
func TestServicesPG_UnsignedRequestsReachNoAdministrativeOperation(t *testing.T) {
	st := &cognitoStore{db: freshPGDB(t)}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	cog := newCognitoHandler(csWithSAR(true), "default", "000000000000", "us-east-1", "http://shim", st, testSigner(t), discardLogger())
	cog.authz = checkerInMode(t, "enforce", dataplaneauthz.PolicyDoc{Name: "admin", AppliesTo: []string{"User::admin"},
		Statements: []policyengine.Statement{dpAllow([]string{"*"}, "*")}})
	admin := iam.Claims{Sub: "admin"}
	code, out := cognitoCall(t, cog, admin, "CreateUserPool", `{"PoolName":"pool"}`)
	if code != http.StatusOK {
		t.Fatalf("CreateUserPool = %d %v", code, out)
	}
	pool := out["UserPool"].(map[string]any)["Id"].(string)
	code, out = cognitoCall(t, cog, admin, "CreateUserPoolClient", `{"UserPoolId":"`+pool+`","ClientName":"app"}`)
	if code != http.StatusOK {
		t.Fatalf("CreateUserPoolClient = %d %v", code, out)
	}
	client := out["UserPoolClient"].(map[string]any)["ClientId"].(string)

	gw := &unsignedAPIGW{}
	others := map[string]*unsignedSpy{"iam": {}, "sts": {}, "s3": {}, "dynamodb": {}, "lambda": {}, "kms": {}, "organizations": {}}
	services := map[string]awsService{"apigateway": gw, "cognito-idp": cog}
	for name, s := range others {
		services[name] = s
	}
	rt := &serviceRouter{services: services, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	send := func(method, target, host, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://shim.local:4566"+path, strings.NewReader(body))
		if host != "" {
			r.Host = host
		}
		if target != "" {
			r.Header.Set("X-Amz-Target", target)
			r.Header.Set("Content-Type", "application/x-amz-json-1.1")
		}
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, r)
		return w
	}

	// Cognito: every administrative operation, unsigned, is refused and changes nothing.
	pooled := `{"UserPoolId":"` + pool + `","Username":"mallory","TemporaryPassword":"Passw0rd!","Password":"Passw0rd!","Permanent":true,"ClientId":"` + client + `","AuthFlow":"ADMIN_USER_PASSWORD_AUTH","AuthParameters":{"USERNAME":"mallory","PASSWORD":"Passw0rd!"}}`
	for _, op := range []string{"CreateUserPool", "DescribeUserPool", "DeleteUserPool", "ListUserPools",
		"CreateUserPoolClient", "DescribeUserPoolClient", "ListUserPoolClients", "DeleteUserPoolClient",
		"AdminCreateUser", "AdminConfirmSignUp", "AdminSetUserPassword", "AdminInitiateAuth", "AdminGetUser",
		"AdminDeleteUser", "AdminAddUserToGroup", "SetUserPoolMfaConfig"} {
		w := send(http.MethodPost, "AWSCognitoIdentityProviderService."+op, "", "/", pooled)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "NotAuthorizedException") {
			t.Errorf("unsigned Cognito %s = %d %s, want 403 NotAuthorizedException", op, w.Code, w.Body)
		}
	}
	// An operation that is neither an end user's nor fronted is refused too, never run.
	for _, op := range []string{"UpdateUserPool", "AddCustomAttributes", "UpdateUserPoolClient"} {
		if w := send(http.MethodPost, "AWSCognitoIdentityProviderService."+op, "", "/", pooled); w.Code < 400 {
			t.Errorf("unsigned Cognito %s = %d %s, want a refusal", op, w.Code, w.Body)
		}
	}
	if code, out := cognitoCall(t, cog, admin, "AdminGetUser", `{"UserPoolId":"`+pool+`","Username":"mallory"}`); code == http.StatusOK {
		t.Errorf("an unsigned AdminCreateUser made a user: %v", out)
	}
	if code, out := cognitoCall(t, cog, admin, "DescribeUserPool", `{"UserPoolId":"`+pool+`"}`); code != http.StatusOK {
		t.Errorf("an unsigned DeleteUserPool removed the pool: %d %v", code, out)
	}
	// The end-user side still answers anonymously (SignUp is an end user's), so the refusals above are
	// the administrative line, not a closed door.
	if w := send(http.MethodPost, "AWSCognitoIdentityProviderService.SignUp", "", "/",
		`{"ClientId":"`+client+`","Username":"eve","Password":"Passw0rd!long"}`); w.Code != http.StatusOK {
		t.Errorf("unsigned SignUp = %d %s, want the end user's operation to run", w.Code, w.Body)
	}

	// API Gateway: its management API, unsigned, is never reached — directly, through the invoke prefix
	// with a path that climbs out of it, or on an execute-api host.
	send(http.MethodPost, "", "", "/v2/apis", `{"Name":"x","ProtocolType":"HTTP"}`)
	send(http.MethodPost, "", "", "/restapis", `{"name":"x"}`)
	send(http.MethodDelete, "", "", "/v2/apis/abc", "")
	send(http.MethodPost, "", "", "/_apigw/abc/../../v2/apis", `{"Name":"x"}`)
	send(http.MethodPost, "", "abc.execute-api.us-east-1.amazonaws.com", "/v2/apis", `{"Name":"x"}`)
	if len(gw.served) != 0 {
		t.Errorf("API Gateway's management API was handed unsigned requests: %v", gw.served)
	}
	if len(gw.invoked) != 2 {
		t.Errorf("the invoke-shaped requests reach the data plane alone: %v", gw.invoked)
	}

	// Every other front door: an unsigned administrative call is refused before any door sees it.
	send(http.MethodPost, "", "", "/", url.Values{"Action": {"CreateUser"}, "UserName": {"x"}}.Encode())
	send(http.MethodPost, "", "", "/", url.Values{"Action": {"AssumeRole"}, "RoleArn": {"arn:aws:iam::000000000000:role/x"}, "RoleSessionName": {"s"}}.Encode())
	send(http.MethodPut, "", "", "/some-bucket", "")
	send(http.MethodPost, "DynamoDB_20120810.DeleteTable", "", "/", `{"TableName":"t"}`)
	send(http.MethodDelete, "", "", "/2015-03-31/functions/f", "")
	send(http.MethodPost, "TrentService.ScheduleKeyDeletion", "", "/", `{"KeyId":"k"}`)
	send(http.MethodPost, "AWSOrganizationsV20161128.CreateAccount", "", "/", `{"AccountName":"a","Email":"a@example.com"}`)
	for name, s := range others {
		if len(s.served) != 0 {
			t.Errorf("%s was handed unsigned requests: %v", name, s.served)
		}
	}
}
