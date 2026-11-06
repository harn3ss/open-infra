package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// cognitoMemberClaims is the member account's bob, whom cognitoMemberAuthz lets administer user pools.
var cognitoMemberClaims = iam.Claims{Sub: "bob", Account: testMember}

func cognitoMemberAuthz(t *testing.T) *dataplaneauthz.Checker {
	t.Helper()
	return checkerInMode(t, "legacy", dataplaneauthz.PolicyDoc{Name: "pools", AppliesTo: []string{"User::" + memberHome + "/bob"},
		Statements: []policyengine.Statement{dpAllow([]string{"cognito-idp:*"}, "*")}})
}

// cognitoMemberCall is cognitoCall as the router hands a member account's request to an account-scoped door.
func cognitoMemberCall(t *testing.T, h *cognitoHandler, op, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://cognito/", strings.NewReader(body))
	ctx := withAccountHome(req.Context(), memberHome)
	ctx = awsidentity.WithIdentity(ctx, awsidentity.Current().ForAccount(testMember, memberHome))
	req = req.WithContext(inAccountScope(ctx))
	req.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService."+op)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	w := httptest.NewRecorder()
	h.serve(w, req, cognitoMemberClaims, "r-m")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// cognitoAnonCall is an unsigned end-user request (SignUp, InitiateAuth …), which names no account.
func cognitoAnonCall(t *testing.T, h *cognitoHandler, op, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://cognito/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService."+op)
	w := httptest.NewRecorder()
	h.serveAnonymous(w, req, "r-a")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A pool made before accounts (no account column) is the management account's: the column is added with
// nothing to migrate, and the management account still administers the pool.
func TestServicesPG_CognitoAccountColumnNeedsNoMigration(t *testing.T) {
	db := freshPGDB(t)
	if _, err := db.Exec(`CREATE TABLE cognito_pools (pool_id text PRIMARY KEY, name text NOT NULL,
		password_policy jsonb NOT NULL DEFAULT '{}', created timestamptz NOT NULL DEFAULT now());
		INSERT INTO cognito_pools (pool_id, name) VALUES ('us-east-1_old', 'old')`); err != nil {
		t.Fatal(err)
	}
	st := &cognitoStore{db: db}
	for i := 0; i < 2; i++ { // and again: the schema is idempotent
		if err := st.ensureSchema(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	p, ok, err := st.getPool(context.Background(), "us-east-1_old")
	if err != nil || !ok || p.Account != "" || p.Name != "old" {
		t.Fatalf("the earlier pool = %+v %v %v, want the management account's", p, ok, err)
	}
	h := newCognitoHandler(csWithSAR(true), "default", "000000000000", "us-east-1", "http://shim", st, testSigner(t), discardLogger())
	h.authz = cognitoMemberAuthz(t)
	if code, out := cognitoCall(t, h, iam.Claims{Sub: "u"}, "DescribeUserPool", `{"UserPoolId":"us-east-1_old"}`); code != http.StatusOK {
		t.Errorf("the management account describing its earlier pool = %d %v", code, out)
	}
	if code, out := cognitoMemberCall(t, h, "DescribeUserPool", `{"UserPoolId":"us-east-1_old"}`); code != http.StatusBadRequest || out["__type"] != "ResourceNotFoundException" {
		t.Errorf("a member account describing the management account's pool = %d %v", code, out)
	}
}

// Each account's user pools are its own: a member account creates and administers its pools (their ARNs
// carry its account); the management account's pool — even one of the same name — is a pool that does not
// exist to the member, and the member's to the management account; the end-user operations still work by
// client id on either account's pool.
func TestServicesPG_CognitoPoolsPerAccount(t *testing.T) {
	st := &cognitoStore{db: freshPGDB(t)}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := newCognitoHandler(csWithSAR(true), "default", "000000000000", "us-east-1", "http://shim", st, testSigner(t), discardLogger())
	h.authz = cognitoMemberAuthz(t)
	mgmtUser := iam.Claims{Sub: "u"}

	code, out := cognitoCall(t, h, mgmtUser, "CreateUserPool", `{"PoolName":"shared"}`)
	if code != http.StatusOK {
		t.Fatalf("management CreateUserPool = %d %v", code, out)
	}
	mp := out["UserPool"].(map[string]any)
	mgmtPool := mp["Id"].(string)
	if mp["Arn"] != "arn:aws:cognito-idp:us-east-1:000000000000:userpool/"+mgmtPool {
		t.Errorf("the management account's pool ARN = %v", mp["Arn"])
	}
	code, out = cognitoMemberCall(t, h, "CreateUserPool", `{"PoolName":"shared"}`)
	if code != http.StatusOK {
		t.Fatalf("member CreateUserPool = %d %v", code, out)
	}
	up := out["UserPool"].(map[string]any)
	memberPool := up["Id"].(string)
	if memberPool == mgmtPool || up["Arn"] != "arn:aws:cognito-idp:us-east-1:"+testMember+":userpool/"+memberPool {
		t.Errorf("the member account's pool = %v", up)
	}
	if p, _, _ := st.getPool(context.Background(), mgmtPool); p.Account != "" {
		t.Errorf("the management account's pool is recorded under %q", p.Account)
	}
	if p, _, _ := st.getPool(context.Background(), memberPool); p.Account != testMember {
		t.Errorf("the member account's pool is recorded under %q", p.Account)
	}

	// Each describes its own.
	if code, out := cognitoMemberCall(t, h, "DescribeUserPool", `{"UserPoolId":"`+memberPool+`"}`); code != http.StatusOK || out["UserPool"].(map[string]any)["Name"] != "shared" {
		t.Errorf("member DescribeUserPool (own) = %d %v", code, out)
	}
	if code, out := cognitoCall(t, h, mgmtUser, "DescribeUserPool", `{"UserPoolId":"`+mgmtPool+`"}`); code != http.StatusOK {
		t.Errorf("management DescribeUserPool (own) = %d %v", code, out)
	}

	notFound := func(name string, code int, out map[string]any) {
		t.Helper()
		if code != http.StatusBadRequest || out["__type"] != "ResourceNotFoundException" {
			t.Errorf("%s = %d %v, want ResourceNotFoundException", name, code, out)
		}
	}
	// The member reaches nothing of the management account's pool, by any administrative operation.
	for _, c := range []struct{ op, body string }{
		{"DescribeUserPool", `{"UserPoolId":"` + mgmtPool + `"}`},
		{"CreateUserPoolClient", `{"UserPoolId":"` + mgmtPool + `","ClientName":"x"}`},
		{"ListUserPoolClients", `{"UserPoolId":"` + mgmtPool + `"}`},
		{"AdminCreateUser", `{"UserPoolId":"` + mgmtPool + `","Username":"mallory","TemporaryPassword":"Passw0rd!"}`},
		{"AdminGetUser", `{"UserPoolId":"` + mgmtPool + `","Username":"alice"}`},
		{"AdminConfirmSignUp", `{"UserPoolId":"` + mgmtPool + `","Username":"alice"}`},
		{"AdminSetUserPassword", `{"UserPoolId":"` + mgmtPool + `","Username":"alice","Password":"Passw0rd!x","Permanent":true}`},
		{"DeleteUserPool", `{"UserPoolId":"` + mgmtPool + `"}`},
	} {
		code, out := cognitoMemberCall(t, h, c.op, c.body)
		notFound("member "+c.op+" on the management account's pool", code, out)
	}
	if _, ok, _ := st.getPool(context.Background(), mgmtPool); !ok {
		t.Fatal("the member deleted the management account's pool")
	}
	if _, exists, _ := st.getUser(context.Background(), mgmtPool, "mallory"); exists {
		t.Error("the member created a user in the management account's pool")
	}
	// Nor does the management account reach the member's.
	for _, c := range []struct{ op, body string }{
		{"DescribeUserPool", `{"UserPoolId":"` + memberPool + `"}`},
		{"AdminCreateUser", `{"UserPoolId":"` + memberPool + `","Username":"mallory","TemporaryPassword":"Passw0rd!"}`},
		{"DeleteUserPool", `{"UserPoolId":"` + memberPool + `"}`},
	} {
		code, out := cognitoCall(t, h, mgmtUser, c.op, c.body)
		notFound("management "+c.op+" on the member's pool", code, out)
	}
	if _, ok, _ := st.getPool(context.Background(), memberPool); !ok {
		t.Fatal("the management account deleted the member's pool")
	}

	// The member administers its own pool: a client, a user; the end user signs in by client id, unsigned.
	code, out = cognitoMemberCall(t, h, "CreateUserPoolClient", `{"UserPoolId":"`+memberPool+`","ClientName":"web","ExplicitAuthFlows":["ALLOW_USER_PASSWORD_AUTH"]}`)
	if code != http.StatusOK {
		t.Fatalf("member CreateUserPoolClient = %d %v", code, out)
	}
	client := out["UserPoolClient"].(map[string]any)["ClientId"].(string)
	if code, out := cognitoMemberCall(t, h, "AdminCreateUser", `{"UserPoolId":"`+memberPool+`","Username":"carol","TemporaryPassword":"Passw0rd!"}`); code != http.StatusOK {
		t.Fatalf("member AdminCreateUser = %d %v", code, out)
	}
	if code, out := cognitoMemberCall(t, h, "ListUserPoolClients", `{"UserPoolId":"`+memberPool+`"}`); code != http.StatusOK || len(out["UserPoolClients"].([]any)) != 1 {
		t.Errorf("member ListUserPoolClients = %d %v", code, out)
	}
	code, out = cognitoAnonCall(t, h, "InitiateAuth", `{"AuthFlow":"USER_PASSWORD_AUTH","ClientId":"`+client+`","AuthParameters":{"USERNAME":"carol","PASSWORD":"Passw0rd!"}}`)
	if code != http.StatusOK || out["AuthenticationResult"] == nil {
		t.Errorf("an end user signing in to the member's pool by client id = %d %v", code, out)
	}
	if code, out := cognitoAnonCall(t, h, "SignUp", `{"ClientId":"`+client+`","Username":"dave","Password":"Passw0rd!"}`); code != http.StatusOK {
		t.Errorf("an end user signing up to the member's pool by client id = %d %v", code, out)
	}
	// AdminInitiateAuth names the pool: the member's own works, the management account's does not exist.
	code, out = cognitoMemberCall(t, h, "AdminInitiateAuth", `{"UserPoolId":"`+memberPool+`","ClientId":"`+client+`","AuthFlow":"ADMIN_USER_PASSWORD_AUTH","AuthParameters":{"USERNAME":"carol","PASSWORD":"Passw0rd!"}}`)
	if code != http.StatusOK {
		t.Errorf("member AdminInitiateAuth (own) = %d %v", code, out)
	}
	code, out = cognitoMemberCall(t, h, "AdminInitiateAuth", `{"UserPoolId":"`+mgmtPool+`","ClientId":"`+client+`","AuthFlow":"ADMIN_USER_PASSWORD_AUTH","AuthParameters":{"USERNAME":"carol","PASSWORD":"Passw0rd!"}}`)
	notFound("member AdminInitiateAuth on the management account's pool", code, out)

	// A member principal its own policy does not allow is refused.
	req := httptest.NewRequest(http.MethodPost, "http://cognito/", strings.NewReader(`{"UserPoolId":"`+memberPool+`"}`))
	ctx := awsidentity.WithIdentity(withAccountHome(req.Context(), memberHome), awsidentity.Current().ForAccount(testMember, memberHome))
	req = req.WithContext(inAccountScope(ctx))
	req.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService.DescribeUserPool")
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "eve", Account: testMember}, "r-e")
	if w.Code != http.StatusForbidden {
		t.Errorf("a member principal with no policy = %d, want 403", w.Code)
	}

	// The member deletes its own pool.
	if code, out := cognitoMemberCall(t, h, "DeleteUserPool", `{"UserPoolId":"`+memberPool+`"}`); code != http.StatusOK {
		t.Errorf("member DeleteUserPool (own) = %d %v", code, out)
	}
	if _, ok, _ := st.getPool(context.Background(), mgmtPool); !ok {
		t.Error("the management account's pool of the same name went with the member's")
	}
}

// Cognito is an account-scoped front door.
func TestCognito_AccountScoped(t *testing.T) {
	if !accountScopedServices["cognito-idp"] {
		t.Error("cognito-idp is not registered as account-scoped")
	}
}
