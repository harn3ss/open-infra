package cfn

import (
	"context"
	"strings"
	"testing"
)

// restV1Translate deploys tmpl through the REST v1 collation with a capturing hook, returning the plan
// the shim would provision (nil when refused), the error, and the sentinel's caveats.
func restV1Translate(t *testing.T, tmpl string, params map[string]string) (*RestAPIPlan, error) {
	t.Helper()
	opts := deployOpts()
	opts.Params = params
	var captured map[string]any
	opts.ProvisionRestAPI = func(_ context.Context, spec map[string]any) (string, error) {
		captured = spec
		return "api-1", nil
	}
	if _, err := Deploy(context.Background(), []byte(tmpl), opts, &fakeApplier{}); err != nil {
		return nil, err
	}
	p, err := ParseRestAPIPlan(captured)
	if err != nil {
		t.Fatal(err)
	}
	return &p, nil
}

// The REST v1 collation is closed-world: a property that would restrict who reaches the API, or change
// what it serves, refuses the stack instead of being dropped.
func TestRestV1_ClosedWorld_RefusesWhatItCannotServe(t *testing.T) {
	for name, c := range map[string]struct{ from, to, want string }{
		"resource policy": {"Properties: { Name: orders-api }",
			`Properties: { Name: orders-api, Policy: { Version: "2012-10-17", Statement: [ { Effect: Deny, Principal: "*", Action: "execute-api:Invoke", Resource: "*" } ] } }`,
			"property Policy is not translatable"},
		"private endpoint": {"Properties: { Name: orders-api }",
			"Properties: { Name: orders-api, EndpointConfiguration: { Types: [ PRIVATE ] } }", "EndpointConfiguration PRIVATE is not served"},
		"vpc endpoint ids": {"Properties: { Name: orders-api }",
			"Properties: { Name: orders-api, EndpointConfiguration: { Types: [ PRIVATE ], VpcEndpointIds: [ vpce-1 ] } }", "property VpcEndpointIds is not translatable"},
		"openapi body": {"Properties: { Name: orders-api }",
			"Properties: { Name: orders-api, Body: { openapi: 3.0.1 } }", "property Body is not translatable"},
		"default endpoint disabled": {"Properties: { Name: orders-api }",
			"Properties: { Name: orders-api, DisableExecuteApiEndpoint: true }", "DisableExecuteApiEndpoint: true is not served"},
		"lambda authorizer": {"  Deployment:\n", `  Auth:
    Type: AWS::ApiGateway::Authorizer
    Properties: { RestApiId: !Ref ApiGatewayRestApi, Name: a, Type: TOKEN, AuthorizerUri: arn:aws:lambda:fn, IdentitySource: method.request.header.Authorization }
  Deployment:
`, "property AuthorizerUri is not translatable"},
		"iam auth": {"      AuthorizationType: NONE\n      ApiKeyRequired: true", "      AuthorizationType: AWS_IAM\n      ApiKeyRequired: true",
			"AuthorizationType AWS_IAM is not enforced"},
		"authorization scopes": {"      ApiKeyRequired: true", "      ApiKeyRequired: true\n      AuthorizationScopes: [ orders/read ]",
			"property AuthorizationScopes is not translatable"},
		"selection pattern": {`IntegrationResponses: [ { StatusCode: "200", ResponseTemplates: { "application/json": "" } } ]`,
			`IntegrationResponses: [ { StatusCode: "200", ResponseTemplates: { "application/json": "" } }, { StatusCode: "500", SelectionPattern: ".*Error.*" } ]`,
			"SelectionPattern is not served"},
		"integration credentials": {"Integration: { Type: AWS_PROXY, IntegrationHttpMethod: POST, Uri: some-lambda }",
			"Integration: { Type: AWS_PROXY, IntegrationHttpMethod: POST, Uri: some-lambda, Credentials: arn:aws:iam::1:role/r }",
			"property Credentials is not translatable"},
		"vpc link": {"Integration: { Type: AWS_PROXY, IntegrationHttpMethod: POST, Uri: some-lambda }",
			"Integration: { Type: HTTP_PROXY, IntegrationHttpMethod: GET, Uri: http://x, ConnectionType: VPC_LINK }",
			"ConnectionType VPC_LINK is not served"},
		"passthrough never": {"Type: MOCK\n", "Type: MOCK\n        PassthroughBehavior: NEVER\n", "PassthroughBehavior NEVER is not served"},
		"stage canary": {"StageName: prod, Variables", "StageName: prod, CanarySetting: { PercentTraffic: 10 }, Variables",
			"property CanarySetting is not translatable"},
		"deployment stage settings": {"Properties: { RestApiId: !Ref ApiGatewayRestApi }",
			"Properties: { RestApiId: !Ref ApiGatewayRestApi, StageDescription: { ThrottlingRateLimit: 5 } }", "property StageDescription is not translatable"},
		"api key not a boolean": {"Properties: { Name: k1, Enabled: true }", "Properties: { Name: k1, Enabled: maybe }", "Enabled must be true or false"},
	} {
		tmpl := strings.Replace(restV1Stack, c.from, c.to, 1)
		if tmpl == restV1Stack {
			t.Fatalf("%s: the case did not change the template", name)
		}
		if _, err := restV1Translate(t, tmpl, nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want a refusal containing %q, got %v", name, c.want, err)
		}
	}
}

// Settings that change only operation (rate limits, logging, caching) are accepted and reported.
func TestRestV1_ClosedWorld_ReportsWhatItDoesNotApply(t *testing.T) {
	tmpl := strings.NewReplacer(
		"UsagePlanName: up1,", "UsagePlanName: up1, Throttle: { RateLimit: 10, BurstLimit: 20 }, Quota: { Limit: 1000, Period: DAY },",
		"StageName: prod, Variables", "StageName: prod, MethodSettings: [ { HttpMethod: \"*\", ResourcePath: \"/*\", ThrottlingRateLimit: 5 } ], Variables",
	).Replace(restV1Stack)
	plan, err := BuildPlan([]byte(tmpl), nil, "s")
	if err != nil {
		t.Fatal(err)
	}
	var fid []string
	for _, fi := range plan.Fidelity {
		fid = append(fid, fi.Detail)
	}
	all := strings.Join(fid, "\n")
	for _, want := range []string{"Plan: Throttle is not enforced", "Plan: Quota is not enforced", "ProdStage: MethodSettings is not applied"} {
		if !strings.Contains(all, want) {
			t.Errorf("the plan's fidelity summary does not list %q:\n%s", want, all)
		}
	}
	if len(plan.Blockers) != 0 {
		t.Fatalf("operation-only settings must not refuse: %v", plan.Blockers)
	}
	if _, err := restV1Translate(t, tmpl, nil); err != nil {
		t.Fatalf("deploy: %v", err)
	}
}

// CloudFormation booleans arrive as true/false or as the strings a parameter Ref produces. A method's
// ApiKeyRequired from a parameter is honored (not read as false, which would serve it keyless), and an
// ApiKey with Enabled "false" is disabled (not read as enabled).
func TestRestV1_StringBooleansAreHonored(t *testing.T) {
	tmpl := "Parameters:\n  NeedKey: { Type: String, Default: \"true\" }\n  KeyOn: { Type: String, Default: \"false\" }\n" +
		strings.NewReplacer(
			"      ApiKeyRequired: true", "      ApiKeyRequired: !Ref NeedKey",
			"Properties: { Name: k1, Enabled: true }", "Properties: { Name: k1, Enabled: !Ref KeyOn }",
			"Name: body-only, ValidateRequestBody: true", "Name: body-only, ValidateRequestBody: \"true\"",
		).Replace(restV1Stack)
	plan, err := restV1Translate(t, tmpl, nil)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	get, _ := methodByVerb(plan.Methods, "GET")
	if !get.APIKeyRequired {
		t.Error("ApiKeyRequired from a parameter (\"true\") was read as false — the method would be served without a key")
	}
	if len(plan.APIKeys) != 1 || plan.APIKeys[0].Enabled {
		t.Errorf("ApiKey Enabled \"false\" must disable the key: %+v", plan.APIKeys)
	}
	if len(plan.Validators) != 1 || !plan.Validators[0].ValidateRequestBody {
		t.Errorf("ValidateRequestBody \"true\" must validate: %+v", plan.Validators)
	}
}
