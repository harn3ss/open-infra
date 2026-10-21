package cfn

import (
	"context"
	"strings"
	"testing"
)

// a Serverless-Framework-shaped REST v1 stack (one RestApi, logical id ApiGatewayRestApi) exercising
// the collation: a resource off the root, an AWS_PROXY method + a MOCK CORS method with VTL + responses,
// a model, a validator, a deployment+stage with variables, and account-level key/plan/plan-key.
const restV1Stack = `
Resources:
  ApiGatewayRestApi:
    Type: AWS::ApiGateway::RestApi
    Properties: { Name: orders-api }
  ItemsResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref ApiGatewayRestApi
      ParentId: !GetAtt ApiGatewayRestApi.RootResourceId
      PathPart: items
  GetItems:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref ApiGatewayRestApi
      ResourceId: !Ref ItemsResource
      HttpMethod: GET
      AuthorizationType: NONE
      ApiKeyRequired: true
      Integration: { Type: AWS_PROXY, IntegrationHttpMethod: POST, Uri: some-lambda }
      MethodResponses: [ { StatusCode: "200" } ]
  OptionsItems:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref ApiGatewayRestApi
      ResourceId: !Ref ItemsResource
      HttpMethod: OPTIONS
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates: { "application/json": "{\"statusCode\":200}" }
        IntegrationResponses: [ { StatusCode: "200", ResponseTemplates: { "application/json": "" } } ]
  ItemModel:
    Type: AWS::ApiGateway::Model
    Properties: { RestApiId: !Ref ApiGatewayRestApi, ContentType: application/json, Name: Item, Schema: { type: object } }
  Validator:
    Type: AWS::ApiGateway::RequestValidator
    Properties: { RestApiId: !Ref ApiGatewayRestApi, Name: body-only, ValidateRequestBody: true }
  Deployment:
    Type: AWS::ApiGateway::Deployment
    Properties: { RestApiId: !Ref ApiGatewayRestApi }
  ProdStage:
    Type: AWS::ApiGateway::Stage
    Properties: { RestApiId: !Ref ApiGatewayRestApi, DeploymentId: !Ref Deployment, StageName: prod, Variables: { ver: "1" } }
  Key:
    Type: AWS::ApiGateway::ApiKey
    Properties: { Name: k1, Enabled: true }
  Plan:
    Type: AWS::ApiGateway::UsagePlan
    Properties: { UsagePlanName: up1, ApiStages: [ { ApiId: !Ref ApiGatewayRestApi, Stage: prod } ] }
  PlanKey:
    Type: AWS::ApiGateway::UsagePlanKey
    Properties: { KeyId: !Ref Key, KeyType: API_KEY, UsagePlanId: !Ref Plan }
`

func methodByVerb(ms []RestMethodPlan, verb string) (RestMethodPlan, bool) {
	for _, m := range ms {
		if m.HTTPMethod == verb {
			return m, true
		}
	}
	return RestMethodPlan{}, false
}

func TestDeploy_RestV1_Collation(t *testing.T) {
	f := &fakeApplier{}
	var captured map[string]any
	calls := 0
	opts := deployOpts()
	opts.ProvisionRestAPI = func(_ context.Context, spec map[string]any) (string, error) {
		captured = spec
		calls++
		return "api-xyz", nil
	}
	rec, err := Deploy(context.Background(), []byte(restV1Stack), opts, f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if calls != 1 {
		t.Fatalf("ProvisionRestAPI called %d times, want 1", calls)
	}
	// The sentinel is provisioned via the hook — NO apigateway k8s object is applied (only the record).
	for _, id := range f.applied {
		if !strings.HasPrefix(id, "ConfigMap/cfn-stack-") {
			t.Errorf("unexpected k8s apply %q — REST v1 must not kubectl-apply anything", id)
		}
	}
	// The created api id is recorded on the stack resource for teardown.
	var provisionedID string
	for _, r := range rec.Resources {
		if r.Kind == apigwRestV1Kind {
			provisionedID = r.ProvisionedID
		}
	}
	if provisionedID != "api-xyz" {
		t.Errorf("stack record ProvisionedID = %q, want api-xyz", provisionedID)
	}

	plan, perr := ParseRestAPIPlan(captured)
	if perr != nil {
		t.Fatalf("parse plan: %v", perr)
	}
	if plan.Name != "orders-api" {
		t.Errorf("plan.Name = %q", plan.Name)
	}
	if len(plan.Resources) != 1 || plan.Resources[0].PathPart != "items" || plan.Resources[0].Parent != rootResourceRef {
		t.Errorf("resources = %+v (want one /items off the root)", plan.Resources)
	}
	get, ok := methodByVerb(plan.Methods, "GET")
	if !ok || get.Resource != "ItemsResource" || !get.APIKeyRequired || get.Integration == nil || get.Integration.Type != "AWS_PROXY" {
		t.Errorf("GET method = %+v (want on ItemsResource, apiKeyRequired, AWS_PROXY)", get)
	}
	if len(get.MethodResponses) != 1 || get.MethodResponses[0].StatusCode != "200" {
		t.Errorf("GET methodResponses = %+v", get.MethodResponses)
	}
	opt, ok := methodByVerb(plan.Methods, "OPTIONS")
	if !ok || opt.Integration == nil || opt.Integration.Type != "MOCK" || opt.Integration.RequestTemplates["application/json"] == "" {
		t.Errorf("OPTIONS method = %+v (want MOCK with a request template)", opt)
	}
	if opt.Integration.IntegrationResponses["200"] == nil {
		t.Errorf("OPTIONS integration responses = %+v (want a 200 entry)", opt.Integration.IntegrationResponses)
	}
	if len(plan.Models) != 1 || plan.Models[0].Name != "Item" {
		t.Errorf("models = %+v", plan.Models)
	}
	if len(plan.Validators) != 1 || !plan.Validators[0].ValidateRequestBody {
		t.Errorf("validators = %+v", plan.Validators)
	}
	if len(plan.Stages) != 1 || plan.Stages[0].StageName != "prod" || plan.Stages[0].Variables["ver"] != "1" {
		t.Errorf("stages = %+v", plan.Stages)
	}
	if len(plan.APIKeys) != 1 || plan.APIKeys[0].Name != "k1" || !plan.APIKeys[0].Enabled {
		t.Errorf("apiKeys = %+v", plan.APIKeys)
	}
	if len(plan.UsagePlans) != 1 {
		t.Fatalf("usagePlans = %+v", plan.UsagePlans)
	}
	up := plan.UsagePlans[0]
	if up.Name != "up1" || len(up.APIStages) != 1 || up.APIStages[0].Stage != "prod" {
		t.Errorf("usage plan stages = %+v", up)
	}
	if len(up.Keys) != 1 || up.Keys[0] != "Key" {
		t.Errorf("usage plan keys = %+v (want [Key])", up.Keys)
	}
}

func TestDeploy_RestV1_NoHookRefuses(t *testing.T) {
	o := deployOpts() // no ProvisionRestAPI hook (a CLI deploy)
	_, err := Deploy(context.Background(), []byte(restV1Stack), o, &fakeApplier{})
	if err == nil || !strings.Contains(err.Error(), "in-cluster") {
		t.Fatalf("a REST v1 stack with no hook must refuse mentioning the in-cluster path, got: %v", err)
	}
}

func TestDeploy_RestV1_RollbackDeprovisions(t *testing.T) {
	// A KMS key ordered AFTER the api (DependsOn) fails to apply — the already-provisioned API must be
	// torn down via DeprovisionRestAPI (no orphan).
	stack := restV1Stack + `
  FailKey:
    Type: AWS::KMS::Key
    DependsOn: ApiGatewayRestApi
    Properties: { Description: boom }
`
	f := &fakeApplier{failOn: "EncryptionKey/" + k8sName("FailKey")}
	var deprovisioned []string
	opts := deployOpts()
	opts.ProvisionRestAPI = func(_ context.Context, _ map[string]any) (string, error) { return "api-xyz", nil }
	opts.DeprovisionRestAPI = func(_ context.Context, id string) error {
		deprovisioned = append(deprovisioned, id)
		return nil
	}
	rec, err := Deploy(context.Background(), []byte(stack), opts, f)
	if err == nil {
		t.Fatal("expected the deploy to fail and roll back")
	}
	if rec.Status != "CREATE_FAILED" {
		t.Errorf("status = %q, want CREATE_FAILED", rec.Status)
	}
	if len(deprovisioned) != 1 || deprovisioned[0] != "api-xyz" {
		t.Errorf("deprovisioned = %v, want [api-xyz] (rollback must tear the API down)", deprovisioned)
	}
}
