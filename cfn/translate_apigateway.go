// API Gateway REST v1 CFN deploy executor — the collation half (#295).
//
// REST v1 has no single Crossplane kind: it is a stateful, ordered multi-resource sequence provisioned
// through the aws-shim's `apigateway` REST v1 API. So — like a Lambda-backed custom resource — it is NOT
// a kubectl-applied manifest. Instead the whole API collates into ONE sentinel manifest carrying a
// RestAPIPlan, and the deploy loop hands that plan to the ProvisionRestAPI hook (set by the in-cluster
// aws-shim doorway), which materializes it by driving the apigateway API in order. A CLI deploy (no
// hook) refuses rather than guessing — exactly the custom-resource stance.
//
// The plan carries LOGICAL references, not real ids: a resource's parent, a method's resource, a
// method's authorizer/validator, a usage-plan key's key/plan are all named by CloudFormation logical id
// (or the sentinel "<root>" for the API's seeded root resource). The executor assigns real ids as it
// creates each object and resolves these logical references on the fly — so nothing here needs an id
// that only exists after provisioning (which is what makes Fn::GetAtt RootResourceId unresolvable at
// translate time; carrying the logical graph sidesteps it).
package cfn

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	apigwRestV1APIVersion = "cfn.openinfra.dev/v1"
	apigwRestV1Kind       = "ApiGatewayRestV1Provision"
	// rootResourceRef is the logical "parent" of a resource/method attached to the API's seeded root
	// (CloudFormation expresses this as Fn::GetAtt <RestApi>.RootResourceId).
	rootResourceRef = "<root>"
)

// RestAPIPlan is the complete description of a REST v1 API (+ the account-level keys/usage plans declared
// in the same stack) to provision via the aws-shim apigateway API. Exported so the shim doorway's
// ProvisionRestAPI hook can parse it from the sentinel's Spec with ParseRestAPIPlan.
type RestAPIPlan struct {
	LogicalID   string               `json:"logicalId"`
	Name        string               `json:"name"`
	Resources   []RestResourcePlan   `json:"resources,omitempty"`
	Methods     []RestMethodPlan     `json:"methods,omitempty"`
	Models      []RestModelPlan      `json:"models,omitempty"`
	Validators  []RestValidatorPlan  `json:"validators,omitempty"`
	Authorizers []RestAuthorizerPlan `json:"authorizers,omitempty"`
	Stages      []RestStagePlan      `json:"stages,omitempty"`
	APIKeys     []RestAPIKeyPlan     `json:"apiKeys,omitempty"`
	UsagePlans  []RestUsagePlanPlan  `json:"usagePlans,omitempty"`
}

type RestResourcePlan struct {
	LogicalID string `json:"logicalId"`
	Parent    string `json:"parent"` // parent resource logical id, or rootResourceRef
	PathPart  string `json:"pathPart"`
}

type RestIntegrationPlan struct {
	Type                  string                       `json:"type"` // AWS | AWS_PROXY | HTTP | HTTP_PROXY | MOCK
	URI                   string                       `json:"uri,omitempty"`
	IntegrationHTTPMethod string                       `json:"integrationHttpMethod,omitempty"`
	RequestTemplates      map[string]string            `json:"requestTemplates,omitempty"`
	IntegrationResponses  map[string]map[string]string `json:"integrationResponses,omitempty"` // statusCode → (contentType → VTL)
}

type RestMethodResponsePlan struct {
	StatusCode         string            `json:"statusCode"`
	ResponseModels     map[string]string `json:"responseModels,omitempty"`
	ResponseParameters map[string]bool   `json:"responseParameters,omitempty"`
}

type RestMethodPlan struct {
	Resource          string                   `json:"resource"` // resource logical id, or rootResourceRef
	HTTPMethod        string                   `json:"httpMethod"`
	AuthorizationType string                   `json:"authorizationType,omitempty"`
	Authorizer        string                   `json:"authorizer,omitempty"` // authorizer logical id
	APIKeyRequired    bool                     `json:"apiKeyRequired,omitempty"`
	RequestValidator  string                   `json:"requestValidator,omitempty"` // validator logical id
	RequestModels     map[string]string        `json:"requestModels,omitempty"`
	RequestParameters map[string]bool          `json:"requestParameters,omitempty"`
	Integration       *RestIntegrationPlan     `json:"integration,omitempty"`
	MethodResponses   []RestMethodResponsePlan `json:"methodResponses,omitempty"`
}

type RestModelPlan struct {
	LogicalID   string `json:"logicalId"`
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Schema      string `json:"schema,omitempty"` // JSON Schema as a string (how AWS carries it)
}

type RestValidatorPlan struct {
	LogicalID                 string `json:"logicalId"`
	Name                      string `json:"name"`
	ValidateRequestBody       bool   `json:"validateRequestBody"`
	ValidateRequestParameters bool   `json:"validateRequestParameters"`
}

type RestAuthorizerPlan struct {
	LogicalID      string   `json:"logicalId"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	ProviderARNs   []string `json:"providerArns,omitempty"`
	IdentitySource string   `json:"identitySource,omitempty"`
}

type RestStagePlan struct {
	StageName string            `json:"stageName"`
	Variables map[string]string `json:"variables,omitempty"`
}

type RestAPIKeyPlan struct {
	LogicalID string `json:"logicalId"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Value     string `json:"value,omitempty"`
}

type RestUsagePlanPlan struct {
	LogicalID string             `json:"logicalId"`
	Name      string             `json:"name"`
	APIStages []RestUsagePlanAPI `json:"apiStages,omitempty"`
	Keys      []string           `json:"keys,omitempty"` // api-key logical ids associated with this plan
}

type RestUsagePlanAPI struct {
	Stage string `json:"stage"` // api is always THIS plan's RestApi (single-API stacks)
}

// ParseRestAPIPlan reconstructs a RestAPIPlan from a sentinel manifest's Spec (JSON round-trip). The
// aws-shim doorway's ProvisionRestAPI hook calls this.
func ParseRestAPIPlan(spec map[string]any) (RestAPIPlan, error) {
	var p RestAPIPlan
	b, err := json.Marshal(spec)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(b, &p)
	return p, err
}

// planToSpec marshals a RestAPIPlan into the map[string]any a Manifest.Spec holds.
func planToSpec(p RestAPIPlan) map[string]any {
	b, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// The REST v1 collation is closed-world, like every other translator: each AWS::ApiGateway::* resource
// (and each nested block it carries) names the properties the shim's REST v1 API honors, the ones that
// change nothing it serves (reported as caveats), and nothing else. Any other property refuses the
// stack, since dropping it silently would serve a different API than the template describes — a resource
// policy or a PRIVATE endpoint would be served open, a Lambda authorizer would be skipped.
var apigwKnown = map[string]map[string]bool{
	"AWS::ApiGateway::RestApi": {
		"Name": true, "Description": true, "Tags": true, "EndpointConfiguration": true, "FailOnWarnings": true,
		"MinimumCompressionSize": true, "ApiKeySourceType": true, "DisableExecuteApiEndpoint": true,
	},
	"AWS::ApiGateway::Resource": {"RestApiId": true, "ParentId": true, "PathPart": true},
	"AWS::ApiGateway::Method": {
		"RestApiId": true, "ResourceId": true, "HttpMethod": true, "AuthorizationType": true, "AuthorizerId": true,
		"ApiKeyRequired": true, "RequestValidatorId": true, "RequestModels": true, "RequestParameters": true,
		"Integration": true, "MethodResponses": true, "OperationName": true,
	},
	"AWS::ApiGateway::Model":            {"RestApiId": true, "Name": true, "ContentType": true, "Schema": true, "Description": true},
	"AWS::ApiGateway::RequestValidator": {"RestApiId": true, "Name": true, "ValidateRequestBody": true, "ValidateRequestParameters": true},
	"AWS::ApiGateway::Authorizer": {
		"RestApiId": true, "Name": true, "Type": true, "ProviderARNs": true, "IdentitySource": true,
		"AuthorizerResultTtlInSeconds": true, "AuthType": true,
	},
	"AWS::ApiGateway::Deployment": {"RestApiId": true, "StageName": true, "Description": true},
	"AWS::ApiGateway::Stage": {
		"RestApiId": true, "StageName": true, "DeploymentId": true, "Variables": true, "Description": true, "Tags": true,
		"MethodSettings": true, "AccessLogSetting": true, "TracingEnabled": true, "CacheClusterEnabled": true,
		"CacheClusterSize": true, "DocumentationVersion": true,
	},
	"AWS::ApiGateway::ApiKey": {
		"Name": true, "Enabled": true, "Value": true, "Description": true, "Tags": true, "CustomerId": true,
		"GenerateDistinctId": true,
	},
	"AWS::ApiGateway::UsagePlan":    {"UsagePlanName": true, "ApiStages": true, "Description": true, "Tags": true, "Throttle": true, "Quota": true},
	"AWS::ApiGateway::UsagePlanKey": {"KeyId": true, "KeyType": true, "UsagePlanId": true},
}

var (
	apigwIntegrationKnown = map[string]bool{
		"Type": true, "Uri": true, "IntegrationHttpMethod": true, "RequestTemplates": true, "IntegrationResponses": true,
		"PassthroughBehavior": true, "TimeoutInMillis": true, "CacheKeyParameters": true, "CacheNamespace": true,
		"ConnectionType": true,
	}
	apigwIntegrationResponseKnown = map[string]bool{"StatusCode": true, "ResponseTemplates": true, "SelectionPattern": true, "ResponseParameters": true}
	apigwMethodResponseKnown      = map[string]bool{"StatusCode": true, "ResponseModels": true, "ResponseParameters": true}
	apigwEndpointKnown            = map[string]bool{"Types": true}
	apigwAPIStageKnown            = map[string]bool{"ApiId": true, "Stage": true, "Throttle": true}
)

// apigwCollation gathers the findings (refusals) and caveats of one REST v1 collation, each attributed to
// the CloudFormation resource it came from.
type apigwCollation struct {
	ctx *stackCtx
	f   []Finding
	cav []string
}

func (a *apigwCollation) refuse(id, msg string) { a.f = append(a.f, Finding{"Resource " + id, msg}) }

func (a *apigwCollation) caveat(id, msg string) { a.cav = append(a.cav, id+": "+msg) }

// props resolves child id's properties and refuses any its type does not name.
func (a *apigwCollation) props(id string) map[string]any {
	sp, _ := a.ctx.resolveProps(id)
	a.f = append(a.f, blockUnknownProps(id, sp, apigwKnown[a.ctx.template.Resources[id].Type])...)
	return sp
}

// block reads a nested object property, refusing keys known does not name and a value that is not an
// object. where names it in findings ("Integration", "MethodResponses[1]").
func (a *apigwCollation) block(id, where string, v any, known map[string]bool) map[string]any {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		a.refuse(id, where+" does not resolve to an object")
		return nil
	}
	a.f = append(a.f, blockUnknownProps(id+"."+where, m, known)...)
	return m
}

// blocks reads a list-of-objects property through block.
func (a *apigwCollation) blocks(id, where string, v any, known map[string]bool) []map[string]any {
	if v == nil {
		return nil
	}
	l, ok := v.([]any)
	if !ok {
		a.refuse(id, where+" does not resolve to a list")
		return nil
	}
	var out []map[string]any
	for i, e := range l {
		if m := a.block(id, fmt.Sprintf("%s[%d]", where, i), e, known); m != nil {
			out = append(out, m)
		}
	}
	return out
}

// boolean reads a CloudFormation boolean (true/false or "true"/"false"), def when absent; anything else
// refuses — read as false, an ApiKeyRequired that came from a parameter would serve the method keyless.
func (a *apigwCollation) boolean(id, where string, v any, def bool) bool {
	if v == nil {
		return def
	}
	b, ok := cfnBoolValue(v)
	if !ok {
		a.refuse(id, fmt.Sprintf("%s must be true or false (got %v)", where, v))
		return def
	}
	return b
}

// boolMap reads a {name: boolean} map (RequestParameters, ResponseParameters) strictly.
func (a *apigwCollation) boolMap(id, where string, v any) map[string]bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		if v != nil && !ok {
			a.refuse(id, where+" does not resolve to an object")
		}
		return nil
	}
	out := map[string]bool{}
	for _, k := range sortedKeys(m) {
		out[k] = a.boolean(id, where+"."+k, m[k], false)
	}
	return out
}

// present reports whether a property is set to anything but AWS::NoValue.
func present(props map[string]any, k string) bool {
	v, ok := props[k]
	return ok && v != nil
}

// translateAPIGatewayRestAPI collates a stack's AWS::ApiGateway::* resources that belong to THIS RestApi
// (plus the account-level API keys/usage plans, when this is the sole RestApi in the stack) into one
// RestAPIPlan sentinel. The child resource types translate to nil (composed here).
func translateAPIGatewayRestAPI(logicalID string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	fin := func(msg string) []Finding { return []Finding{{"Resource " + logicalID, msg}} }
	if ctx == nil {
		return nil, fin("a REST API needs stack context to collate its resources")
	}
	a := &apigwCollation{ctx: ctx}
	a.f = append(a.f, blockUnknownProps(logicalID, props, apigwKnown["AWS::ApiGateway::RestApi"])...)
	name, _ := concrete(props["Name"])
	if name == "" {
		name = logicalID
	}
	plan := RestAPIPlan{LogicalID: logicalID, Name: name}
	a.restAPIProps(logicalID, props)

	// Resources (scoped to this api), each carrying its parent as a logical ref.
	for _, rid := range ctx.apigwChildren("AWS::ApiGateway::Resource", logicalID) {
		raw, _ := ctx.rawProps(rid)
		sp := a.props(rid)
		part, _ := concrete(sp["PathPart"])
		plan.Resources = append(plan.Resources, RestResourcePlan{
			LogicalID: rid, Parent: ctx.apigwParentRef(raw["ParentId"], logicalID), PathPart: part,
		})
	}
	// Models.
	for _, mid := range ctx.apigwChildren("AWS::ApiGateway::Model", logicalID) {
		sp := a.props(mid)
		name, _ := concrete(sp["Name"])
		if name == "" {
			name = mid
		}
		ct, _ := concrete(sp["ContentType"])
		if ct == "" {
			ct = "application/json"
		}
		plan.Models = append(plan.Models, RestModelPlan{LogicalID: mid, Name: name, ContentType: ct, Schema: schemaString(sp["Schema"])})
	}
	// Request validators.
	for _, vid := range ctx.apigwChildren("AWS::ApiGateway::RequestValidator", logicalID) {
		sp := a.props(vid)
		n, _ := concrete(sp["Name"])
		plan.Validators = append(plan.Validators, RestValidatorPlan{
			LogicalID: vid, Name: n,
			ValidateRequestBody:       a.boolean(vid, "ValidateRequestBody", sp["ValidateRequestBody"], false),
			ValidateRequestParameters: a.boolean(vid, "ValidateRequestParameters", sp["ValidateRequestParameters"], false),
		})
	}
	// Authorizers. The shim fronts Cognito user pool authorizers only; a Lambda (TOKEN/REQUEST) one has
	// nothing to run it, so it refuses here rather than at provisioning.
	for _, aid := range ctx.apigwChildren("AWS::ApiGateway::Authorizer", logicalID) {
		sp := a.props(aid)
		n, _ := concrete(sp["Name"])
		at, _ := concrete(sp["Type"])
		if at != "COGNITO_USER_POOLS" {
			a.refuse(aid, fmt.Sprintf("authorizer Type %q is not served — the REST v1 front door validates Cognito user pool (COGNITO_USER_POOLS) tokens only; a Lambda (TOKEN/REQUEST) authorizer has nothing to run it", at))
		}
		if present(sp, "AuthType") {
			a.caveat(aid, "AuthType is not kept — it labels the authorizer for generated SDKs and changes nothing validated")
		}
		if present(sp, "AuthorizerResultTtlInSeconds") {
			a.caveat(aid, "AuthorizerResultTtlInSeconds is not applied — every request's token is validated (nothing is cached)")
		}
		plan.Authorizers = append(plan.Authorizers, RestAuthorizerPlan{
			LogicalID: aid, Name: n, Type: at,
			ProviderARNs:   asStrings(sp["ProviderARNs"]),
			IdentitySource: concreteOr(sp["IdentitySource"], ""),
		})
	}
	// Methods (+ inline integration + method/integration responses).
	for _, mid := range ctx.apigwChildren("AWS::ApiGateway::Method", logicalID) {
		plan.Methods = append(plan.Methods, a.method(mid, logicalID))
	}
	// Stages (each points at the single post-tree deployment snapshot the executor takes).
	for _, sid := range ctx.apigwChildren("AWS::ApiGateway::Stage", logicalID) {
		sp := a.props(sid)
		a.stageProps(sid, sp)
		sn, _ := concrete(sp["StageName"])
		if sn == "" {
			a.refuse(sid, "StageName is required")
			continue
		}
		plan.Stages = append(plan.Stages, RestStagePlan{StageName: sn, Variables: stringMapOf(sp["Variables"])})
	}
	// A Deployment that carries an inline StageName (the older single-call form) also makes a stage.
	for _, did := range ctx.apigwChildren("AWS::ApiGateway::Deployment", logicalID) {
		sp := a.props(did)
		if sn, _ := concrete(sp["StageName"]); sn != "" && !hasStage(plan.Stages, sn) {
			plan.Stages = append(plan.Stages, RestStagePlan{StageName: sn})
		}
	}

	// Account-level API keys + usage plans — only when this is the sole RestApi in the stack (otherwise
	// which api a key unlocks is ambiguous; the child translator blocks that case rather than guessing).
	if ctx.apigwRestAPICount() == 1 {
		for _, kid := range ctx.apigwAllOfType("AWS::ApiGateway::ApiKey") {
			sp := a.props(kid)
			n, _ := concrete(sp["Name"])
			for _, p := range []string{"CustomerId", "GenerateDistinctId"} {
				if present(sp, p) {
					a.caveat(kid, p+" is not kept — it identifies the key for AWS Marketplace / naming and changes nothing the key unlocks")
				}
			}
			plan.APIKeys = append(plan.APIKeys, RestAPIKeyPlan{
				LogicalID: kid, Name: n, Enabled: a.boolean(kid, "Enabled", sp["Enabled"], true), Value: concreteOr(sp["Value"], ""),
			})
		}
		for _, pid := range ctx.apigwAllOfType("AWS::ApiGateway::UsagePlan") {
			sp := a.props(pid)
			n, _ := concrete(sp["UsagePlanName"])
			for _, p := range []string{"Throttle", "Quota"} {
				if present(sp, p) {
					a.caveat(pid, p+" is not enforced — the REST v1 front door does not rate-limit or count requests per key (AWS applies usage-plan limits on a best-effort basis and advises against relying on them for access control)")
				}
			}
			up := RestUsagePlanPlan{LogicalID: pid, Name: n, Keys: ctx.apigwUsagePlanKeys(pid)}
			for i, m := range a.blocks(pid, "ApiStages", sp["ApiStages"], apigwAPIStageKnown) {
				if present(m, "Throttle") {
					a.caveat(pid, fmt.Sprintf("ApiStages[%d].Throttle is not enforced — the front door does not rate-limit per method", i))
				}
				if st, _ := concrete(m["Stage"]); st != "" {
					up.APIStages = append(up.APIStages, RestUsagePlanAPI{Stage: st})
				}
			}
			plan.UsagePlans = append(plan.UsagePlans, up)
		}
		for _, uk := range ctx.apigwAllOfType("AWS::ApiGateway::UsagePlanKey") {
			sp := a.props(uk)
			if kt, _ := concrete(sp["KeyType"]); kt != "API_KEY" {
				a.refuse(uk, fmt.Sprintf("KeyType must be API_KEY (got %v)", sp["KeyType"]))
			}
		}
	}

	if len(a.f) > 0 {
		return nil, a.f
	}
	return &Manifest{
		APIVersion: apigwRestV1APIVersion,
		Kind:       apigwRestV1Kind,
		Name:       ctx.name(logicalID),
		Spec:       planToSpec(plan),
		Caveats:    a.cav,
	}, nil
}

// restAPIProps checks the RestApi's own settings: the endpoint types the front door serves, and the
// options that would restrict who can reach the API (refused: served open, they would widen it).
func (a *apigwCollation) restAPIProps(id string, props map[string]any) {
	if ec := a.block(id, "EndpointConfiguration", props["EndpointConfiguration"], apigwEndpointKnown); ec != nil {
		for _, t := range asStrings(ec["Types"]) {
			switch t {
			case "REGIONAL", "EDGE":
				a.caveat(id, "EndpointConfiguration "+t+": served at the shim's one REST v1 endpoint (there are no edge locations or regions)")
			case "PRIVATE":
				a.refuse(id, "EndpointConfiguration PRIVATE is not served — a private API is reachable only through VPC endpoints, and the shim's REST v1 endpoint is reachable from the whole network; refusing rather than serving it open")
			default:
				a.refuse(id, "EndpointConfiguration type "+t+" is not an API Gateway endpoint type")
			}
		}
	}
	if v, ok := props["ApiKeySourceType"]; ok && v != nil {
		if s, _ := concrete(v); s != "HEADER" {
			a.refuse(id, fmt.Sprintf("ApiKeySourceType %v is not served — the front door reads API keys from the x-api-key header (HEADER) only", v))
		}
	}
	if a.boolean(id, "DisableExecuteApiEndpoint", props["DisableExecuteApiEndpoint"], false) {
		a.refuse(id, "DisableExecuteApiEndpoint: true is not served — the shim always serves the API at its default endpoint; refusing rather than serving an endpoint the template turned off")
	}
	if present(props, "MinimumCompressionSize") {
		a.caveat(id, "MinimumCompressionSize is not applied — responses are not compressed")
	}
	if present(props, "FailOnWarnings") {
		a.caveat(id, "FailOnWarnings has no effect — the API is built from the template's resources, not an imported definition")
	}
}

// stageProps reports the stage settings that change only operation (logging, tracing, caching, per-method
// throttling), none of which the front door applies.
func (a *apigwCollation) stageProps(id string, sp map[string]any) {
	for _, p := range []string{"MethodSettings", "AccessLogSetting", "TracingEnabled", "CacheClusterEnabled", "CacheClusterSize", "DocumentationVersion"} {
		if present(sp, p) {
			a.caveat(id, p+" is not applied — the front door has no per-method throttling, response cache, access logs or tracing for a stage")
		}
	}
}

// method collates one AWS::ApiGateway::Method (with its inline Integration and responses) into a
// RestMethodPlan, carrying authorizer/validator/resource as logical refs.
func (a *apigwCollation) method(methodID, apiID string) RestMethodPlan {
	c := a.ctx
	raw, _ := c.rawProps(methodID)
	sp := a.props(methodID)
	m := RestMethodPlan{
		Resource:          c.apigwResourceRef(raw["ResourceId"], apiID),
		HTTPMethod:        concreteOr(sp["HttpMethod"], ""),
		AuthorizationType: concreteOr(sp["AuthorizationType"], ""),
		APIKeyRequired:    a.boolean(methodID, "ApiKeyRequired", sp["ApiKeyRequired"], false),
		RequestModels:     stringMapOf(sp["RequestModels"]),
		RequestParameters: a.boolMap(methodID, "RequestParameters", sp["RequestParameters"]),
	}
	switch m.AuthorizationType {
	case "", "NONE", "COGNITO_USER_POOLS":
	case "AWS_IAM":
		a.refuse(methodID, "AuthorizationType AWS_IAM is not enforced on the REST v1 invoke path (requests are not SigV4-verified there) — use a COGNITO_USER_POOLS authorizer")
	case "CUSTOM":
		a.refuse(methodID, "AuthorizationType CUSTOM (a Lambda authorizer) is not served — use a COGNITO_USER_POOLS authorizer")
	default:
		a.refuse(methodID, fmt.Sprintf("AuthorizationType %q is not an API Gateway authorization type", m.AuthorizationType))
	}
	if present(sp, "OperationName") {
		a.caveat(methodID, "OperationName is not kept — it names the method in generated SDKs and changes nothing served")
	}
	// An authorizer or validator outside the stack (or a literal id) has no plan to provision: the method
	// would be served without it, so it refuses.
	for _, ref := range []struct{ prop, typ string; dst *string }{
		{"AuthorizerId", "AWS::ApiGateway::Authorizer", &m.Authorizer},
		{"RequestValidatorId", "AWS::ApiGateway::RequestValidator", &m.RequestValidator},
	} {
		if !present(sp, ref.prop) {
			continue
		}
		if t, ok := getAttTarget(raw[ref.prop]); ok && c.isType(t, ref.typ) {
			*ref.dst = t
		} else {
			a.refuse(methodID, fmt.Sprintf("%s must reference an in-stack %s — a method whose %s is not provisioned would be served without it", ref.prop, ref.typ, strings.TrimSuffix(ref.prop, "Id")))
		}
	}
	if integ := a.block(methodID, "Integration", sp["Integration"], apigwIntegrationKnown); integ != nil {
		m.Integration = a.integration(methodID, integ)
	}
	for i, rm := range a.blocks(methodID, "MethodResponses", sp["MethodResponses"], apigwMethodResponseKnown) {
		sc, _ := concrete(rm["StatusCode"])
		if sc == "" {
			a.refuse(methodID, fmt.Sprintf("MethodResponses[%d].StatusCode is required", i))
			continue
		}
		m.MethodResponses = append(m.MethodResponses, RestMethodResponsePlan{
			StatusCode: sc, ResponseModels: stringMapOf(rm["ResponseModels"]),
			ResponseParameters: a.boolMap(methodID, fmt.Sprintf("MethodResponses[%d].ResponseParameters", i), rm["ResponseParameters"]),
		})
	}
	return m
}

// integration reads a method's Integration block: what the front door does with a request, and the
// response mappings it applies.
func (a *apigwCollation) integration(methodID string, integ map[string]any) *RestIntegrationPlan {
	p := &RestIntegrationPlan{
		Type:                  concreteOr(integ["Type"], ""),
		URI:                   concreteOr(integ["Uri"], ""),
		IntegrationHTTPMethod: concreteOr(integ["IntegrationHttpMethod"], ""),
		RequestTemplates:      stringMapOf(integ["RequestTemplates"]),
	}
	if v := integ["PassthroughBehavior"]; v != nil {
		if s, _ := concrete(v); s != "WHEN_NO_MATCH" {
			a.refuse(methodID, fmt.Sprintf("Integration.PassthroughBehavior %v is not served — a request whose content type has no template passes through unchanged (WHEN_NO_MATCH); refusing rather than passing requests the template meant to reject", v))
		}
	}
	if v := integ["ConnectionType"]; v != nil {
		if s, _ := concrete(v); s != "INTERNET" {
			a.refuse(methodID, fmt.Sprintf("Integration.ConnectionType %v is not served — there are no VPC links; the integration is called directly (INTERNET)", v))
		}
	}
	if present(integ, "TimeoutInMillis") {
		a.caveat(methodID, "Integration.TimeoutInMillis is not applied — the front door's own request timeout applies")
	}
	for _, k := range []string{"CacheKeyParameters", "CacheNamespace"} {
		if present(integ, k) {
			a.caveat(methodID, "Integration."+k+" is not applied — there is no response cache")
		}
	}
	for i, m := range a.blocks(methodID, "Integration.IntegrationResponses", integ["IntegrationResponses"], apigwIntegrationResponseKnown) {
		where := fmt.Sprintf("Integration.IntegrationResponses[%d]", i)
		sc, _ := concrete(m["StatusCode"])
		if sc == "" {
			a.refuse(methodID, where+".StatusCode is required")
			continue
		}
		a.f = append(a.f, shapeFindings(methodID+"."+where, m, nil, []string{"ResponseTemplates", "ResponseParameters"}, []string{"SelectionPattern"})...)
		if sp, _ := concrete(m["SelectionPattern"]); sp != "" {
			a.refuse(methodID, where+".SelectionPattern is not served — the front door does not select an integration response by the backend's error or status; every response takes the default mapping, so a pattern-mapped error would answer with the default status")
		}
		if present(m, "ResponseParameters") {
			a.caveat(methodID, where+".ResponseParameters are not applied — response headers are not mapped from the integration response")
		}
		if p.IntegrationResponses == nil {
			p.IntegrationResponses = map[string]map[string]string{}
		}
		p.IntegrationResponses[sc] = stringMapOf(m["ResponseTemplates"])
	}
	return p
}

// translateAPIGatewayChild is the no-op translator for the AWS::ApiGateway::* types collated into their
// RestApi. It returns nil (composed) when a parent RestApi is resolvable, and BLOCKS otherwise — a child
// with no in-stack RestApi would otherwise be silently dropped (a partial apply).
func translateAPIGatewayChild(logicalID string, _ map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	if ctx == nil {
		return nil, nil
	}
	cfnType := ctx.template.Resources[logicalID].Type
	switch cfnType {
	case "AWS::ApiGateway::ApiKey", "AWS::ApiGateway::UsagePlan", "AWS::ApiGateway::UsagePlanKey":
		switch ctx.apigwRestAPICount() {
		case 1:
			return nil, nil // collated into the sole RestApi
		case 0:
			return nil, []Finding{{"Resource " + logicalID, cfnType + " has no in-stack AWS::ApiGateway::RestApi to attach to — author it via the apigateway API, or add the RestApi to this stack"}}
		default:
			return nil, []Finding{{"Resource " + logicalID, cfnType + " with multiple RestApis in one stack is ambiguous (which api a key unlocks) — author keys/usage plans via the apigateway API"}}
		}
	default:
		// resource-tree / method / model / validator / authorizer / deployment / stage: collated into
		// their RestApi (by RestApiId). A dangling one (no in-stack api) blocks.
		if _, ok := ctx.apigwParentAPI(logicalID); ok {
			return nil, nil
		}
		return nil, []Finding{{"Resource " + logicalID, cfnType + " references no in-stack AWS::ApiGateway::RestApi (RestApiId) — a dangling REST v1 resource can't be provisioned"}}
	}
}

// --- collation helpers on stackCtx ---

// apigwChildren returns the logical ids of all resources of cfnType whose RestApiId !Ref/!GetAtt's apiID.
func (c *stackCtx) apigwChildren(cfnType, apiID string) []string {
	return c.collatedChildren(cfnType, "RestApiId", apiID)
}

// apigwParentAPI returns the RestApi logical id a resource references via RestApiId, if in-stack.
func (c *stackCtx) apigwParentAPI(logicalID string) (string, bool) {
	raw, ok := c.rawProps(logicalID)
	if !ok {
		return "", false
	}
	t, ok := getAttTarget(raw["RestApiId"])
	if !ok {
		return "", false
	}
	if res, in := c.template.Resources[t]; in && res.Type == "AWS::ApiGateway::RestApi" {
		return t, true
	}
	return "", false
}

// apigwParentRef resolves a resource's ParentId to a logical parent: the API's seeded root when it is
// Fn::GetAtt <thisApi>.RootResourceId, otherwise the referenced in-stack Resource's logical id.
func (c *stackCtx) apigwParentRef(parentIDRaw any, apiID string) string {
	t, ok := getAttTarget(parentIDRaw)
	if !ok || t == apiID {
		return rootResourceRef
	}
	return t
}

func (c *stackCtx) apigwAllOfType(cfnType string) []string {
	var ids []string
	for cid, res := range c.template.Resources {
		// included() is the guard: a resource its template Conditions-off must not be collated
		// into the API, exactly as it must not be provisioned. Without it a gated-off ApiKey or
		// UsagePlan is attached anyway — a silently-deployed rule the template said to leave out.
		if res.Type == cfnType && c.included(res) {
			ids = append(ids, cid)
		}
	}
	sortStrs(ids)
	return ids
}

func (c *stackCtx) apigwRestAPICount() int {
	n := 0
	for _, res := range c.template.Resources {
		if res.Type == "AWS::ApiGateway::RestApi" && c.included(res) {
			n++
		}
	}
	return n
}

// apigwUsagePlanKeys returns the api-key logical ids associated with a usage plan via an in-stack
// AWS::ApiGateway::UsagePlanKey.
func (c *stackCtx) apigwUsagePlanKeys(planID string) []string {
	var keys []string
	for cid, res := range c.template.Resources {
		if res.Type != "AWS::ApiGateway::UsagePlanKey" || !c.included(res) {
			continue
		}
		raw, _ := c.rawProps(cid)
		if t, ok := getAttTarget(raw["UsagePlanId"]); !ok || t != planID {
			continue
		}
		if k, ok := getAttTarget(raw["KeyId"]); ok {
			keys = append(keys, k)
		}
	}
	sortStrs(keys)
	return keys
}

// apigwResourceRef resolves a method's ResourceId: the API root when Fn::GetAtt <api>.RootResourceId,
// else the referenced Resource's logical id.
func (c *stackCtx) apigwResourceRef(resIDRaw any, apiID string) string {
	t, ok := getAttTarget(resIDRaw)
	if !ok || t == apiID {
		return rootResourceRef
	}
	return t
}

// --- small value coercions (local to the apigateway collation) ---

func schemaString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case map[string]any:
		b, _ := json.Marshal(s)
		return string(b)
	}
	return ""
}

func asStrings(v any) []string {
	var out []string
	for _, e := range sliceOfAny(v) {
		if s, ok := concrete(e); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func sliceOfAny(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func stringMapOf(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, val := range m {
		if s, ok := concrete(val); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hasStage(stages []RestStagePlan, name string) bool {
	for _, s := range stages {
		if s.StageName == name {
			return true
		}
	}
	return false
}
