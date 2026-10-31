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

import "encoding/json"

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

// translateAPIGatewayRestAPI collates a stack's AWS::ApiGateway::* resources that belong to THIS RestApi
// (plus the account-level API keys/usage plans, when this is the sole RestApi in the stack) into one
// RestAPIPlan sentinel. The child resource types translate to nil (composed here).
func translateAPIGatewayRestAPI(logicalID string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	fin := func(msg string) []Finding { return []Finding{{"Resource " + logicalID, msg}} }
	if ctx == nil {
		return nil, fin("a REST API needs stack context to collate its resources")
	}
	var f []Finding
	name, _ := concrete(props["Name"])
	if name == "" {
		name = logicalID
	}
	plan := RestAPIPlan{LogicalID: logicalID, Name: name}

	// Resources (scoped to this api), each carrying its parent as a logical ref.
	for _, rid := range ctx.apigwChildren("AWS::ApiGateway::Resource", logicalID) {
		raw, _ := ctx.rawProps(rid)
		sp, _ := ctx.resolveProps(rid)
		part, _ := concrete(sp["PathPart"])
		plan.Resources = append(plan.Resources, RestResourcePlan{
			LogicalID: rid, Parent: ctx.apigwParentRef(raw["ParentId"], logicalID), PathPart: part,
		})
	}
	// Models.
	for _, mid := range ctx.apigwChildren("AWS::ApiGateway::Model", logicalID) {
		sp, _ := ctx.resolveProps(mid)
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
		sp, _ := ctx.resolveProps(vid)
		n, _ := concrete(sp["Name"])
		plan.Validators = append(plan.Validators, RestValidatorPlan{
			LogicalID: vid, Name: n,
			ValidateRequestBody:       asBool(sp["ValidateRequestBody"]),
			ValidateRequestParameters: asBool(sp["ValidateRequestParameters"]),
		})
	}
	// Authorizers.
	for _, aid := range ctx.apigwChildren("AWS::ApiGateway::Authorizer", logicalID) {
		sp, _ := ctx.resolveProps(aid)
		n, _ := concrete(sp["Name"])
		at, _ := concrete(sp["Type"])
		plan.Authorizers = append(plan.Authorizers, RestAuthorizerPlan{
			LogicalID: aid, Name: n, Type: at,
			ProviderARNs:   asStrings(sp["ProviderARNs"]),
			IdentitySource: concreteOr(sp["IdentitySource"], ""),
		})
	}
	// Methods (+ inline integration + method/integration responses).
	for _, mid := range ctx.apigwChildren("AWS::ApiGateway::Method", logicalID) {
		m, mf := ctx.apigwMethodPlan(mid, logicalID)
		f = append(f, mf...)
		plan.Methods = append(plan.Methods, m)
	}
	// Stages (each points at the single post-tree deployment snapshot the executor takes).
	for _, sid := range ctx.apigwChildren("AWS::ApiGateway::Stage", logicalID) {
		sp, _ := ctx.resolveProps(sid)
		sn, _ := concrete(sp["StageName"])
		if sn == "" {
			continue
		}
		plan.Stages = append(plan.Stages, RestStagePlan{StageName: sn, Variables: stringMapOf(sp["Variables"])})
	}
	// A Deployment that carries an inline StageName (the older single-call form) also makes a stage.
	for _, did := range ctx.apigwChildren("AWS::ApiGateway::Deployment", logicalID) {
		sp, _ := ctx.resolveProps(did)
		if sn, _ := concrete(sp["StageName"]); sn != "" && !hasStage(plan.Stages, sn) {
			plan.Stages = append(plan.Stages, RestStagePlan{StageName: sn})
		}
	}

	// Account-level API keys + usage plans — only when this is the sole RestApi in the stack (otherwise
	// which api a key unlocks is ambiguous; the child translator blocks that case rather than guessing).
	if ctx.apigwRestAPICount() == 1 {
		for _, kid := range ctx.apigwAllOfType("AWS::ApiGateway::ApiKey") {
			sp, _ := ctx.resolveProps(kid)
			n, _ := concrete(sp["Name"])
			plan.APIKeys = append(plan.APIKeys, RestAPIKeyPlan{
				LogicalID: kid, Name: n, Enabled: asBoolDefault(sp["Enabled"], true), Value: concreteOr(sp["Value"], ""),
			})
		}
		for _, pid := range ctx.apigwAllOfType("AWS::ApiGateway::UsagePlan") {
			sp, _ := ctx.resolveProps(pid)
			n, _ := concrete(sp["UsagePlanName"])
			up := RestUsagePlanPlan{LogicalID: pid, Name: n, Keys: ctx.apigwUsagePlanKeys(pid)}
			for _, as := range sliceOfAny(sp["ApiStages"]) {
				m, ok := as.(map[string]any)
				if !ok {
					continue
				}
				if st, _ := concrete(m["Stage"]); st != "" {
					up.APIStages = append(up.APIStages, RestUsagePlanAPI{Stage: st})
				}
			}
			plan.UsagePlans = append(plan.UsagePlans, up)
		}
	}

	if len(f) > 0 {
		return nil, f
	}
	return &Manifest{
		APIVersion: apigwRestV1APIVersion,
		Kind:       apigwRestV1Kind,
		Name:       k8sName(logicalID),
		Spec:       planToSpec(plan),
	}, nil
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
		if res.Type == cfnType {
			ids = append(ids, cid)
		}
	}
	sortStrs(ids)
	return ids
}

func (c *stackCtx) apigwRestAPICount() int {
	n := 0
	for _, res := range c.template.Resources {
		if res.Type == "AWS::ApiGateway::RestApi" {
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
		if res.Type != "AWS::ApiGateway::UsagePlanKey" {
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

// apigwMethodPlan collates one AWS::ApiGateway::Method (with its inline Integration + MethodResponses)
// into a RestMethodPlan, carrying authorizer/validator/resource as logical refs.
func (c *stackCtx) apigwMethodPlan(methodID, apiID string) (RestMethodPlan, []Finding) {
	raw, _ := c.rawProps(methodID)
	sp, _ := c.resolveProps(methodID)
	m := RestMethodPlan{
		Resource:          c.apigwResourceRef(raw["ResourceId"], apiID),
		HTTPMethod:        concreteOr(sp["HttpMethod"], ""),
		AuthorizationType: concreteOr(sp["AuthorizationType"], ""),
		APIKeyRequired:    asBool(sp["ApiKeyRequired"]),
		RequestModels:     stringMapOf(sp["RequestModels"]),
		RequestParameters: boolMapOf(sp["RequestParameters"]),
	}
	if a, ok := getAttTarget(raw["AuthorizerId"]); ok {
		m.Authorizer = a
	}
	if v, ok := getAttTarget(raw["RequestValidatorId"]); ok {
		m.RequestValidator = v
	}
	if integ, ok := sp["Integration"].(map[string]any); ok {
		m.Integration = apigwIntegrationPlan(integ)
	}
	for _, mr := range sliceOfAny(sp["MethodResponses"]) {
		rm, ok := mr.(map[string]any)
		if !ok {
			continue
		}
		sc, _ := concrete(rm["StatusCode"])
		if sc == "" {
			continue
		}
		m.MethodResponses = append(m.MethodResponses, RestMethodResponsePlan{
			StatusCode: sc, ResponseModels: stringMapOf(rm["ResponseModels"]), ResponseParameters: boolMapOf(rm["ResponseParameters"]),
		})
	}
	return m, nil
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

func apigwIntegrationPlan(integ map[string]any) *RestIntegrationPlan {
	p := &RestIntegrationPlan{
		Type:                  concreteOr(integ["Type"], ""),
		URI:                   concreteOr(integ["Uri"], ""),
		IntegrationHTTPMethod: concreteOr(integ["IntegrationHttpMethod"], ""),
		RequestTemplates:      stringMapOf(integ["RequestTemplates"]),
	}
	for _, ir := range sliceOfAny(integ["IntegrationResponses"]) {
		m, ok := ir.(map[string]any)
		if !ok {
			continue
		}
		sc, _ := concrete(m["StatusCode"])
		if sc == "" {
			continue
		}
		if p.IntegrationResponses == nil {
			p.IntegrationResponses = map[string]map[string]string{}
		}
		p.IntegrationResponses[sc] = stringMapOf(m["ResponseTemplates"])
	}
	return p
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

func asBool(v any) bool { b, _ := v.(bool); return b }

func asBoolDefault(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
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

func boolMapOf(v any) map[string]bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	out := map[string]bool{}
	for k, val := range m {
		out[k] = asBool(val)
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
