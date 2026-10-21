// CloudFormation deploy executor for API Gateway REST v1 (#295): materializes a collated cfn.RestAPIPlan
// by driving the apigwV1Store in order. The cfn engine (via the aws-shim CloudFormation doorway) hands
// the whole API as one plan — this turns it into real resources, assigning ids and resolving the plan's
// LOGICAL references (a resource's parent, a method's resource/authorizer/validator, a usage-plan key's
// key) to those ids as it goes. Any failure tears down the partial API before returning, so a failed
// provision never orphans a half-built API (and the stack-level rollback then has nothing to clean).
package main

import (
	"context"
	"fmt"

	"github.com/harn3ss/open-infra/cfn"
)

// provisionRestAPIPlan creates a REST v1 API from a collated plan and returns the created API id.
func (h *apigwV1Handler) provisionRestAPIPlan(ctx context.Context, plan cfn.RestAPIPlan) (string, error) {
	if h.store == nil {
		return "", fmt.Errorf("the API Gateway data layer is not configured on this shim (set SQS_PG_URI)")
	}
	apiID := shortID(10)
	name := plan.Name
	if name == "" {
		name = plan.LogicalID
	}
	// Any error past the create tears the partial API down (no orphan), then surfaces.
	fail := func(err error) (string, error) {
		_, _ = h.store.deleteAPI(ctx, apiID)
		return "", err
	}
	if err := h.store.createAPI(ctx, restAPI{ID: apiID, Name: name}); err != nil {
		return "", fmt.Errorf("create REST API: %w", err)
	}
	// Seed the root resource "/" and map the plan's logical references to real ids as we create things.
	rootID := shortID(10)
	if err := h.store.createResource(ctx, apiID, restResource{ID: rootID, PathPart: "", FullPath: "/"}); err != nil {
		return fail(fmt.Errorf("seed root resource: %w", err))
	}
	resID := map[string]string{"<root>": rootID} // logical id (or "<root>") -> resource id
	fullPath := map[string]string{rootID: "/"}

	// Resources in parent-before-child order: repeatedly place any whose parent is already placed.
	pending := append([]cfn.RestResourcePlan(nil), plan.Resources...)
	for len(pending) > 0 {
		progressed := false
		var still []cfn.RestResourcePlan
		for _, rp := range pending {
			parentID, ok := resID[rp.Parent]
			if !ok {
				still = append(still, rp)
				continue
			}
			id := shortID(10)
			full := childFullPath(fullPath[parentID], rp.PathPart)
			if err := h.store.createResource(ctx, apiID, restResource{ID: id, ParentID: parentID, PathPart: rp.PathPart, FullPath: full}); err != nil {
				return fail(fmt.Errorf("create resource %s: %w", rp.LogicalID, err))
			}
			resID[rp.LogicalID] = id
			fullPath[id] = full
			progressed = true
		}
		if !progressed {
			return fail(fmt.Errorf("resource tree has an unresolvable parent reference (dangling or cyclic): %d resource(s) could not be placed", len(still)))
		}
		pending = still
	}

	// Models (keyed by name — methods reference models by name, so no id map needed).
	for _, mp := range plan.Models {
		if err := h.store.createModel(ctx, apiID, restModel{Name: mp.Name, ContentType: mp.ContentType, Schema: parseModelSchema(mp.Schema)}); err != nil {
			return fail(fmt.Errorf("create model %s: %w", mp.Name, err))
		}
	}
	// Request validators (logical id -> validator id).
	validatorID := map[string]string{}
	for _, vp := range plan.Validators {
		id := shortID(10)
		if err := h.store.createRequestValidator(ctx, apiID, restRequestValidator{ID: id, Name: vp.Name, ValidateRequestBody: vp.ValidateRequestBody, ValidateRequestParameters: vp.ValidateRequestParameters}); err != nil {
			return fail(fmt.Errorf("create request validator %s: %w", vp.LogicalID, err))
		}
		validatorID[vp.LogicalID] = id
	}
	// Authorizers (logical id -> authorizer id). COGNITO_USER_POOLS only; others refuse (fail-closed,
	// matching the live handler) rather than silently admitting a method the shim can't vet.
	authorizerID := map[string]string{}
	for _, ap := range plan.Authorizers {
		if ap.Type != "COGNITO_USER_POOLS" {
			return fail(fmt.Errorf("authorizer %s type %q is not fronted (COGNITO_USER_POOLS only; TOKEN/REQUEST/AWS_IAM refuse fail-closed)", ap.LogicalID, ap.Type))
		}
		var issuer string
		for _, arn := range ap.ProviderARNs {
			if iss := h.resolveCognitoIssuer(arn); iss != "" {
				issuer = iss
				break
			}
		}
		if issuer == "" {
			return fail(fmt.Errorf("authorizer %s: providerARNs resolve to no issuer", ap.LogicalID))
		}
		id := shortID(10)
		if err := h.store.createAuthorizer(ctx, apiID, restAuthorizer{ID: id, Name: ap.Name, Type: "COGNITO_USER_POOLS", Issuer: issuer, IdentitySource: headerFromIdentitySource(ap.IdentitySource)}); err != nil {
			return fail(fmt.Errorf("create authorizer %s: %w", ap.LogicalID, err))
		}
		authorizerID[ap.LogicalID] = id
	}

	// Methods (+ their integration, integration responses, method responses).
	for _, mp := range plan.Methods {
		rid, ok := resID[mp.Resource]
		if !ok {
			return fail(fmt.Errorf("method %s references unknown resource %q", mp.HTTPMethod, mp.Resource))
		}
		authType := mp.AuthorizationType
		if authType == "" {
			authType = "NONE"
		}
		m := restMethod{
			ResourceID: rid, HTTPMethod: mp.HTTPMethod, AuthorizationType: authType,
			AuthorizerID: authorizerID[mp.Authorizer], APIKeyRequired: mp.APIKeyRequired,
			RequestValidatorID: validatorID[mp.RequestValidator],
			RequestModels:      mp.RequestModels, RequestParameters: mp.RequestParameters,
		}
		if err := h.store.putMethod(ctx, apiID, m); err != nil {
			return fail(fmt.Errorf("put method %s on %s: %w", mp.HTTPMethod, mp.Resource, err))
		}
		if mp.Integration != nil {
			ig := mp.Integration
			if err := h.store.putIntegration(ctx, apiID, restIntegration{
				ResourceID: rid, HTTPMethod: mp.HTTPMethod, Type: ig.Type, URI: ig.URI,
				IntegrationHTTPMethod: ig.IntegrationHTTPMethod, PayloadFormatVersion: "1.0", RequestTemplates: ig.RequestTemplates,
			}); err != nil {
				return fail(fmt.Errorf("put integration on %s %s: %w", mp.HTTPMethod, mp.Resource, err))
			}
			for sc, tmpls := range ig.IntegrationResponses {
				if err := h.store.putIntegrationResponse(ctx, apiID, rid, mp.HTTPMethod, sc, tmpls); err != nil {
					return fail(fmt.Errorf("put integration response %s on %s %s: %w", sc, mp.HTTPMethod, mp.Resource, err))
				}
			}
		}
		for _, mr := range mp.MethodResponses {
			if err := h.store.putMethodResponse(ctx, apiID, restMethodResponse{ResourceID: rid, HTTPMethod: mp.HTTPMethod, StatusCode: mr.StatusCode, ResponseModels: mr.ResponseModels, ResponseParameters: mr.ResponseParameters}); err != nil {
				return fail(fmt.Errorf("put method response %s on %s %s: %w", mr.StatusCode, mp.HTTPMethod, mp.Resource, err))
			}
		}
	}

	// One deployment snapshot of the whole tree, then every stage points at it.
	snap, err := h.store.snapshot(ctx, apiID)
	if err != nil {
		return fail(fmt.Errorf("snapshot: %w", err))
	}
	depID := shortID(10)
	if err := h.store.createDeployment(ctx, apiID, depID, snap); err != nil {
		return fail(fmt.Errorf("create deployment: %w", err))
	}
	for _, sp := range plan.Stages {
		if err := h.store.putStage(ctx, apiID, sp.StageName, depID, sp.Variables); err != nil {
			return fail(fmt.Errorf("create stage %s: %w", sp.StageName, err))
		}
	}

	// Account-level API keys + usage plans (+ their key associations).
	keyID := map[string]string{} // logical id -> api key id
	for _, kp := range plan.APIKeys {
		id := shortID(10)
		value := kp.Value
		if value == "" {
			value = shortID(40)
		}
		if err := h.store.createAPIKey(ctx, restAPIKey{ID: id, Name: kp.Name, Value: value, Enabled: kp.Enabled}); err != nil {
			return fail(fmt.Errorf("create api key %s: %w", kp.LogicalID, err))
		}
		keyID[kp.LogicalID] = id
	}
	for _, pp := range plan.UsagePlans {
		id := shortID(10)
		up := restUsagePlan{ID: id, Name: pp.Name}
		for _, as := range pp.APIStages {
			up.APIStages = append(up.APIStages, restUsagePlanAPI{APIID: apiID, Stage: as.Stage})
		}
		if err := h.store.createUsagePlan(ctx, up); err != nil {
			return fail(fmt.Errorf("create usage plan %s: %w", pp.LogicalID, err))
		}
		for _, kLogical := range pp.Keys {
			kid, ok := keyID[kLogical]
			if !ok {
				return fail(fmt.Errorf("usage plan %s references unknown api key %q", pp.LogicalID, kLogical))
			}
			if err := h.store.createUsagePlanKey(ctx, id, kid); err != nil {
				return fail(fmt.Errorf("associate key %s with usage plan %s: %w", kLogical, pp.LogicalID, err))
			}
		}
	}

	return apiID, nil
}

// deprovisionRestAPI deletes a provisioned REST v1 API (idempotent — a missing api is not an error), for
// stack rollback and teardown.
func (h *apigwV1Handler) deprovisionRestAPI(ctx context.Context, apiID string) error {
	if h.store == nil || apiID == "" {
		return nil
	}
	_, err := h.store.deleteAPI(ctx, apiID)
	return err
}

// parseModelSchema decodes a model's JSON-Schema string into the map the store stores (nil when empty or
// unparseable — a model with no usable schema imposes no constraint, like AWS).
func parseModelSchema(s string) map[string]any {
	return schemaFromBody(s)
}
