package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// Stage-2 AppSync MANAGEMENT wire protocol: the compatibility skin that lets AWS's
// own AppSync tooling — CloudFormation, CDK, `aws appsync create-resolver` — run unchanged by
// translating AWS management verbs into a PATCH on the neutral kind: GraphQLApi object. This is the
// edge; it comes AFTER the native model is sound. The neutral core never learns AWS's addressing —
// the skin owns the identity mapping (apiId, typeName, fieldName) → (namespace, name, resolvers[]
// entry). Per-verb graduation, exactly like the shim's other services: we claim the verbs we prove,
// never "AppSync management API compatible".
//
// apiId encoding (the skin's mapping, opaque to AWS): "<namespace>.<name>" of the GraphQLApi object,
// or bare "<name>" in the default namespace.

// apiStore reads and writes a GraphQLApi claim as a raw object, so read-modify-write preserves every
// field the management verbs don't touch (metadata, status, other spec). The real implementation is
// the cluster's REST client (restAPIStore); tests use an in-memory fake.
type apiStore interface {
	Get(ctx context.Context, ns, name string) (map[string]any, error)
	Update(ctx context.Context, ns, name string, obj map[string]any) error
}

// mgmtParams is a parsed management request (path segments + decoded body).
type mgmtParams struct {
	apiID     string
	ns, name  string
	typeName  string
	fieldName string
	dsName    string
	body      map[string]any
}

// serveManagement handles /v1/... AppSync control-plane requests. The caller is already authenticated
// (SigV4, by the router); here we run a STRONGER coarse gate than the data plane — managing an API is
// a write, so it needs `update` on graphqlapis in the target namespace, via the same impersonated
// SubjectAccessReview as every other front door — then translate the verb into a CR patch.
func (h *appsyncHandler) serveManagement(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	p, verb, err := parseManagement(r)
	if err != nil {
		writeMgmtError(w, http.StatusBadRequest, "BadRequestException", requestID, err.Error())
		return
	}
	if verb == "" {
		writeMgmtError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
			"this AppSync management operation is not fronted by open-infra (proven verbs: CreateResolver, UpdateResolver, DeleteResolver, GetResolver, CreateDataSource, DeleteDataSource)")
		return
	}

	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, "update", "openinfra.dev", "graphqlapis", p.ns, p.name); !allowed {
		h.logger.Warn("appsync management denied", "user", claims.Sub, "api", p.apiID, "verb", verb, "reason", reason)
		writeMgmtError(w, http.StatusForbidden, "UnauthorizedException", requestID,
			"not authorized to manage this GraphQL API")
		return
	}

	// GetResolver is read-only; everything else is read-modify-write on the CR.
	if verb == "GetResolver" {
		obj, err := h.apis.Get(r.Context(), p.ns, p.name)
		if err != nil {
			writeMgmtError(w, http.StatusNotFound, "NotFoundException", requestID, "no such API: "+p.apiID)
			return
		}
		res, err := applyManagement(obj, verb, p)
		if err != nil {
			writeMgmtError(w, http.StatusNotFound, "NotFoundException", requestID, err.Error())
			return
		}
		writeMgmtJSON(w, http.StatusOK, requestID, res)
		return
	}

	obj, err := h.apis.Get(r.Context(), p.ns, p.name)
	if err != nil {
		writeMgmtError(w, http.StatusNotFound, "NotFoundException", requestID, "no such API: "+p.apiID)
		return
	}
	res, err := applyManagement(obj, verb, p)
	if err != nil {
		writeMgmtError(w, http.StatusBadRequest, "BadRequestException", requestID, err.Error())
		return
	}
	if err := h.apis.Update(r.Context(), p.ns, p.name, obj); err != nil {
		h.logger.Warn("appsync management apply failed", "api", p.apiID, "verb", verb, "error", err.Error())
		writeMgmtError(w, http.StatusBadGateway, "InternalFailureException", requestID, "could not apply the change to the API")
		return
	}
	status := http.StatusOK
	if strings.HasPrefix(verb, "Create") {
		status = http.StatusCreated
	}
	writeMgmtJSON(w, status, requestID, res)
}

// parseManagement turns an HTTP request into (params, verb). An unknown/unhandled shape returns verb=""
// so the caller answers with an honest NotImplemented (per-verb graduation, no faking).
func parseManagement(r *http.Request) (mgmtParams, string, error) {
	// /v1/apis/{apiId}/types/{typeName}/resolvers[/{fieldName}]
	// /v1/apis/{apiId}/datasources[/{name}]
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segs) < 3 || segs[0] != "v1" || segs[1] != "apis" {
		return mgmtParams{}, "", fmt.Errorf("unrecognized management path")
	}
	p := mgmtParams{apiID: segs[2]}
	p.ns, p.name = splitAPIID(p.apiID)

	if len(r.Header.Get("Content-Length")) > 0 || r.Body != nil {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &p.body); err != nil {
				return p, "", fmt.Errorf("invalid JSON body")
			}
		}
	}

	switch {
	case len(segs) >= 6 && segs[3] == "types" && segs[5] == "resolvers":
		p.typeName = segs[4]
		if len(segs) >= 7 { // .../resolvers/{fieldName}
			p.fieldName = segs[6]
			switch r.Method {
			case http.MethodGet:
				return p, "GetResolver", nil
			case http.MethodPost, http.MethodPut:
				return p, "UpdateResolver", nil
			case http.MethodDelete:
				return p, "DeleteResolver", nil
			}
		} else if r.Method == http.MethodPost { // .../resolvers  (Create)
			p.fieldName, _ = p.body["fieldName"].(string)
			return p, "CreateResolver", nil
		}
	case len(segs) >= 4 && segs[3] == "datasources":
		if len(segs) >= 5 { // .../datasources/{name}
			p.dsName = segs[4]
			if r.Method == http.MethodDelete {
				return p, "DeleteDataSource", nil
			}
		} else if r.Method == http.MethodPost {
			p.dsName, _ = p.body["name"].(string)
			return p, "CreateDataSource", nil
		}
	}
	return p, "", nil // recognized path shape but unhandled verb → honest NotImplemented
}

// splitAPIID maps the opaque AWS apiId to a GraphQLApi (namespace, name). "<ns>.<name>" or bare
// "<name>" (default namespace). This mapping is the skin's alone; the neutral kind never sees apiId.
func splitAPIID(apiID string) (ns, name string) {
	if i := strings.Index(apiID, "."); i >= 0 {
		return apiID[:i], apiID[i+1:]
	}
	return "default", apiID
}

// applyManagement mutates the GraphQLApi object per the verb and returns the AWS-shaped response body.
// It is a PURE function over the raw object — the whole of the identity mapping and verb→patch logic,
// with no I/O — which is what makes it fully unit-testable.
func applyManagement(obj map[string]any, verb string, p mgmtParams) (map[string]any, error) {
	spec := ensureMap(obj, "spec")

	switch verb {
	case "CreateResolver", "UpdateResolver":
		if p.typeName == "" || p.fieldName == "" {
			return nil, fmt.Errorf("resolver requires a typeName and fieldName")
		}
		entry := map[string]any{"type": p.typeName, "field": p.fieldName}
		if ds, ok := p.body["dataSourceName"].(string); ok && ds != "" {
			entry["dataSource"] = ds
		}
		// Runtime mapping: AWS APPSYNC_JS → our appsync-js (code carried in `code`); absent → VTL.
		if rt, ok := p.body["runtime"].(map[string]any); ok && rt["name"] == "APPSYNC_JS" {
			entry["runtime"] = "appsync-js"
			entry["request"], _ = p.body["code"].(string)
		} else {
			entry["runtime"] = "appsync-vtl"
			entry["request"], _ = p.body["requestMappingTemplate"].(string)
			entry["response"], _ = p.body["responseMappingTemplate"].(string)
		}
		upsert(spec, "resolvers", entry, func(e map[string]any) bool {
			return e["type"] == p.typeName && e["field"] == p.fieldName
		})
		return map[string]any{"resolver": awsResolver(p, entry)}, nil

	case "DeleteResolver":
		remove(spec, "resolvers", func(e map[string]any) bool {
			return e["type"] == p.typeName && e["field"] == p.fieldName
		})
		return map[string]any{}, nil

	case "GetResolver":
		e := find(spec, "resolvers", func(e map[string]any) bool {
			return e["type"] == p.typeName && e["field"] == p.fieldName
		})
		if e == nil {
			return nil, fmt.Errorf("no resolver %s.%s", p.typeName, p.fieldName)
		}
		return map[string]any{"resolver": awsResolver(p, e)}, nil

	case "CreateDataSource":
		if p.dsName == "" {
			return nil, fmt.Errorf("data source requires a name")
		}
		entry := map[string]any{"name": p.dsName}
		if t, ok := p.body["type"].(string); ok {
			entry["type"] = mapDataSourceType(t)
		}
		upsert(spec, "dataSources", entry, func(e map[string]any) bool { return e["name"] == p.dsName })
		return map[string]any{"dataSource": map[string]any{"name": p.dsName, "dataSourceArn": "arn:open-infra:appsync:" + p.apiID + ":datasource/" + p.dsName}}, nil

	case "DeleteDataSource":
		remove(spec, "dataSources", func(e map[string]any) bool { return e["name"] == p.dsName })
		return map[string]any{}, nil
	}
	return nil, fmt.Errorf("unhandled verb %q", verb)
}

// awsResolver re-dresses our resolver entry in AppSync's response shape (enough for tooling to accept
// the round-trip). resolverArn carries the skin's identity mapping back to the caller.
func awsResolver(p mgmtParams, e map[string]any) map[string]any {
	return map[string]any{
		"typeName":                e["type"],
		"fieldName":               e["field"],
		"dataSourceName":          e["dataSource"],
		"requestMappingTemplate":  e["request"],
		"responseMappingTemplate": e["response"],
		"resolverArn":             fmt.Sprintf("arn:open-infra:appsync:%s:types/%v/resolvers/%v", p.apiID, e["type"], e["field"]),
	}
}

// mapDataSourceType maps AWS data-source types onto open-appsync's. AMAZON_DYNAMODB → dynamodb,
// HTTP → http, otherwise memory (dev). (open-appsync's neutral set; the skin owns the translation.)
func mapDataSourceType(awsType string) string {
	switch awsType {
	case "AMAZON_DYNAMODB":
		return "dynamodb"
	case "HTTP":
		return "http"
	default:
		return "memory"
	}
}

// --- small helpers over the raw object's spec arrays ---

func ensureMap(obj map[string]any, key string) map[string]any {
	if m, ok := obj[key].(map[string]any); ok {
		return m
	}
	m := map[string]any{}
	obj[key] = m
	return m
}

func specList(spec map[string]any, key string) []any {
	if l, ok := spec[key].([]any); ok {
		return l
	}
	return nil
}

func upsert(spec map[string]any, key string, entry map[string]any, match func(map[string]any) bool) {
	list := specList(spec, key)
	for i, it := range list {
		if e, ok := it.(map[string]any); ok && match(e) {
			list[i] = entry
			spec[key] = list
			return
		}
	}
	spec[key] = append(list, entry)
}

func remove(spec map[string]any, key string, match func(map[string]any) bool) {
	list := specList(spec, key)
	out := list[:0]
	for _, it := range list {
		if e, ok := it.(map[string]any); ok && match(e) {
			continue
		}
		out = append(out, it)
	}
	spec[key] = out
}

func find(spec map[string]any, key string, match func(map[string]any) bool) map[string]any {
	for _, it := range specList(spec, key) {
		if e, ok := it.(map[string]any); ok && match(e) {
			return e
		}
	}
	return nil
}

// --- AWS restJson1 response/error writers ---

func writeMgmtJSON(w http.ResponseWriter, status int, requestID string, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeMgmtError(w http.ResponseWriter, status int, errorType, requestID, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-ErrorType", errorType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": message})
}
