// AppSync management reads over kind: GraphQLApi: GetGraphqlApi, ListGraphqlApis, GetIntrospectionSchema,
// GetSchemaCreationStatus, GetDataSource, ListDataSources, GetFunction and ListFunctions, in the restJson1
// shapes the AWS CLI and SDKs parse.
//
// A read needs `get` on graphqlapis in the API's namespace (ListGraphqlApis: `list`, namespace by
// namespace — an API in a namespace the caller may not list is not listed), where the management writes
// need `update`; an assumed role's authority is its data-plane policy, appsync:<Operation> on
// GraphQLApi::<apiId> (ListGraphqlApis on GraphQLApi::*), as for the writes.
//
// What the claim has no counterpart for is left out rather than invented. An API has no API-wide
// authentication type (open-appsync enforces the schema's @aws_* directives), so none is answered. A
// pipeline function is kept inline in each resolver that runs it, without the name or id its
// FunctionConfiguration had: a function is identified by its content (data source, runtime, templates),
// so one shared by several pipelines is one function, and its id is a hash of that content — stable for as
// long as the function does not change — which serves as its name too. GetIntrospectionSchema answers the
// SDL as written (directives included); the JSON introspection result is the engine's to give (its
// __schema query), and is refused here rather than half-built.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// appsyncListMax is the most items a List answers in one page (AppSync's maxResults ceiling).
const appsyncListMax = 25

func appsyncReadVerb(verb string) bool {
	switch verb {
	case "GetGraphqlApi", "ListGraphqlApis", "GetIntrospectionSchema", "GetSchemaCreationStatus",
		"GetDataSource", "ListDataSources", "GetFunction", "ListFunctions":
		return true
	}
	return false
}

// serveRead answers a read verb. p names the API (but for ListGraphqlApis).
func (h *appsyncHandler) serveRead(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string, p mgmtParams, verb string) {
	if verb == "ListGraphqlApis" {
		h.listGraphqlApis(w, r, claims, requestID)
		return
	}
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, "get", "openinfra.dev", "graphqlapis", p.ns, p.name); !allowed {
		h.logger.Warn("appsync read denied", "user", claims.Sub, "api", p.apiID, "verb", verb, "reason", reason)
		writeMgmtError(w, http.StatusForbidden, "UnauthorizedException", requestID, "not authorized to read this GraphQL API")
		return
	}
	if claims.AssumedRole != "" {
		if denied, reason := dataPlaneDenied(r.Context(), h.authz, claims, "appsync:"+verb, "GraphQLApi", p.apiID, r); denied {
			h.logger.Warn("appsync read denied (assumed role)", "user", claims.Sub, "api", p.apiID, "verb", verb, "reason", reason)
			writeMgmtError(w, http.StatusForbidden, "UnauthorizedException", requestID, "not authorized to read this GraphQL API")
			return
		}
	}
	obj, err := h.apis.Get(r.Context(), p.ns, p.name)
	if err != nil {
		writeMgmtError(w, http.StatusNotFound, "NotFoundException", requestID, "GraphQL API "+p.apiID+" not found.")
		return
	}
	spec, _ := obj["spec"].(map[string]any)
	q := r.URL.Query()
	switch verb {
	case "GetGraphqlApi":
		writeMgmtJSON(w, http.StatusOK, requestID, map[string]any{"graphqlApi": h.graphqlAPIJSON(p.apiID, obj)})
	case "GetIntrospectionSchema":
		switch q.Get("format") {
		case "SDL":
		case "JSON":
			writeMgmtError(w, http.StatusBadRequest, "BadRequestException", requestID,
				"format JSON is not served by the open-infra shim (the engine answers the __schema introspection query); request format SDL")
			return
		default:
			writeMgmtError(w, http.StatusBadRequest, "BadRequestException", requestID, "format must be SDL or JSON")
			return
		}
		sdl, _ := spec["schema"].(string)
		if strings.TrimSpace(sdl) == "" {
			writeMgmtError(w, http.StatusNotFound, "NotFoundException", requestID, "GraphQL API "+p.apiID+" has no schema.")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sdl))
	case "GetSchemaCreationStatus":
		status, details := schemaCreationStatus(obj)
		writeMgmtJSON(w, http.StatusOK, requestID, map[string]any{"status": status, "details": details})
	case "GetDataSource":
		for _, it := range specList(spec, "dataSources") {
			if ds, ok := it.(map[string]any); ok && ds["name"] == p.dsName {
				writeMgmtJSON(w, http.StatusOK, requestID, map[string]any{"dataSource": h.dataSourceJSON(p.apiID, ds)})
				return
			}
		}
		writeMgmtError(w, http.StatusNotFound, "NotFoundException", requestID, "Data source "+p.dsName+" not found.")
	case "ListDataSources":
		var items []map[string]any
		for _, it := range specList(spec, "dataSources") {
			if ds, ok := it.(map[string]any); ok {
				items = append(items, h.dataSourceJSON(p.apiID, ds))
			}
		}
		page, next, ok := appsyncPage(items, q)
		if !ok {
			writeMgmtError(w, http.StatusBadRequest, "BadRequestException", requestID, "invalid maxResults or nextToken")
			return
		}
		writeMgmtJSON(w, http.StatusOK, requestID, withNext(map[string]any{"dataSources": page}, next))
	case "GetFunction":
		for _, fn := range pipelineFunctions(spec) {
			if fn.id == p.fnID {
				writeMgmtJSON(w, http.StatusOK, requestID, map[string]any{"functionConfiguration": h.functionJSON(p.apiID, fn)})
				return
			}
		}
		writeMgmtError(w, http.StatusNotFound, "NotFoundException", requestID, "Function "+p.fnID+" not found.")
	case "ListFunctions":
		var items []map[string]any
		for _, fn := range pipelineFunctions(spec) {
			items = append(items, h.functionJSON(p.apiID, fn))
		}
		page, next, ok := appsyncPage(items, q)
		if !ok {
			writeMgmtError(w, http.StatusBadRequest, "BadRequestException", requestID, "invalid maxResults or nextToken")
			return
		}
		writeMgmtJSON(w, http.StatusOK, requestID, withNext(map[string]any{"functions": page}, next))
	}
}

// listGraphqlApis lists the GraphQLApi claims a page at a time (the API server's own paging), keeping
// those in namespaces the caller may list graphqlapis in.
func (h *appsyncHandler) listGraphqlApis(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	ctx := r.Context()
	if denied, reason := dataPlaneDenied(ctx, h.authz, claims, "appsync:ListGraphqlApis", "GraphQLApi", "", r); denied {
		h.logger.Warn("appsync ListGraphqlApis denied", "user", claims.Sub, "reason", reason)
		writeMgmtError(w, http.StatusForbidden, "UnauthorizedException", requestID, "not authorized to list GraphQL APIs")
		return
	}
	q := r.URL.Query()
	limit := int64(appsyncListMax)
	if s := q.Get("maxResults"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > appsyncListMax {
			writeMgmtError(w, http.StatusBadRequest, "BadRequestException", requestID, "maxResults must be between 0 and 25")
			return
		}
		if n > 0 {
			limit = int64(n)
		}
	}
	objs, next, err := h.apis.List(ctx, limit, q.Get("nextToken"))
	if err != nil {
		h.logger.Warn("appsync ListGraphqlApis failed", "error", err.Error())
		writeMgmtError(w, http.StatusBadRequest, "BadRequestException", requestID, "could not list the GraphQL APIs (an expired nextToken lists again from the start)")
		return
	}
	mayList := map[string]bool{}
	apis := []any{}
	for _, obj := range objs {
		md, _ := obj["metadata"].(map[string]any)
		ns, _ := md["namespace"].(string)
		name, _ := md["name"].(string)
		ok, seen := mayList[ns]
		if !seen {
			ok, _ = iam.CanDo(ctx, h.cs, claims, "list", "openinfra.dev", "graphqlapis", ns, "")
			mayList[ns] = ok
		}
		if ok {
			apis = append(apis, h.graphqlAPIJSON(ns+"."+name, obj))
		}
	}
	writeMgmtJSON(w, http.StatusOK, requestID, withNext(map[string]any{"graphqlApis": apis}, next))
}

func withNext(m map[string]any, next string) map[string]any {
	if next != "" {
		m["nextToken"] = next
	}
	return m
}

// appsyncPage pages a list held in one claim: nextToken is the offset of the next item.
func appsyncPage(items []map[string]any, q map[string][]string) (page []map[string]any, next string, ok bool) {
	limit := appsyncListMax
	if v := first(q["maxResults"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > appsyncListMax {
			return nil, "", false
		}
		if n > 0 {
			limit = n
		}
	}
	start := 0
	if v := first(q["nextToken"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > len(items) {
			return nil, "", false
		}
		start = n
	}
	end := start + limit
	if end >= len(items) {
		end = len(items)
	} else {
		next = strconv.Itoa(end)
	}
	page = items[start:end]
	if page == nil {
		page = []map[string]any{}
	}
	return page, next, true
}

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

func (h *appsyncHandler) apiARN(apiID string) string {
	return "arn:aws:appsync:" + h.region + ":" + h.account + ":apis/" + apiID
}

// graphqlAPIJSON is a GraphQLApi claim in AppSync's GraphqlApi shape.
func (h *appsyncHandler) graphqlAPIJSON(apiID string, obj map[string]any) map[string]any {
	md, _ := obj["metadata"].(map[string]any)
	spec, _ := obj["spec"].(map[string]any)
	name, _ := md["name"].(string)
	if name == "" {
		_, name = splitAPIID(apiID)
	}
	out := map[string]any{"apiId": apiID, "name": name, "arn": h.apiARN(apiID), "apiType": "GRAPHQL", "visibility": "GLOBAL"}
	if st, _ := obj["status"].(map[string]any); st != nil {
		if u, _ := st["url"].(string); u != "" {
			out["uris"] = map[string]any{"GRAPHQL": u}
		}
	}
	intro := "ENABLED"
	if lim, _ := spec["limits"].(map[string]any); lim != nil {
		if lim["introspection"] == "disabled" {
			intro = "DISABLED"
		}
		if d, ok := lim["maxDepth"].(float64); ok && d > 0 {
			out["queryDepthLimit"] = int(d)
		} else if d, ok := lim["maxDepth"].(int64); ok && d > 0 {
			out["queryDepthLimit"] = d
		}
	}
	out["introspectionConfig"] = intro
	return out
}

// schemaCreationStatus maps the claim onto GetSchemaCreationStatus: an API with no schema has none to
// create; one with a schema has it once the claim is Ready.
func schemaCreationStatus(obj map[string]any) (status, details string) {
	spec, _ := obj["spec"].(map[string]any)
	if sdl, _ := spec["schema"].(string); strings.TrimSpace(sdl) == "" {
		return "NOT_APPLICABLE", "The API has no schema."
	}
	st, _ := obj["status"].(map[string]any)
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Synced" && m["status"] == "False" {
			msg, _ := m["message"].(string)
			return "FAILED", msg
		}
	}
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" && m["status"] == "True" {
			return "SUCCESS", "The schema is being served."
		}
	}
	return "PROCESSING", "The API is not ready yet."
}

// dataSourceJSON is a spec.dataSources entry in AppSync's DataSource shape. A source's credentials (its
// connectionSecret) are not part of it.
func (h *appsyncHandler) dataSourceJSON(apiID string, ds map[string]any) map[string]any {
	name, _ := ds["name"].(string)
	typ, _ := ds["type"].(string)
	endpoint, _ := ds["endpoint"].(string)
	out := map[string]any{"name": name, "dataSourceArn": h.apiARN(apiID) + "/datasources/" + name}
	switch typ {
	case "dynamodb":
		out["type"] = "AMAZON_DYNAMODB"
		c := map[string]any{"awsRegion": h.region}
		if coll, _ := ds["collection"].(string); coll != "" {
			c["tableName"] = coll
		}
		out["dynamodbConfig"] = c
	case "http":
		out["type"] = "HTTP"
		if endpoint != "" {
			out["httpConfig"] = map[string]any{"endpoint": endpoint}
		}
	case "lambda":
		out["type"] = "AWS_LAMBDA" // its endpoint is the function's URL, not a function ARN
	case "rds":
		out["type"] = "RELATIONAL_DATABASE"
	case "opensearch":
		out["type"] = "AMAZON_OPENSEARCH_SERVICE"
		if endpoint != "" {
			out["openSearchServiceConfig"] = map[string]any{"endpoint": endpoint, "awsRegion": h.region}
		}
	case "eventbridge":
		out["type"] = "AMAZON_EVENTBRIDGE"
	default: // none, memory (an in-memory development store): no backend AppSync would name
		out["type"] = "NONE"
	}
	return out
}

// appsyncFunction is a pipeline function as the claim keeps it.
type appsyncFunction struct {
	id                  string
	dataSource, runtime string
	request, response   string
}

// pipelineFunctions is every distinct function the API's pipeline resolvers run, in the order first run.
func pipelineFunctions(spec map[string]any) []appsyncFunction {
	var out []appsyncFunction
	seen := map[string]bool{}
	resolvers := specList(spec, "resolvers")
	// Resolvers in a stable order (type, field), so the listing does not follow edit order.
	sorted := make([]map[string]any, 0, len(resolvers))
	for _, it := range resolvers {
		if m, ok := it.(map[string]any); ok {
			sorted = append(sorted, m)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a := fnStr(sorted[i]["type"]) + "." + fnStr(sorted[i]["field"])
		b := fnStr(sorted[j]["type"]) + "." + fnStr(sorted[j]["field"])
		return a < b
	})
	for _, res := range sorted {
		fl, _ := res["functions"].([]any)
		for _, f := range fl {
			m, _ := f.(map[string]any)
			fn := appsyncFunction{dataSource: fnStr(m["dataSource"]), runtime: fnStr(m["runtime"]),
				request: fnStr(m["request"]), response: fnStr(m["response"])}
			if fn.runtime == "" {
				fn.runtime = "appsync-vtl"
			}
			sum := sha256.Sum256([]byte(fn.dataSource + "\x00" + fn.runtime + "\x00" + fn.request + "\x00" + fn.response))
			fn.id = hex.EncodeToString(sum[:])[:26]
			if !seen[fn.id] {
				seen[fn.id] = true
				out = append(out, fn)
			}
		}
	}
	return out
}

// functionJSON is a pipeline function in AppSync's FunctionConfiguration shape.
func (h *appsyncHandler) functionJSON(apiID string, fn appsyncFunction) map[string]any {
	out := map[string]any{"functionId": fn.id, "name": fn.id, "dataSourceName": fn.dataSource,
		"functionArn": h.apiARN(apiID) + "/functions/" + fn.id}
	if fn.runtime == "appsync-js" {
		out["runtime"] = map[string]any{"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
		out["code"] = fn.request
	} else {
		out["functionVersion"] = "2018-05-29"
		out["requestMappingTemplate"] = fn.request
		if fn.response != "" {
			out["responseMappingTemplate"] = fn.response
		}
	}
	return out
}
