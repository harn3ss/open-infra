// API Gateway v2 pure logic for the aws-shim (polyhedron#169): management-path → op dispatch, route
// matching with AWS precedence, the 2.0/1.0 proxy-event builders, and the Lambda-response translator.
// Kept side-effect-free so the contract (the part AWS handlers actually depend on) is unit-tested.
package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// agwOpFromRequest maps an apigatewayv2 REST management path + method to an op and the api id it targets.
// Paths: /v2/apis[/{apiId}[/routes|integrations|stages|deployments|authorizers]].
func agwOpFromRequest(r *http.Request) (op, apiID string, ok bool) {
	segs := splitPath(r.URL.Path)
	if len(segs) < 2 || segs[0] != "v2" || segs[1] != "apis" {
		return "", "", false
	}
	switch len(segs) {
	case 2: // /v2/apis
		switch r.Method {
		case http.MethodPost:
			return "CreateApi", "", true
		case http.MethodGet:
			return "GetApis", "", true
		}
	case 3: // /v2/apis/{apiId}
		apiID = segs[2]
		switch r.Method {
		case http.MethodGet:
			return "GetApi", apiID, true
		case http.MethodDelete:
			return "DeleteApi", apiID, true
		}
	case 4: // /v2/apis/{apiId}/<sub>
		apiID = segs[2]
		switch segs[3] {
		case "routes":
			if r.Method == http.MethodPost {
				return "CreateRoute", apiID, true
			}
			if r.Method == http.MethodGet {
				return "GetRoutes", apiID, true
			}
		case "integrations":
			if r.Method == http.MethodPost {
				return "CreateIntegration", apiID, true
			}
		case "stages":
			if r.Method == http.MethodPost {
				return "CreateStage", apiID, true
			}
			if r.Method == http.MethodGet {
				return "GetStages", apiID, true
			}
		case "deployments":
			if r.Method == http.MethodPost {
				return "CreateDeployment", apiID, true
			}
		case "authorizers":
			if r.Method == http.MethodPost {
				return "CreateAuthorizer", apiID, true
			}
		}
	}
	return "", "", false
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstSeg(path string) (seg, rest string) {
	t := strings.TrimPrefix(path, "/")
	i := strings.IndexByte(t, '/')
	if i < 0 {
		return t, "/"
	}
	return t[:i], "/" + t[i+1:]
}

// validRouteKey accepts "<METHOD> /<path>" (the only non-$default shape). Method ∈ the HTTP verbs or ANY.
func validRouteKey(rk string) bool {
	parts := strings.SplitN(rk, " ", 2)
	if len(parts) != 2 {
		return false
	}
	if !validMethod(parts[0]) {
		return false
	}
	return strings.HasPrefix(parts[1], "/")
}

func validMethod(m string) bool {
	switch m {
	case "ANY", http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// functionFromURI resolves a Lambda integrationUri (an ARN or a bare name) to the function name. Strips a
// trailing :qualifier (version/alias) since the shim does not resolve qualifiers.
func functionFromURI(uri string) string {
	name := uri
	if i := strings.Index(uri, ":function:"); i >= 0 {
		name = uri[i+len(":function:"):]
	}
	// arn may carry a :<qualifier> after the name.
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	return name
}

// matchRoute picks the best-matching route for (method, path) with AWS HTTP API precedence: more static
// segments win, then path variables, then the greedy {proxy+}, then the $default route. An exact method
// beats ANY. Returns the route, the extracted path parameters, and whether anything matched.
func matchRoute(routes []agwRoute, method, path string) (agwRoute, map[string]string, bool) {
	actual := splitPath(path)
	var best agwRoute
	var bestParams map[string]string
	bestScore := -1
	var defaultRoute *agwRoute

	for i := range routes {
		rt := routes[i]
		if rt.RouteKey == "$default" {
			r := rt
			defaultRoute = &r
			continue
		}
		parts := strings.SplitN(rt.RouteKey, " ", 2)
		if len(parts) != 2 {
			continue
		}
		rMethod, rPath := parts[0], parts[1]
		methodOK := rMethod == method || rMethod == "ANY"
		if !methodOK {
			continue
		}
		params, static, greedy, ok := matchTemplate(splitPath(rPath), actual)
		if !ok {
			continue
		}
		// Any match scores >= 0 (so it beats the -1 "nothing matched" sentinel and the $default fallback):
		// more static segments win first, then a non-greedy (exact-length) match, then an exact method.
		score := static * 1000
		if !greedy {
			score += 100
		}
		if rMethod != "ANY" {
			score += 10
		}
		if score > bestScore {
			bestScore = score
			best = rt
			bestParams = params
		}
	}
	if bestScore >= 0 {
		return best, bestParams, true
	}
	if defaultRoute != nil {
		return *defaultRoute, map[string]string{}, true
	}
	return agwRoute{}, nil, false
}

// matchTemplate matches a template's segments against the actual segments. Returns extracted params, the
// count of static (literal) segments matched, whether a greedy {proxy+} was used, and success.
func matchTemplate(tmpl, actual []string) (params map[string]string, static int, greedy, ok bool) {
	params = map[string]string{}
	// greedy {proxy+} only valid as the LAST template segment.
	if n := len(tmpl); n > 0 && isGreedy(tmpl[n-1]) {
		if len(actual) < n-1 {
			return nil, 0, false, false
		}
		for i := 0; i < n-1; i++ {
			if !segMatch(tmpl[i], actual[i], params, &static) {
				return nil, 0, false, false
			}
		}
		params["proxy"] = strings.Join(actual[n-1:], "/")
		return params, static, true, true
	}
	if len(tmpl) != len(actual) {
		return nil, 0, false, false
	}
	for i := range tmpl {
		if !segMatch(tmpl[i], actual[i], params, &static) {
			return nil, 0, false, false
		}
	}
	return params, static, false, true
}

func segMatch(t, a string, params map[string]string, static *int) bool {
	if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
		name := strings.TrimSuffix(strings.TrimPrefix(t, "{"), "}")
		params[name] = a
		return true
	}
	if t == a {
		*static++
		return true
	}
	return false
}

func isGreedy(t string) bool { return t == "{proxy+}" }

// buildProxyEvent constructs the API Gateway v2 proxy event in the requested payload format (2.0 default).
func buildProxyEvent(pfv string, r *http.Request, apiID, stage, routeKey, path string, pathParams map[string]string, body []byte, requestID string) map[string]any {
	now := time.Now().UTC()
	bodyStr, isB64 := encodeBody(body)
	sourceIP := clientIP(r)
	if pfv == "1.0" {
		resource := "/"
		if p := strings.SplitN(routeKey, " ", 2); len(p) == 2 {
			resource = p[1]
		}
		ev := map[string]any{
			"version":                         "1.0",
			"resource":                        resource,
			"path":                            path,
			"httpMethod":                      r.Method,
			"headers":                         singleValueHeaders(r, false),
			"multiValueHeaders":               multiValueHeaders(r),
			"queryStringParameters":           singleValueQuery(r),
			"multiValueQueryStringParameters": multiValueQuery(r),
			"pathParameters":                  nilIfEmpty(pathParams),
			"isBase64Encoded":                 isB64,
			"requestContext": map[string]any{
				"accountId":    "open-infra",
				"apiId":        apiID,
				"httpMethod":   r.Method,
				"path":         "/" + stage + path,
				"protocol":     "HTTP/1.1",
				"resourcePath": resource,
				"stage":        stage,
				"requestId":    requestID,
				"identity":     map[string]any{"sourceIp": sourceIP, "userAgent": r.UserAgent()},
			},
		}
		if bodyStr != "" || isB64 {
			ev["body"] = bodyStr
		} else {
			ev["body"] = nil
		}
		return ev
	}
	// 2.0 (default)
	ev := map[string]any{
		"version":               "2.0",
		"routeKey":              routeKey,
		"rawPath":               path,
		"rawQueryString":        r.URL.RawQuery,
		"headers":               singleValueHeaders(r, true),
		"queryStringParameters": singleValueQuery(r),
		"pathParameters":        nilIfEmpty(pathParams),
		"isBase64Encoded":       isB64,
		"requestContext": map[string]any{
			"accountId":  "open-infra",
			"apiId":      apiID,
			"domainName": apiID + ".execute-api.amazonaws.com",
			"http": map[string]any{
				"method": r.Method, "path": path, "protocol": "HTTP/1.1",
				"sourceIp": sourceIP, "userAgent": r.UserAgent(),
			},
			"requestId": requestID,
			"routeKey":  routeKey,
			"stage":     stage,
			"time":      now.Format("02/Jan/2006:15:04:05 -0700"),
			"timeEpoch": now.UnixMilli(),
		},
	}
	if cookies := cookieList(r); len(cookies) > 0 {
		ev["cookies"] = cookies
	}
	if bodyStr != "" || isB64 {
		ev["body"] = bodyStr
	}
	return ev
}

// writeProxyResponse translates the Lambda's returned JSON into the real HTTP response. For 2.0 a response
// WITHOUT statusCode is the "simplified" form (the whole payload is the body, 200 + application/json).
func writeProxyResponse(w http.ResponseWriter, pfv string, upstreamStatus int, fnOut []byte, requestID string) {
	if upstreamStatus >= http.StatusBadRequest {
		// the function itself failed at the HTTP layer (not a structured proxy response)
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	var m map[string]any
	structured := false
	if err := json.Unmarshal(fnOut, &m); err == nil {
		_, structured = m["statusCode"]
	}
	if pfv == "1.0" && !structured {
		// v1 REQUIRES a structured response; a bare payload is a malformed handler → 502.
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	if !structured {
		// v2 simplified response: the whole payload is the body.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fnOut)
		return
	}
	status := toInt(m["statusCode"])
	if status == 0 {
		status = http.StatusOK
	}
	// headers
	if hs, ok := m["headers"].(map[string]any); ok {
		for k, v := range hs {
			if s, ok := v.(string); ok {
				w.Header().Set(k, s)
			}
		}
	}
	if mv, ok := m["multiValueHeaders"].(map[string]any); ok {
		for k, arr := range mv {
			for _, v := range sliceOf(arr) {
				if s, ok := v.(string); ok {
					w.Header().Add(k, s)
				}
			}
		}
	}
	for _, c := range sliceOf(m["cookies"]) {
		if s, ok := c.(string); ok {
			w.Header().Add("Set-Cookie", s)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("x-amzn-RequestId", requestID)
	body := ""
	if b, ok := m["body"].(string); ok {
		body = b
	}
	if b64, _ := m["isBase64Encoded"].(bool); b64 {
		if raw, err := base64.StdEncoding.DecodeString(body); err == nil {
			w.WriteHeader(status)
			_, _ = w.Write(raw)
			return
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// --- request decomposition helpers ---

func encodeBody(body []byte) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	if utf8.Valid(body) {
		return string(body), false
	}
	return base64.StdEncoding.EncodeToString(body), true
}

func singleValueHeaders(r *http.Request, lower bool) map[string]string {
	out := map[string]string{}
	for k, vs := range r.Header {
		key := k
		if lower {
			key = strings.ToLower(k)
		}
		out[key] = strings.Join(vs, ",")
	}
	return out
}

func multiValueHeaders(r *http.Request) map[string][]string {
	out := map[string][]string{}
	for k, vs := range r.Header {
		out[k] = vs
	}
	return out
}

func singleValueQuery(r *http.Request) map[string]string {
	q := r.URL.Query()
	if len(q) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, vs := range q {
		out[k] = strings.Join(vs, ",")
	}
	return out
}

func multiValueQuery(r *http.Request) map[string][]string {
	q := r.URL.Query()
	if len(q) == 0 {
		return nil
	}
	out := map[string][]string{}
	for k, vs := range q {
		out[k] = vs
	}
	return out
}

func cookieList(r *http.Request) []string {
	var out []string
	for _, c := range r.Cookies() {
		out = append(out, c.Name+"="+c.Value)
	}
	return out
}

func nilIfEmpty(m map[string]string) any {
	if len(m) == 0 {
		return nil
	}
	return m
}
