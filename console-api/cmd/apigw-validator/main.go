// apigw-validator is open-infra's API Gateway request-validation tier: a small reverse proxy that
// sits in front of HttpApi routes which declare a request Model (JSON Schema) and/or required
// parameters. It validates each request AT THE GATEWAY — before the backend — and returns an
// AWS-API-Gateway-shaped 400 Bad Request on failure (the faithful behavior; AWS validates body +
// parameters against a Model and rejects with 400), otherwise it proxies to the route's backend.
//
// Only routes with validation are pointed at this service (by the HttpApi composition); everything
// else goes straight Traefik->backend. One instance per HttpApi; its route table is a mounted
// ConfigMap (ROUTES_CONFIG, default /config/routes.json):
//
//	{"routes":[{"methods":["POST","PUT"],"pathPrefix":"/orders","upstream":"http://orders.ns.svc.cluster.local:80",
//	            "requiredHeaders":["x-api-key"],"requiredQuery":["v"],"bodySchema":{<JSON Schema>}}]}
//
// bodySchema supports the JSON Schema keywords API Gateway Models use in practice: type, required,
// properties, items, enum, minimum/maximum, minLength/maxLength, pattern, additionalProperties:false.
// Unsupported keywords are ignored (documented), never a silent pass of something that should fail.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

// reMatch reports whether s matches the (RE2) pattern. A malformed pattern returns an error, which
// the caller treats as "don't reject" so a bad Model can't wedge every request.
func reMatch(pattern, s string) (bool, error) { return regexp.MatchString(pattern, s) }

type route struct {
	Methods         []string       `json:"methods"`
	PathPrefix      string         `json:"pathPrefix"`
	Upstream        string         `json:"upstream"`
	RequiredHeaders []string       `json:"requiredHeaders"`
	RequiredQuery   []string       `json:"requiredQuery"`
	BodySchema      map[string]any `json:"bodySchema"`
}

type config struct {
	Routes []route `json:"routes"`
}

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	sortRoutesLongestFirst(&c)
	return &c, nil
}

// sortRoutesLongestFirst orders routes by descending path-prefix length so match() returns the most
// specific route.
func sortRoutesLongestFirst(c *config) {
	sort.SliceStable(c.Routes, func(i, j int) bool { return len(c.Routes[i].PathPrefix) > len(c.Routes[j].PathPrefix) })
}

// match finds the route for a request (method + longest matching path prefix).
func (c *config) match(method, path string) *route {
	for i := range c.Routes {
		r := &c.Routes[i]
		if r.PathPrefix != "" && !strings.HasPrefix(path, r.PathPrefix) {
			continue
		}
		if len(r.Methods) > 0 && !containsFold(r.Methods, method) {
			continue
		}
		return r
	}
	return nil
}

func containsFold(ss []string, v string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// validateRequest returns a non-empty reason when the request violates the route's rules.
func validateRequest(r *route, h http.Header, q url.Values, body []byte) string {
	for _, name := range r.RequiredHeaders {
		if h.Get(name) == "" {
			return "missing required header: " + name
		}
	}
	for _, name := range r.RequiredQuery {
		if _, ok := q[name]; !ok {
			return "missing required query parameter: " + name
		}
	}
	if len(r.BodySchema) == 0 {
		return ""
	}
	if len(body) == 0 {
		return "request body is required and must match the model"
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return "request body is not valid JSON"
	}
	return validateSchema(r.BodySchema, v, "body")
}

// validateSchema is a focused JSON Schema validator (the keywords API Gateway Models use). It
// returns "" when valid, else a human-readable reason naming the failing path.
func validateSchema(schema map[string]any, v any, path string) string {
	if t, ok := schema["type"].(string); ok {
		if reason := checkType(t, v, path); reason != "" {
			return reason
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		if !anyEqual(enum, v) {
			return path + " must be one of the allowed values"
		}
	}
	switch val := v.(type) {
	case map[string]any:
		if req, ok := schema["required"].([]any); ok {
			for _, rn := range req {
				if name, ok := rn.(string); ok {
					if _, present := val[name]; !present {
						return path + "." + name + " is required"
					}
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		if addl, ok := schema["additionalProperties"].(bool); ok && !addl && props != nil {
			for k := range val {
				if _, declared := props[k]; !declared {
					return path + "." + k + " is not an allowed property"
				}
			}
		}
		for name, sub := range props {
			if subSchema, ok := sub.(map[string]any); ok {
				if child, present := val[name]; present {
					if reason := validateSchema(subSchema, child, path+"."+name); reason != "" {
						return reason
					}
				}
			}
		}
	case []any:
		if items, ok := schema["items"].(map[string]any); ok {
			for i, el := range val {
				if reason := validateSchema(items, el, fmt.Sprintf("%s[%d]", path, i)); reason != "" {
					return reason
				}
			}
		}
	case string:
		if reason := checkString(schema, val, path); reason != "" {
			return reason
		}
	case float64:
		if reason := checkNumber(schema, val, path); reason != "" {
			return reason
		}
	}
	return ""
}

func checkType(t string, v any, path string) string {
	ok := false
	switch t {
	case "object":
		_, ok = v.(map[string]any)
	case "array":
		_, ok = v.([]any)
	case "string":
		_, ok = v.(string)
	case "number":
		_, ok = v.(float64)
	case "integer":
		f, isF := v.(float64)
		ok = isF && f == float64(int64(f))
	case "boolean":
		_, ok = v.(bool)
	case "null":
		ok = v == nil
	default:
		ok = true // unknown type keyword — don't reject
	}
	if !ok {
		return path + " must be of type " + t
	}
	return ""
}

func checkString(schema map[string]any, s, path string) string {
	if m, ok := schema["minLength"].(float64); ok && float64(len(s)) < m {
		return fmt.Sprintf("%s must be at least %d characters", path, int(m))
	}
	if m, ok := schema["maxLength"].(float64); ok && float64(len(s)) > m {
		return fmt.Sprintf("%s must be at most %d characters", path, int(m))
	}
	if p, ok := schema["pattern"].(string); ok && p != "" {
		if matched, err := reMatch(p, s); err == nil && !matched {
			return path + " does not match the required pattern"
		}
	}
	return ""
}

func checkNumber(schema map[string]any, n float64, path string) string {
	if m, ok := schema["minimum"].(float64); ok && n < m {
		return fmt.Sprintf("%s must be >= %v", path, m)
	}
	if m, ok := schema["maximum"].(float64); ok && n > m {
		return fmt.Sprintf("%s must be <= %v", path, m)
	}
	return ""
}

func anyEqual(list []any, v any) bool {
	for _, item := range list {
		if fmt.Sprintf("%v", item) == fmt.Sprintf("%v", v) {
			return true
		}
	}
	return false
}

func main() {
	cfgPath := getenv("ROUTES_CONFIG", "/config/routes.json")
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("apigw-validator: %v", err)
	}
	addr := ":" + getenv("PORT", "8080")
	log.Printf("apigw-validator listening on %s with %d validated route(s)", addr, len(cfg.Routes))
	log.Fatal(http.ListenAndServe(addr, handler(cfg)))
}

func handler(cfg *config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		rt := cfg.match(r.Method, r.URL.Path)
		if rt == nil || rt.Upstream == "" {
			// The composition only routes validated paths here; a miss is a misconfiguration.
			writeGatewayError(w, http.StatusBadGateway, "no validated route matches this request")
			return
		}
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
		if reason := validateRequest(rt, r.Header, r.URL.Query(), body); reason != "" {
			writeGatewayError(w, http.StatusBadRequest, reason)
			return
		}
		u, err := url.Parse(rt.Upstream)
		if err != nil {
			writeGatewayError(w, http.StatusBadGateway, "invalid upstream")
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		r.ContentLength = int64(len(body))
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.ServeHTTP(w, r)
	}
}

// writeGatewayError emits AWS API Gateway's validation error shape (a JSON {message}).
func writeGatewayError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
