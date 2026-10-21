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
// bodySchema supports the JSON Schema keywords API Gateway Models use in practice (type, required,
// properties, items, enum, minimum/maximum, minLength/maxLength, pattern, additionalProperties:false)
// — the exact logic lives in internal/apigwschema, shared with the aws-shim REST API v1 data plane so
// a Model validates identically on both surfaces (#295).
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
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/apigwschema"
)

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

// validateRequest returns a non-empty reason when the request violates the route's rules. Required
// header/query presence is route-shaped and checked here; the Model body validation is the shared
// apigwschema logic (identical to the REST v1 data plane).
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
	return apigwschema.ValidateBody(r.BodySchema, body)
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
