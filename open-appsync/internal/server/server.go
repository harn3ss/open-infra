// Package server assembles the open-appsync engine from a declarative config directory and serves it
// over HTTP. The config (a ConfigMap in the deployed component) is: a config.json listing data
// sources + resolvers, plus the VTL request/response templates as sibling .vtl files (files, not
// inline strings, so templates carry no JSON/YAML escaping). Schema/resolver authoring through an
// AWS-shaped management API is a later rung; slice 1 takes the resolver set as config, per the handoff.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
	"go.mongodb.org/mongo-driver/mongo"
)

// runtimeAppsyncVTL is the one runtime slice-1 ships. The field exists (and is validated) so §2.5's
// future dialects (js, a neutral format) slot in as a new value with no schema change — an unknown
// runtime fails closed rather than silently defaulting.
const runtimeAppsyncVTL = "appsync-vtl"

// Config is the engine's declarative wiring.
type Config struct {
	DataSources []DataSourceConfig `json:"dataSources"`
	Resolvers   []ResolverConfig   `json:"resolvers"`
}

type DataSourceConfig struct {
	Name       string `json:"name"`
	Type       string `json:"type"`       // "dynamodb" (FerretDB-backed) | "memory" (ephemeral, dev/demo)
	Collection string `json:"collection"` // dynamodb: the FerretDB collection ("table")
}

type ResolverConfig struct {
	Type       string `json:"type"` // "Query" | "Mutation"
	Field      string `json:"field"`
	DataSource string `json:"dataSource"`
	Runtime    string `json:"runtime"`  // "appsync-vtl" (default). The §2.5 extension point's field.
	Request    string `json:"request"`  // filename of the request mapping template (relative to the config dir)
	Response   string `json:"response"` // filename of the response mapping template
}

// Load reads config.json + its template files from dir and builds a ready GraphQL engine. mongoDB is
// the FerretDB database backing "dynamodb" data sources; pass nil when only "memory" sources are used
// (dev/demo/tests) — a "dynamodb" source then errors loudly rather than silently degrading.
func Load(dir string, mongoDB *mongo.Database) (*graphql.Engine, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("open-appsync: read config.json: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("open-appsync: parse config.json: %w", err)
	}

	stores := map[string]dynamodb.Store{}
	for _, ds := range cfg.DataSources {
		switch ds.Type {
		case "memory":
			stores[ds.Name] = dynamodb.NewMemStore()
		case "dynamodb":
			if mongoDB == nil {
				return nil, fmt.Errorf("open-appsync: data source %q is type dynamodb but no MONGO_URI is configured", ds.Name)
			}
			if ds.Collection == "" {
				return nil, fmt.Errorf("open-appsync: data source %q (dynamodb) needs a collection", ds.Name)
			}
			stores[ds.Name] = dynamodb.NewFerretStore(mongoDB.Collection(ds.Collection))
		default:
			return nil, fmt.Errorf("open-appsync: data source %q has unknown type %q (slice 1: memory | dynamodb)", ds.Name, ds.Type)
		}
	}

	// One VTL engine, shared by every appsync-vtl runtime (it is stateless apart from its $util
	// providers). A future runtime value builds its own runtime here.
	engine := vtl.New()

	registry := map[string]resolver.Resolver{}
	for _, rc := range cfg.Resolvers {
		src, ok := stores[rc.DataSource]
		if !ok {
			return nil, fmt.Errorf("open-appsync: resolver %s.%s references unknown data source %q", rc.Type, rc.Field, rc.DataSource)
		}
		req, err := os.ReadFile(filepath.Join(dir, rc.Request))
		if err != nil {
			return nil, fmt.Errorf("open-appsync: resolver %s.%s: read request template: %w", rc.Type, rc.Field, err)
		}
		resp, err := os.ReadFile(filepath.Join(dir, rc.Response))
		if err != nil {
			return nil, fmt.Errorf("open-appsync: resolver %s.%s: read response template: %w", rc.Type, rc.Field, err)
		}

		rt, err := buildRuntime(rc.Runtime, engine, string(req), string(resp))
		if err != nil {
			return nil, fmt.Errorf("open-appsync: resolver %s.%s: %w", rc.Type, rc.Field, err)
		}
		// Fail closed (handoff §2): one malformed template keeps the WHOLE config from loading, so the
		// engine never serves it — the error surfaces in the pod (and thus the XR's not-ready status)
		// rather than on the first request.
		if v, ok := rt.(runtime.Validator); ok {
			if err := v.Validate(); err != nil {
				return nil, fmt.Errorf("open-appsync: resolver %s.%s is invalid, refusing to serve: %w", rc.Type, rc.Field, err)
			}
		}
		registry[rc.Type+"."+rc.Field] = resolver.Resolver{Runtime: rt, Source: src}
	}

	return graphql.New(registry), nil
}

// buildRuntime selects the runtime for a resolver by its declared `runtime` value (the §2.5 extension
// point). Empty defaults to appsync-vtl; an unknown value is rejected (fail closed) rather than
// silently substituted.
func buildRuntime(name string, engine *vtl.Engine, request, response string) (runtime.Runtime, error) {
	switch name {
	case "", runtimeAppsyncVTL:
		return vtlruntime.New(engine, request, response), nil
	default:
		return nil, fmt.Errorf("unknown runtime %q (slice 1: %q)", name, runtimeAppsyncVTL)
	}
}

// Handler serves GraphQL over HTTP: POST /graphql {query, variables} → {data, errors}. This is the
// endpoint the aws-shim's `appsync` service forwards to (it appends /graphql), and a GraphQL client
// can hit directly. GraphQL errors are returned in-band ({errors:[…]}), so the HTTP status is 200
// even for a resolver error, per GraphQL-over-HTTP convention.
func Handler(e *graphql.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, graphql.Result{
				Errors: []graphql.GqlError{{Message: "GraphQL requests must be POST"}}})
			return
		}
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, graphql.Result{
				Errors: []graphql.GqlError{{Message: "invalid GraphQL request body"}}})
			return
		}
		writeJSON(w, http.StatusOK, e.Execute(r.Context(), body.Query, body.Variables))
	}
}

// TestResolverRequest is the input to the test-resolver endpoint: a resolver's templates plus a
// sample $ctx to run them against. `result` is optional — supply it to also see the response phase
// (the data source is NOT called; you provide the result the response template would see).
type TestResolverRequest struct {
	Runtime  string         `json:"runtime"`  // "appsync-vtl" (default)
	Request  string         `json:"request"`  // request mapping template source
	Response string         `json:"response"` // response mapping template source
	Context  map[string]any `json:"context"`  // the $ctx: {"args":…,"identity":…,"source":…}
	Result   *any           `json:"result"`   // optional sample data-source result → runs the response phase
}

// TestResolverResponse shows what the templates produce: the neutral request Operation and, if a
// sample result was supplied, the response value. A resolver-thrown error (e.g. $util.error()) is
// reported with its errorType — the difference between authoring with feedback and authoring blind.
type TestResolverResponse struct {
	RequestOp any    `json:"requestOp,omitempty"` // the neutral data-source operation the request phase emits
	Response  any    `json:"response,omitempty"`  // the response value (only when `result` was supplied)
	Error     string `json:"error,omitempty"`
	ErrorType string `json:"errorType,omitempty"`
}

// TestResolverHandler exposes the probe harness on user input (handoff §3): POST a resolver + a sample
// $ctx and get back exactly what its templates render, without deploying it or touching a data source.
// It is an authoring aid on the engine itself (not an AWS wire API); nothing here mutates state.
func TestResolverHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, TestResolverResponse{Error: "test-resolver requests must be POST"})
			return
		}
		var req TestResolverRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, TestResolverResponse{Error: "invalid test-resolver body"})
			return
		}
		rt, err := buildRuntime(req.Runtime, vtl.New(), req.Request, req.Response)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, TestResolverResponse{Error: err.Error()})
			return
		}
		ctx := req.Context
		if ctx == nil {
			ctx = map[string]any{}
		}

		op, err := rt.RenderRequest(ctx)
		if err != nil {
			writeJSON(w, http.StatusOK, errResp(err))
			return
		}
		out := TestResolverResponse{RequestOp: map[string]any(op)}

		// Only run the response phase if the caller supplied a sample result to feed it.
		if req.Result != nil {
			ctx["result"] = *req.Result
			resp, err := rt.RenderResponse(ctx)
			if err != nil {
				writeJSON(w, http.StatusOK, errResp(err))
				return
			}
			out.Response = resp
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// errResp renders a resolver error, unwrapping a *vtl.ThrowError so the errorType is shown.
func errResp(err error) TestResolverResponse {
	out := TestResolverResponse{Error: err.Error()}
	var te *vtl.ThrowError
	if errors.As(err, &te) {
		out.Error = te.Message
		out.ErrorType = te.ErrorType
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
