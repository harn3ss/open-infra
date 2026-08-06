// Package server assembles the open-appsync engine from a declarative config directory and serves it
// over HTTP. The config (a ConfigMap in the deployed component) is: a config.json listing data
// sources + resolvers, plus the VTL request/response templates as sibling .vtl files (files, not
// inline strings, so templates carry no JSON/YAML escaping). Schema/resolver authoring through an
// AWS-shaped management API is a later rung; slice 1 takes the resolver set as config, per the handoff.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
	"go.mongodb.org/mongo-driver/mongo"
)

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
		registry[rc.Type+"."+rc.Field] = resolver.Resolver{Request: string(req), Response: string(resp), Source: src}
	}

	return graphql.New(vtl.New(), registry), nil
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
