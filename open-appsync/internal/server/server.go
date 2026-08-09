// Package server assembles the open-appsync engine from a declarative config directory and serves it
// over HTTP. The config (a ConfigMap in the deployed component) is: a config.json listing data
// sources + resolvers, plus the VTL request/response templates as sibling.vtl files (files, not
// inline strings, so templates carry no JSON/YAML escaping). Schema/resolver authoring through an
// AWS-shaped management API is a later rung; slice 1 takes the resolver set as config,.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/awsscalars"
	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/httpsource"
	"github.com/harn3ss/open-infra/open-appsync/internal/jsruntime"
	"github.com/harn3ss/open-infra/open-appsync/internal/lambdasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/harn3ss/open-infra/open-appsync/internal/subscription"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
	"go.mongodb.org/mongo-driver/mongo"
)

// The runtime values a resolver may declare (the extension point's field). appsync-vtl and appsync-js
// are the two tenants; an unknown value fails closed rather than silently defaulting.
const (
	runtimeAppsyncVTL = "appsync-vtl"
	runtimeAppsyncJS  = "appsync-js"
)

// Config is the engine's declarative wiring.
type Config struct {
	DataSources   []DataSourceConfig   `json:"dataSources"`
	Resolvers     []ResolverConfig     `json:"resolvers"`
	Subscriptions []SubscriptionConfig `json:"subscriptions"` // Subscription-type fields
	Limits        *LimitsConfig        `json:"limits"`        // hostile-load guards; nil = safe defaults
}

// SubscriptionConfig is one Subscription-type field: a response mapping (subscriptions have no request
// phase — the push source calls them), the mutations that trigger it, an optional subject, and an auth
// requirement checked at subscribe time.
type SubscriptionConfig struct {
	Field       string            `json:"field"`
	Subject     string            `json:"subject"`     // bus subject; defaults to "sub." + field
	Runtime     string            `json:"runtime"`     // appsync-vtl (default) | appsync-js
	Response    string            `json:"response"`    // response mapping template filename
	TriggeredBy []string          `json:"triggeredBy"` // mutation field names that publish to this subscription
	Auth        authz.Requirement `json:"auth"`
}

// LimitsConfig is the hostile-load hardening  as declared on a GraphQLApi. Guards are ON
// by default even when this block is present: maxDepth/maxCost of 0 (or unset) fall back to the safe
// default; set a NEGATIVE value to deliberately disable a guard (opt-out is explicit, never implicit).
type LimitsConfig struct {
	MaxDepth         int      `json:"maxDepth"`
	MaxCost          int      `json:"maxCost"`
	PersistedOnly    bool     `json:"persistedOnly"`
	PersistedQueries []string `json:"persistedQueries"` // raw query documents; hashed (sha256) at load
	// Introspection: "" | "enabled" (default) | "disabled" | "authenticated-only". Gates who may read
	// the schema via __schema/__type — a recon-vs-tooling trade-off left to the operator, safe-by-choice.
	Introspection string `json:"introspection"`
}

type DataSourceConfig struct {
	Name       string `json:"name"`
	Type       string `json:"type"`       // "memory" | "dynamodb" (FerretDB-backed) | "http" | "lambda"
	Collection string `json:"collection"` // dynamodb: the FerretDB collection ("table")
	Endpoint   string `json:"endpoint"`   // http: base URL; lambda: the function (kind: Function) URL
}

type ResolverConfig struct {
	Type  string `json:"type"` // "Query" | "Mutation" (root), or any object type (e.g. "Post") for a per-field resolver
	Field string `json:"field"`

	// Unit resolver (the default): one runtime step over one data source.
	DataSource string `json:"dataSource"`
	Runtime    string `json:"runtime"`  // "appsync-vtl" (default). The runtime extension point's field.
	Request    string `json:"request"`  // filename of the request mapping template (relative to the config dir)
	Response   string `json:"response"` // filename of the response mapping template

	// Pipeline resolver: if Functions is non-empty this is a pipeline lifecycle and the unit fields
	// above are ignored. Before/After are optional single-template steps (files) that touch no data
	// source; each function is a unit step over its own data source.
	Before    string           `json:"before"`    // filename of the before mapping template (optional)
	After     string           `json:"after"`     // filename of the after mapping template (optional)
	Functions []FunctionConfig `json:"functions"` // ordered pipeline functions

	// Auth is the field-level authorization requirement, enforced by the executor before the
	// resolver runs. Zero = public. Checked against the shared k8s RBAC boundary (a SubjectAccessReview).
	Auth authz.Requirement `json:"auth"`
}

type FunctionConfig struct {
	DataSource string `json:"dataSource"`
	Runtime    string `json:"runtime"` // "appsync-vtl" (default)
	Request    string `json:"request"`
	Response   string `json:"response"`
}

// Load reads config.json + its template files from dir and builds a ready GraphQL engine. mongoDB is
// the FerretDB database backing "dynamodb" data sources; pass nil when only "memory" sources are used
// (dev/demo/tests) — a "dynamodb" source then errors loudly rather than silently degrading.
func Load(dir string, mongoDB *mongo.Database, opts ...graphql.Option) (*graphql.Engine, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("open-appsync: read config.json: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("open-appsync: parse config.json: %w", err)
	}

	stores := map[string]datasource.Store{}
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
		case "http":
			if ds.Endpoint == "" {
				return nil, fmt.Errorf("open-appsync: data source %q (http) needs an endpoint", ds.Name)
			}
			stores[ds.Name] = httpsource.New(ds.Endpoint)
		case "lambda":
			if ds.Endpoint == "" {
				return nil, fmt.Errorf("open-appsync: data source %q (lambda) needs an endpoint (the function URL)", ds.Name)
			}
			stores[ds.Name] = lambdasource.New(ds.Endpoint)
		default:
			return nil, fmt.Errorf("open-appsync: data source %q has unknown type %q (memory | dynamodb | http | lambda)", ds.Name, ds.Type)
		}
	}

	// One VTL engine, shared by every appsync-vtl runtime (it is stateless apart from its $util
	// providers). A future runtime value builds its own runtime here.
	engine := vtl.New()

	registry := map[string]resolver.Resolver{}
	for _, rc := range cfg.Resolvers {
		res, err := buildResolver(dir, engine, stores, rc)
		if err != nil {
			return nil, fmt.Errorf("open-appsync: resolver %s.%s: %w", rc.Type, rc.Field, err)
		}
		registry[rc.Type+"."+rc.Field] = res
	}

	// The optional SDL schema (a schema.graphql sibling file, kept out of config.json to avoid JSON
	// escaping — same reason the .vtl templates are files). When present, it powers __schema/__type
	// introspection; when absent, the engine still serves resolvers and introspection reports
	// unavailable. Fail closed on malformed SDL — the API never serves a half-parsed type graph.
	engineOpts := []graphql.Option{graphql.WithLimits(buildLimits(cfg.Limits))}
	sdl, err := readSchemaSDL(dir)
	if err != nil {
		return nil, err
	}
	if sdl != "" {
		schema, err := graphql.ParseSchema(sdl)
		if err != nil {
			return nil, fmt.Errorf("open-appsync: parse schema.graphql: %w", err)
		}
		// Register AppSync's custom-scalar validators at the edge (the engine core stays vendor-neutral).
		// Only scalars the schema declares are ever consulted; these are best-effort FORMAT checks, not
		// AWS-byte-exact fidelity (see internal/awsscalars for the two clocks).
		engineOpts = append(engineOpts, graphql.WithSchema(schema), graphql.WithScalarValidators(awsscalars.Validators()))
		// LOUDLY label AppSync auth directives as declared-but-not-enforced (advisory). They parse and are
		// reported in introspection, but open-appsync does not enforce them yet — access control is via
		// resolver SAR auth. Enforcement is being added per-mode (api-key → iam → cognito/oidc → lambda).
		if declared := schema.DeclaredAuthDirectives(); len(declared) > 0 {
			log.Printf("open-appsync: WARNING: schema declares AppSync auth directives %v that are NOT ENFORCED (advisory only) — field access is governed by resolver SAR auth, not these directives", declared)
		}
	}

	// Limits first (so an explicit WithLimits in opts could override), then caller options (the SAR
	// authorizer wired by main).
	engineOpts = append(engineOpts, opts...)
	return graphql.New(registry, engineOpts...), nil
}

// dedupe returns the input with duplicate strings removed, preserving first-seen order.
func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// readSchemaSDL reads the optional schema.graphql from the config dir, returning "" when there is none.
func readSchemaSDL(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "schema.graphql"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("open-appsync: read schema.graphql: %w", err)
	}
	return string(b), nil
}

// LoadSubscriptions reads the config's subscription section and builds a subscription Manager (over the
// given bus) plus the graphql.Publisher that publishes a mutation's result to the subscriptions it
// triggers. Returns (nil, nil, nil) when no subscriptions are declared. main wires the returned
// publisher into the engine (graphql.WithPublisher) and serves the Manager over WebSocket.
func LoadSubscriptions(dir string, bus subscription.Bus, authorizer authz.Authorizer) (*subscription.Manager, graphql.Publisher, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("open-appsync: read config.json: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, nil, fmt.Errorf("open-appsync: parse config.json: %w", err)
	}
	if len(cfg.Subscriptions) == 0 {
		return nil, nil, nil
	}

	// SDL-native triggers: @aws_subscribe(mutations:) on the schema's Subscription fields, merged with
	// the config's triggeredBy (AppSync parity — an imported schema's triggers work without duplication).
	schemaTriggers := map[string][]string{} // subscription field → mutations
	if sdl, err := readSchemaSDL(dir); err != nil {
		return nil, nil, err
	} else if sdl != "" {
		schema, err := graphql.ParseSchema(sdl)
		if err != nil {
			return nil, nil, fmt.Errorf("open-appsync: parse schema.graphql: %w", err)
		}
		for mut, subs := range schema.SubscriptionTriggers() {
			for _, sub := range subs {
				schemaTriggers[sub] = append(schemaTriggers[sub], mut)
			}
		}
	}

	engine := vtl.New()
	var fields []subscription.Field
	trigger := map[string][]string{} // mutation field → subscription fields
	for _, sc := range cfg.Subscriptions {
		subject := sc.Subject
		if subject == "" {
			subject = "sub." + sc.Field
		}
		// A subscription is a single response step (no request phase / data source).
		rt, err := loadStep(dir, engine, sc.Runtime, "", sc.Response)
		if err != nil {
			return nil, nil, fmt.Errorf("open-appsync: subscription %s: %w", sc.Field, err)
		}
		fields = append(fields, subscription.Field{Name: sc.Field, Subject: subject, Response: rt, Auth: sc.Auth})
		// Config triggeredBy plus any @aws_subscribe-declared mutations for this field (deduped).
		for _, mut := range dedupe(append(append([]string{}, sc.TriggeredBy...), schemaTriggers[sc.Field]...)) {
			trigger[mut] = append(trigger[mut], sc.Field)
		}
	}
	mgr := subscription.NewManager(bus, authorizer, fields)
	return mgr, &subPublisher{mgr: mgr, trigger: trigger}, nil
}

// subPublisher adapts a mutation's success into subscription publishes: for each subscription the
// mutation triggers, it puts the mutation's result onto that subscription's subject.
type subPublisher struct {
	mgr     *subscription.Manager
	trigger map[string][]string
}

func (p *subPublisher) PublishForMutation(ctx context.Context, mutationField string, result any) {
	subs := p.trigger[mutationField]
	if len(subs) == 0 {
		return
	}
	event, ok := result.(map[string]any)
	if !ok {
		event = map[string]any{"result": result}
	}
	for _, sf := range subs {
		_ = p.mgr.Publish(ctx, sf, event)
	}
}

// buildLimits turns the declarative limits into engine guards, safe by default: a nil block, or a
// zero/unset numeric limit, keeps the protective default; a NEGATIVE value opts out of that guard.
func buildLimits(lc *LimitsConfig) graphql.Limits {
	limits := graphql.DefaultLimits()
	if lc == nil {
		return limits
	}
	limits.MaxDepth = safeLimit(lc.MaxDepth, limits.MaxDepth)
	limits.MaxCost = safeLimit(lc.MaxCost, limits.MaxCost)
	limits.PersistedOnly = lc.PersistedOnly
	limits.Introspection = lc.Introspection
	if len(lc.PersistedQueries) > 0 {
		limits.Persisted = map[string]bool{}
		for _, q := range lc.PersistedQueries {
			sum := sha256.Sum256([]byte(q))
			limits.Persisted[hex.EncodeToString(sum[:])] = true
		}
	}
	return limits
}

// safeLimit keeps the protective default when a limit is unset (0), applies a positive override, and
// treats a negative value as an explicit opt-out (unlimited).
func safeLimit(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	default:
		return v
	}
}

// buildResolver assembles one field's lifecycle from its config: a pipeline when Functions is set,
// otherwise a unit resolver. Every template is validated (fail closed): one malformed template makes
// the whole Load fail, so the engine never serves a half-broken API.
func buildResolver(dir string, engine *vtl.Engine, stores map[string]datasource.Store, rc ResolverConfig) (resolver.Resolver, error) {
	if len(rc.Functions) == 0 {
		src, ok := stores[rc.DataSource]
		if !ok {
			return resolver.Resolver{}, fmt.Errorf("references unknown data source %q", rc.DataSource)
		}
		rt, err := loadStep(dir, engine, rc.Runtime, rc.Request, rc.Response)
		if err != nil {
			return resolver.Resolver{}, err
		}
		return resolver.Resolver{Runtime: rt, Source: src, Auth: rc.Auth}, nil
	}

	// Pipeline lifecycle.
	p := &resolver.Pipeline{}
	if rc.Before != "" {
		// before is a single-template step: its request phase runs (stash/abort), no response phase.
		rt, err := loadStep(dir, engine, rc.Runtime, rc.Before, "")
		if err != nil {
			return resolver.Resolver{}, fmt.Errorf("before: %w", err)
		}
		p.Before = rt
	}
	for i, fc := range rc.Functions {
		src, ok := stores[fc.DataSource]
		if !ok {
			return resolver.Resolver{}, fmt.Errorf("function %d references unknown data source %q", i, fc.DataSource)
		}
		rt, err := loadStep(dir, engine, fc.Runtime, fc.Request, fc.Response)
		if err != nil {
			return resolver.Resolver{}, fmt.Errorf("function %d: %w", i, err)
		}
		p.Functions = append(p.Functions, resolver.Function{Runtime: rt, Source: src})
	}
	if rc.After != "" {
		// after is a single-template step: its response phase shapes the final value, no request phase.
		rt, err := loadStep(dir, engine, rc.Runtime, "", rc.After)
		if err != nil {
			return resolver.Resolver{}, fmt.Errorf("after: %w", err)
		}
		p.After = rt
	}
	return resolver.Resolver{Pipeline: p, Auth: rc.Auth}, nil
}

// loadStep reads a step's request/response template files (an empty filename means an empty, unused
// template phase), builds its runtime, and validates it (fail closed on a malformed template).
func loadStep(dir string, engine *vtl.Engine, runtimeName, reqFile, respFile string) (runtime.Runtime, error) {
	req, err := readTemplate(dir, reqFile)
	if err != nil {
		return nil, fmt.Errorf("read request template: %w", err)
	}
	resp, err := readTemplate(dir, respFile)
	if err != nil {
		return nil, fmt.Errorf("read response template: %w", err)
	}
	rt, err := buildRuntime(runtimeName, engine, req, resp)
	if err != nil {
		return nil, err
	}
	if v, ok := rt.(runtime.Validator); ok {
		if err := v.Validate(); err != nil {
			return nil, fmt.Errorf("invalid, refusing to serve: %w", err)
		}
	}
	return rt, nil
}

// readTemplate reads a template file, or returns "" for an empty filename (an unused phase of a
// single-template pipeline step).
func readTemplate(dir, file string) (string, error) {
	if file == "" {
		return "", nil
	}
	b, err := os.ReadFile(filepath.Join(dir, file))
	return string(b), err
}

// buildRuntime selects the runtime for a resolver by its declared `runtime` value (the extension
// point). Empty defaults to appsync-vtl; an unknown value is rejected (fail closed) rather than
// silently substituted.
func buildRuntime(name string, engine *vtl.Engine, request, response string) (runtime.Runtime, error) {
	switch name {
	case "", runtimeAppsyncVTL:
		return vtlruntime.New(engine, request, response), nil
	case runtimeAppsyncJS:
		// A JS resolver is one module (defining request(ctx)/response(ctx)) carried in the request
		// field; the response field is unused. It shares the engine's $util providers.
		return jsruntime.New(engine.Util(), request)
	default:
		return nil, fmt.Errorf("unknown runtime %q (available: %q, %q)", name, runtimeAppsyncVTL, runtimeAppsyncJS)
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
			Query         string         `json:"query"`
			OperationName string         `json:"operationName"`
			Variables     map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, graphql.Result{
				Errors: []graphql.GqlError{{Message: "invalid GraphQL request body"}}})
			return
		}
		// The caller's identity is established UPSTREAM (the aws-shim's SigV4→principal) and conveyed as
		// headers; carry it through the context for field-level authz. The engine never trusts a
		// client to assert these directly — in production only the shim, an internal peer, sets them.
		ctx := authz.NewContext(r.Context(), identityFromHeaders(r))
		writeJSON(w, http.StatusOK, e.ExecuteOp(ctx, body.Query, body.OperationName, body.Variables))
	}
}

// identityFromHeaders reads the caller's principal from the shim-set headers: X-OpenInfra-User and a
// comma-separated X-OpenInfra-Groups.
func identityFromHeaders(r *http.Request) authz.Identity {
	id := authz.Identity{Username: r.Header.Get("X-OpenInfra-User")}
	if g := r.Header.Get("X-OpenInfra-Groups"); g != "" {
		for _, part := range strings.Split(g, ",") {
			if s := strings.TrimSpace(part); s != "" {
				id.Groups = append(id.Groups, s)
			}
		}
	}
	return id
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
// sample result was supplied, the response value. A resolver-thrown error (e.g. $util.error) is
// reported with its errorType — the difference between authoring with feedback and authoring blind.
type TestResolverResponse struct {
	RequestOp any    `json:"requestOp,omitempty"` // the neutral data-source operation the request phase emits
	Response  any    `json:"response,omitempty"`  // the response value (only when `result` was supplied)
	Error     string `json:"error,omitempty"`
	ErrorType string `json:"errorType,omitempty"`
}

// TestResolverHandler exposes the probe harness on user input: POST a resolver + a sample
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
