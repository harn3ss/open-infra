package graphql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

// Limits are the hostile-load guards. GraphQL's cost asymmetry — the client composes
// demand, the server owns cost — makes an unguarded endpoint a denial-of-service risk, which matters
// MOST for the least-resourced operator this project is built for. So these are GraphQL properties
// (not AppSync ones) enforced in the neutral engine, with defaults that protect an operator who set
// nothing (DefaultLimits). 0 disables a numeric limit — that is opt-OUT, and is never the default.
type Limits struct {
	MaxDepth      int             // reject queries whose selection nesting exceeds this (0 = unlimited)
	MaxCost       int             // reject queries with more than this many fields (0 = unlimited)
	PersistedOnly bool            // when true, only pre-registered query documents run
	Persisted     map[string]bool // allow-list of sha256(query) hex digests, for PersistedOnly mode

	// Introspection gates who may read the schema via __schema/__type. Introspection-on lets any client
	// discover the whole API — great for tooling, a recon aid for an untrusted one — so it is a toggle,
	// not always-open. "" / IntrospectionEnabled: allowed (AWS AppSync's default; best dev ergonomics).
	// IntrospectionDisabled: never. IntrospectionAuthenticated: only a non-anonymous caller (off for
	// untrusted). __typename is unaffected — it names a type, it does not dump the schema.
	Introspection string
}

// Introspection toggle values for Limits.Introspection.
const (
	IntrospectionEnabled       = "enabled"            // default
	IntrospectionDisabled      = "disabled"           // never answer __schema/__type
	IntrospectionAuthenticated = "authenticated-only" // answer only for a non-anonymous caller
)

// DefaultLimits protects an unconfigured operator: bounded depth and cost, arbitrary queries allowed.
func DefaultLimits() Limits { return Limits{MaxDepth: 10, MaxCost: 1000} }

// Publisher is notified after a mutation field resolves successfully, so a subscription layer can push
// the result to matching subscribers. It is optional (default: none); the executor stays subscription-
// unaware beyond this one hook, keeping the coupling minimal.
type Publisher interface {
	PublishForMutation(ctx context.Context, mutationField string, result any)
}

// ParseSubscription parses a `subscription { field(args) {... } }` operation and returns the root
// field name and its evaluated arguments (resolving $variables) — what the WebSocket handler needs to
// register a subscriber. It rejects a non-subscription operation.
func ParseSubscription(query string, variables map[string]any) (field string, args map[string]any, err error) {
	op, err := parseQuery(query)
	if err != nil {
		return "", nil, err
	}
	if op.opType != "subscription" {
		return "", nil, errors.New("graphql: not a subscription operation")
	}
	// Expand fragments so a subscription authored with a spread still resolves to its single field.
	selections, err := flattenSelections(op.selections, op.fragments, nil, variables, map[string]bool{})
	if err != nil {
		return "", nil, err
	}
	if len(selections) != 1 {
		return "", nil, errors.New("graphql: a subscription must select exactly one field")
	}
	sel := selections[0]
	return sel.name, evalArgs(sel.args, variables), nil
}

// Engine executes GraphQL operations against a set of resolvers. Resolvers are keyed by
// "<RootType>.<field>", e.g. "Query.getTodo" / "Mutation.createTodo" (schema intake /: the
// mapping of a field to the resolver that backs it). Each resolver carries its own runtime, so the
// executor holds no VTL (or any other runtime) knowledge — it dispatches fields and projects
// selection sets. It enforces Limits before running any resolver.
type Engine struct {
	resolvers  map[string]resolver.Resolver
	limits     Limits
	authorizer authz.Authorizer
	publisher  Publisher
	schema     *Schema                    // parsed SDL type graph; nil = introspection unavailable (no schema supplied)
	validators map[string]ScalarValidator // custom-scalar validators by scalar name (neutral seam; edge-registered)
}

// WithPublisher sets the mutation publisher (default: none) — the hook the subscription layer uses.
func WithPublisher(p Publisher) Option { return func(e *Engine) { e.publisher = p } }

// WithSchema attaches the parsed SDL type graph so the engine can answer __schema/__type introspection.
// Without it, introspection fields return an error (the executor still runs resolvers normally — the
// type graph is a reader for introspection, not a precondition for execution in this slice).
func WithSchema(s *Schema) Option { return func(e *Engine) { e.schema = s } }

// WithScalarValidators registers custom-scalar validators by scalar name (the neutral validation seam).
// The core stays vendor-neutral; AWS scalar rules are registered here by the edge (see internal/awsscalars).
func WithScalarValidators(v map[string]ScalarValidator) Option {
	return func(e *Engine) { e.validators = v }
}

// Option configures an Engine (hostile-load guards, the field authorizer, …).
type Option func(*Engine)

// WithLimits sets the hostile-load guards (default: DefaultLimits).
func WithLimits(l Limits) Option { return func(e *Engine) { e.limits = l } }

// WithAuthorizer sets the field-level authorizer (default: authz.AllowAll — no enforcement).
func WithAuthorizer(a authz.Authorizer) Option { return func(e *Engine) { e.authorizer = a } }

// New builds an engine: safe-by-default limits and no field-auth enforcement (AllowAll) unless
// options say otherwise. The variadic options keep New(resolvers) valid.
func New(resolvers map[string]resolver.Resolver, opts ...Option) *Engine {
	e := &Engine{resolvers: resolvers, limits: DefaultLimits(), authorizer: authz.AllowAll{}}
	for _, o := range opts {
		o(e)
	}
	return e
}

// NewWithLimits builds an engine with explicit hostile-load guards (kept for existing callers).
func NewWithLimits(resolvers map[string]resolver.Resolver, limits Limits) *Engine {
	return New(resolvers, WithLimits(limits))
}

// GqlError is a GraphQL error entry, carrying AppSync's errorType where the resolver threw one.
type GqlError struct {
	Message   string `json:"message"`
	Path      []any  `json:"path,omitempty"`
	ErrorType string `json:"errorType,omitempty"`
}

// Result is a GraphQL response: {data, errors}.
type Result struct {
	Data   map[string]any `json:"data,omitempty"`
	Errors []GqlError     `json:"errors,omitempty"`
}

// Execute parses and runs an operation, returning the GraphQL {data, errors} response. Each
// top-level field runs its resolver (request→execute→response); a resolver error becomes a GraphQL
// error with that field's path and its data set to null, exactly as AppSync surfaces it.
func (e *Engine) Execute(ctx context.Context, query string, variables map[string]any) Result {
	return e.ExecuteOp(ctx, query, "", variables)
}

// ExecuteOp is Execute with an explicit operationName, needed when the document carries more than one
// operation (the GraphQL-over-HTTP `operationName`). An empty name selects the sole operation.
func (e *Engine) ExecuteOp(ctx context.Context, query, operationName string, variables map[string]any) Result {
	doc, err := parseDocument(query)
	if err != nil {
		return Result{Errors: []GqlError{{Message: err.Error()}}}
	}
	op, err := doc.selectOperation(operationName)
	if err != nil {
		return Result{Errors: []GqlError{{Message: err.Error(), ErrorType: "ValidationError"}}}
	}
	// Coerce the supplied variables against their declared types (defaults applied, required checked,
	// mismatches rejected) before they are substituted into arguments OR read by @skip/@include. The
	// coerced map replaces the raw.
	coerced, ge := (coercer{schema: e.schema, validators: e.validators}).variables(op.varDefs, variables)
	if ge != nil {
		return Result{Errors: []GqlError{*ge}}
	}
	variables = coerced
	// Validate fragments (unknown / cycle), apply @skip/@include, and bound the query: flattenSelections
	// expands every fragment unconditionally, which is a safe UPPER bound for the depth/cost guards and
	// catches malformed documents before anything runs. (Type-conditional collection for actual execution
	// happens per object in collectFields — see below.)
	flat, err := flattenSelections(op.selections, op.fragments, e.schema, variables, map[string]bool{})
	if err != nil {
		return Result{Errors: []GqlError{{Message: err.Error(), ErrorType: "ValidationError"}}}
	}
	if ge := e.checkLimits(query, flat); ge != nil {
		return Result{Errors: []GqlError{*ge}}
	}
	rootType := "Query"
	if op.opType == "mutation" {
		rootType = "Mutation"
	}

	// Collect the root fields for the root type, applying fragment type conditions + directives. The root
	// type is concrete, so all its type conditions apply, but this is the same collectFields the nested
	// levels use — one execution model.
	ec := &execCtx{ctx: ctx, vars: variables, frags: op.fragments}
	selections, err := e.collectFields(op.selections, rootType, ec, map[string]bool{})
	if err != nil {
		return Result{Errors: []GqlError{{Message: err.Error(), ErrorType: "ValidationError"}}}
	}

	data := map[string]any{}
	var errs []GqlError
	for _, sel := range selections {
		respKey := sel.name
		if sel.alias != "" {
			respKey = sel.alias
		}
		if sel.name == "__typename" { // GraphQL meta-field: the root type's name
			data[respKey] = rootType
			continue
		}
		// Introspection meta-fields (Query only). They read the schema graph; the toggle decides who may.
		if rootType == "Query" && (sel.name == "__schema" || sel.name == "__type") {
			val, ge := e.introspect(ctx, sel, variables)
			if ge != nil {
				errs = append(errs, GqlError{Message: ge.Message, Path: []any{respKey}, ErrorType: ge.ErrorType})
				data[respKey] = nil
				continue
			}
			// Project the introspection result through the fragment-aware path with an unknown type, so
			// the wire introspection query's fragments (on __Type / __InputValue) expand (leniently — the
			// meta-objects aren't in the user type graph) and no per-field resolvers fire.
			pv, verrs := e.projectValue(ec, val, sel.selections, "", []any{respKey})
			data[respKey] = pv
			errs = append(errs, verrs...)
			continue
		}
		key := rootType + "." + sel.name
		r, ok := e.resolvers[key]
		if !ok {
			errs = append(errs, GqlError{Message: "no resolver for field " + key, Path: []any{respKey}})
			data[respKey] = nil
			continue
		}
		// AppSync auth-mode gate (@aws_api_key, …): enforce the field's declared mode before running.
		if ge := e.checkFieldAuth(ctx, rootType, sel.name); ge != nil {
			errs = append(errs, GqlError{Message: ge.Message, Path: []any{respKey}, ErrorType: ge.ErrorType})
			data[respKey] = nil
			continue
		}
		// Field-level authorization: consult the shared boundary BEFORE running the resolver. A
		// denial surfaces as Unauthorized with the field null, and the resolver — and its data source —
		// never runs. This is the lifecycle's job; the runtime step stays auth-unaware.
		id := authz.FromContext(ctx)
		if !r.Auth.IsZero() {
			if err := e.authorizer.Authorize(ctx, id, r.Auth); err != nil {
				errs = append(errs, GqlError{Message: err.Error(), Path: []any{respKey}, ErrorType: "Unauthorized"})
				data[respKey] = nil
				continue
			}
		}
		gctx := map[string]any{"args": evalArgs(sel.args, variables), "identity": identityMap(id)}
		res, rerr := r.Resolve(ctx, gctx)
		if rerr != nil {
			ge := GqlError{Message: rerr.Error(), Path: []any{respKey}}
			var te *vtl.ThrowError
			if errors.As(rerr, &te) {
				ge.Message = te.Message
				ge.ErrorType = te.ErrorType
			}
			errs = append(errs, ge)
			data[respKey] = nil
			continue
		}
		val, nerrs := e.projectValue(ec, res, sel.selections, namedFieldType(e.schema, rootType, sel.name), []any{respKey})
		data[respKey] = val
		errs = append(errs, nerrs...)
		// A successful mutation may trigger subscriptions: hand the unprojected result to the publisher,
		// which fans it to matching subscribers. The executor stays otherwise subscription-unaware.
		if rootType == "Mutation" && e.publisher != nil {
			e.publisher.PublishForMutation(ctx, sel.name, res)
		}
	}
	return Result{Data: data, Errors: errs}
}

// enforcedAuthModes are the AppSync auth modes open-appsync actually enforces. Modes graduated into this
// set one at a time (api-key → iam → cognito/oidc → lambda) — see the auth-directive decision. With
// aws_lambda now enforced, all five AWS auth modes gate fields; the aws-shim validates each mode and
// forwards the mapped identity, and the field's SAR check decides (one policy world).
var enforcedAuthModes = map[string]bool{
	authz.ModeAPIKey:  true,
	authz.ModeIAM:     true,
	authz.ModeOIDC:    true,
	authz.ModeCognito: true,
	authz.ModeLambda:  true,
}

// checkFieldAuth enforces a field's auth rules (the neutral form of its `@aws_*` directives). It fires
// ONLY when EVERY rule's mode is one we enforce, so a field that also lists a not-yet-enforced mode stays
// advisory and is never over-denied. When it fires, the request must satisfy at least ONE rule: its
// authenticated mode matches the rule's mode AND — if the rule carries requiredGroups — the caller
// belongs to one of them. The group check is FAIL-CLOSED: a caller with missing/empty groups cannot
// satisfy a group-restricted rule. The mapped identity then flows into the normal SAR check
// (resolver.Auth), keeping authorization in the one policy world.
func (e *Engine) checkFieldAuth(ctx context.Context, parentType, fieldName string) *GqlError {
	if e.schema == nil {
		return nil
	}
	rules := e.schema.fieldAuthRules(parentType, fieldName)
	if len(rules) == 0 {
		return nil
	}
	for _, r := range rules {
		if !enforcedAuthModes[r.mode] {
			return nil // advisory: a mode we don't enforce yet is present — don't gate this field
		}
	}
	reqMode := authz.Mode(ctx)
	callerGroups := authz.FromContext(ctx).Groups
	modes := make([]string, 0, len(rules))
	for _, r := range rules {
		modes = append(modes, r.mode)
		if r.mode != reqMode {
			continue
		}
		if len(r.requiredGroups) == 0 {
			return nil // mode matches, no group restriction
		}
		if groupsIntersect(callerGroups, r.requiredGroups) {
			return nil // mode matches AND caller is in a required group
		}
		// mode matches but the group check fails (incl. caller with no groups) → this rule denies;
		// fall through so another rule may still satisfy the request (fail-closed if none does).
	}
	return &GqlError{Message: "this field requires " + strings.Join(modes, " or ") + " authentication", ErrorType: "Unauthorized"}
}

// groupsIntersect reports whether the caller belongs to any of the required groups. An empty caller set
// (missing/unparseable groups) never intersects — the group check is fail-closed.
func groupsIntersect(caller, required []string) bool {
	if len(caller) == 0 || len(required) == 0 {
		return false
	}
	have := make(map[string]bool, len(caller))
	for _, g := range caller {
		have[g] = true
	}
	for _, g := range required {
		if have[g] {
			return true
		}
	}
	return false
}

// introspect answers a __schema or __type meta-field, subject to the introspection toggle. It returns
// the raw introspection value (which the caller projects the selection set onto) or a GraphQL error.
func (e *Engine) introspect(ctx context.Context, sel selection, variables map[string]any) (any, *GqlError) {
	if ge := e.introspectionGate(ctx); ge != nil {
		return nil, ge
	}
	if e.schema == nil {
		return nil, &GqlError{Message: "introspection is unavailable: this API has no schema (SDL) configured", ErrorType: "IntrospectionUnavailable"}
	}
	if sel.name == "__schema" {
		return e.schema.introspectSchema(), nil
	}
	// __type(name: "…")
	nameArg, ok := evalArgs(sel.args, variables)["name"].(string)
	if !ok || nameArg == "" {
		return nil, &GqlError{Message: "__type requires a String `name` argument", ErrorType: "ValidationError"}
	}
	return e.schema.introspectType(nameArg), nil // nil → the field resolves to null, per spec
}

// introspectionGate applies the Limits.Introspection toggle: enabled (default) allows all; disabled
// refuses; authenticated-only refuses an anonymous (untrusted) caller. Returns nil when allowed.
func (e *Engine) introspectionGate(ctx context.Context) *GqlError {
	switch e.limits.Introspection {
	case "", IntrospectionEnabled:
		return nil
	case IntrospectionDisabled:
		return &GqlError{Message: "introspection is disabled on this API", ErrorType: "IntrospectionDisabled"}
	case IntrospectionAuthenticated:
		if authz.FromContext(ctx).Username == "" {
			return &GqlError{Message: "introspection is restricted to authenticated callers", ErrorType: "IntrospectionDisabled"}
		}
		return nil
	default:
		// An unknown mode fails closed (refuse) rather than silently allowing schema disclosure.
		return &GqlError{Message: "introspection is disabled on this API", ErrorType: "IntrospectionDisabled"}
	}
}

// checkLimits enforces the hostile-load guards against a parsed operation, returning a GraphQL error
// (with an errorType naming the guard) if the document is rejected, or nil if it may run.
func (e *Engine) checkLimits(query string, selections []selection) *GqlError {
	if e.limits.PersistedOnly {
		sum := sha256.Sum256([]byte(query))
		if !e.limits.Persisted[hex.EncodeToString(sum[:])] {
			return &GqlError{Message: "only persisted (pre-registered) queries are allowed", ErrorType: "PersistedQueryRequired"}
		}
	}
	if e.limits.MaxDepth > 0 {
		if d := selectionsDepth(selections); d > e.limits.MaxDepth {
			return &GqlError{Message: fmt.Sprintf("query depth %d exceeds the maximum of %d", d, e.limits.MaxDepth), ErrorType: "MaxDepthExceeded"}
		}
	}
	if e.limits.MaxCost > 0 {
		if c := selectionsCost(selections); c > e.limits.MaxCost {
			return &GqlError{Message: fmt.Sprintf("query cost %d exceeds the maximum of %d", c, e.limits.MaxCost), ErrorType: "MaxCostExceeded"}
		}
	}
	return nil
}

// selectionsDepth is the deepest selection-set nesting (top-level fields are depth 1). Introspection
// meta-fields (__schema/__type/__typename) are excluded: their subtree is server-shaped (the ofType
// chain a tool writes just walks wrappers, bounded by the schema), not client-composed load — and the
// standard introspection query nests ~7 deep, which would otherwise trip the default guard.
func selectionsDepth(sels []selection) int {
	max := 0
	for _, s := range sels {
		if strings.HasPrefix(s.name, "__") {
			continue
		}
		d := 1
		if len(s.selections) > 0 {
			d += selectionsDepth(s.selections)
		}
		if d > max {
			max = d
		}
	}
	return max
}

// selectionsCost is the total number of fields in the query (a simple, honest cost proxy). Introspection
// meta-fields are excluded for the same reason as depth: their cost is bounded by schema size.
func selectionsCost(sels []selection) int {
	n := 0
	for _, s := range sels {
		if strings.HasPrefix(s.name, "__") {
			continue
		}
		n += 1 + selectionsCost(s.selections)
	}
	return n
}

// identityMap exposes the caller as $ctx.identity for mapping templates (username + groups), mirroring
// AppSync's $ctx.identity. Empty for an anonymous caller.
func identityMap(id authz.Identity) map[string]any {
	groups := make([]any, len(id.Groups))
	for i, g := range id.Groups {
		groups[i] = g
	}
	return map[string]any{"username": id.Username, "groups": groups}
}

// evalArgs turns parsed argument values into plain Go values, resolving $variables.
func evalArgs(args map[string]valueNode, vars map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range args {
		out[k] = evalValue(v, vars)
	}
	return out
}

func evalValue(v valueNode, vars map[string]any) any {
	switch v.kind {
	case "scalar":
		return v.val
	case "enum":
		return v.val // the enum value's name, as a string
	case "var":
		return vars[v.val.(string)]
	case "list":
		src := v.val.([]valueNode)
		out := make([]any, len(src))
		for i, e := range src {
			out[i] = evalValue(e, vars)
		}
		return out
	case "object":
		src := v.val.(map[string]valueNode)
		out := map[string]any{}
		for k, e := range src {
			out[k] = evalValue(e, vars)
		}
		return out
	}
	return nil
}

// execCtx carries the per-request state threaded through nested resolution: the caller context, the
// coerced variables (for args + directives), and the document's fragments (for per-object collection).
type execCtx struct {
	ctx   context.Context
	vars  map[string]any
	frags map[string]fragmentDef
}

// collectFields is the GraphQL CollectFields for one object: it expands the selection set's fragment
// spreads and inline fragments into a flat field list, including a fragment ONLY when its type condition
// applies to concreteType (polymorphic dispatch for interfaces/unions) and its @skip/@include allow it.
// It does NOT recurse into a field's own sub-selections — those are collected when that field's value is
// resolved, against that value's concrete type.
func (e *Engine) collectFields(sels []selection, concreteType string, ec *execCtx, open map[string]bool) ([]selection, error) {
	var out []selection
	for _, sel := range sels {
		skip, err := shouldSkip(sel.directives, ec.vars)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		switch {
		case sel.fragmentSpread != "":
			frag, ok := ec.frags[sel.fragmentSpread]
			if !ok {
				return nil, fmt.Errorf("graphql: unknown fragment %q", sel.fragmentSpread)
			}
			if open[sel.fragmentSpread] {
				return nil, fmt.Errorf("graphql: fragment cycle detected at %q", sel.fragmentSpread)
			}
			if !e.typeConditionApplies(frag.typeCondition, concreteType) {
				continue
			}
			open[sel.fragmentSpread] = true
			sub, err := e.collectFields(frag.selections, concreteType, ec, open)
			delete(open, sel.fragmentSpread)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		case sel.inline:
			if !e.typeConditionApplies(sel.typeCondition, concreteType) {
				continue
			}
			sub, err := e.collectFields(sel.selections, concreteType, ec, open)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		default:
			out = append(out, sel)
		}
	}
	return out, nil
}

// typeConditionApplies reports whether a fragment's `on Type` condition applies to an object of
// concreteType: no condition applies to all; an exact match applies; an object type applies to any
// interface it implements or any union it belongs to. When the concrete type is unknown ("" — an
// abstract field whose resolver gave no __typename hint, or no schema) it is lenient (applies), so
// fields are not silently dropped.
func (e *Engine) typeConditionApplies(cond, concreteType string) bool {
	if cond == "" || cond == concreteType || concreteType == "" {
		return true
	}
	if e.schema == nil {
		return true
	}
	if nt := e.schema.types[concreteType]; nt != nil {
		for _, iface := range nt.interfaces {
			if iface == cond {
				return true
			}
		}
	}
	if ct := e.schema.types[cond]; ct != nil && ct.kind == kindUnion {
		for _, member := range ct.possibleTypes {
			if member == concreteType {
				return true
			}
		}
	}
	return false
}

// concreteTypeOf determines an object's concrete type for polymorphic dispatch: a `__typename` string in
// the value wins (the convention a resolver uses for an interface/union field), else the field's declared
// type when it is concrete; an abstract declared type with no hint yields "" (unknown → lenient).
func (e *Engine) concreteTypeOf(value map[string]any, declaredType string) string {
	if tn, ok := value["__typename"].(string); ok && tn != "" {
		return tn
	}
	if e.schema != nil {
		if nt := e.schema.types[declaredType]; nt != nil && (nt.kind == kindInterface || nt.kind == kindUnion) {
			return "" // abstract, no hint
		}
	}
	return declaredType
}

// projectValue projects a resolved value against a selection set, running per-field resolvers for any
// nested field that has one registered. It is the resolver-aware counterpart of the introspection
// project(). An empty selection set returns the value as a leaf; a list projects element-wise (each
// element resolving its own concrete type). declaredType is the field's type from the graph.
func (e *Engine) projectValue(ec *execCtx, val any, sels []selection, declaredType string, path []any) (any, []GqlError) {
	if len(sels) == 0 {
		return val, nil
	}
	switch v := val.(type) {
	case map[string]any:
		return e.resolveObject(ec, e.concreteTypeOf(v, declaredType), v, sels, path)
	case []any:
		out := make([]any, len(v))
		var errs []GqlError
		for i, elem := range v {
			ev, eerrs := e.projectValue(ec, elem, sels, declaredType, append(append([]any{}, path...), i))
			out[i] = ev
			errs = append(errs, eerrs...)
		}
		return out, errs
	default:
		return val, nil // scalar (selection set on a scalar is ignored)
	}
}

// resolveObject resolves each selected field on an object of concreteType. It first collects the fields
// that apply to this object (fragment type conditions + directives). A field with a registered resolver
// "<concreteType>.<field>" runs it (with $ctx.source = this object) — the per-nested-field resolver —
// then projects the result against the field's sub-selections. A field without a resolver is read
// structurally from the object. __typename resolves to concreteType; field auth is enforced as at root.
func (e *Engine) resolveObject(ec *execCtx, concreteType string, source map[string]any, sels []selection, path []any) (map[string]any, []GqlError) {
	fields, err := e.collectFields(sels, concreteType, ec, map[string]bool{})
	if err != nil {
		return nil, []GqlError{{Message: err.Error(), Path: path, ErrorType: "ValidationError"}}
	}
	out := map[string]any{}
	var errs []GqlError
	for _, sel := range fields {
		respKey := sel.name
		if sel.alias != "" {
			respKey = sel.alias
		}
		if sel.name == "__typename" {
			if concreteType != "" {
				out[respKey] = concreteType
			} else {
				out[respKey] = nil
			}
			continue
		}
		childPath := append(append([]any{}, path...), respKey)
		fieldType := namedFieldType(e.schema, concreteType, sel.name)

		// AppSync auth-mode/group gate — enforced for EVERY selected field regardless of whether it has
		// its own resolver. A sensitive scalar (e.g. `secret: String @aws_iam`) is usually resolverless,
		// read structurally from the parent result; its directive must still gate it, or it would be
		// silently public. So the gate runs BEFORE the resolver-vs-structural branch below.
		if ge := e.checkFieldAuth(ec.ctx, concreteType, sel.name); ge != nil {
			errs = append(errs, GqlError{Message: ge.Message, Path: childPath, ErrorType: ge.ErrorType})
			out[respKey] = nil
			continue
		}

		r, ok := e.resolvers[concreteType+"."+sel.name]
		if !ok || concreteType == "" {
			// No per-field resolver: project the value the parent resolver already produced.
			v, verrs := e.projectValue(ec, source[sel.name], sel.selections, fieldType, childPath)
			out[respKey] = v
			errs = append(errs, verrs...)
			continue
		}

		// Per-nested-field resolver. Field-level SAR auth is enforced before it runs, as at the root.
		id := authz.FromContext(ec.ctx)
		if !r.Auth.IsZero() {
			if err := e.authorizer.Authorize(ec.ctx, id, r.Auth); err != nil {
				errs = append(errs, GqlError{Message: err.Error(), Path: childPath, ErrorType: "Unauthorized"})
				out[respKey] = nil
				continue
			}
		}
		rctx := map[string]any{"args": evalArgs(sel.args, ec.vars), "identity": identityMap(id), "source": source}
		res, rerr := r.Resolve(ec.ctx, rctx)
		if rerr != nil {
			ge := GqlError{Message: rerr.Error(), Path: childPath}
			var te *vtl.ThrowError
			if errors.As(rerr, &te) {
				ge.Message = te.Message
				ge.ErrorType = te.ErrorType
			}
			errs = append(errs, ge)
			out[respKey] = nil
			continue
		}
		v, verrs := e.projectValue(ec, res, sel.selections, fieldType, childPath)
		out[respKey] = v
		errs = append(errs, verrs...)
	}
	return out, errs
}

// namedFieldType returns the named type of typeName's field's return type (unwrapping LIST/NON_NULL), or
// "" when the schema, type, or field is unknown.
func namedFieldType(schema *Schema, typeName, field string) string {
	if schema == nil || typeName == "" {
		return ""
	}
	nt := schema.types[typeName]
	if nt == nil {
		return ""
	}
	for _, f := range nt.fields {
		if f.name == field {
			return namedOf(f.typ)
		}
	}
	return ""
}

// namedOf unwraps LIST/NON_NULL wrappers to the underlying named type's name.
func namedOf(tr typeRef) string {
	for tr.kind != "" {
		tr = *tr.elem
	}
	return tr.name
}
