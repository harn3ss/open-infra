# open-appsync

open-infra's **resolver-first, VTL-faithful** AWS AppSync engine. Its reason to exist: give teams
locked into AWS AppSync — the ones with **resolver specialists**, VTL templates, and data-source
wiring — an open, self-hostable door off of it. For that audience, GraphQL wire-compatibility is not
enough; the value is running their *existing resolver investment* unmodified.

It is **not** a GraphQL-over-tables engine wearing an AppSync mask — that would be a leaky
abstraction the moment a specialist writes a resolver the underlying engine can't model. It is a
reimplementation of the AppSync resolver contract, built on a **graduation ladder**: the narrowest
genuinely-useful, provably-faithful slice first; widen only after a probe proves it.

## Decisions (pinned)

- **In-repo, server-side.** A Go module here (like `apply-sink`), not a separate repo — it runs
  *inside* the platform and stays in the mono-repo's probe/CI discipline. The aws-shim's `appsync`
  service fronts it (SigV4 → coarse IAM gate → forward), so identity stays "one policy world."
- **Purpose-built in Go**, not Apollo (Node). The whole platform is Go; Apollo wouldn't help with
  the VTL request/response lifecycle — the actual value — which must be built regardless. One stack,
  tight control over the resolver cycle.
- **DynamoDB binding → FerretDB-on-DocumentDB** (the existing open-infra DynamoDB→Mongo parity). The
  binding translates the VTL-emitted DynamoDB operation into the backing store.
- **Probe anchor = AWS's *documented* VTL/`$util` behavior.** A live diff against real AWS AppSync
  needs an AWS account — the very thing this frees teams from — so the ground truth is AWS's
  published resolver-template semantics and worked examples (the same discipline as the SigV4 test
  vectors). A one-time real-AppSync capture from a target team would strengthen it later.

## The runtime interface (the extension point)

A resolver's `runtime` is not a label for AWS's two dialects — it is a **real extension point**
(`internal/runtime`). The contract is exactly three frozen terms so a stranger can implement a runtime
we never wrote, without asking questions:

1. **In** — the resolver `$ctx` (arguments, identity, source; and the data-source result on the
   response phase).
2. **Out** — a **neutral `Operation`**: the data-source document, in a shape the data source
   understands *regardless of which runtime produced it*. Today VTL renders it; a JS runtime must
   render the same.
3. **Error/null** — a runtime returns `(value, error)`; a resolver-thrown error (VTL's `$util.error()`)
   surfaces on the field.

VTL is the first tenant (`internal/vtlruntime`) and it plugs in through this interface **with no
backstage pass** — the resolver lifecycle (`internal/resolver`) drives `runtime.Runtime` and knows
nothing about VTL. This is the thing AWS structurally can't offer. A **second, real, non-VTL tenant** —
a sandboxed JavaScript runtime (`internal/jsruntime`, goja) — now runs through the same front door with
no backstage pass, coexisting with VTL in one registry. Two tenants, not one: **the interface is
treated as stable going forward.** (That is a statement about the *interface* — JS-as-a-runtime itself
is still an experimental rung; don't conflate the two.) Openness earned by two tenants, not declared on
one.

### JavaScript resolvers (`runtime: appsync-js`)

A resolver may declare `runtime: appsync-js` and carry a **real APPSYNC_JS module** — `import { util }
from '@aws-appsync/utils'` + `export function request(ctx)` / `export function response(ctx)`, the exact
shape AWS requires — and it runs here **unmodified** (the engine strips the ES-module framing goja can't
parse and injects `util` as a global). It runs on **goja** (pure-Go ECMAScript): no `require`, no Node
APIs, no fs/net/fetch, no timers — **capability-by-injection, deny-by-absence.** The only capability a
resolver gets is the injected `util` object (backed by the *same* `$util` implementation as VTL, so no
drift). A resolver reaching for ambient capability fails closed (proven by a negative probe). And it is
**behavior-faithful**: `probe/goldens-js/` diffs the same modules against real AWS `evaluate-code`.
Sandboxing untrusted user code matters *most* for the least-resourced operator this project serves.

### Step vs lifecycle

`runtime.Runtime` is the **step** contract, not "the resolver contract." A step transforms `$ctx`
(request phase → an *optional* neutral `Operation`; response phase → a value). A **resolver** is a
*lifecycle* that composes steps (`internal/resolver`):

- **unit** — one step over one data source (slice 1).
- **pipeline** — `before → [function…] → after`, with `$ctx.stash` shared across steps and
  `$ctx.prev.result` threaded from each function to the next. `before`/`after` are steps that emit **no
  Operation** (they only shape `$ctx`); a function is a unit step over its own source.
- **subscription** — a later rung; it inverts to setup-then-push (not built).

This is why the Out term is *optional* (a step may return a nil Operation → the lifecycle skips the
data-source call): it lets pipelines and subscriptions **extend** open-appsync instead of forking it.
The parallel on the data side (`internal/dynamodb`): `Store.Execute` is the **call-source** contract
(DynamoDB/HTTP/Lambda/RDS all fit "call → result"); a subscription's push source is a separate thing,
not a `Store`.

### Data sources are neutral and first-class

`datasource.Store` (the call-source contract) lives in its own package — not inside `dynamodb` — so
nothing in the engine or the resolver lifecycle owes anything to one source's shape. Two real,
differently-shaped call-sources prove it: the DynamoDB-style store (`{"operation":"GetItem",…}`) and an
HTTP source (`internal/httpsource`, `{"method":"POST","resourcePath":"/x","params":{…}}`). A resolver
targets either through the **same** lifecycle and executor; **no code path branches on data-source
type** — only a `Store` implementation knows its own operation shape. Declared on `kind: GraphQLApi`
via `dataSources[].type: http` + `endpoint`. (A push source — a subscription's event stream — is a
different kind of thing, not a `Store`; see below.)

### Field-level authorization (one policy world)

A resolver may declare an `auth` requirement (a k8s RBAC verb on a resource). The **executor** consults
an injected `Authorizer` **before** running the field's resolver; on denial the field is `Unauthorized`,
null, and the resolver — and its data source — never runs. The production `Authorizer`
(`internal/k8sauth`) performs an **impersonated `SubjectAccessReview`** against the cluster — the *same*
RBAC + permission boundary the console, Terraform, and the aws-shim use, so this is "one policy world at
field granularity," not a parallel rule engine. The caller's identity is established upstream (the
shim's SigV4→principal, conveyed as `X-OpenInfra-User`/`-Groups`) and exposed to templates as
`$ctx.identity`. Authorization lives in the lifecycle, never in a runtime step — the step stays
auth-unaware. Out of cluster the engine logs loudly that field auth is **not** enforced.

### Hostile-load guards (safe by default)

GraphQL's cost asymmetry (the client composes demand, the server owns cost) makes an unguarded endpoint
a DoS risk — which matters most for the least-resourced operator. The engine enforces, before any
resolver runs: **depth** limiting, **cost** (field-count) limiting, and an optional **persisted-query**
allow-list (only pre-registered documents run). Defaults are ON (`graphql.DefaultLimits`: depth 10,
cost 1000); a `GraphQLApi`'s `limits` block tunes them; a negative value is an explicit opt-out.
Honest label: this is what will let open-appsync be called *safe to expose to untrusted clients* — per
rung, once proven; until then, *trusted-client / internal use*.

### Subscriptions (setup-then-push — experimental, label held)

Subscriptions **invert** the lifecycle: not request→execute→response, but *setup-then-push*. At
**subscribe** time a setup step authorizes the caller (the field's `auth`, the same boundary) and
registers a **filter** in the per-node **registry** (the one new piece of connection-scoped state). At
**mutation** time the mutation's result is **published** to the field's subject. At **push** time every
node fans the event out to its local subscribers whose filter matches, shaping each with the
subscriber's response step. The event source is a **push source (a Bus), not a `datasource.Store`** —
the same call-vs-stream split the data-source contract draws.

Built and proven: the **enhanced filter engine** (`eq/ne/in/contains/beginsWith/ranges`, dotted fields,
AND-within-filter / OR-across-filters — the genuinely hard part), the **registry** + naive
O(subscribers) fanout (a filter index is deferred until load proves it's needed), the **Bus port** with
an in-memory bus (single node) and a **JetStream bus** (`internal/subscription/jetstream.go`, build-tag
`integration`) where a durable consumer gives reconnect/resume, the **Manager** (setup-then-push,
subscribe-time auth gate, publish, filtered fanout), and the **`graphql-transport-ws` WebSocket front
door** (`/graphql-ws`) — proven end-to-end with a real client (connection_init/ack, argument-filtered
subscribe, matching vs non-matching delivery, complete). A successful mutation auto-publishes to the
subscriptions it triggers (the executor's publish hook). The deployed demo serves `onCreateTodo`.

**Label held (honest):** the graduation bar for this rung is **temporal, not a unit test** — a
**node-kill chaos scenario** (kill a subscription-holding node mid-stream; prove reconnect/resume with
no lost and no duplicated events past the acked point, on the nightly clock). The transport is now
wired and the durable JetStream bus is integration-tested; subscriptions stay **experimental** until
that chaos run is green. The code is done; the temporal proof is not.

## Authoring: `kind: GraphQLApi` (the neutral plane)

`kind: GraphQLApi` (`openinfra.dev`) is the neutral authoring plane: **one** object carrying a schema
plus inline arrays of data sources and resolvers, each resolver declaring a `runtime` and its inline
request/response templates. It renders exactly like `kind: HttpApi` — an XRD + a go-templating
Composition, **no bespoke controller** — into (a) a ConfigMap in the shape `server.Load` reads and
(b) the engine Deployment + Service, with a config-checksum annotation that rolls the pod on any
change. It is deliberately one kind, not AWS's separate `Resolver`/`DataSource` management nouns.

**Fail-closed:** the engine validates every template on load and refuses to serve if one is malformed
— an invalid resolver keeps the whole API from coming up (pod stays not-ready, error in its logs). It
is not "rejected at apply instant" (there is no validating webhook).

**Test-resolver loop:** `POST /test-resolver` runs a resolver against a sample `$ctx` and shows what
the templates produce (the neutral request `Operation`, and the response value if you supply a sample
result) — authoring with feedback instead of blind. Same mechanism as the corpus probe, on user input.

### Who retrains, and who doesn't

- **The resolver author (the specialist) learns nothing.** Their VTL — `$util`, DynamoDB marshalling,
  the `2018-05-29` shape — is byte-for-byte identical inside the `appsync-vtl` runtime. No refactor may
  touch that fidelity.
- **The person wiring resolvers** sees a new *envelope* temporarily: an entry in a `GraphQLApi` object
  instead of `CreateResolver`. Template identical; envelope open-infra-shaped.
- **Stage 2 (shipped as a front door, per-verb):** the AWS management shim translates `CreateResolver`
  / `CreateDataSource` / … into a patch on this same `GraphQLApi` object (in the aws-shim, at `/v1/...`),
  so the AWS person runs existing tooling unchanged and never sees the envelope. It graduates per verb
  (proven: CreateResolver, UpdateResolver, DeleteResolver, GetResolver, CreateDataSource,
  DeleteDataSource); the skin owns AWS's `(apiId, typeName, fieldName)` mapping and the neutral core
  never learns it. Neutral core now, zero-retraining at the edge.

Honest label for this release: *a neutral engine that runs a team's VTL* — **not yet** the AWS
packaging (authoring) experience.

## What's built

Everything below is implemented and covered by `go test -race ./...`; all of it ships **experimental**
(see *Maturity* for why, and for the two gates that are still open).

- **The VTL engine + `$util`** and the resolver **request → execute → response** lifecycle — a real
  AppSync VTL resolver runs end-to-end against a DynamoDB-style data source and returns the GraphQL
  result AWS would.
- **The GraphQL executor** (`internal/graphql`): field→resolver dispatch, arguments + `$variables`,
  selection-set projection, `{data, errors}` with resolver-thrown `errorType`.
- **Fragments** (named `...F` + inline `... on T { }`) expanded before execution, with unknown-fragment
  and cycle rejection; and **variable coercion** — the declared operation variables are validated and
  normalized against their wrapped types before any resolver runs (`ID!` rejects null, `[String!]`
  rejects a null element, an enum rejects an off-list value, an input object rejects unknown/missing-
  required fields; defaults applied), rejecting mismatches with a `ValidationError`. Custom-scalar
  *value* validation is deferred (see below); the wrapper/nullability/enum/input-object layer is coerced.
- **An in-memory schema type system + introspection** (`internal/graphql/schema.go`, `introspect.go`):
  the API's SDL parses into a name→type map where a field's return type is a *reference* carrying its
  wrappers (`Post`, `Post!`, `[Post]`, `[Post!]!` are four distinct types), and `__schema` / `__type`
  are answered by reading that map back out in the spec-mandated shape. See *Introspection* below for
  the operability gates it graduated on.
- **Data sources**: an in-memory store and a **FerretDB-backed** DynamoDB-style store
  (`internal/dynamodb`), plus an **HTTP** source (`internal/httpsource`) — behind the neutral
  `datasource.Store` contract, with no data-source-type branching in the engine or lifecycle.
- **The runtime extension point** (`internal/runtime`) with two tenants: **VTL** (`internal/vtlruntime`)
  and a sandboxed **JavaScript** runtime (`internal/jsruntime`, goja). Two tenants through one front
  door ⇒ the interface is treated as stable.
- **Lifecycles**: `unit` and **pipeline** (`before → functions → after`, `stash`/`prev.result`
  threaded); **subscriptions** (setup-then-push) over an in-memory or **JetStream** bus, with a
  `graphql-transport-ws` WebSocket front door (`/graphql-ws`).
- **Field-level authorization** via an impersonated `SubjectAccessReview` (`internal/k8sauth`) — the
  same RBAC boundary the rest of open-infra uses.
- **Hostile-load guards** (depth / cost / persisted-query), safe by default.
- **Authoring**: `kind: GraphQLApi` (renders the engine config, no bespoke controller) + a
  `/test-resolver` loop; and a **Stage-2 AWS management shim** that translates AppSync management verbs
  into patches on the `GraphQLApi` object (per-verb).
- **Compatibility probe**: runtime **goldens harnesses** for both runtimes — VTL (`probe/goldens/`) and
  APPSYNC_JS (`probe/goldens-js/`) — whose cases are **captured from real AWS AppSync**
  (`evaluate-mapping-template` / `evaluate-code`) and diffed in CI. Both are behavior-faithful.

## Introspection

Set `spec.schema` (GraphQL SDL) on a `kind: GraphQLApi` and the engine parses it into an in-memory type
graph and answers **`__schema` / `__type`** over it — so the GraphQL ecosystem (graphql-codegen, Apollo,
GraphiQL) can build a client schema from the API. The SDL rides to the engine as a `schema.graphql`
sibling file (kept out of `config.json` to avoid JSON escaping — same reason the `.vtl` templates are
files). Without a schema the engine still resolves fields; introspection just reports unavailable.

**How it graduated (operability, not fidelity).** Introspection is standard GraphQL — AWS has no dialect
here — so a byte-match-AWS golden proves little. The bar is instead *does a real tool consume it*:

1. **Conformance** (`probe/introspection_probe_test.go`, `TestIntrospection_CanonicalQueryShape`) — fire
   the standard introspection query and validate the response is the spec's shape, wrappers exact.
2. **Real-tool-consumes** (`TestIntrospection_RealToolConsumes` → `probe/introspection/consume.mjs`) —
   feed the result to **graphql-js `buildClientSchema`** and **graphql-codegen**; assert they reconstruct
   the schema (`[Todo!]!`, `ID!`, `[String!]`, enum defaults, custom scalars, all three roots survive)
   and generate TypeScript types. This is the operability golden — the ecosystem builds against
   open-infra or it doesn't.

**Toggle (security).** Introspection-on lets any client read the whole schema — a tooling boon and a
recon aid — so it is a toggle, wired into the hostile-load seam: `spec.limits.introspection` is
`enabled` (default; AWS AppSync's behavior), `disabled` (never), or `authenticated-only` (off for
untrusted/anonymous callers). `__typename` is unaffected.

**Fragments (named + inline).** The parser accepts fragment spreads (`...Name`) and inline fragments
(`... on Type { }`); they are expanded to plain fields before execution, with unknown-fragment and
fragment-cycle rejection and (when a schema is present) type-condition existence checks. This closes the
introspection corner above: gate #2 now feeds the **verbatim wire introspection query** graphql-js sends
(fragment-laden) straight through the parser+executor, not a hand-inlined stand-in. Polymorphic dispatch
(applying `on Type` only to matching runtime objects for interfaces/unions) is a later rung; field
collection is currently unconditional, which is correct for well-formed queries against a matching shape.

`__typename` resolves at every nesting level (root and nested/list), returning the concrete type name
from the type graph — the field Apollo/Relay caches require — and stays outside the introspection toggle.

**Custom-scalar validation (neutral seam).** Coercion runs a per-scalar validator for declared custom
scalars: the core validates *that a scalar validates* via a registered `ScalarValidator` and knows
nothing about any vendor's scalar; AWS rules (AWSDateTime, AWSJSON, AWSEmail, …) live at the edge in
`internal/awsscalars` and the server wires them in. Two clocks, not conflated: Tier-0 best-effort
*format* validation ships now; Tier-1 AppSync-byte-exact scalar fidelity is a separate future golden.

**Honest scope.** Directive *execution* (`@skip`/`@include`) and AWS-scalar *fidelity* lean on this type
graph but each graduates on its own evidence — none is promoted by proximity.

## Maturity — two independent gates

These are separate on purpose: shipping the authoring plane alongside the runtime does **not** make
either "proven."

- **The runtime gate — CLEARED (behavior-faithful).** The runtime runs live end-to-end (SigV4 GraphQL
  client → aws-shim `appsync` → open-appsync → a real VTL resolver → data source → `{data}`; wrong
  signature → 401), and its `$util`/VTL output is now **diffed against real AWS AppSync**: the goldens
  in `probe/goldens/` were captured from a live account (via `evaluate-mapping-template`) and the CI
  diff is green against them. That capture surfaced and fixed two real divergences from the DynamoDB SDK
  shape we'd initially assumed — AppSync emits `N` as a JSON number and `NULL` as JSON `null` — so the
  runtime is **behavior-faithful, not just documented-faithful**. (Re-run `probe/goldens/capture.sh` to
  refresh against AWS.)
- **The authoring plane + runtime interface.** `kind: GraphQLApi`, the extension point, and
  `/test-resolver` ship experimental on their own bar (`go test -race ./...` green; on-cluster, a
  resolver authored through Terraform reconciling into the engine config and a live request exercising
  it, plus the fail-closed negative).

**Subscriptions** carry a further gate: their graduation is a **node-kill chaos scenario** (kill a
subscription-holding node mid-stream; prove reconnect/resume with no lost and no duplicated events past
the acked point). The code and the durable JetStream bus are in place; that run is what removes the
label.

This is **not a full AppSync** — each widening graduates behind its own probe.

## Layout

- `internal/runtime/` — the runtime extension-point contract (the three frozen terms).
- `internal/vtl/` — the VTL interpreter + the AppSync `$util` helper library (the heart of fidelity).
- `internal/vtlruntime/` — the VTL tenant of the runtime interface.
- `internal/jsruntime/` — the JavaScript tenant (goja-sandboxed) of the runtime interface.
- `internal/resolver/` — the request→execute→response lifecycle (drives any runtime).
- `internal/datasource/` — the neutral call-source contract (`Store`).
- `internal/dynamodb/` — the DynamoDB-style data source (in-memory + FerretDB-backed).
- `internal/httpsource/` — an HTTP data source (the second, differently-shaped call-source).
- `internal/authz/` — the field-auth port (Requirement/Identity/Authorizer); `internal/k8sauth/` — the
  production SubjectAccessReview authorizer.
- `internal/subscription/` — the subscription rung: filter engine, registry, Bus (in-memory +
  JetStream), and the setup-then-push Manager (experimental; chaos-bar held). The WebSocket front door
  (`graphql-transport-ws`) is `internal/server/subscription_ws.go` (`/graphql-ws`).
- `internal/graphql/` — the GraphQL parser + executor (field→resolver dispatch, projection).
- `internal/server/` — config loader (`server.Load`) + HTTP handlers (`/graphql`, `/test-resolver`).
- `cmd/open-appsync/` — the engine binary.
- `probe/` — the docs-anchored resolver corpus + probes + the runtime goldens harness
  (`probe/goldens/`, the runtime gate).
