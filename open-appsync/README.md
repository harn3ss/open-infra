# open-appsync

open-infra's **resolver-first, VTL-faithful** AWS AppSync engine. Its reason to exist: give teams
locked into AWS AppSync — the ones with **resolver specialists**, VTL templates, and data-source
wiring — an open, self-hostable door off of it. For that audience, GraphQL wire-compatibility is not
enough; the value is running their *existing resolver investment* unmodified. (Design of record:
`open-infra-open-appsync-handoff.md`.)

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
  binding translates the VTL-emitted DynamoDB operation into the backing store. (Slice 1 proves the
  VTL engine with a mock data source; the FerretDB binding is piece 3.)
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
nothing about VTL. This is the thing AWS structurally can't offer. The interface is **not** blessed as
stable on one implementation: it is proven with VTL through the front door and a second, trivial
runtime in tests (`internal/resolver/resolver_test.go`), and stays internal/changeable until a real
second tenant lands — openness earned by two tenants, not declared on one.

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
- **Stage 2 (later, at the edge):** an AWS management shim (`CreateResolver` / the CloudFormation type)
  becomes a patch on this same `GraphQLApi` object, so the AWS person runs existing templates
  unchanged and never sees the envelope. Neutral core now, zero-retraining at the edge.

Honest label for this release: *a neutral engine that runs a team's VTL* — **not yet** the AWS
packaging (authoring) experience.

## Graduation ladder

- **Slice 1 — VTL over one DynamoDB-style data source.** One real VTL resolver runs faithfully
  end-to-end. Pieces: (1) schema intake, (2) **the VTL engine + `$util`** — the heart, (3) one
  data-source binding, (4) resolver lifecycle glue, (5) the compatibility probe.
  - **Done:** piece 2 (the VTL engine + `$util`), piece 4 (the resolver request→execute→response
    lifecycle), and piece 5 (a docs-anchored corpus) — a real AppSync VTL resolver runs end-to-end
    against a DynamoDB-style data source and returns the GraphQL result AWS would (proven with the
    in-memory `dynamodb.MemStore`).
  - **Also done:** the GraphQL executor (`internal/graphql`) — a real query/mutation string drives
    the resolvers (field→resolver dispatch, arguments + `$variables`, selection-set projection,
    `{data, errors}` with resolver-thrown `errorType`). The whole stack — schema intake → execute →
    resolver lifecycle → `$util` → data source — runs from an actual GraphQL operation.
  - **Also done:** piece 3 — the FerretDB-backed `dynamodb.Store` (`internal/dynamodb/ferret.go`):
    translates the VTL-emitted DynamoDB op onto Mongo/FerretDB on one collection, same `Store`
    interface as MemStore (a resolver runs unchanged against either). Pure translation unit-tested;
    a live round-trip is `-tags integration` (needs a FerretDB).
  - **Also done:** `cmd/open-appsync` + `internal/server` (POST /graphql), deployed as the real
    engine (`components.openAppsync`), so the shim's `appsync` service fronts it end-to-end.
  - **Also done (this release, Clock B — see below):** the runtime **extension point**
    (`internal/runtime` + `internal/vtlruntime`), the **`kind: GraphQLApi`** authoring plane with
    fail-closed load validation, the `/test-resolver` loop, and the runtime **goldens harness**
    (`probe/goldens/`). All ship labeled experimental.
  - **Slice-1 "not yet" (flagged):** subscriptions, a second *data source*, an AWS *management*
    wire protocol (`CreateResolver`/CloudFormation — Stage 2), JavaScript resolvers, pipeline
    resolvers.
- **Rung 2 — subscriptions over JetStream.** AppSync's WebSocket protocol mapped onto NATS
  JetStream; graduates only with a chaos scenario that kills a subscription-holding node and proves
  clients reconnect/resume.
- **Rung 3+** — second data source, JS resolvers, pipeline resolvers, a management API, per-group
  role mapping, query-cost/depth limiting.

## Status — two independent honesty clocks

Do not let them blur: shipping the authoring plane alongside the runtime does **not** make either
"proven."

- **Clock A — the runtime.** The runtime runs live end-to-end (SigV4 GraphQL client → aws-shim
  `appsync` → open-appsync → a real VTL resolver → data source → `{data}`; wrong signature → 401),
  and the docs-anchored corpus probe is green. It stays **EXPERIMENTAL** until the goldens
  (`probe/goldens/`) are captured from **real AppSync** and the CI diff is green against them — the
  one thing that removes the word (see `probe/goldens/README.md`). Today the goldens are seeded from
  AWS's *documented* behavior, so the harness is proven but the capture is pending (maintainer's
  account, once).
- **Clock B — the authoring plane + runtime interface.** `kind: GraphQLApi`, the `internal/runtime`
  extension point, and `/test-resolver` are a **brand-new experimental rung** on their own bar
  (`go test -race ./...` green; on-cluster, a resolver authored through Terraform reconciling into the
  engine config and a live request exercising it, plus the fail-closed negative). Building them does
  not make them proven; they ship labeled experimental even though the runtime is more mature.

This is **not a full AppSync** — the slice-1 "not yet" list still applies, and each widening graduates
behind its own probe.

## Layout

- `internal/runtime/` — the runtime extension-point contract (the three frozen terms).
- `internal/vtl/` — the VTL interpreter + the AppSync `$util` helper library (piece 2, the heart).
- `internal/vtlruntime/` — the VTL tenant of the runtime interface.
- `internal/resolver/` — the request→execute→response lifecycle (drives any runtime).
- `internal/dynamodb/` — the DynamoDB-style data source (in-memory + FerretDB-backed).
- `internal/graphql/` — the GraphQL parser + executor (field→resolver dispatch, projection).
- `internal/server/` — config loader (`server.Load`) + HTTP handlers (`/graphql`, `/test-resolver`).
- `cmd/open-appsync/` — the engine binary.
- `probe/` — the docs-anchored resolver corpus + probes (piece 5) + the runtime goldens harness
  (`probe/goldens/`, Clock A).
