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
  - **Next:** the engine HTTP server (`cmd/open-appsync`, POST /graphql) loading a schema/resolver
    config + image + manifest to **deploy** (swap the nginx placeholder), so the shim's `appsync`
    service fronts the real engine end-to-end.
  - **Slice-1 "not yet" (flagged):** subscriptions, multiple data-source types, a management API,
    JavaScript resolvers, pipeline resolvers.
- **Rung 2 — subscriptions over JetStream.** AppSync's WebSocket protocol mapped onto NATS
  JetStream; graduates only with a chaos scenario that kills a subscription-holding node and proves
  clients reconnect/resume.
- **Rung 3+** — second data source, JS resolvers, pipeline resolvers, a management API, per-group
  role mapping, query-cost/depth limiting.

## Status

**EXPERIMENTAL — slice 1 runs live end-to-end.** The deployed component (`components.openAppsync`)
is the real engine (`cmd/open-appsync`, a demo Todo API). Verified on-cluster: a SigV4-signed GraphQL
client → the aws-shim's `appsync` service → open-appsync → a real VTL resolver → the data source →
`{data}` (a `createTodo` mutation then `getTodo` query round-trip; wrong signature → 401). The
docs-anchored VTL/`$util` corpus probe is green in CI.

Honest limits: fidelity is anchored on AWS's *documented* behavior, **not diffed against a live AWS
AppSync** (that needs an AWS account). And this is **not a full AppSync** — the slice-1 "not yet"
list (subscriptions, multiple data-source types, JavaScript/pipeline resolvers, a management API)
still applies. Each widening graduates behind its own probe.

## Layout

- `internal/vtl/` — the VTL interpreter + the AppSync `$util` helper library (piece 2, the heart).
- `probe/` — the docs-anchored resolver corpus + the probe that runs it (piece 5).
