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
  - **Next:** piece 3 — the FerretDB binding (translate the VTL-emitted DynamoDB operation onto
    Mongo/FerretDB, behind the same `dynamodb.Store` interface, integration-tested); piece 1 + a
    GraphQL query executor (parse SDL, walk selection sets → invoke resolvers); then **deploy** (swap
    the nginx placeholder for this engine) and light up the end-to-end compatibility probe.
  - **Slice-1 "not yet" (flagged):** subscriptions, multiple data-source types, a management API,
    JavaScript resolvers, pipeline resolvers.
- **Rung 2 — subscriptions over JetStream.** AppSync's WebSocket protocol mapped onto NATS
  JetStream; graduates only with a chaos scenario that kills a subscription-holding node and proves
  clients reconnect/resume.
- **Rung 3+** — second data source, JS resolvers, pipeline resolvers, a management API, per-group
  role mapping, query-cost/depth limiting.

## Status

**UN-PROVEN.** The deployed component (`components.openAppsync`) is currently a placeholder that
returns an honest `NotImplemented` GraphQL error. This module is slice 1 under construction; it does
not count as proven until its probe is green.

## Layout

- `internal/vtl/` — the VTL interpreter + the AppSync `$util` helper library (piece 2, the heart).
- `probe/` — the docs-anchored resolver corpus + the probe that runs it (piece 5).
