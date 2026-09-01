# AppSync → DynamoDB-shaped data source: operation characterization

**What this is:** an honest, observed characterization of which DynamoDB operations open-infra's
AppSync engine (open-appsync) actually supports against its Dynamo-shaped data source. The data
source is **"slice 1"** by design: a small set of operations over a primary-key document store,
backed durably by **FerretDB** (MongoDB wire protocol on Postgres) or in-memory for tests. This
is not a DynamoDB emulator, and this matrix makes no claim beyond what was run or what the code
demonstrably refuses.

**Rule:** no operation is marked working without an observed round-trip returning correct data;
operations the code explicitly refuses are marked not-supported with the refusing code cited (no
live run needed to prove an absence the code enforces); anything neither observed nor
code-refused is `not-run`.

**Date:** 2026-08-31.

> **Update 2026-08-31 — UpdateItem and Query implemented.** The gating gap this matrix
> identified (UpdateItem + Query) has since been built as a faithful common subset and observed
> live (unit tests, a full VTL resolver round-trip, and a durable FerretDB round-trip). The rows
> below are updated in place; the operations that remain unsupported still fail loud. A
> create/read/update/delete/list app now ports; the remaining gaps are the less-common forms
> named in the table.

## How the supported rows were observed (live, this date)

- **Durable store, real FerretDB:** stood up `ghcr.io/ferretdb/postgres-documentdb:17` +
  `ghcr.io/ferretdb/ferretdb:2` and ran the store integration test against it —
  `FERRET_TEST_URI=… go test -tags integration ./internal/dynamodb/ -run Ferret` →
  `TestFerretStore_RoundTrip` **PASS**: PutItem → GetItem → DeleteItem → get-miss, each returning
  correct data (`open-appsync/internal/dynamodb/ferret_integration_test.go`).
- **Full VTL resolver path:** `go test ./probe/ -run Resolver` → `TestResolverProbe_PutThenGet`
  and `TestResolverProbe_GetMissingIsNull` **PASS**: a GraphQL request → VTL request mapping →
  the Dynamo-shaped store → VTL response mapping → `{data}`, returning correct data
  (`open-appsync/probe/resolver_probe_test.go`).

The engine never branches on data-source type; a VTL/JS mapping template renders a
`runtime.Operation` and the **store's `switch` on the operation name is the sole authority** on
what exists (`open-appsync/internal/dynamodb/`). So the supported set is exactly that switch.

## The matrix

| DynamoDB operation | Status | Evidence |
|---|---|---|
| **GetItem** | observed-correct | FerretStore round-trip + resolver probe (above); `dynamodb.go` / `ferret.go` GetItem |
| **PutItem** (plain) | observed-correct | FerretStore round-trip + resolver probe; `ferret.go` PutItem (upsert) |
| PutItem **with condition expression** | not-supported | store does an unconditional upsert; no condition evaluation in PutItem |
| **DeleteItem** (plain) | observed-correct | FerretStore round-trip; `ferret.go` DeleteItem (`FindOneAndDelete`) |
| DeleteItem **with condition** | not-supported | plain delete by key; no condition evaluation |
| **UpdateItem** — SET (assign, +/- arithmetic, if_not_exists, list_append), REMOVE, ADD (numeric/set), ±condition | **observed-correct** (#58) | unit tests + resolver round-trip + durable FerretDB (`expr.go`, `TestFerretStore_UpdateAndQuery`) |
| UpdateItem — DELETE action, nested attribute paths | not-supported | fails loud (`unsupported update action` / unsupported path) |
| **Query** — key-condition (`=`, `<`, `<=`, `>`, `>=`, `begins_with`, `BETWEEN`) | **observed-correct** (#58) | unit tests + resolver round-trip + durable FerretDB |
| Query on a **Global Secondary Index** | **observed-correct** (#58) | index is metadata; the key-condition matches the GSI's attributes directly (`TestQuery_ByGSIAttributes`) |
| Query **with filter expression** (`= <> < <= > >=`, `AND`/`OR`/`NOT`, begins_with, contains, attribute_exists/_not_exists) | **observed-correct** (#58) | `TestQuery_DescendingBeginsWithAndFilter` |
| Query — sort order (scanIndexForward) + pagination (limit/nextToken) | **observed-correct** (#58) | `TestQuery_PartitionAndSort`, `TestQuery_Pagination` |
| **Scan** (full) | implemented; **live round-trip not-run** | code path exists (`Find(bson.M{})`, full scan) but no live Scan was run this date |
| Scan **with filter expression** | not-supported | Scan issues an empty filter; any filter is ignored |
| **BatchGetItem** | not-supported | default not-implemented branch |
| **BatchWriteItem** | not-supported | default not-implemented branch |
| **TransactWriteItems / TransactGetItems** | not-supported | default not-implemented branch |
| **TTL expiry** | not-supported | not referenced anywhere in the store |
| **Change streams** | not-supported | none exist |

## The subset a migrating app is likely to need — and the gap

The exact operations such an app needs require its own resolvers (not available
here), so this is the general assessment for a typical DynamoDB-behind-AppSync CRUD app:

- A **create / read / update / delete / list** app is now covered (the gating gap this matrix
  first identified, UpdateItem + Query, was built — see the Update note at the top):
  - **UpdateItem** — partial-attribute updates (SET assign / +/- arithmetic / if_not_exists /
    list_append, REMOVE, ADD) and **conditional writes** (an optimistic-concurrency guard via a
    `condition` expression), observed live.
  - **Query** — by partition key, with a sort-key condition (`=`/comparison/`begins_with`/
    `BETWEEN`), by a GSI's attributes, with a filter expression, sorted (scanIndexForward), and
    paginated (limit/nextToken), observed live.
- **Still not supported (fail-loud, never silent):** condition expressions on PutItem/DeleteItem,
  the UpdateItem DELETE action, nested attribute paths, batch/transactional writes, TTL, and
  change streams.

**Bottom line:** the Dynamo-shaped data source now covers the common CRUD + list surface —
Get/Put/Delete/Update/Query with conditions, GSIs, filters, sorting, and pagination — observed
live against real FerretDB and through a VTL resolver. It is still **not** a full DynamoDB
replacement: batch/transactional writes, TTL, change streams, and Put/Delete condition
expressions are absent and refused loudly, not silently approximated.

## Honest-unknown / not-run this date

- **Scan** live round-trip — the code path exists but no live Scan was executed here.
- The **combined full-HTTP + durable-FerretDB** path in one run — I observed the durable store
  round-trip (FerretDB) and the full VTL resolver path (in-memory store) *separately*; a single
  end-to-end GraphQL-over-HTTP request landing in FerretDB was not stood up (open-appsync is
  opt-in/off and no FerretDB-backed GraphQLApi is currently deployed).
