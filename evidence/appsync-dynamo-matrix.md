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
| PutItem **with condition expression** | not-supported | store does an unconditional upsert; no condition evaluation in the op handler |
| **DeleteItem** (plain) | observed-correct | FerretStore round-trip; `ferret.go` DeleteItem (`FindOneAndDelete`) |
| DeleteItem **with condition** | not-supported | plain delete by key; no condition evaluation |
| **UpdateItem** (SET/ADD/REMOVE, ±condition) | **not-supported** | falls to the default branch — explicit `operation "UpdateItem" not implemented (slice 1: GetItem/PutItem/DeleteItem/Scan)` |
| **Query** (key-condition) | **not-supported** | no `case "Query"` in the store; default not-implemented branch |
| Query on a **Global Secondary Index** | **not-supported** | no index concept; GetItem addresses only the primary key (serialized to `_id`) |
| Query **with filter expression** | **not-supported** | Query itself is absent |
| **Scan** (full) | implemented; **live round-trip not-run** | code path exists (`Find(bson.M{})`, full scan) but no live Scan was run this date |
| Scan **with filter expression** | not-supported | Scan issues an empty filter; any filter is ignored |
| **BatchGetItem** | not-supported | default not-implemented branch |
| **BatchWriteItem** | not-supported | default not-implemented branch |
| **TransactWriteItems / TransactGetItems** | not-supported | default not-implemented branch |
| **TTL expiry** | not-supported | not referenced anywhere in the store |
| **Change streams** | not-supported | none exist |

## The subset a migrating app is likely to need — and the gap

The exact operations the pilot app needs require the pilot app's own resolvers (not available
here), so this is the general assessment for a typical DynamoDB-behind-AppSync CRUD app:

- A basic **create/read/delete-by-key** app is covered: PutItem, GetItem, DeleteItem all
  round-trip correctly, live.
- **Two operations most such apps rely on are not supported, and this is the gating gap:**
  - **UpdateItem** — partial-attribute updates (SET/ADD/REMOVE) and conditional writes. Today an
    update must be modeled as read-modify-PutItem in the resolver, and there is **no** conditional
    write (no optimistic-concurrency guard).
  - **Query** — listing items by partition key, by a GSI, or with a filter. This is the primary
    read pattern for list/collection views; only GetItem-by-key and full Scan exist.
- Condition expressions, GSIs, batch/transactional writes, and TTL are also absent.

**Bottom line:** the Dynamo-shaped data source is a faithful **primary-key document store for
Get/Put/Delete**, not a DynamoDB replacement. An app that only creates, reads, and deletes items
by key ports as-is; an app that uses UpdateItem, Query, GSIs, conditions, batches, transactions,
or TTL does **not**, and the specific missing operations are named above. Closing the subset the
pilot actually needs is separate work, gated on this characterization.

## Honest-unknown / not-run this date

- **Scan** live round-trip — the code path exists but no live Scan was executed here.
- The **combined full-HTTP + durable-FerretDB** path in one run — I observed the durable store
  round-trip (FerretDB) and the full VTL resolver path (in-memory store) *separately*; a single
  end-to-end GraphQL-over-HTTP request landing in FerretDB was not stood up (open-appsync is
  opt-in/off and no FerretDB-backed GraphQLApi is currently deployed).
