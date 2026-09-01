# AppSync pilot-readiness report

An honest, observed read on whether a representative app of the prospect's shape — an
AppSync GraphQL API with DynamoDB-backed VTL resolvers, subscriptions, and API-key auth —
runs on open-infra. Every "faithful" row below is backed by a live on-cluster round-trip
against a deployed `kind: GraphQLApi`; rows that were not run live are marked so, never
assumed.

**Date:** 2026-08-31.

## open-appsync is experimental

open-appsync is open-infra's own resolver-first, VTL-faithful GraphQL engine, on its own
graduation ladder — **experimental**, not a present-tense parity claim against AWS AppSync.
This report states what was observed on that engine on this date; it does not assert AppSync
parity.

## What was stood up (live, on-cluster)

A throwaway `kind: GraphQLApi` ("pilot") in its own namespace, with:

- a **DynamoDB-shaped data source backed by real FerretDB** (a DocumentDB-Postgres +
  FerretDB deployment; `spec.mongoURI` → that endpoint);
- a representative **Notes** schema — `Note{ id, room, title, body, ts, version }` — with CRUD
  + list resolvers and a subscription;
- **VTL resolvers**: `createNote` (PutItem), `getNote` (GetItem), `updateNote` (UpdateItem),
  `deleteNote` (DeleteItem), `listNotes` (Query by room);
- **`@aws_api_key`** auth on every field, from a key→identity Secret;
- **`onCreateNote` `@aws_subscribe(mutations:["createNote"])`** subscription.

It was driven over HTTP (`POST /graphql`, `x-api-key`) and WebSocket
(`/graphql-ws`, graphql-transport-ws) via a port-forward to the API's Service.

## Per-feature results

| Feature | Verdict | Observation (live, 2026-08-31) |
|---|---|---|
| Dynamo **create** (PutItem) | **faithful** | `createNote` returned the written item with an autoId |
| Dynamo **read** (GetItem) | **faithful** | `getNote(id)` returned the item; a deleted id returned `null` |
| Dynamo **update** (UpdateItem) | **faithful** | `updateNote` applied `SET body` + `ADD version` → `{body:"edited", version:1}` |
| Dynamo **delete** (DeleteItem) | **faithful** | `deleteNote` returned the item; a subsequent `getNote` was `null` |
| Dynamo **list** (Query by partition) | **faithful** | `listNotes(room)` returned all notes in the room, `nextToken: null` |
| **`@aws_api_key`** auth | **faithful** | a keyed request resolved; a request with **no** key was denied `Unauthorized: this field requires aws_api_key authentication` (fail-closed) |
| **Subscriptions** (`@aws_subscribe`) | **faithful** | a WS subscriber to `onCreateNote` received the pushed note when `createNote` fired |
| Dynamo ops beyond CRUD+list | **experimental-gap** | UpdateItem DELETE action, nested paths, Put/Delete condition expressions, BatchGet/Write, Transact*, TTL, change streams are **not supported** and fail loud (see `evidence/appsync-dynamo-matrix.md`) |
| **`@aws_iam`** auth (SigV4) | **not-run live** | enforced by the engine given the shim-set mode (covered by the engine auth tests), but a live SigV4 request **through the aws-shim** was not stood up in this sweep — the pilot hit open-appsync directly, without the shim in front |
| **`@aws_cognito_user_pools` / `@aws_oidc`** auth | **not-run live** | the engine consumes + enforces these JWTs (issuer/audience/expiry/signature via the shim; `cognito_groups` fail-closed) per its auth tests, but a live request with a real Cognito/OIDC token through the shim was not run here — and there is **no managed user pool** (see `docs/auth-migration.md`) |
| **`@aws_lambda`** auth | advisory | parsed + reported in introspection; not enforced (per the engine) |
| Distributed tracing (X-Ray) | absent | not shipped (see `docs/tracing.md`) |

## The exact gaps that would block THIS prospect

1. **DynamoDB coverage beyond CRUD + partition-key list.** Get/Put/Update/Delete/Query
   (with sort-key conditions, GSI-by-attribute, filters, sorting, pagination) are faithful.
   If the app relies on batch or transactional writes, TTL, condition expressions on
   Put/Delete, or the UpdateItem DELETE action, those are not supported (and fail loud, not
   silently). The precise matrix is `evidence/appsync-dynamo-matrix.md`.
2. **Auth modes verified live only for `@aws_api_key` + subscriptions.** `@aws_iam` and
   `@aws_cognito_user_pools`/`@aws_oidc` are engine-enforced and unit-tested, but their live
   round-trip **through the aws-shim** (SigV4 / a real JWT) was not run in this sweep. That
   shim-fronted live verification is the outstanding item for a Cognito-fronted app.
3. **No managed Cognito user pool.** Identity must come from an external IdP (or open-infra
   IAM + OIDC); open-infra consumes tokens, it does not host sign-up/sign-in. See
   `docs/auth-migration.md`.
4. **Amplify frontend hosting/build is out of scope** — deployer-external. See
   `docs/aws-migration.md`.

## Reproducing

Deploy a `kind: GraphQLApi` with a `dynamodb` data source and `spec.mongoURI` pointing at a
FerretDB endpoint (an `Application` with `database.engine: mongo`, or a standalone FerretDB),
an `apiKeysSecret`, CRUD/list resolvers, and a `@aws_subscribe` subscription; then
`POST /graphql` with `x-api-key`, and subscribe over `/graphql-ws`. The pilot manifests used
here were throwaway and torn down after the run.
