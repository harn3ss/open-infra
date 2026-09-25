# AWS-SDK shim (opt-in)

The AWS shim is an **AWS-shaped front door onto open-infra's real backends**. An unmodified
application built for the AWS SDK — pointed at the shim's endpoint — believes it is talking to AWS;
the shim verifies the request's SigV4 signature against an open-infra access key, resolves the
caller to their open-infra principal, enforces the **same** RBAC and permission boundary the
console and Terraform provider use, calls the real backend, and re-dresses the response in AWS's
exact byte-shape.

It is **not** an emulator. LocalStack/Floci *fake* AWS for throwaway testing; their fidelity is
bounded by what they chose to implement — the same false-green risk open-infra designs against
everywhere. The shim fronts *durable* backends, not fakes.

> **Status: opt-in, OFF by default.** The shim is a router with pluggable per-service handlers — one
> front door, many domain experts, each dispatched by the AWS service the client signs for. **Seventeen
> services are fronted and each is proven by a real-AWS-SDK compatibility probe** (`probe/aws-shim-*.sh`,
> exit 0 live): **S3** (MinIO), **STS** (identity + `AssumeRole`/web-identity), **Lambda** (Knative
> `Function`s), **AppSync** (over the **open-appsync** engine — experimental), **DynamoDB** (FerretDB +
> a documentdb Postgres for transactions), **SQS**, **SNS**, **KMS** (Vault Transit), **Secrets Manager**
> (Vault-KMS-encrypted), **EventBridge** (scheduled + event-driven), **RDS** (real PostgreSQL via
> CloudNativePG), **CloudWatch Logs**, **SSM Parameter Store** (Vault-KMS-encrypted SecureString), and
> **API Gateway** (HTTP API v2 — the runtime HTTP→Lambda proxy, completing the serverless triad), and
> **CloudWatch metrics + alarms** (alarms that genuinely evaluate and fire SNS actions), and **Kinesis Data
> Streams** (ordered, sharded, replayable), and **Cognito** (user pools issuing real, JWKS-verifiable JWTs).
> Every one enforces the *same* SigV4 + one-policy-world (RBAC +
> Cedar) path — never a parallel auth. It is one optional AWS-shaped surface over the platform, never a
> core dependency. Each service is **built, probed, and counted** the same gated way; a service the shim
> has not made faithful is an honest `501`, never a silent partial. Some carry deliberate, documented
> **divergences and carve-outs** (AppSync/open-appsync is experimental; several services refuse specific
> flags rather than fake them) — those are listed per service below. "Fronted and probe-proven" is not
> "all of AWS": it is a specific, verified surface.

## Enabling it

Set the component flag and re-run the installer (idempotent, GitOps-reconciled):

```yaml
# config.yaml
components:
  awsShim: true   # OFF by default
```

```sh
./install.sh
```

Argo CD then syncs `platform/aws-shim/`: the shim Deployment/Service, its scoped RBAC, an egress
NetworkPolicy, and a one-shot Job that mints the shim's non-root MinIO service account. Nothing is
hand-run.

## Pointing a client at it

This is entirely client-side — the AWS console has no part in it. Set the SDK's **endpoint
override** and use **path-style** S3 addressing:

```sh
export AWS_ENDPOINT_URL=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566
export AWS_ACCESS_KEY_ID=<your open-infra access key id>
export AWS_SECRET_ACCESS_KEY=<your open-infra secret>

aws --endpoint-url "$AWS_ENDPOINT_URL" s3api put-object \
  --bucket my-bucket --key hello.txt --body ./hello.txt
```

Two things to get right, both one-liners:

- **Path-style addressing.** AWS defaults to virtual-host style (`my-bucket.host/…`), which breaks
  against a raw `host:port`. Flip the S3 client to path-style (`AWS_S3_ADDRESSING_STYLE=path`, or
  `s3api` which already uses it). v1 supports path-style only.
- **Credentials must be present.** The SDK refuses to sign with no credentials — but these are
  *open-infra* keys, validated by the shim against open-infra IAM, not real AWS keys.

## Identity and enforcement — one policy world

The shim does **not** get its own notion of who-you-are-and-what-you-can-do. The request path is:

1. **Authenticate (SigV4).** The access key ID travels in the clear (it only *names* the caller);
   the signature rides along, computed from the secret, which is never on the wire. The shim looks
   up the key's secret and **recomputes and constant-time-compares the signature**. A caller who
   merely *names* a valid key but cannot reproduce its signature is rejected — exactly as AWS
   returns `SignatureDoesNotMatch`. Because SigV4 signs the method, path, headers, and payload
   hash, a passing signature also proves the request was not tampered with in flight.
2. **Resolve the principal.** The access key's owner is resolved to its owning `kind: User` and
   that user's **current** groups — fresh on every request, so revoking a group takes effect
   immediately without touching the key.
3. **Authorize.** The shim runs the **same impersonated `SubjectAccessReview`** the console uses
   (shared `internal/iam.CanDo`), against the `openinfra:<user>`/`openinfra:<group>` identity — the
   very same RBAC compiled from `kind: Policy`/`Role`/`Group`, bounded by the permission boundary.

The console, the Terraform provider, and the shim all resolve through that one policy layer. The
shim shares the console-api Go module precisely so it *imports* that authorization core rather than
reimplementing a weaker parallel one.

### The credential store

An access key is a sub-resource of a `kind: User`, stored as one Kubernetes Secret per key
(`iam-ak-<hash>`), labelled with its owner. Because SigV4 verification is symmetric — the shim must
HMAC with the same secret the client used — the store holds the **actual** secret (protected by
etcd encryption at rest + tightly-scoped RBAC), not a one-way hash the way passwords are. The key's
*permissions* are never stored: they are always the owner's current groups, evaluated fresh.

Least privilege by namespace split: the shim reads access-key Secrets only in its **own**
namespace, and reads `kind: User` (never Secrets) in the console namespace. Its only cluster-wide
grant is `create subjectaccessreviews` — which asks the API server a question and grants nothing.

## Services

The shim dispatches by the AWS service the client signed for (read from the SigV4 credential
scope). Each service is an independent handler with its own decoder, authorization mapping, and
error dialect.

Every fronted service is **probe-proven** — a real AWS-SDK client drives it against a deployed shim and
asserts the *semantics*, not just a 200 (`probe/aws-shim-<svc>.sh`, exit 0). Full detail per service is in
the sections below; the one-line summary:

| Service | Backend | Protocol | Notable divergences / carve-outs (see section) |
|---|---|---|---|
| **[S3](#s3-faithful-proven)** | MinIO | REST/XML | path-style only |
| **[STS](#sts-faithful)** | identity / Vault-sealed tokens | query/XML | `AssumeRole` opt-in (Vault-custodied sealing key) |
| **[Lambda](#lambda-knative-function-invoke)** | Knative `Function` | Lambda REST | qualifiers/versions not resolved |
| **[AppSync](#appsync-graphql-over-open-appsync--slice-1-runs-live-experimental)** | open-appsync engine | GraphQL | **experimental**; needs `components.openAppsync` |
| **[DynamoDB](#dynamodb-ferretdb--documentdb-postgres-transactions)** | FerretDB + documentdb Postgres | JSON 1.0 | `ProjectionExpression`, streams `501` |
| **[SQS](#sqs-postgres-backed-probe-proven)** | Postgres | JSON | FIFO refused (standard only) |
| **[SNS](#sns-query-protocol-durable-sqs-fan-out-probe-proven)** | Postgres + SQS fan-out | query/XML | `sqs` protocol only; FilterPolicy/`.fifo`/http refused |
| **[KMS](#kms-vault-transit-backed-json-protocol-probe-proven)** | Vault Transit | JSON 1.1 | symmetric only; grants/key-policies refused |
| **[Secrets Manager](#secrets-manager-vaultkms-backed-json-protocol-probe-proven)** | Postgres + KMS-encrypted values | JSON 1.1 | auto-rotation + custom `KmsKeyId` refused |
| **[EventBridge](#eventbridge-kubernetesjetstream-backed-json-protocol-probe-proven)** | in-proc scheduler + JetStream/SQS delivery | JSON 1.1 | Lambda+SQS targets only; `RoleArn` refused |
| **[RDS](#rds-real-postgresql-via-cloudnativepg-query-protocol-probe-proven)** | CloudNativePG (real Postgres) | query/XML | postgres only; MultiAZ/replicas/PITR/`StorageEncrypted` refused |
| **[CloudWatch Logs](#cloudwatch-logs-postgres-backed-json-protocol-probe-proven)** | Postgres | JSON 1.1 | Logs Insights refused; retention genuinely enforced |
| **[SSM Parameter Store](#ssm-parameter-store-postgres--kms-backed-json-protocol-probe-proven)** | Postgres + KMS-encrypted SecureString | JSON 1.1 | Standard tier only; Advanced/policies refused |
| **[API Gateway (HTTP API v2)](#api-gateway-http-api-v2-two-plane-runtimelambda-proxy-probe-proven)** | Postgres + runtime HTTP→Lambda proxy | restJson1 (REST paths) | REST API v1 + non-Lambda integrations refused |
| **[CloudWatch (metrics + alarms)](#cloudwatch-metrics--alarms-postgres-backed-owned-evaluator-query-protocol-probe-proven)** | Postgres + owned alarm evaluator | query/XML | dashboards + metric-math refused; SNS actions only |
| **[Kinesis Data Streams](#kinesis-data-streams-postgres-backed-ordered-sharded-replayable-probe-proven)** | Postgres (ordered shard log) | JSON 1.1 | resharding + enhanced fan-out refused |
| **[Cognito (user pools)](#cognito-user-pools-real-rs256-jwts-probe-proven)** | Postgres + RSA-signed JWTs | JSON 1.1 | SRP / identity pools / hosted UI / MFA refused |

**IAM management** (SigV4 service `iam`) is fronted and its management ops + policy translation are live, but
it is held out of the probe-proven count above until its **live `AssumeRole`→enforcement** round-trip can run
(gated on STS enablement) — see [IAM (management API + JSON→Cedar)](#iam-management-api--jsoncedar-translation-partial-live) below.

**Still not fronted** (honest `501`, never a silent fake, until built + probed): ECS/EKS, Route 53,
SES (a `kind: EmailSender` exists), Step Functions (an owned `kind: StateMachine` engine exists), and the rest
of the AWS surface. Adding a service is one registry entry; it
graduates the same gated way — built → exercised → **proven by a probe** → counted. The shim never claims a
service it hasn't made faithful.

### S3 (faithful, proven)

`PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `HeadBucket`, `ListObjectsV2`,
`ListBuckets`, with S3-faithful ETags, headers, list XML, and error codes/statuses. `PutObject`
also **decodes aws-chunked framing** — the per-chunk size/signature wrapping an SDK adds when it
sends a trailing checksum (the AWS CLI v2 default in many paths) — so the object is stored raw, not
with the framing bytes. Guarded by a decoder unit test and a probe step that forces a chunked
upload (`--checksum-algorithm CRC32`) and asserts byte-identity.

### STS (faithful)

`aws sts get-caller-identity` — the first call most SDKs and tools make to confirm "who am I / does
auth work." It has no backend: the shim reflects the identity it already proved via SigV4 as an
open-infra-shaped ARN (`arn:openinfra:iam::open-infra:user/<name>`), so there is nothing to
translate and nothing to get subtly wrong. Any authenticated principal may call it (as on AWS).

#### AssumeRole — temporary session credentials (opt-in)

`aws sts assume-role` (and `assume-role-with-web-identity`, the IRSA-shaped workload path) mints a
faithful AWS temporary credential: an `ASIA…` access key id, a secret, and an opaque `SessionToken`,
15m–12h (1h default). The shim first checks the target `kind: Role`'s `spec.trust` (who may assume
it — a list of principals, `"*"`, or empty ⇒ nobody, fail closed); later requests signed with the
temporary credential and carrying the `SessionToken` are then authorized as principal type `Role`,
so the Role's `kind: Policy` data-plane blocks govern the session — one policy world, no parallel
authz.

The session token is **stateless by construction**: it is an AES-256-GCM sealed blob carrying the
session (role, groups, session name, caller, the temp secret, and the expiry). The shim recovers the
temp secret from the token itself to verify the request's SigV4 signature, so there is **no
server-side session store** to replicate across replicas or lose on restart — exactly how AWS STS
scales. This is opt-in and OFF until a sealing key is available (below); with no key, `AssumeRole`
answers `InvalidAction` and no session tokens are accepted, so the identity surface is unchanged.

#### Sealing-key custody (Vault) and rotation

The one piece of long-lived key material — the 32-byte AES sealing key — is **custodied in Vault**,
never in a Kubernetes Secret. The shim authenticates to Vault with its **own ServiceAccount token**
via Kubernetes auth (Vault role `aws-shim-sts`, scoped to read exactly one path,
`sts/data/signing-key`, and nothing else), the same custody discipline the encryption-key /
volume-crypto / parameter / CA reconcilers use — so nothing with cluster-wide `get secrets` can read
the key, and no static Vault credential is stored anywhere. `STS_SIGNING_KEY` (base64 AES-256)
remains an explicit dev/override fallback for setups without Vault. A missing or unreachable Vault is
non-fatal: it logs a warning and leaves `AssumeRole` disabled (fail closed).

The shim re-fetches the key from Vault periodically (`STS_KEY_REFRESH`, default 10m) and applies a
**dual-key overlap**: on a rotation the new key becomes primary (used to mint and verify) while the
previous key is retained for one window (verify only). A key rotation therefore does **not** cut
sessions minted moments before it — they remain verifiable until the previous key ages out.

**Revocation (stated plainly, not hidden).** A stateless sealed token carries no server-side session
entry to delete, so revocation works by making the shim **reject** an otherwise-valid token at verify
rather than by deleting state. The levers, in order:

- **(a) Short default TTL (1h)** bounds the exposure of any leaked session on its own.
- **(b) Per-role "Revoke sessions"** — the faithful analog of AWS's `AWSRevokeOlderSessions`. The
  session token carries its issue time (`iat`); a `kind: Role`'s `spec.revokeSessionsBefore` cutoff
  (settable to "now" from the console Role → Revoke sessions action) makes the shim reject any session
  of **that role** issued before the cutoff, while new assumes keep working. Targeted to one role, no
  global disruption, minimal state (one timestamp per role, self-pruning past expiry). The shim reads
  the cutoff off the Role on a short cache TTL, so a revoke takes effect within roughly that window,
  not instantly; a control-plane read blip serves the last-known cutoff rather than un-revoking.
- **(c) Rotating the Vault sealing key is the blunt "revoke-all"** — once the rotated-out key leaves
  the overlap window, every session it sealed (all roles and users, including the caller's own) fails
  `aead.Open` and falls closed at once. Interim / break-glass; disruptive.

Honest edge: there is still **no single-session** revoke (revoking one session of a role without the
others) — that would need a per-session `jti` deny-list, which makes verification stateful and is not
built. Size the session TTL to the blast radius you can tolerate, and use (b) to cut a role's current
sessions without a global rotation.

### Lambda (Knative Function invoke; probe-proven)

`Invoke` maps onto `kind: Function`: `POST /2015-03-31/functions/{name}/invocations` forwards the
payload to the Function's cluster-local Knative address (which drives scale-from-zero) and returns
the response, with Lambda's JSON error dialect and `X-Amz-Function-Error` semantics. Authorization
is the same impersonated `SubjectAccessReview` (invoke → `create` on `functions` — invoking runs code,
so it is a write, not a read). v1 supports `RequestResponse` (sync), `Event` (async — durably queued via
JetStream with retries + a per-function DLQ), and `DryRun`, resolving Functions in a single configured
namespace; version qualifiers and cross-namespace resolution are the flagged next steps. `probe/aws-shim-lambda.sh`
proves it live (a real SDK `Invoke` of a deployed `kind: Function` round-trips).

### AppSync (GraphQL; over open-appsync — slice 1 runs live, experimental)

AppSync's data plane *is* GraphQL-over-HTTP. A client (Amplify/Apollo with IAM auth) signs a
`POST {query, variables}` with SigV4 (service `appsync`); the shim verifies it, runs the coarse
platform-membership gate, and forwards the GraphQL body to the engine, returning the response
verbatim.

The engine is **open-appsync** (`components.openAppsync`) — open-infra's own **resolver-first,
VTL-faithful** AppSync engine, built to serve teams locked into AppSync by their resolver
investment (VTL templates, data-source wiring, `$util` helpers). It is *not* a GraphQL-over-tables
engine wearing a mask: that would be a leaky abstraction the moment a specialist writes a resolver
the underlying engine can't model. open-appsync is on its own **graduation ladder** (slice 1 = VTL
over one DynamoDB-style data source; subscriptions-over-JetStream is rung 2). **Slice 1 runs live
end-to-end** — a SigV4-signed `createTodo` mutation then `getTodo` query round-trips through the shim
→ open-appsync → a real VTL resolver (autoId + DynamoDB typed marshalling) → the data source → `{data}`
(verified on-cluster). The runtime is **behavior-faithful**: `$util`/VTL and the JS runtime are diffed in
CI against goldens **captured from a live AWS AppSync account** (via the `evaluate-mapping-template` /
`evaluate-code` APIs), not just AWS's *documented* behavior. The runtime covers subscriptions over
WS + JetStream, JS/pipeline resolvers, additional data-source types, and a Stage-2 management wire
protocol. What stays open — hence "broader parity experimental" — is a
subscription node-kill chaos streak, per-source fidelity captures, and the authoring-plane rung. See the
current parity map in [open-appsync/README.md](../open-appsync/README.md).

Authorization stays "one policy world": the shim authenticates (SigV4 → principal) and runs the
coarse impersonated `SubjectAccessReview` gate; because open-appsync is our own engine, the shim
conveys the verified principal as the engine's auth context (`X-OpenInfra-User`) and open-appsync
enforces fine-grained (per-resolver/field) authz internally against the same principals — no foreign
admin secret, no vendor-specific role header. Client headers are never forwarded (a fresh upstream
request), so no identity/role/secret header can be smuggled to the engine.

With `components.openAppsync` disabled the `appsync` service returns `502` (no engine to route to).

**Authoring (data plane vs management plane).** The shim fronts the AppSync **data plane** (running
GraphQL) *and*, at `/v1/...`, the AppSync **management plane** — told apart by path (both sign for the
SigV4 service `appsync`). Authoring the API natively is **`kind: GraphQLApi`** (one object carrying
inline data sources + resolvers, each declaring a `runtime` and its templates), rendered with no
bespoke controller; a resolver author's VTL is byte-for-byte identical there — zero retraining.

The AWS **management** wire protocol (Stage 2) is the compatibility skin: it translates AWS management
verbs into a **patch on the neutral `GraphQLApi` object**, so AWS tooling (CloudFormation, CDK,
`aws appsync ...`) can drive open-infra unchanged. The skin owns AWS's `(apiId, typeName, fieldName)`
identity mapping (apiId = `<namespace>.<name>`); the neutral kind never learns AWS's addressing. It
graduates **per verb**, like every shim service — proven so far (front door + negatives):
`CreateResolver`, `UpdateResolver`, `DeleteResolver`, `GetResolver`, `CreateDataSource`,
`DeleteDataSource`. An unhandled verb answers an honest `NotImplemented`. The caller is gated by the
same impersonated `SubjectAccessReview` as every other front door (`update graphqlapis` in the target
namespace). This is **not** "AppSync management API compatible" — it is exactly the verbs listed.
Native/neutral model first; AWS door second. See [open-appsync/README.md](../open-appsync/README.md).

**Honest limitations (flagged, not hidden):**

- **Authorization is coarse in v1.** The read-vs-write gate is a *real* impersonated
  `SubjectAccessReview` (readers get read-only S3; powerusers/admins get read-write), but it is
  **bucket-agnostic** — open-infra has no per-bucket RBAC resource yet, a gap the platform already
  tracks for object storage. Per-bucket authorization (a `kind: Bucket` or a boundary addition) is
  the next graduation.
- **Single MinIO identity.** The shim acts to MinIO as one scoped, non-root service account.
  Per-principal MinIO users with per-bucket policies are the graduation that pairs with per-bucket
  authorization.
- **Path-style only**, header-auth only (no presigned URLs yet), no multipart upload yet.

Each new operation or service graduates the same gated way the chaos-oracle adapters do: built →
exercised → proven by the probe → counted.

### DynamoDB (FerretDB + documentdb Postgres transactions)

The DynamoDB front door speaks the **AWS JSON protocol** (`X-Amz-Target: DynamoDB_20120810.<Op>`) over
**FerretDB** (a MongoDB wire front end on a `documentdb`-extension Postgres). Supported: `CreateTable`,
`DescribeTable`, `GetItem`, `PutItem`, `DeleteItem`, `Query` (key-condition + filter + sort +
pagination), `UpdateItem` (update + condition expressions), `Scan`, `BatchGetItem`, `BatchWriteItem`
(capped at DynamoDB's 100/25 limits), **`TransactWriteItems`** (atomic Put/Update/Delete +
`ConditionExpression`), **`TransactGetItems`** (consistent multi-item snapshot), and
**`UpdateTimeToLive`/`DescribeTimeToLive`**. It runs live — the full wire path is exercised by
integration round-trips (`dynamo_integration_test.go`, `-tags integration`).

**Transactions:** FerretDB has no Mongo transactions, so the whole transaction surface drops to the
documentdb Postgres *behind* FerretDB — one `BEGIN/COMMIT` over the same `documentdb_api` calls, with
in-transaction reads (a condition/update sees the txn's own consistent state) and `TransactGetItems` on a
`REPEATABLE READ` snapshot; a failed `ConditionExpression` rolls the whole transaction back with per-item
`CancellationReasons` (needs `MONGO_PG_URI`). **TTL:** a background reaper sweeps expired items (DynamoDB
TTL is an epoch *number*, which a Mongo Date-only TTL index cannot act on). Declared `kind: Table` objects
are registered from their spec-mirror ConfigMaps, so a cfn-/GitOps-applied table is usable without a runtime
`CreateTable`. Refused loudly, not faked (`501`): `ProjectionExpression`, `ListTables`, `DeleteTable`, and
streams. Needs `MONGO_URI` (+ `MONGO_PG_URI` for transactions).

### SQS (Postgres-backed; probe-proven)

The SQS front door speaks the **AWS JSON protocol** (`X-Amz-Target: AmazonSQS.<Op>`, what current
SDKs and the aws CLI v2 use). Supported: `CreateQueue`, `GetQueueUrl`, `GetQueueAttributes`,
`SetQueueAttributes`, `DeleteQueue`, `ListQueues`, `SendMessage`, `SendMessageBatch`, `ReceiveMessage`,
`DeleteMessage`, `DeleteMessageBatch`, `ChangeMessageVisibility`, `PurgeQueue`.

**Backend: Postgres, not JetStream — a deliberate decision.** JetStream is already deployed and is the
obvious first thought, but SQS's **ReceiptHandle** is a correctness-and-security boundary: a handle is
issued per receive, and a *stale* handle must never delete a message that has since been redelivered to
another consumer (that would be silent data loss). Over a row-locked SQL table this is structural — the
handle is regenerated in the same `UPDATE ... FOR UPDATE SKIP LOCKED` that claims the message, so an old
handle simply matches no row on delete. Visibility timeout, per-message `ChangeMessageVisibility`
(including `0` = immediate redeliver), `ApproximateReceiveCount`, and `maxReceiveCount`→DLQ all fall out
of the same table. JetStream's connection-held ack model does not map cleanly onto SQS's *stateless*
receive-handle-then-later-delete flow, and engineering an unforgeable, stale-rejecting handle across
separate HTTP requests is exactly the kind of subtlety that ships a false green. Cost: one small,
dedicated CNPG Postgres (the shim's own state, never a customer DB). What Postgres does **not** give vs
JetStream — native push/fan-out — SQS does not need (it is poll-based; fan-out is SNS's job).

Faithful semantics: `MD5OfMessageBody` and `MD5OfMessageAttributes` are computed exactly as AWS defines
them (SDKs verify both); long polling (`WaitTimeSeconds`) returns an **empty success**, not an error;
`ReceiveMessage`'s `VisibilityTimeout`/`MaxNumberOfMessages` overrides and the queue defaults are both
honored; a `RedrivePolicy` genuinely moves a message to its DLQ after `maxReceiveCount` receives, with
`ApproximateReceiveCount` observable. Authorized through the one policy world — coarse SAR plus Cedar
`dataPlane` at **queue** granularity, with `sqs:ReceiveMessage` separable from `sqs:DeleteMessage` (a
receive-but-not-delete consumer is a real configuration).

**Deliberate divergences (refused honestly, never faked):**
- **FIFO** (`.fifo`) queues are refused at `CreateQueue` — the group-ordering + dedup contract is not
  implemented, and a FIFO queue that isn't FIFO is worse than an absent one.
- The **legacy query protocol** is refused — current SDKs use JSON.
- Standard queues are **at-least-once and unordered**, as AWS's are (we are not stronger than AWS).
- One shim replica today; the RBAC/data path is single-writer (matches the shim's overall posture).

`probe/aws-shim-sqs.sh` proves it end to end: send→receive→delete with both MD5s verified; a
received-but-not-deleted message **redelivers** after its visibility timeout (`ApproximateReceiveCount`
grows); a **stale ReceiptHandle is rejected**; `maxReceiveCount` **dead-letters** a message that is then
receivable on the DLQ; long-poll returns an empty success; and the negatives — wrong secret →
`SignatureDoesNotMatch`, and a receive-only principal **denied** `DeleteMessage` while still able to
receive.

### SNS (query protocol; durable SQS fan-out; probe-proven)

The SNS front door speaks the AWS **query protocol** (form-encoded request, XML response) — unlike SQS's
JSON. Supported: `CreateTopic`, `DeleteTopic`, `ListTopics`, `Get`/`SetTopicAttributes`, `Subscribe`,
`Unsubscribe`, `List`/`ListSubscriptionsByTopic`, `Get`/`SetSubscriptionAttributes`, `Publish`.

Its core value is the canonical AWS pattern — a topic **fanning out to N SQS queues** — and it is
**durable by construction**: `Publish` inserts the (enveloped) message into each subscribed queue via the
SQS store *before* it returns, so a returned `MessageId` always means the message was persisted for every
current subscription. It is never the fire-and-forget publish SNS makes easy. Delivery uses the default
**wrapped envelope** (`Type`, `MessageId`, `TopicArn`, `Message`, `Timestamp`, `UnsubscribeURL`), or the
bare payload when a subscription sets `RawMessageDelivery=true`. Authorized through the one policy world;
`sns:Subscribe` is **separable from `sns:Publish`** — Subscribe points the platform's outbound delivery
at a destination and is independently grantable.

**Deliberate divergences, refused honestly (never accepted-and-dropped):**
- v1 supports the **`sqs`** subscription protocol only. `lambda`, `http`/`https` (an egress surface that
  needs a confirmation handshake + destination allowlist), `email`, `sms`, `application`, `firehose` are
  refused at `Subscribe` — a subscription that exists but never delivers is worse than a rejected one.
- **Message `FilterPolicy`** is refused (accepting-and-ignoring would deliver messages a subscriber
  explicitly filtered out — a correctness + privacy defect).
- **`.fifo` topics** are refused.
- A **topic resource `Policy`** on `SetTopicAttributes` is refused — this is a one-policy-world (Cedar),
  not a second authorization engine that would silently ignore the document.
- The delivered envelope **omits** the message `Signature`/`SigningCertURL` rather than emitting a
  meaningless one — subscribers cannot cryptographically verify, and the docs say so rather than teach a
  false "verified".

`probe/aws-shim-sns.sh` proves it: one topic with **two** SQS subscriptions delivers to **both**; the
default wrapped envelope's `.Message` is the published body while `RawMessageDelivery=true` yields the
bare payload; a `FilterPolicy` and an `https` subscription are both **refused**; and the negatives —
wrong secret → `SignatureDoesNotMatch`, and a **publish-only principal (granted `sns:Publish` via Cedar)
is denied `sns:Subscribe`** while still able to publish.

### KMS (Vault Transit-backed; JSON protocol; probe-proven)

The KMS front door speaks the AWS **JSON protocol** (`X-Amz-Target: TrentService.<Op>`). A customer master
key (CMK) is a **HashiCorp Vault Transit key** named `kms-<keyId>`; the shim performs every cryptographic
operation *in Vault* and the key material **never leaves it**, so the trust boundary is exactly Vault's,
not this process's. The shim reaches Transit with its **own** ServiceAccount token (k8s-auth role
`aws-shim-kms`, whose Vault policy is scoped to the `kms-*` key prefix only — it cannot touch the
platform's encryption/volume-crypto keys). CMK **metadata** (lifecycle state, description, rotation flag,
aliases) lives in the shared SQS/SNS Postgres; only the metadata, never key bytes.

Supported: `CreateKey`, `DescribeKey`, `ListKeys`, `Create`/`Update`/`Delete`/`ListAliases`, `Encrypt`,
`Decrypt`, `GenerateDataKey`(`WithoutPlaintext`), `GenerateRandom`, `ReEncrypt`, `Enable`/`DisableKey`,
`Enable`/`DisableKeyRotation`, `GetKeyRotationStatus`, `ScheduleKeyDeletion`, `CancelKeyDeletion`.

Faithful semantics that matter:
- **Envelope encryption** — `GenerateDataKey` returns a plaintext data key plus its ciphertext under the CMK.
- **EncryptionContext binds cryptographically.** It is passed to Vault as AEAD **associated-data** on the
  `aes256-gcm96` cipher, so a `Decrypt` with a different (or absent) context **fails the tag check** —
  never a silent accept. This is the property emulators most often fake.
- **Lifecycle state machine** — `Disabled` and `PendingDeletion` keys refuse crypto (`DisabledException`
  / `KMSInvalidStateException`); `ScheduleKeyDeletion` enforces the 7–30 day window and
  `CancelKeyDeletion` restores the key. When the window elapses a reaper **crypto-erases** the Vault key
  (after which no ciphertext under it can ever be decrypted) and drops the metadata.
- **Rotation is rotate-safe** — `EnableKeyRotation` rotates the Transit key; ciphertext from before a
  rotation still decrypts.
- The `CiphertextBlob` is an opaque, self-describing envelope (`base64(json{v,k,c})`) carrying the key id,
  so `Decrypt` needs no `KeyId` — exactly as AWS.
- Authorized through the one policy world; **`kms:Encrypt` is separable from `kms:Decrypt`** at key
  granularity (for `Decrypt` the key is resolved from the ciphertext blob so the fine-grained check still
  scopes correctly).
- **Every operation writes a structured audit record** (`kms audit`): the resolved open-infra principal
  (the *who*, not the access-key id), the op, the key, the decision (allow/deny), and the EncryptionContext
  keys — the trail an auditor reads for AU-2/AU-9 and SC-12. It flows to Loki with the rest of the platform
  audit. `Encrypt` enforces AWS's **4 KB** plaintext limit (`ValidationException`), and a tampered or
  foreign ciphertext fails **`InvalidCiphertextException`**, never a garbage plaintext.

**Deliberate divergences, refused honestly (never silently downgraded):**
- **Symmetric only.** `CreateKey` with an asymmetric/HMAC `KeyUsage`/`KeySpec` (RSA, ECC, SIGN_VERIFY,
  GENERATE_VERIFY_MAC) is **refused** (`UnsupportedOperationException`); `Sign`/`Verify`/`GetPublicKey`/
  `GenerateMac` are not implemented. A "symmetric key masquerading as asymmetric" is precisely the
  unevaluable defect this program refuses.
- **No KMS key policies / grants.** Authorization is the shim's one policy world (RBAC + Cedar), not a
  second KMS-native resource-policy engine that would silently ignore a supplied document.
- **Automatic rotation is coarser than AWS.** Vault has no scheduled rotation, so `EnableKeyRotation`
  rotates once immediately and records the flag; it is not AWS's yearly cadence. Documented, not hidden.
- **Multi-Region keys, custom key stores, imported key material, and tags** are not implemented.

`probe/aws-shim-kms.sh` proves it over real SDK round-trips — round-trip identity, the EncryptionContext
binding (wrong **and** absent context rejected), a **tampered** ciphertext rejected
(`InvalidCiphertextException`), envelope-key decrypt, `GenerateRandom`, the disable / schedule-deletion
state machine, rotate-safety, and that the `Encrypt` **wrote an audit record naming the principal** — plus
the negatives: an asymmetric `CreateKey` refused, a wrong secret rejected on signature, and an
**encrypt-only principal (granted only `kms:Encrypt` via Cedar) denied `kms:Decrypt`** while still able to
encrypt.

### Secrets Manager (Vault/KMS-backed; JSON protocol; probe-proven)

The Secrets Manager front door speaks the AWS **JSON protocol** (`X-Amz-Target: secretsmanager.<Op>`).
Supported: `CreateSecret`, `GetSecretValue`, `PutSecretValue`, `UpdateSecret`, `DescribeSecret`,
`ListSecrets`, `ListSecretVersionIds`, `DeleteSecret`, `RestoreSecret`, `TagResource`, `UntagResource`,
`UpdateSecretVersionStage`, `GetRandomPassword`.

**The KMS relationship is real, not a wrapper.** Every secret value is encrypted through the shim's own
**KMS doorway** — under the Vault Transit key `kms-aws-secretsmanager` (the analog of AWS's
`aws/secretsmanager` managed key), with the **secret name bound as AEAD associated-data**. The value never
sits in Postgres as plaintext; a database compromise yields only ciphertext undecryptable without Vault.
A caller-supplied non-default `KmsKeyId` is **refused** (`InvalidParameterException`), never
accepted-and-ignored — the caller must not believe they chose a key we did not use.

**Versioning + staging labels are implemented faithfully** — the part most often collapsed to "latest
wins". Each `PutSecretValue` creates a new version; promoting it moves the `AWSCURRENT` label and demotes
the prior version to `AWSPREVIOUS`, so in-flight clients keep working across a switch and a new credential
can sit as `AWSPENDING` before it becomes what clients receive. Vault KV has version numbers but no staging
labels, so the label→version map is maintained in Postgres, atomically (a single transaction per move).
`GetSecretValue` honors `VersionId` or `VersionStage` and never silently falls back to `AWSCURRENT` when a
specific version was asked for. `SecretString` and `SecretBinary` are stored and returned as written —
never transcoded.

**Deletion has a real recovery window** (7–30 days, default 30): a deleted secret fails `GetSecretValue`
with `InvalidRequestException` while `RestoreSecret` still brings it back; `ForceDeleteWithoutRecovery`
skips the window. ARNs carry AWS's six-character random suffix, stable for the secret's life.

Authorized through the one policy world at **per-secret** granularity: **`secretsmanager:GetSecretValue`
is separable from `secretsmanager:DescribeSecret`** (metadata-read is a different privilege from
value-read), and a principal scoped to secret A cannot read secret B. Every operation writes a structured
`secretsmanager audit` record (principal, op, secret, version/stage, decision) → Loki. This doorway is
Vault/KMS-backed with its own path scoping; it is deliberately **not** generic read access to Kubernetes
Secrets, so it does not bypass the shim's `KEYS_NAMESPACE` boundary.

**Deliberate carve-outs, refused honestly (never silently ignored):**
- **Automatic/scheduled rotation** — `RotateSecret`/`CancelRotateSecret` are refused
  (`InvalidRequestException`). The versioning + staging machinery that *makes* rotation possible is
  implemented, but a secret reporting `RotationEnabled: true` while nothing rotates is a compliance
  false-green, so `DescribeSecret` reports `RotationEnabled: false` — the truth.
- **Custom `KmsKeyId`** — refused (see above); all secrets use the default managed key.
- **Resource policies** (`PutResourcePolicy`) — authorization is the one Cedar policy world, not a second
  engine that would silently ignore the document.

`probe/aws-shim-secretsmanager.sh` proves all of this over real SDK round-trips — exact-value read, the
`AWSCURRENT`/`AWSPREVIOUS` move, a `VersionId` read, a byte-identical `SecretBinary`, delete→refuse→restore,
honest rotation fields, `GetRandomPassword`, the audit record — plus the negatives: wrong secret rejected,
a **describe-only principal denied the value** while still seeing metadata, and an **A-scoped principal
denied secret B**.

### EventBridge (Kubernetes/JetStream-backed; JSON protocol; probe-proven)

The EventBridge front door speaks the AWS **JSON protocol** (`X-Amz-Target: AWSEvents.<Op>`) and drives
the two dominant patterns: **scheduled** invocation (cron/rate → a target on a schedule) and
**event-driven** routing (`PutEvents` → pattern-match → a target). Supported ops: `PutRule`, `DeleteRule`,
`DescribeRule`, `ListRules`, `EnableRule`, `DisableRule`, `PutTargets`, `RemoveTargets`,
`ListTargetsByRule`, `PutEvents`, `CreateEventBus`, `DeleteEventBus`, `ListEventBuses`, `TestEventPattern`.

**Invocation authority — the sharp security question, answered explicitly.** A rule target is an
instruction for the platform to invoke something *on the caller's behalf, when no one is present* — a
privilege-escalation surface. In this shim a triggered invocation runs under the **rule creator's
authority**, and `PutTargets` verifies, with the caller's live claims, that they may invoke/send to each
target — the same check they would face invoking it directly. **You cannot wire a rule to a target you
could not invoke yourself**, so a rule is not an escalation path. It is **never** the shim's own ambient
authority. A `RoleArn` on a target is refused in v1. Every fire is audited to the creating principal.
(Divergence from AWS: authority is verified at `PutTargets`, not re-checked per fire; documented, not hidden.)

**Scheduling.** `rate(N unit)` and six-field AWS `cron(min hour dom month dow year)` are parsed
deliberately — AWS cron is **not** Unix cron: it has a year field, uses `?` for "no specific value", and
numbers day-of-week **1=Sun..7=Sat**. A five-field Unix expression, or any expression that cannot be
faithfully evaluated, is **refused at `PutRule`** (`ValidationException`) rather than mis-scheduled.
Schedules are evaluated in **UTC**. An **in-process scheduler** fires due rules; rules are persisted, so it
resumes after a restart. Divergence: it is single-replica and does **not** catch up a fire that a restart
straddles — but a missed fire is logged/metered, never silent.

**Event patterns** are a real matching language, not string compare: exact-match by default, arrays as
OR-lists, nested objects, and the content filters `prefix`, `suffix`, `anything-but`, `numeric`, `exists`,
`cidr`, `equals-ignore-case`, `wildcard`. A pattern using any **other** operator is **refused at
`PutRule`** (`InvalidEventPatternException`). `TestEventPattern` uses the exact same matcher the router
uses, so it can never give a different answer.

**Targets — decided set, rest refused.** **Lambda** (delivered durably via the JetStream async invoker —
retry + dead-letter) and **SQS** (durable Postgres queue) are supported. Any other target type is
**refused at `PutTargets`**, never accepted into a rule that then silently never fires. `InputPath` and
`InputTransformer` are refused (a constant `Input` is honored); delivering a raw event to a handler
expecting a transformed one is the kind of silent shape-mismatch this refuses. Max **5 targets per rule**.

**`PutEvents`** publishes custom events (1..10 entries, 256 KB each) with per-entry `FailedEntryCount`.
The delivered event carries the AWS envelope (`version`, `id`, `detail-type`, `source`, `account`, `time`,
`region`, `resources`, `detail`); a scheduled fire carries `source: aws.events`, `detail-type: Scheduled
Event`. The `default` bus always exists; custom buses are a tenancy boundary.

Authorized through the one policy world at rule/bus granularity (`events:PutRule`, `events:PutTargets`,
`events:PutEvents`, `events:DescribeRule`, …); `DisableRule` genuinely stops the rule and `DescribeRule`
reports the true state. Structured `eventbridge audit` records (principal, op, rule, target, decision) →
Loki, including a `TargetDeliveryFailed` record for a missed delivery.

`probe/aws-shim-eventbridge.sh` proves it by observing **real effects** through an SQS sink: a
`rate(1 minute)` rule delivers **twice** (recurrence) with the correct `aws.events` envelope, `DisableRule`
**stops** it, a six-field cron fires (a five-field one is refused), an EventPattern **admits** a matching
`PutEvents` and **excludes** a non-matching one (and `TestEventPattern` agrees) — plus the negatives: wrong
secret rejected, the **escalation fence** (targeting a Lambda the caller can't invoke is refused), and a
DescribeRule-only principal denied `PutTargets`.

### RDS (real PostgreSQL via CloudNativePG; query protocol; probe-proven)

RDS is a **different shape** from the other doorways. For S3/DynamoDB/SQS the SDK call *is* the data path;
for RDS the AWS SDK touches only the **control plane** (`CreateDBInstance`, `DescribeDBInstances`,
`CreateDBSnapshot`) — once an instance exists, applications connect over the **native Postgres wire
protocol** with a normal driver and the SDK is out of the picture. So the two halves are scoped separately:

- **Data path (real Postgres, no emulation):** a DB instance is a genuine **CloudNativePG (CNPG) Cluster**
  — actual PostgreSQL, with real transactions, isolation, constraints, and the query planner. "Is this a
  real Postgres?" is answered by construction. Customer databases live in their own namespace
  (`open-infra-rds`), deliberately separate from the shim's internal SQS Postgres and from any
  platform-internal database — a multi-tenant customer DB never shares the shim's own state.
- **Control plane (query protocol, XML):** `CreateDBInstance`, `DescribeDBInstances`, `ModifyDBInstance`,
  `DeleteDBInstance`, `CreateDBSnapshot`, `DescribeDBSnapshots`, `DeleteDBSnapshot`,
  `RestoreDBInstanceFromDBSnapshot`.

**Provisioning is genuinely asynchronous.** `CreateDBInstance` returns `creating`; `DescribeDBInstances`
reports the *real* CNPG state and only reports `available` — with an `Endpoint` — once the database truly
accepts connections, so an SDK waiter works. The `Endpoint.Address` is the CNPG `-rw` Service DNS
(`<id>-rw.open-infra-rds.svc.cluster.local:5432`) — genuinely reachable and stable across restarts/failover.
The `MasterUsername`/`MasterUserPassword` genuinely become the database owner's credentials (via a
CNPG basic-auth secret) and are **never** returned by `DescribeDBInstances`.

**Snapshots and restore are real** (the highest-stakes item — a backup that has never been restored is not
a backup). `CreateDBSnapshot` is a CNPG **volumeSnapshot** Backup on the Longhorn CSI; `RestoreDB
InstanceFromDBSnapshot` bootstraps a **new** Cluster recovered from that snapshot. The probe proves it by
restoring and reading a row back from the restored copy.

**Honored capability flags** (mapped to reality, never accept-and-ignore): `DBInstanceClass` → real pod
requests/limits (an unrecognized class is **refused**, never quietly under-provisioned); `AllocatedStorage`
→ PVC size; `DeletionProtection` → actually blocks `DeleteDBInstance`; `SkipFinalSnapshot: false` +
`FinalDBSnapshotIdentifier` → really takes that snapshot before deleting.

**Refused honestly, never faked:** a non-`postgres` `Engine` (PostgreSQL only in v1); `MultiAZ: true` (a
single failure domain cannot provide multi-AZ durability — claiming it would be a dangerous false green);
read replicas; point-in-time recovery (`DescribeDBInstances` does **not** report a `LatestRestorableTime`
that cannot be honored); custom parameter groups; and **`StorageEncrypted: true`** — genuine at-rest
encryption needs per-volume LUKS key provisioning (and key propagation across snapshot/restore) that the
RDS path does not yet wire, so v1 refuses it rather than reporting `StorageEncrypted: true` over storage
that is not genuinely encrypted (that field is read directly by compliance tooling — a false one is worse
than absent). Each returns a real error at the call, not a silent downgrade.

**Authorization — and where the policy world ends.** Control-plane ops use the same one policy world as the
other front doors (coarse impersonated SubjectAccessReview on `applications` + fine-grained Cedar `rds:*`
at instance granularity; `rds:DeleteDBInstance`/`rds:RestoreDBInstanceFromDBSnapshot` independently
grantable). The shim's own ServiceAccount holds the scoped CNPG-management RBAC in `open-infra-rds`.
**But once a caller has the endpoint and credentials, they connect straight to Postgres and the Cedar
policy world is not in that path at all** — in-database authorization is Postgres's own roles and grants.
That is not a defect (it is equally true of real RDS), but it is stated plainly here rather than left as an
overclaim of "one policy world." (Operationally, because each instance mints a new CNPG cluster
ServiceAccount the Cedar corpus cannot know in advance, the control-plane authz webhook **defers those
`open-infra-rds` infra ServiceAccounts to RBAC** — CNPG's own tight per-cluster RBAC governs them — without
relaxing Cedar over users, the console, or applications.)

`probe/aws-shim-rds.sh` proves it, crossing the boundary the other probes do not: it creates an instance,
waits on the SDK's own waiter until `available`, **connects with a real `psql` client** (from an in-cluster
pod to the instance's Service DNS endpoint), writes and reads a row (proving the endpoint is genuinely
reachable and genuinely Postgres), then snapshots it, **restores the snapshot into a new instance and
verifies the row is present in the restored copy**, and confirms `DeletionProtection` blocks a delete —
plus the negatives (wrong secret; `StorageEncrypted`/`MultiAZ`/non-postgres engine refused; a describe-only
principal denied `CreateDBInstance`).

### CloudWatch Logs (Postgres-backed; JSON protocol; probe-proven)

CloudWatch Logs is where AWS SDKs, agents, and Lambda runtimes write logs **by default**, and — the real
argument for the doorway — in AWS it is where **audit evidence lands** (NIST 800-53 AU-2/AU-6/AU-9/AU-11).
The front door speaks the AWS **JSON protocol** (`X-Amz-Target: Logs_20140328.<Op>`). Supported:
`CreateLogGroup`, `CreateLogStream`, `PutLogEvents`, `DescribeLogGroups`, `DescribeLogStreams`,
`PutRetentionPolicy`, `DeleteLogGroup`, `DeleteLogStream`, `TagLogGroup`, `GetLogEvents`, `FilterLogEvents`.

**Backend decision: Postgres, not Loki.** The cluster runs Loki, but the CloudWatch Logs API contract needs
ordered byte-identical read-back with original millisecond timestamps, terminating pagination, and — the
compliance pivot — **genuine per-group retention at AWS's day granularity**, which a reaper over SQL rows
enforces exactly and Loki's global retention does not. So this API is Postgres-backed; **Loki remains the
cluster's own log/observability stack** (pod logs, the shim's own audit lines). They are deliberately
separate concerns.

**`PutLogEvents`' strict contract is enforced:** events must be **chronological** by timestamp (else
`InvalidParameterException`); timestamps are **milliseconds** since epoch; events more than 2 hours in the
future or past a group's retention are **rejected** and reported in `rejectedLogEventsInfo` (not silently
stored); batch limits (10,000 events, 1 MB, 256 KB/event) return the real error. **Sequence tokens** follow
AWS's current relaxed behavior — accepted with or without, always echoed back as `nextSequenceToken`, never
rejected on mismatch (settled this way because current SDKs no longer require them and older ones only need
the token echoed).

**Retention is enforced, so the reported number is the truth.** `PutRetentionPolicy` accepts only AWS's
fixed day set; a background reaper deletes events past each group's `retentionInDays`, and
`DescribeLogGroups` reports it — never a `retentionInDays` nothing honors (an auditor reading it for AU-11
gets the truth in both directions).

**Reads return what was written.** `GetLogEvents` returns events with their original timestamps and
messages in order, with forward/backward tokens that **terminate** (the forward token stabilizes when the
stream is exhausted, so a client loop ends). `FilterLogEvents` genuinely filters on term/quoted-phrase
matching (AND); the **JSON-selector (`{…}`) and metric-filter (`[…]`) pattern syntaxes, and the `?`/`-`
operators, are refused** (`InvalidParameterException`) rather than silently returning unfiltered data.

Authorized through the one policy world at **log-group** granularity: **`logs:PutLogEvents` (write) is
separable from `logs:GetLogEvents` (read)** — an app can emit logs it cannot read back — and a principal
scoped to group A **cannot read group B** (logs carry sensitive data; cross-tenant read is the risk).
**`logs:DeleteLogGroup` is an audit-integrity operation** (AU-9): its own audit record is marked
`AUDIT-INTEGRITY` and goes to the shim's audit sink (Loki), which the deleter cannot reach.

**Deliberate carve-outs, refused honestly:** CloudWatch Logs **Insights** (`StartQuery`/`GetQueryResults`/
`StopQuery`) — a query language that returned approximate results would be worse than absent; the
unsupported filter-pattern syntaxes above. **Lambda function logs do NOT currently land in
`/aws/lambda/<name>`** in this store — a Knative function's stdout goes to the cluster log stack (Loki), not
the CloudWatch Logs API; wiring that path is a documented next step, stated so an operator checking a
function's logs here is not surprised.

`probe/aws-shim-cloudwatchlogs.sh` proves all of this over real SDK round-trips — ordered byte-identical
read-back with original ms timestamps, out-of-order batch rejected, `FilterLogEvents` matches only the
matching event (empty pattern returns all; a JSON-selector pattern refused), pagination terminates,
retention reported truthfully (non-allowed value refused) — plus the negatives: wrong secret rejected, a
**write-only principal denied `GetLogEvents`** while still able to `PutLogEvents`, and an **A-scoped
principal denied group B**.

### SSM Parameter Store (Postgres + KMS-backed; JSON protocol; probe-proven)

The SSM Parameter Store front door speaks the AWS **JSON 1.1 protocol** (`X-Amz-Target: AmazonSSM.<Op>`)
and is where AWS SDKs, agents, and IaC read application configuration and secrets **by default** — a
hierarchical `/app/prod/db/host` name tree with versions, labels, and encrypted `SecureString` values.
Backed by the shared SQS/KMS Postgres for the name/version/label tree; `SecureString` values are genuinely
encrypted under the shim's own KMS doorway (Vault Transit key `kms-aws-ssm`, the analog of AWS's `aws/ssm`
managed key, with the parameter name bound as AEAD associated-data) — the plaintext never sits in Postgres.

Implemented, and faithful over real round-trips: `PutParameter`/`GetParameter`/`GetParameters`/
`GetParametersByPath` (recursive vs immediate-level), `DeleteParameter`(s), `DescribeParameters`,
`GetParameterHistory`, `LabelParameterVersion`, `AddTagsToResource`/`RemoveTagsFromResource`/
`ListTagsForResource`. `String`, `StringList`, and `SecureString` types; sequential integer versioning with
`Overwrite` semantics (a create on an existing name without `Overwrite` is refused `ParameterAlreadyExists`);
reads by `name`, `name:version`, and `name:label`. A `GetParameter` with `WithDecryption=false` on a
`SecureString` returns the **ciphertext verbatim** (exactly as AWS does); `WithDecryption=true` is a
**two-permission** action — additive to `ssm:GetParameter`, it is subject to a `kms:Decrypt` check on the
managed key, so a principal whose policy denies `kms:Decrypt` reads the ciphertext but is denied the
plaintext. Authorization is the one policy world: coarse impersonated `SubjectAccessReview` plus the
fine-grained Cedar dataPlane at **per-parameter / per-path-prefix** granularity (a principal scoped to
`Parameter::/app/a/*` is denied `/app/b/*`).

**Deliberate carve-outs, refused honestly:** the **Advanced tier** and **Intelligent-Tiering** (and the
parameter policies — expiration / no-change-notification — that only exist there) are refused
(`ValidationException`); Standard tier only, with the real 4 KB value cap. A caller-supplied non-default
`KeyId` on a `SecureString` is refused rather than accepted-and-ignored. This is a Vault/KMS-backed parameter
store; it is not generic read access to Kubernetes Secrets and does not bypass the shim's `KEYS_NAMESPACE`
boundary. A pre-existing `kind: Parameter` CRD models declared parameters; this doorway is the runtime AWS
API over the same store idea.

`probe/aws-shim-ssm.sh` proves all of this over real SDK round-trips — exact value at Version 1, no-overwrite
refused then overwrite→Version 2 with `:1` still returning v1 (version history), `StringList` round-trip,
`SecureString` returned as `vault:…` ciphertext without decryption and plaintext with it, `GetParametersByPath`
recursive vs immediate counts, label read-back, delete→`ParameterNotFound`, Advanced tier refused, and a
`GetParameter` audit record naming the principal — plus the negatives: wrong secret rejected, a **path-scoped
principal denied a sibling path**, and the **two-permission split** (a decrypt-denied principal reads the
ciphertext but is denied the plaintext).

### API Gateway (HTTP API v2; two-plane; runtime→Lambda proxy; probe-proven)

API Gateway is the REST/HTTP complement to AppSync that completes the AWS serverless triad — **API Gateway →
Lambda → DynamoDB**. Scoped to **HTTP API (v2)**; REST API (v1) is a much larger, deliberately refused
surface. Like RDS it splits into **two planes**:

- **Control plane** — the apigatewayv2 management API, spoken as **restJson1 over REST paths** (`POST /v2/apis`,
  `POST /v2/apis/{apiId}/routes`, …), *not* `X-Amz-Target` dispatch. `CreateApi`/`GetApi(s)`/`DeleteApi`,
  `CreateRoute`/`GetRoutes`, `CreateIntegration`, `CreateStage`/`GetStages`, `CreateDeployment`,
  `CreateAuthorizer`. Authenticated by the shared SigV4 path; authorized by the one policy world (coarse
  `SubjectAccessReview` + Cedar `apigateway:<Op>`). This is **platform-admin** authorization — who may create
  APIs. State (apis/routes/integrations/stages/authorizers) is on the shared Postgres.
- **Data plane — the runtime proxy IS the product.** A real HTTP request to the API's invoke URL is translated
  into the **API Gateway v2 proxy event** (`version`, `routeKey`, `rawPath`, `rawQueryString`, `headers`,
  `queryStringParameters`, `pathParameters`, `requestContext.http`, `body`, `isBase64Encoded`, `cookies`) and
  proxied to a Lambda (a Knative `Function`, reached cluster-locally the same way the Lambda doorway does).
  The Lambda's returned **`{statusCode, headers, body, isBase64Encoded}`** becomes the actual HTTP response;
  a 2.0 response *without* `statusCode` is the "simplified" form (the whole payload is the body, 200). Both
  payload format **2.0 (default)** and **1.0** are honored per integration. Route matching follows AWS
  precedence: more static segments win, then path variables (`{id}`), then the greedy `{proxy+}`, then the
  `$default` route; an exact method beats `ANY`.

**Two distinct auth layers, never conflated.** The control-plane check above governs *open-infra principals*
managing the API. The API's **own** request auth — a **JWT authorizer** — gates the *application's end users*
at the deployed API, a different trust domain. JWT authorizers validate a bearer token against an issuer +
audience using the **same coreos/go-oidc** JWKS-discovery + signature/issuer/audience/expiry verification the
STS web-identity path uses (tying to the OIDC IdP registry, polyhedron#136 §2). They **fail closed**: a
missing/unsigned/expired/wrong-audience token is `401`. REQUEST/Lambda authorizers are refused rather than
faked (an authorizer that admits everything is an authentication false green). **CORS** is first-class:
preflight `OPTIONS` is answered by the gateway itself, and `Access-Control-Allow-*` headers are applied to
responses.

**Invoke URL (documented divergence):** AWS uses `https://<api-id>.execute-api.<region>.amazonaws.com/`, which
would need per-API wildcard DNS + TLS. The shim returns a stable, in-cluster-routable
`…/_apigw/<api-id>/<path>` as `apiEndpoint` (the `$default` stage serves at the root; a named stage is the
leading path segment) and **also** accepts the AWS-shaped `<api-id>.execute-api.…` `Host` for a client that
overrides endpoint resolution. **Deliberate carve-outs, refused honestly:** REST API v1; non-`AWS_PROXY`
integrations (`HTTP_PROXY` etc.) refused at `CreateIntegration` rather than accepted into a route that 502s;
REQUEST/Lambda authorizers.

`probe/aws-shim-apigateway.sh` proves this end to end — a real SDK builds the API/integration/route/stage, a
real HTTP POST to the invoke URL confirms the Lambda received the faithful **2.0 event** (path parameter,
method, query, body) and that its returned payload became the HTTP response body, a **JWT authorizer**
(against a throwaway RSA OIDC issuer) **rejects missing/unsigned/expired and admits a valid** token, and a
**CORS preflight** succeeds — plus the negatives: wrong secret → signature mismatch, a `HTTP_PROXY`
integration refused, and a principal **denied `apigateway:CreateApi`** refused. The **structured
proxy-response translation** (a handler's `{statusCode, headers, body, isBase64Encoded}` → the real HTTP
status + headers, the 1.0-requires-structured rule, and upstream-error→502) is covered by the deterministic
unit tests (`apigateway_test.go`), since the public echo image the probe uses does not emit a JSON
`statusCode`; the live probe proves the event contract and the response-becomes-the-body (2.0 simplified)
path. See [`examples/apigw-lambda/`](../examples/apigw-lambda/) for the full handler contract.

### CloudWatch (metrics + alarms; Postgres-backed, owned evaluator; query protocol; probe-proven)

The other half of CloudWatch (Logs shipped above): applications and the AWS SDK emit custom metrics with
`PutMetricData`, dashboards and autoscaling read them back, and **alarms** turn a metric breach into a
notification — the operational monitoring an ops team needs to run the platform. Spoken as the AWS **query
protocol** (form request, XML response), the SNS/RDS family. Implemented: `PutMetricData`,
`GetMetricStatistics`, `GetMetricData`, `ListMetrics`, `PutMetricAlarm`, `DescribeAlarms`, `DeleteAlarms`,
`SetAlarmState`.

**Backend decision: Postgres + an owned evaluator, not Prometheus** (the same reasoning as CloudWatch Logs).
AWS alarm semantics — `EvaluationPeriods` / `DatapointsToAlarm` / `TreatMissingData` / `ComparisonOperator`
+ SNS actions — do not map onto Prometheus recording/alerting rules, and **an alarm that is created but never
evaluates is worse than absent** (the operator sees it in `DescribeAlarms` and believes they have coverage
they do not). Datapoints are SQL rows; an in-process evaluator (like the EventBridge scheduler) aggregates
each alarm over its evaluation window and transitions `OK`/`ALARM`/`INSUFFICIENT_DATA`, firing SNS
`AlarmActions` on entry to `ALARM`. `SetAlarmState` also fires actions, as AWS does.

Faithful over real round-trips: a metric's identity is **namespace + name + dimensions** (a datapoint on a
different dimension value is a different time series — never silently merged into a wrong aggregate);
`GetMetricStatistics` aggregates over the `Period` with `Average`/`Sum`/`Minimum`/`Maximum`/`SampleCount`
and **percentiles** (`ExtendedStatistics` `pNN`); `StatisticValues` (pre-aggregated min/max/sum/count) are
honored; millisecond/second timestamps as with Logs. Authorization is the one policy world at **namespace
granularity** — a tenant cannot write into or **read** another tenant's namespace (cross-tenant
`GetMetricData` is a data-exposure hole, the same shape as cross-tenant log read).

**Deliberate carve-outs, refused honestly:** dashboards (`PutDashboard`); **metric-math expressions** in
`GetMetricData` (refused rather than returning wrong math — a dashboard computing the wrong number is worse
than one that errors); and **alarm actions that are not an SNS topic** are refused at `PutMetricAlarm` rather
than accepted as an action that never fires. The alarm evaluation is a faithful approximation of AWS's
M-of-N-with-missing-data algorithm, not a byte-exact reimplementation.

`probe/aws-shim-cloudwatch.sh` proves this end to end — `PutMetricData` then `GetMetricStatistics` returns
the value aggregated correctly over the period (`Sum`/`Average`/`Maximum`/`Minimum`/`SampleCount`) with a
**dimension on a different value excluded** from the aggregate, a `p50` percentile computes, an alarm
**genuinely transitions to `ALARM`** on breaching data and **fires its SNS action** (received through the
SNS→SQS doorways), and `TreatMissingData=breaching` is honored — plus the negatives: wrong secret →
signature mismatch, and a **cross-tenant metric read is denied**.

### Kinesis Data Streams (Postgres-backed; ordered, sharded, replayable; probe-proven)

Kinesis is the **ordered, sharded, replayable** streaming primitive — deliberately distinct from the
unordered SQS and no-retention SNS doorways. Anything that needs ordered replay or multiple independent
readers of the same stream needs this, not the messaging doorways. Speaks AWS JSON 1.1
(`X-Amz-Target: Kinesis_20131202.<Op>`): `CreateStream`/`DescribeStream`/`DescribeStreamSummary`/`ListStreams`/
`DeleteStream`, `PutRecord`/`PutRecords`, `GetShardIterator`/`GetRecords`/`ListShards`, and retention changes.

**Backend decision: Postgres, not JetStream.** Kinesis's contract is strict per-shard ordering with monotonic
`SequenceNumber`s, replay within a retention window, and shard iterators that advance and report
`MillisBehindLatest`. JetStream's per-subject ordering does not map to the shard / partition-key + explicit
`SequenceNumber` contract for free, so — as with the CloudWatch doorways — SQL rows keyed `(stream, shard,
seq)` give exact control: the `SequenceNumber` is a per-shard monotonic counter (atomic, persisted → stable
across restarts), order is the seq order, and replay is a re-read from an earlier seq. A record is assigned
to a shard by a stable hash of its `PartitionKey`, so the same key always keeps its order in one shard while
different keys distribute across shards; `DescribeStream`/`ListShards` report the contiguous 2^128 hash-key
topology truthfully. Retention (default 24h, extendable) is genuinely enforced by a reaper, so the reported
`RetentionPeriodHours` is truthful (compliance-adjacent, like Logs). `PutRecords` reports partial failure
**per record** (`FailedRecordCount` + per-entry `ErrorCode`, including the real 1 MiB per-record limit), never
collapsed into a whole-request error. Authorization is the one policy world at **stream granularity** — a
tenant cannot read another tenant's stream, and read (`Get*`) is separable from write (`Put*`).

**Deliberate carve-outs, refused honestly:** resharding (`SplitShard`/`MergeShards`) — the shard count is
fixed at create (`DescribeStream` still reports the topology truthfully); enhanced fan-out
(`SubscribeToShard`) and KCL lease coordination; the shard/`SequenceNumber` mapping is the shim's own
(documented) shape, not AWS's exact 128-bit hash-range assignment (same same-key-same-shard + distribution
properties). See [`examples/kinesis-pipeline/`](../examples/kinesis-pipeline/) for a producer/consumer.

`probe/aws-shim-kinesis.sh` proves the ordering/replay semantics that distinguish this service — records with
the same `PartitionKey` return **in order with monotonic `SequenceNumber`s**, `TRIM_HORIZON` **re-reads from
the start** (replay), distinct keys **distribute across shards**, `MillisBehindLatest` is reported, and a
`PutRecords` partial failure surfaces **per record** — plus the negatives: wrong secret → signature mismatch,
a **cross-tenant stream read is denied**, and a **read-only principal is denied `PutRecord`** while still able
to read.

### Cognito (user pools; real RS256 JWTs; probe-proven)

User-pool authentication for applications whose end users sign in with Cognito. Speaks AWS JSON 1.1
(`X-Amz-Target: AWSCognitoIdentityProviderService.<Op>`). Implemented: `CreateUserPool`/`DescribeUserPool`/
`DeleteUserPool`, `CreateUserPoolClient`, `SignUp`/`ConfirmSignUp`, `AdminCreateUser`/`AdminConfirmSignUp`/
`AdminSetUserPassword`, `InitiateAuth`/`AdminInitiateAuth` (`USER_PASSWORD_AUTH` + `REFRESH_TOKEN_AUTH`),
`GetUser`/`AdminGetUser`, `GlobalSignOut`, plus each pool's **JWKS** and OIDC discovery endpoints.

**Two trust domains, not conflated.** The **control plane** (`CreateUserPool`, `CreateUserPoolClient`, the
`Admin*` ops) is privileged, SigV4-signed by an open-infra principal, authorized by the one policy world
(coarse SAR + Cedar `cognito-idp:<Op>`). The pool's **end-user auth** (`SignUp`/`InitiateAuth`/`GetUser`/
`GlobalSignOut`) is the *application's* users — unauthenticated at the SigV4 layer (the user has no AWS creds),
routed to the handler anonymously; the admin ops are refused from that path.

**The token contract is the heart, and it's real.** `InitiateAuth` returns genuine **RS256 JWTs** (id / access
/ refresh) signed by the shim's RSA key (persisted in a Secret so tokens survive a restart) and **verifiable
against the pool's JWKS** — the pool's issuer is `<shim>/cognito/<pool-id>` and its JWKS/discovery are served
there, so the API Gateway JWT authorizer (#169) and any app verify these tokens. Passwords are **bcrypt**; the
configured **password policy is genuinely enforced** at `SignUp`/`AdminSetUserPassword` (a weak password is
`InvalidPasswordException`, not silently accepted — an IA-5 false green); a wrong password is
`NotAuthorizedException`; **`GlobalSignOut` genuinely invalidates** (a per-user `tokens_valid_after` cutoff, so
every already-issued token fails verification afterward — ties to the session-revocation model of #147).

**Deliberate carve-outs, refused honestly:** **SRP** (`USER_SRP_AUTH`) and custom auth (a broken SRP handshake
looks like an app bug — refused at `CreateUserPoolClient`); **MFA** (a pool that advertises MFA it doesn't
enforce is an IA-2 false green — refused at `CreateUserPool`); identity pools; the hosted UI; Lambda triggers.
No email/SMS delivery, so `SignUp` confirmation codes aren't verified — `AdminConfirmSignUp` is the reliable
path (never claims a code was verified when it wasn't).

`probe/aws-shim-cognito.sh` proves this end to end — a pool + client; the password policy enforced at sign-up;
sign-up + confirm + `InitiateAuth` returning a JWT with faithful claims; the pool's JWKS/discovery served; **an
API Gateway JWT authorizer pointed at the pool ADMITS the issued token and rejects a garbage one** (the real
cryptographic verification, Cognito→API Gateway); `GlobalSignOut` invalidating the token — plus the negatives
(control-plane wrong secret → signature mismatch; a non-admin principal denied `AdminCreateUser`). See
[`examples/cognito-app/`](../examples/cognito-app/).

### IAM (management API + JSON→Cedar translation; partial-live)

The AWS IAM management verbs over the platform's existing `kind: Role`/`Policy`/`User` entities (SigV4 service
`iam`, query protocol). This is the API-compatible branch (Branch A): an application's existing AWS IAM
Terraform/CDK creates roles and policies against the shim. Implemented: `CreateRole`/`GetRole`/`DeleteRole`/
`ListRoles`, `CreatePolicy`/`GetPolicy`/`DeletePolicy`/`ListPolicies`, `AttachRolePolicy`/`DetachRolePolicy`/
`PutRolePolicy`/`ListAttachedRolePolicies`, `CreateUser`/`GetUser`/`DeleteUser`/`ListUsers`, the access-key
verbs, and `SimulatePrincipalPolicy`.

**One policy world, no second engine.** `CreatePolicy` translates the AWS PolicyDocument through
`policyengine.ImportAWS` into the SAME Cedar statements the data plane already enforces, stored on a
`kind: Policy`'s `spec.dataPlane`. A role assumed via the STS doorway is then an **independent principal whose
authority is exactly its attached policies**, evaluated **closed / default-deny** (a role with no policy can
do nothing) — the faithful AWS model, and a deliberate departure from the additive-over-coarse-RBAC model a
User gets. The coarse k8s-RBAC gate does not apply to an assumed role (k8s RBAC is not the role's authority);
its policies are. This is the authority model of polyhedron#168/#174: the Cedar query carries the assumed
session as the principal, the shim's backend credentials are never the authorization subject (a confused
deputy would pass the allow case and fail every deny), and a session may only narrow.

**Translation fidelity is guarded, not assumed.** `ImportAWS` reports (never silently drops) anything it can't
honor, and the doorway **refuses** a policy with any unsupported part (`MalformedPolicyDocument`) rather than
storing a grant that differs from the JSON. `NotAction`/`NotResource` — which the importer drops silently —
are rejected explicitly. Deny statements translate to Cedar `forbid` (forbid overrides permit). The importer
covers S3/DynamoDB/Lambda actions + a narrow condition set (authenticated, sourceIp); anything outside that is
refused, not narrowed.

**Status: partial-live.** `probe/aws-shim-iam.sh` proves, against the deployed shim: `CreatePolicy`
(JSON→Cedar) + `CreateRole` (trust) + `AttachRolePolicy`; `SimulatePrincipalPolicy` faithful **both
directions** (allow `s3:GetObject` on the granted bucket; deny it on another bucket = resource fidelity; deny
`s3:ListBucket` = action fidelity; explicit `Deny` → `explicitDeny` = forbid fidelity — the exact Cedar query
the data plane runs for a `Role` principal); `CreateAccessKey` yields a key that authenticates; and the
negatives (wrong secret → signature mismatch, `NotAction` refused). The **live `AssumeRole`→S3 round-trip**
(the end-to-end confused-deputy detector) requires **STS to be enabled** (a Vault `sts/signing-key`, the same
operator bootstrap as KMS); until then the probe reports that one assertion as gated (exit 42) rather than
faking it. IAM is therefore not yet counted in the probe-proven service tally above.

## The compatibility probe

`probe/aws-shim-s3.sh` is the trust-earning artifact (it makes the support matrix *verified*, not
asserted). It fires **real AWS SDK** calls (`aws` CLI) at a deployed shim and asserts byte-faithful
behavior — not merely HTTP 200 — plus the two negatives that are the whole point:

- put-object → get-object returns **identical bytes** (durability, not just a 200);
- a well-formed quoted **ETag** is returned; list shows the key; path-style round-trips;
- **a valid key ID with a wrong secret is rejected** (`SignatureDoesNotMatch`) — authentication
  actually fires; naming a key is not enough (no authentication theater);
- **a reader attempting a write is denied** (`AccessDenied`) — the boundary actually fires — while
  the reader can still read.

```sh
SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-s3.sh   # e.g. behind a kubectl port-forward
```

Exit `0` = faithful, `1` = a real fidelity/enforcement failure, `42` = inconclusive (a prerequisite
was missing, so nothing was proven — neither green nor red), mirroring the chaos suite convention.

## Why in-repo, not a separate service

Things that run *inside* the platform live in the platform repo; things users pull to *talk to* the
platform live outside (the Terraform provider is correctly its own repo). The shim is server-side,
married to MinIO/IAM, and — crucially — shares the one authorization core. A separate repo or a
separate auth path would be a false-green generator and a soft way past the boundary.
