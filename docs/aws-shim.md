# AWS-SDK shim (experimental)

The AWS shim is an **AWS-shaped front door onto open-infra's real backends**. An unmodified
application built for the AWS SDK — pointed at the shim's endpoint — believes it is talking to AWS;
the shim verifies the request's SigV4 signature against an open-infra access key, resolves the
caller to their open-infra principal, enforces the **same** RBAC and permission boundary the
console and Terraform provider use, calls the real backend, and re-dresses the response in AWS's
exact byte-shape.

It is **not** an emulator. LocalStack/Floci *fake* AWS for throwaway testing; their fidelity is
bounded by what they chose to implement — the same false-green risk open-infra designs against
everywhere. The shim fronts *durable* backends, not fakes.

> **Status: experimental, opt-in, OFF by default.** The shim is a router with pluggable per-service
> handlers — one front door, many domain experts. Fronted today: **S3** (over MinIO, proven
> byte-faithful), **STS** GetCallerIdentity (identity reflection), **Lambda** Invoke (over
> `kind: Function`/Knative), **AppSync** (GraphQL, over the **open-appsync** engine — a
> resolver-first, VTL-faithful engine on its own graduation ladder; slice 1 runs live, experimental),
> and **DynamoDB** (create/read/update/delete/query/scan, the batch item APIs, **atomic
> `TransactWriteItems`**, and **TTL** — over FerretDB). It is one optional
> AWS-shaped surface over the platform, never a core
> dependency. Breadth is a roadmap of *earned* graduations — each service built, probed, and
> counted the same gated way — never a claim of coverage. Services whose backend speaks a different
> wire protocol are real translation work and return an honest `501` until
> built, not a hand-wavy stub.

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

| Service | Backend | Operations | Status |
|---|---|---|---|
| **S3** | MinIO | `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `HeadBucket`, `ListObjectsV2`, `ListBuckets` | **Faithful, proven live** — byte-identical round-trip + auth/boundary negatives (`probe/aws-shim-s3.sh`) |
| **STS** | none (identity) | `GetCallerIdentity`; `AssumeRole` + `AssumeRoleWithWebIdentity` (temporary session credentials) | **Faithful** — `GetCallerIdentity` reflects the SigV4-proven principal as an open-infra ARN; `AssumeRole` mints AES-256-GCM-sealed, **stateless** session tokens governed by the assumed `kind: Role`'s trust + data-plane policies (opt-in; sealing key **Vault-custodied**). Unit + e2e tested |
| **Lambda** | `kind: Function` (Knative) | `Invoke` (RequestResponse + `Event` async + `DryRun`) | **Built + unit-tested** — live proof pending a deployed Function |
| **AppSync** | open-appsync (resolver-first VTL engine) | GraphQL data plane (`POST {query,variables}`) | **Slice 1 runs live** (SigV4 → VTL resolver → data source → `{data}`, verified on-cluster); runtime **behavior-faithful** (goldens captured from a live AWS AppSync account, CI-green), broader parity experimental. Needs `components.openAppsync` |
| **DynamoDB** | FerretDB (Mongo-wire) + its documentdb Postgres (transactions) | `CreateTable`, `DescribeTable`, `GetItem`, `PutItem`, `DeleteItem`, `Query` (key-condition + filter + sort + pagination), `UpdateItem` (update + condition expressions), `Scan`, `BatchGetItem`, `BatchWriteItem` (capped at DynamoDB's 100/25 limits), **`TransactWriteItems`** (atomic Put/Update/Delete + `ConditionExpression`), **`TransactGetItems`** (consistent multi-item snapshot), **`UpdateTimeToLive`/`DescribeTimeToLive`** (TTL) | **Runs live** — full wire path exercised by live round-trips (`dynamo_integration_test.go`, `dynamo_transact_integration_test.go`, `-tags integration`). **Transactions:** FerretDB has no Mongo transactions, so the whole transaction surface drops to the documentdb Postgres *behind* FerretDB — one `BEGIN/COMMIT` over the same `documentdb_api` calls, with in-transaction reads (a condition/update sees the txn's own consistent state) and `TransactGetItems` on a `REPEATABLE READ` snapshot; a failed `ConditionExpression` rolls back the whole transaction with per-item `CancellationReasons` (needs `MONGO_PG_URI`). Verified live against `postgres-documentdb:17`. **TTL:** a background reaper sweeps expired items (DynamoDB TTL is epoch-number, which a Mongo Date-only TTL index can't act on). Still `501`, refused loudly not faked: `ProjectionExpression`, `ListTables`, `DeleteTable`, streams. Needs `MONGO_URI` (+ `MONGO_PG_URI` for transactions) |
| Secrets Manager, Kinesis, IAM, Bedrock, … | Sealed Secrets, NATS, RBAC, Model | — | **Not fronted** — real protocol translation; returns `501` until built + probed |

Adding a service is one registry entry; it graduates the same gated way the chaos-oracle adapters
do — built → exercised → proven by a probe → counted. The shim never claims a service it hasn't
made faithful: an unsupported service is an honest `501`, not a silent partial.

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

### Lambda (built; live proof pending)

`Invoke` maps onto `kind: Function`: `POST /2015-03-31/functions/{name}/invocations` forwards the
payload to the Function's cluster-local Knative address (which drives scale-from-zero) and returns
the response, with Lambda's JSON error dialect and `X-Amz-Function-Error` semantics. Authorization
is the same impersonated `SubjectAccessReview` (invoke → `get` on `functions`). v1 supports `RequestResponse` (sync),
`Event` (async — durably queued via JetStream with retries + a per-function DLQ), and `DryRun`,
resolving Functions in a single configured namespace; version qualifiers and cross-namespace
resolution are the flagged next steps.

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
