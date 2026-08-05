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
> `kind: Function`/Knative), and **AppSync** (GraphQL, over a Hasura engine). It is one optional
> AWS-shaped surface over the platform, never a core
> dependency. Breadth is a roadmap of *earned* graduations — each service built, probed, and
> counted the same gated way — never a claim of coverage. Services whose backend speaks a different
> wire protocol (e.g. DynamoDB→Mongo) are real translation work and return an honest `501` until
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
| **STS** | none (identity) | `GetCallerIdentity` | **Faithful** — reflects the SigV4-proven principal as an open-infra ARN; unit-tested |
| **Lambda** | `kind: Function` (Knative) | `Invoke` (RequestResponse) | **Built + unit-tested** — live proof pending a deployed Function |
| **AppSync** | Hasura (over managed Postgres) | GraphQL data plane (`POST {query,variables}`) | **Built + unit-tested** — needs `components.graphql`; engine + secret wiring below |
| DynamoDB, Secrets Manager, Kinesis, IAM, Bedrock, … | Postgres/FerretDB, Sealed Secrets, NATS, RBAC, Model | — | **Not fronted** — real protocol translation; returns `501` until built + probed |

Adding a service is one registry entry; it graduates the same gated way the chaos-oracle adapters
do — built → shaken out → proven by a probe → counted. The shim never claims a service it hasn't
made faithful: an unsupported service is an honest `501`, not a silent partial.

### S3 (faithful, proven)

`PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `HeadBucket`, `ListObjectsV2`,
`ListBuckets`, with S3-faithful ETags, headers, list XML, and error codes/statuses.

### STS (faithful)

`aws sts get-caller-identity` — the first call most SDKs and tools make to confirm "who am I / does
auth work." It has no backend: the shim reflects the identity it already proved via SigV4 as an
open-infra-shaped ARN (`arn:openinfra:iam::open-infra:user/<name>`), so there is nothing to
translate and nothing to get subtly wrong. Any authenticated principal may call it (as on AWS).

### Lambda (built; live proof pending)

`Invoke` maps onto `kind: Function`: `POST /2015-03-31/functions/{name}/invocations` forwards the
payload to the Function's cluster-local Knative address (which drives scale-from-zero) and returns
the response, with Lambda's JSON error dialect and `X-Amz-Function-Error` semantics. Authorization
is the same impersonated `SubjectAccessReview` (invoke → `get` on `functions`). v1 is synchronous
(`RequestResponse`) and resolves Functions in a single configured namespace; async invocation,
version qualifiers, and cross-namespace resolution are the flagged next steps.

### AppSync (GraphQL; needs the engine)

AppSync's data plane *is* GraphQL-over-HTTP. Enable the engine with `components.graphql: true` — it
stands up **Hasura** over a dedicated CloudNativePG Postgres. A client (Amplify/Apollo with IAM
auth) signs a `POST {query, variables}` with SigV4 (service `appsync`); the shim verifies it and
forwards the GraphQL body to the engine's `/v1/graphql`, returning the response verbatim (GraphQL's
`{data, errors}` shape is identical to AppSync's, so clients can't tell the difference).

Authorization is split honestly: the **shim** authenticates (SigV4 → principal) and runs a coarse
platform-membership gate; the **engine** authorizes per operation. The shim presents Hasura's admin
secret (proving it is the trusted gateway) *and* a **non-admin** `x-hasura-role` + `x-hasura-user-id`
derived from the principal — so Hasura applies that role's row/column permissions and **no caller
can act as the engine admin through the shim**. Per-group role mapping and the AppSync *management*
API (schema/resolver CRUD — schemas are managed in Hasura for now) are the flagged graduations.

**Wiring the two opt-in components:** the shim reads the engine's admin secret from a `graphql-admin`
Secret in its own namespace (optional). To connect them, copy it across once:

```sh
kubectl get secret hasura-admin -n open-infra-graphql -o jsonpath='{.data.adminSecret}' \
  | base64 -d | kubectl create secret generic graphql-admin -n open-infra-aws-shim \
    --from-file=adminSecret=/dev/stdin
kubectl rollout restart deploy/aws-shim -n open-infra-aws-shim
```

Until that secret is present the `appsync` service still runs but returns `502` (engine unreachable/
unauthorized). Auto-wiring the shared secret across the two components is a flagged follow-up.

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
shaken out → proven by the probe → counted.

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
