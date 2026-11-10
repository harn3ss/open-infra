# Serverless — `kind: Function` (scale-to-zero)

open-infra's "Lambda": declare a container that serves HTTP and Knative autoscales
it from **0→N→0** based on traffic — nothing runs (and nothing is "billed") while idle.

## Why a separate kind (vs Application)

An `Application` autoscales with an HPA, which **can't scale to zero** (min 1).
Scale-to-zero needs a request-buffering layer (Knative's *activator*) that catches
the first request, cold-starts a pod, and forwards it. That buffer is what
`Function` adds, on top of Knative Serving + net-kourier.

## Usage

```yaml
apiVersion: openinfra.dev/v1
kind: Function
metadata:
  name: api
spec:
  image: ghcr.io/me/api
  port: 8080
  scaling: { min: 0, max: 10, target: 100 }   # min 0 = scale to zero; target = concurrent req/pod
  # memory: 512Mi                              # guaranteed memory (AWS Lambda's memory-size knob)
  # timeout: 60                                # max seconds per request (AWS Lambda's timeout knob)
  # gpu: 1                                     # serverless GPU inference
  # queues: [events]                           # event-driven (injects NATS_URL + OPENINFRA_QUEUES)
  # secrets: [orders-db-app]                   # connect to an app's DB/bucket
```

`memory` (a Kubernetes quantity) is set as both the container request and limit — the analog of
Lambda's memory dial (open-infra does not couple CPU to it the way AWS does). `timeout` is Lambda's
per-invoke timeout.

### Request timeout (honoured end to end)

`timeout` is bounded to **1–900 seconds**, Lambda's own range, and is 300 when unset. As on Lambda, it
counts from when the invoke reaches the function's runtime, so starting an instance from zero (a cold
start) never spends it: a 3-second function called cold returns its result.

- **The function's own timeout.** The runtime (the Node.js, Python and .NET runtimes the platform builds)
  ends an invocation that runs past its timeout. The answer is Lambda's timeout error (`Sandbox.Timedout`,
  `Task timed out after N.NN seconds`), with that line and `Status: timeout` in its log. The context's
  remaining time (`getRemainingTimeInMillis`) counts down to it.
- **The start-up allowance.** The platform's own deadline for the request is the timeout plus 90 seconds,
  the time an instance may take to start from zero. That deadline is the revision timeout, plus the
  time-to-first-byte timeout, which Knative would otherwise leave at 300s whatever your `timeout`.
- **The shared gateway (Kourier/Envoy) idle timeout.** This is the time a request may produce **no
  bytes** at the ingress hop. Its Envoy default is 300s; the platform sets it **above** the largest
  deadline (1050s) cluster-wide, so the gateway never cuts first.
- **A function on its own image** (`spec.image`) runs no runtime of the platform's. So its timeout is the
  revision timeout itself, counted from the request's arrival, a cold start included.
- **Limits.**
  - **Node.js:** a handler that blocks the event loop past its timeout is answered with the timeout once
    the loop is free. Its result is discarded.
  - **Leftover work:** what a timed-out handler leaves running carries on in the instance until it ends.
    Lambda resets the instance instead.
  - **A runtime image of your own** (`code.runtimeImage`): it enforces the timeout if it carries the
    platform's runtime bootstrap at this version or later. An older image is ended at the platform's
    deadline instead, which is the timeout plus 90 seconds.

Declaring a timeout above 900 is **rejected at admission** (the XRD maximum), rather than accepted and
then quietly under-served.

**Telling a timeout from a failure.** A request that runs past its timeout gets **HTTP 504**: from the
runtime, with Lambda's timeout error as the body, or from the revision's queue-proxy at the platform's
deadline. The aws-shim answers both as Lambda's timeout error. A function *error* is different: it is the
function's own status (a 5xx the handler returns, or `X-Amz-Function-Error` on a direct invoke). To
attribute a 504 at the *gateway* level (a wedged stream reclaimed by the idle backstop) versus the
revision, Kourier access logging carries Envoy response flags. An operator can enable
`enable-service-access-logging` in `config-kourier` to see them.

`open-infra init function` scaffolds this. It compiles to a Knative Service with
KPA autoscaling.

## Functions are stateless (by design)

Functions **connect to** resources; they don't own them. We deliberately do NOT
let a Function provision a database or bucket:

- **Lifecycle mismatch** — a function is ephemeral; a database is durable. Tying a
  DB's lifecycle to a scale-to-zero unit means deleting the function deletes data.
- **Connection storms** — 0→N bursts open Nx connections; a raw Postgres has no
  pooling for that (the Lambda+RDS problem that forced AWS to build RDS Proxy).

So provision stateful resources on an `Application`, and either reference their
secret from the function (`spec.secrets: [<app>-db-app]`) or drive it from a queue
(`spec.queues: [...]`).

## Execution role

A function can run as an IAM role — Lambda's **execution role**. Name the role in `spec.role` (Lambda's
`Role`), and the function's code gets the role's temporary credentials: its AWS SDK finds them with no
keys configured, and every AWS call it makes is exactly as authorized as the role's policies.

```yaml
apiVersion: iam.openinfra.dev/v1
kind: Role
metadata:
  name: orders-writer
spec:
  trust: ["Service::lambda.amazonaws.com"]     # Lambda may assume it
---
apiVersion: openinfra.dev/v1
kind: Function
metadata:
  name: orders
spec:
  image: ghcr.io/me/orders
  role: orders-writer                          # or arn:aws:iam::<account>:role/orders-writer
```

The same role from the IAM API:

```sh
aws iam create-role --role-name orders-writer --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
aws iam put-role-policy --role-name orders-writer --policy-name send --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "arn:aws:sqs:us-east-1:<account>:orders"}]}'
```

- **The role** is a `kind: Role` of the function's own account: the role of that name in the function's
  namespace (where a CloudFormation stack creates the roles beside its functions), else in the account's
  IAM home (where `aws iam create-role` creates them). `spec.role` takes the role's name or its ARN; an
  ARN naming another account is refused, as AWS refuses passing another account's role.
- **Its trust policy** must name the Lambda service (`lambda.amazonaws.com`; in `spec.trust`,
  `Service::lambda.amazonaws.com`). Lambda assumes a role it is trusted with only for a function that
  names that role: no other function, and no other workload, can assume it. A trust policy may instead
  name the function's own identity, `system:serviceaccount:<namespace>:fn-<function>`. Conditions on a
  trust statement (`aws:SourceArn`, `aws:SourceAccount`, …) are not evaluated for the Lambda service yet,
  so Lambda does not assume a role whose trust policy has any: leave them out of an execution role's
  trust policy.
- **Naming a role takes `iam:PassRole` on it**, as `CreateFunction` does on AWS: creating a Function with
  `spec.role`, or changing it, is refused unless the requester may pass that role. Administrators may pass
  any role; to let someone else pass one, allow `iam:PassRole` on the role's ARN in their policy.
- **In the function**, the SDK's standard environment is set for it: `AWS_ROLE_ARN` (the role's ARN in the
  function's account), `AWS_WEB_IDENTITY_TOKEN_FILE` (a short-lived token of the function's own identity,
  renewed automatically), `AWS_ROLE_SESSION_NAME` (the function's name, so its session is
  `assumed-role/<role>/<function>`, as on Lambda), and `AWS_ENDPOINT_URL` / `AWS_ENDPOINT_URL_STS` (the
  aws-shim, where the credentials are valid). An image function also gets `AWS_REGION` and
  `AWS_DEFAULT_REGION` (the install's region); a code function keeps its runtime's. The SDK assumes the
  role on its first call and renews the credentials before they expire.
- **A code function also gets the role's credentials as Lambda hands them over**: before the handler loads,
  the runtime assumes the role with the function's token and sets `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, renewing them before they expire. So code that reads
  credentials as it loads, as some SDK v2 libraries do, works as on Lambda. They are the same role's
  temporary credentials, from the same token. If the role cannot be assumed at start, the function still
  starts, and the SDK's web-identity path is left to try. Like any web-identity session,
  the function's carries no MFA context (`aws:MultiFactorAuthPresent` is absent). `GetFunctionConfiguration`
  reports the role as the function's `Role`.
- **A role and package keys don't combine**: a function whose package is read from a bucket with static
  keys (`code.source.secret`) can't also have a role — the handler's SDK would act with those keys ahead of
  the role. Give a function with a role an image, inline code (`code.source.configMap`), or a stored
  deployment package (`code.source.package`, below).
- **A stored deployment package** (`code.source.package`) is how a CloudFormation stack's `.zip` Lambda
  runs ([Lambda .zip functions](cloudformation.md#lambda-zip-functions)):
  - The platform keeps the package, as Lambda keeps one, and names it by its SHA-256.
  - The function's pods fetch it from the aws-shim at cold start with the function's own identity, check
    the hash, and unpack it into `/var/task`. The shim serves a pod only its own function's package: the
    one its configuration was made with, so a published version keeps its own code after
    `UpdateFunctionCode`, as on Lambda.
  - No keys are involved, so it combines with a role.
- **Layers** (`code.layers`, each an S3 bucket and key) are extracted, in order, into `/opt` at cold start.
  A function with its own identity (a role or a stored package) fetches them from the aws-shim with its
  token, as Lambda fetches a function's layers itself: the role needs no access to them. The shim serves
  a function only the layers its configuration names, and only objects its account may read: its own
  buckets, or another account's whose bucket policy grants the account. Each configuration keeps its own
  layers: a published version, or the configuration a failed update leaves running, restarts with the
  layers it was made with. A function whose package is read with keys
  (`code.source.secret`) fetches its layers with those keys.

Execution roles need the aws-shim with STS enabled (its session sealing key), as `sts:AssumeRole` does.
A function without `spec.role` has no role and runs exactly as before: it reaches what it needs through
the secrets and queues it names.

## Serverless GPU

`spec.gpu: 1` makes the function GPU-backed (nvidia runtime + a GPU limit) and,
because it scales to zero, **releases the GPU when idle**. This complements
always-on `kind: Model` (instant, holds a GPU): use a GPU Function for bursty or
infrequent inference where freeing the GPU matters. Cold start includes pod
scheduling + model load. See [`docs/gpu.md`](gpu.md).

## Stream triggers (event-driven)

A function can be driven by a [`Stream`](streaming.md)'s CDC events instead of HTTP
callers — open-infra's Lambda-on-Kinesis. Add a `trigger`:

```yaml
spec:
  image: ghcr.io/me/orders-processor
  trigger: { stream: orders-cdc }   # optional: subject: cdc.orders-cdc.public.orders
```

The platform runs a small **pump** (a durable JetStream consumer) that POSTs each
change event to the function; the function cold-starts on demand and scales back to
zero when the stream is idle. Return 2xx to ack (at-least-once otherwise). Details +
the event format: [`docs/streaming.md`](streaming.md#trigger-a-function-the-lambda-on-kinesis-pattern).

## AWS Lambda invoke (via the aws-shim)

With the `aws-shim` enabled, the AWS SDK / CLI can invoke a Function by name — `aws lambda invoke`
targets `kind: Function` over its Knative address. All three invocation types are supported:

- **`RequestResponse`** (default) — synchronous: the shim forwards the payload and streams the
  function's response back; a function-side error is signalled with `X-Amz-Function-Error`.
  - **How long it runs:** the invoke runs for as long as the function's `timeout` allows (300 s when
    unset), counted from when the invoke reaches the function, so a cold start does not count. A long invoke needs a client that waits too: for example,
    `aws lambda invoke --cli-read-timeout 0`.
  - **Past the timeout:** the invoke ends as Lambda ends it, with `X-Amz-Function-Error: Unhandled` and
    `{"errorType":"Sandbox.Timedout","errorMessage":"RequestId: … Error: Task timed out after N.NN seconds"}`.
  - **`--log-type Tail`** answers the invocation's log in `LogResult`: the last 4 KB of Lambda's `START`,
    what the handler printed during that invocation (stdout and stderr), `END` and `REPORT` lines. On the
    managed runtimes the tail holds that invocation's output only, never another's. A function on its own
    image (`spec.image`) gets the `START`, `END` and `REPORT` lines alone; its output is in its log group
    (`aws logs tail /aws/lambda/<function>`). The request ID is a UUID, the handler's `awsRequestId`.
- **`Event`** (asynchronous) — the shim enqueues the payload to a durable JetStream stream and returns
  `202` immediately. A background worker delivers it to the function and waits for the function's
  `timeout` too; while the function runs, the message is kept in progress, so it is never redelivered
  mid-run. The handler gets the payload as sent, as Lambda passes it. The worker **retries** on failure
  (a function error or a timeout included), and **dead-letters** (to `lambda.dlq.<fn>`) after the delivery
  cap. It survives a shim restart and
  is shared across shim replicas. Requires the shim to have NATS; without it, `Event` is refused (`503`)
  rather than silently dropped.
- **`DryRun`** — runs the authorization check (the shared SubjectAccessReview) and returns `204` without
  invoking — a permission probe.

Every invoke needs `lambda:InvokeFunction` on the function, decided by IAM policy as for every other
front door.

**The handler's context** carries what Lambda's does on the managed runtimes (Node.js, Python, .NET):
- **The invoked ARN** (`invokedFunctionArn`, `invoked_function_arn`, `InvokedFunctionArn`): the ARN the
  caller invoked, with its version or alias qualifier. When the caller is not the aws-shim (Step
  Functions, AppSync), it is the function's own ARN, from its region and its execution role's account, or
  empty for a function with no role.
- **The version that runs** (`functionVersion`): `$LATEST` or the published version's number.
- **`ClientContext`**, when the caller passed one to a synchronous invoke (at most 3583 bytes of base64
  JSON): its `client`, `custom` and `env`.
- **`AWS_EXECUTION_ENV`** is Lambda's identifier, such as `AWS_Lambda_nodejs22.x`.
- **One difference on Node.js:** `callbackWaitsForEmptyEventLoop` is `true`, Lambda's default, but the
  response is sent as soon as the handler calls its callback, which is what Lambda does when it is
  `false`. Work the handler leaves running continues after the response, since the process is not frozen
  between invocations.

## Creating and changing functions with the Lambda API

`aws lambda create-function`, `update-function-code`, `update-function-configuration` and
`delete-function` work through the aws-shim, as do the SDKs' `CreateFunction`, `UpdateFunctionCode`,
`UpdateFunctionConfiguration` and `DeleteFunction`. Each needs its own IAM action on the function's ARN:
`lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`,
`lambda:DeleteFunction`.

```bash
aws lambda create-function --function-name orders --runtime nodejs22.x --handler index.handler \
  --role arn:aws:iam::<account>:role/orders-exec --zip-file fileb://function.zip
aws lambda update-function-code --function-name orders --s3-bucket deploy --s3-key orders/v2.zip
aws lambda update-function-configuration --function-name orders --timeout 60 \
  --environment 'Variables={STAGE=prod}'
aws lambda delete-function --function-name orders
```

- **The execution role (`--role`) is required**, as on AWS, and is checked as Lambda checks it:
  - it must be a role of your account (`Cross-account pass role is not allowed.` otherwise);
  - you need `iam:PassRole` on it;
  - its trust policy must name `lambda.amazonaws.com`, with no conditions. Otherwise the answer is
    `The role defined for the function cannot be assumed by Lambda.`
  - The same checks run when `update-function-configuration` names a role.
- **The code** is a .zip (`--zip-file`, up to 50 MB) or an S3 object (`--s3-bucket`/`--s3-key`, plus
  `--s3-object-version`), on one of the managed runtimes: `nodejs16.x` to `nodejs24.x`, `python3.8`
  to `python3.14`, `dotnet8` or `dotnet10`. These are the Node.js, Python and .NET runtimes AWS Lambda still creates
  functions on, deprecated ones included. A deprecated runtime runs as AWS provides one, as-is: its
  interpreter gets no more upstream security fixes.
  - **An S3 object is read with your permissions:** you need `s3:GetObject` on it.
  - **The package is stored as Lambda stores one:** a later change to the S3 object does not change the
    function. `CodeSha256` and `CodeSize` report the stored package.
  - **An image function** (`--package-type Image --code ImageUri=…`) runs its image instead.
  - **Runtimes follow AWS's deprecation dates:**
    - **From the deprecation date,** the console offers the runtime disabled, as the Lambda console stops
      offering it. The CLI, SDKs and CloudFormation still create and update functions on it.
    - **From the block-create date,** a new function on it is refused, as Lambda refuses it.
    - **From the block-update date,** a change to a function on it is refused too, unless the change moves
      it to a supported runtime.
    - **A function on a deprecated runtime is invoked as before,** indefinitely.

    | Runtime | Deprecated | Block create | Block update |
    |---|---|---|---|
    | `nodejs16.x` | 2024-06-12 | 2027-07-29 | 2027-08-31 |
    | `nodejs18.x` | 2025-09-01 | 2027-07-29 | 2027-08-31 |
    | `nodejs20.x` | 2026-04-30 | 2027-07-29 | 2027-08-31 |
    | `nodejs22.x` | 2027-04-30 | 2027-07-29 | 2027-08-31 |
    | `nodejs24.x` | 2028-04-30 | 2028-06-01 | 2028-07-01 |
    | `python3.8` | 2024-10-14 | 2027-07-29 | 2027-08-31 |
    | `python3.9` | 2025-12-15 | 2027-07-29 | 2027-08-31 |
    | `python3.10` | 2026-10-31 | 2027-07-29 | 2027-08-31 |
    | `python3.11` | 2027-06-30 | 2027-07-29 | 2027-08-31 |
    | `python3.12` | 2028-10-31 | 2028-11-30 | 2029-01-10 |
    | `python3.13` | 2029-06-30 | 2029-07-31 | 2029-08-31 |
    | `python3.14` | 2029-06-30 | 2029-07-31 | 2029-08-31 |
    | `dotnet8` | 2026-11-10 | 2027-07-29 | 2027-08-31 |
    | `dotnet10` | 2028-11-14 | 2028-12-14 | 2029-01-15 |

    These are AWS's dates, from Lambda's
    [runtimes page](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html); when AWS moves
    them, open-infra follows.
- **Where the function lives:** a function you create is your account's. Update and delete reach any
  function of your account, including one a CloudFormation stack made, as on AWS. A name is unique in
  the account: `ResourceConflictException` if it is taken.
- **What the answers hold:**
  - every answer is the function's configuration, as on AWS: `State` starts as `Pending` until the
    function is ready, and an update answers `LastUpdateStatus: InProgress`;
  - `GetFunction` and `GetFunctionConfiguration` report an update that failed as Lambda does:
    `LastUpdateStatus: Failed`, with `LastUpdateStatusReason` and `LastUpdateStatusReasonCode`
    (`InvalidConfiguration` for a configuration the function cannot run, `FunctionError` for code that does
    not start). The function stays `Active` while its previous configuration still serves.
    `ListFunctions` takes its state from each function's own conditions;
  - `RevisionId` names its current revision: an update that passes `--revision-id` changes only that
    revision, or answers `PreconditionFailedException`.
- **A function you create is not published on the gateway** (`expose: false`): on Lambda a function is
  reachable over HTTP only through a function URL, which open-infra does not have yet, so it is invoked
  through the Lambda API.
- **One code source and one runtime:** `UpdateFunctionCode` replaces the function's code source with the
  new package, and `UpdateFunctionConfiguration --runtime` moves a function off a runtime image of its
  own onto the managed runtime, as Lambda has only one of each.
- **Environment variables** replace the function's variables, as on AWS.
  - Lambda's reserved names are refused, and so are the ones the platform sets for the function's role,
    code and endpoints: `AWS_ENDPOINT_URL*`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
    `OPENINFRA_*`.
  - A value is any string, as on Lambda, up to Lambda's 4 KB for all of a function's variables. A
    CloudFormation stack's function takes the same values and fails on the same reserved names and limit.
- **What a function here cannot be is refused, naming the parameter, never dropped:**
  - layers;
  - tags;
  - an architecture other than `x86_64`;
  - dead-letter, KMS, file-system, image-config, code-signing, SnapStart and logging configuration, unless
    left at Lambda's default.
- **Names:** a function name here is lowercase letters, digits and hyphens, up to 63 characters.

## In a VPC

A function can be put in subnets and security groups of a VPC (`--vpc-config`, CloudFormation
`VpcConfig`), as on AWS. Its outbound traffic is then its security groups'. Its DNS goes to the VPC's
resolver, where the VPC's Route 53 Resolver DNS Firewall and query logging apply, and what its groups refuse
is recorded by the VPC's flow logs. That is how a function is egress-isolated, with every refusal recorded.
See [lambda-vpc.md](lambda-vpc.md).

## Versions and aliases

A function's published versions and aliases work as Lambda's: `aws lambda publish-version`,
`create-alias`, `update-alias` (with `--routing-config` for a weighted alias), `list-versions-by-function`,
`list-aliases`, `delete-alias`, and `delete-function --qualifier <version>`; `--publish` on
`create-function` and `update-function-code`. Invoke `<function>:<version>` or `<function>:<alias>`, and
the answer's `X-Amz-Executed-Version` names the version that ran.

- **A version** keeps the code and configuration the function had when it was published. Changing the
  function changes `$LATEST` only; a version runs what it was published with until it is deleted.
- **Publishing waits for the change to roll out:** right after an update, `publish-version` answers
  `ResourceConflictException` (an update in progress) until the new code is running, as Lambda does.
- **An alias** names `$LATEST` or a version and may send a share (0 to 1) of its invocations to one other
  version, for a canary or a blue/green switch. A version an alias names cannot be deleted.
- **Limits:** 100 versions and 50 aliases a function; a function name of up to 59 characters, since a
  version is reached at `v<version>-<name>`.
- **In the `kind: Function`** they are `spec.versions` and `spec.aliases`, which the Lambda API writes.
  Each kept version is a Knative revision at 0% of the function's traffic, so unqualified calls always
  reach `$LATEST`.
- **CloudFormation:** a stack's `AWS::Lambda::Version` and `AWS::Lambda::Alias` are recognized at plan
  and refused at deploy for now: publish and alias with the Lambda API.

## External access

Knative routes via net-kourier, whose gateway gets its own MetalLB IP. For external
URLs, point Knative's `config-domain` at that IP's sslip.io (environment-specific,
set out-of-band).

**Who can call a function.** Kourier is one gateway shared by every tenant, routing by
the request's `Host`, so it is where calls are fenced
(`platform/serverless/function-gateway-isolation.yaml`):

- **`expose: true`** (the default) publishes the function on the gateway's external
  listener: it is public, like a Lambda function URL with no auth, reachable from the
  LAN and from any pod. Set `expose: false` for a function only its invokers may call.
- **The in-cluster URL** `http://<name>.<namespace>.svc.cluster.local` (the internal
  listener, which also wakes a scaled-to-zero function) answers only the platform's
  invokers: the aws-shim (Lambda `Invoke`, API Gateway integrations, Lambda
  authorizers), Step Functions Task states, the console's Test button, the function's
  own trigger pump, GraphQLApi `lambda` data sources, and Traefik (HttpApi routes and
  Ingresses that target a function).
- **Your own code calls a function through `Invoke`** (the AWS SDK pointed at the
  aws-shim), as on AWS: it is authorized there, against the function's policy. A pod
  calling the in-cluster URL directly, even from the function's own namespace, is refused.

The activator, which buffers requests for scaled-to-zero revisions, admits requests only from the
gateway (and health probes from Knative's own autoscaler), so it is no way around this either.
