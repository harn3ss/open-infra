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
Lambda's memory dial (open-infra does not couple CPU to it the way AWS does). `timeout` becomes the
Knative revision timeout — the analog of Lambda's per-invoke timeout.

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
- **`Event`** (asynchronous) — the shim enqueues the payload to a durable JetStream stream and returns
  `202` immediately; a background worker delivers it to the function, **retries** on failure, and
  **dead-letters** (to `lambda.dlq.<fn>`) after the delivery cap. It survives a shim restart and
  is shared across shim replicas. Requires the shim to have NATS; without it, `Event` is refused (`503`)
  rather than silently dropped.
- **`DryRun`** — runs the authorization check (the shared SubjectAccessReview) and returns `204` without
  invoking — a permission probe.

Every invoke is authorized through the one policy world (a SAR: `get` on the `functions` resource), the
same boundary as every other front door. Management APIs (`CreateFunction`, versions/aliases, layers)
are deliberately not fronted — Functions are managed declaratively as `kind: Function`.

## External access

Knative routes via net-kourier, whose gateway gets its own MetalLB IP. For external
URLs, point Knative's `config-domain` at that IP's sslip.io (environment-specific,
set out-of-band). In-cluster, a function is reachable at
`http://<name>.<namespace>.svc.cluster.local` — which already triggers scale-up.
