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
  # gpu: 1                                     # serverless GPU inference
  # queues: [events]                           # event-driven (injects NATS_URL + OPENINFRA_QUEUES)
  # secrets: [orders-db-app]                   # connect to an app's DB/bucket
```

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

## External access

Knative routes via net-kourier, whose gateway gets its own MetalLB IP. For external
URLs, point Knative's `config-domain` at that IP's sslip.io (environment-specific,
set out-of-band). In-cluster, a function is reachable at
`http://<name>.<namespace>.svc.cluster.local` — which already triggers scale-up.
