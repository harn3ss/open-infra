# Distributed tracing

open-infra ships **metrics** (Prometheus + Grafana), **logs** (Loki + promtail), and now
**distributed tracing** — the AWS X-Ray-shaped signal: a single request stitched across the
gateway → service → data source into one trace. It is **experimental**, opt-in per service, and
built on the existing Grafana stack.

## What exists

| AWS | open-infra | Kind of signal |
|---|---|---|
| CloudWatch metrics | Prometheus + Grafana | metrics |
| CloudWatch Logs | Loki (+ promtail) | logs |
| CloudTrail | k8s audit log → Loki | audit events |
| **X-Ray** | **Grafana Tempo (OpenTelemetry)** | **distributed traces** |

## The three pieces

1. **Trace backend** — Grafana **Tempo** (`platform/observability/tempo.yaml`), a single-binary
   deployment with filesystem storage in the `monitoring` namespace, receiving spans over **OTLP**
   (`:4317`/`:4318`) and **Zipkin** (`:9411`). A Tempo datasource is provisioned in Grafana
   (`kube-prometheus-stack.yaml`), with trace-to-logs correlation pointing at the Loki datasource,
   so traces are queryable in Grafana → Explore alongside metrics and logs.
2. **Knative request tracing** — the `KnativeServing` config sets `tracing.backend: zipkin` →
   Tempo's Zipkin receiver (`platform/serverless/knative-serving.yaml`), so every `kind: Function`
   gets per-request spans through the activator / queue-proxy at a 10% sample rate.
3. **First-party service instrumentation** — the console BFF, the aws-shim, and open-appsync are
   instrumented with the OpenTelemetry Go SDK: an `otelhttp` handler wraps each server (inbound
   server spans) and **W3C `traceparent`** propagation is always installed, so a trace flows from
   the shim into open-appsync and stitches end to end. Spans export over OTLP/gRPC to Tempo.

## Enabling / disabling it

Service instrumentation is **opt-in via `OTEL_EXPORTER_OTLP_ENDPOINT`**: the platform manifests set
it to Tempo's OTLP receiver (`http://tempo.monitoring.svc.cluster.local:4317`; the `http://` scheme
selects an insecure in-cluster gRPC connection). Unset it on a service's Deployment to turn tracing
off for that service — with it unset the OpenTelemetry handlers add negligible overhead and no
exporter runs. W3C `traceparent` is honored either way, so an inbound trace context is never
dropped.

## Honest scope

What's instrumented today: inbound HTTP server spans on the three first-party Go services, W3C
context propagation, and Knative per-request Function spans. What's deliberately not yet built:
fine-grained child spans inside resolvers / data-source calls (DynamoDB/FerretDB, MinIO), automatic
`traceparent` injection on *every* outbound hop (the SDK propagator is installed; not every internal
client wraps its transport yet), tail-based sampling, and long-term trace retention tuning (Tempo is
on a local PVC, 7-day retention, like Loki — graduate to the MinIO S3 backend for scale). These are
incremental additions on the now-present pipeline, not a rebuild.
