# Distributed tracing — status: not shipped

Honest answer to "does open-infra have an AWS X-Ray equivalent?": **no.** open-infra ships
**metrics** (Prometheus + Grafana) and **logs** (Loki + promtail). It does **not** ship
distributed tracing — there is no OpenTelemetry, Tempo, Jaeger, or Zipkin component, Knative
request-tracing is left at its default (`backend: none`), and no first-party service emits or
propagates trace context. This was verified by a repo-wide survey, not assumed.

## What exists instead

| AWS | open-infra | Kind of signal |
|---|---|---|
| CloudWatch metrics | Prometheus + Grafana | metrics |
| CloudWatch Logs | Loki (+ promtail) | logs |
| CloudTrail | k8s audit log → Loki | audit events |
| **X-Ray** | **— (nothing) —** | **distributed traces** |

Metrics and logs answer "how much / how often" and "what happened"; they do **not** stitch a
single request across Function → API → data source into one trace. If an app relies on X-Ray to
follow a request end to end, that capability is absent here today.

## The wire-up path (not currently done)

Distributed tracing is a bounded, well-trodden addition on top of the existing Grafana stack —
it just is not built yet. It would take three pieces:

1. **A trace backend** in `platform/observability/` — Grafana **Tempo** fits the existing
   Grafana/Prometheus/Loki stack most cleanly (single Grafana datasource alongside metrics and
   logs); Jaeger or an OTel Collector are alternatives.
2. **Knative request tracing** — Knative Serving natively supports it via the `config-tracing`
   ConfigMap (`backend: opentelemetry`/`zipkin` + the collector endpoint). Today
   `platform/serverless/knative-serving.yaml` sets no `tracing:` block, so it stays at the
   upstream default of `none`. Turning it on gives per-request spans through the activator /
   queue-proxy path for every Function.
3. **Service instrumentation** — add the OpenTelemetry SDK + W3C `traceparent` propagation to the
   first-party Go services (console-api BFF, open-appsync) so the request path stitches end to end
   rather than starting at the gateway.

All three are greenfield; none exists today.

## For a pilot that needs X-Ray

If a prospective app depends on distributed tracing, this is a **known, scoped gap** — not a
hidden one. It is filed as its own follow-on (the Tempo + Knative-tracing + OTel-instrumentation
build above) rather than claimed as present. Nothing in open-infra should be read as implying an
X-Ray-equivalent exists.
