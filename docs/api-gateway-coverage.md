# API Gateway coverage: `kind: HttpApi` vs AWS API Gateway REST (v1)

Honest coverage note for an adopter whose footprint uses **API Gateway REST APIs with stages and
deployments**. `kind: HttpApi` exists, but it is **not** an API Gateway REST-v1 abstraction — and
it is thinner than even HTTP API v2. It is a Crossplane composite that renders **exactly one
Traefik `Ingress`**: a hostname, cert-manager TLS, and a list of path→backend routes. Its own XRD
says so: *"a hostname with path routes onto backends… not an emulator and not the AWS API Gateway
wire protocol."*

## What it is

`spec` surface (the whole of it):

- `domain` (required) — one hostname.
- `tls` (default true) — cert-manager TLS termination.
- `routes[]` (required) — each `{ path, pathType (Prefix|Exact), backend { kind: Function|Application, name, port } }`.

Backends are in-cluster `Function` (Knative) or `Application` Services. No gateway product (Kong /
APISIX / Envoy Gateway), no dedicated gateway pod — it is pure orchestration onto one Ingress.

## Coverage vs API Gateway REST v1

| REST-v1 feature | Status | Note |
|---|---|---|
| Routes / paths | **Covered** | as Traefik Ingress paths (`Prefix`/`Exact`) |
| HTTP methods per route | **Gap** | no `method` field; Ingress paths don't discriminate by verb |
| **Stages** | **Gap (absent)** | no stage concept in the schema |
| **Deployments** (promote/rollback) | **Gap (absent)** | the composite renders a live Ingress directly; no deployment lifecycle |
| Authorizers — JWT / Lambda / IAM / Cognito | **Gap (absent)** | no auth of any kind on the rendered Ingress |
| Usage plans / API keys | **Gap (absent)** | — |
| Rate limiting / throttling | **Covered (basic)** | `spec.rateLimit` (`average`/`burst`) renders a Traefik rateLimit middleware — a per-source token bucket. Not per-API-key usage plans (there are no API keys yet) |
| **WAF (L7)** | **Partial (opt-in, experimental)** | `spec.waf: true` attaches a Traefik Coraza / OWASP CRS middleware to the Ingress. Off by default; requires the `coraza` Traefik plugin enabled on the cluster (see below) |
| Request/response mapping (VTL) | **Gap (absent)** | L7 path proxy only; no transformation layer |
| CORS | **Covered** | `spec.cors` (origins/methods/headers/credentials/max-age) renders a Traefik headers middleware — the API Gateway CORS-equivalent, preflight included |
| Custom domain | **Partial** | one Ingress host + TLS; no APIGW base-path mapping / multi-domain |
| Integrations | **Partial** | in-cluster `Function`/`Application` only; no Lambda-proxy / HTTP / AWS-service / VPC-link |

## The honest read for an adopter

If an app uses API Gateway REST as *"a hostname routing paths to backends,"* `HttpApi` covers
that. If it relies on **stages, deployments, authorizers, usage plans/API keys, throttling, or
VTL mapping templates** — the things that make API Gateway REST *API Gateway* — those are **not
present**, and this note makes no parity claim to the contrary. The gap is acknowledged and
by-design: the XRD notes a management wire protocol "can be fronted by the shim later, on top of
this real backend."

The specific REST-v1 surface that is missing — HTTP methods, stages, deployments, all authorizer
types, usage plans/API keys/throttling, VTL mapping templates, and CORS — is filed as a scoped
follow-on so it is tracked rather than silently absent.

## In-cluster WAF (`spec.waf`)

`kind: HttpApi` can attach an in-cluster L7 web application firewall to its Ingress with
`spec.waf: true`. It renders a per-API Traefik [Coraza](https://coraza.io) middleware running the
OWASP Core Rule Set (ModSecurity-compatible), referenced from the Ingress via
`traefik.ingress.kubernetes.io/router.middlewares`. It is **off by default** and **experimental**.

**Positioning — defense-in-depth, not a CDN replacement.** The strongest edge WAF/DDoS story remains
a CDN in front (open-infra's documented path is BYO-Cloudflare, which provides edge TLS, WAF, and
rate limiting). In-cluster Coraza is for apps that are *not* fronted by such a CDN, or as a second
layer behind one — it inspects L7 requests at the Ingress, which a network SecurityGroup (an L3/L4
Cilium policy) cannot do.

**Prerequisite — enable the Coraza Traefik plugin.** The middleware only functions once the `coraza`
plugin is loaded into Traefik's static configuration. On k3s, apply a `HelmChartConfig` (confirm the
plugin module path and a current version against the plugin's releases before applying — a bad module
reference will fail Traefik startup):

```yaml
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    experimental:
      plugins:
        coraza:
          moduleName: github.com/coreruleset/coraza-http-wasm-traefik
          version: <a released version>
```

This is an operator step (it restarts Traefik) and is intentionally **not** shipped as a live
manifest — a wrong module reference would take down cluster ingress. Until the plugin is enabled,
setting `spec.waf: true` renders a middleware Traefik cannot resolve, so keep it off until then.
