# API Gateway coverage: `kind: HttpApi` vs AWS API Gateway REST (v1)

Honest coverage note for an adopter whose footprint uses **API Gateway REST APIs with stages and
deployments**. `kind: HttpApi` exists, but it is **not** an API Gateway REST-v1 abstraction — and
it is thinner than even HTTP API v2. It is a Crossplane composite that renders **one
Traefik `IngressRoute`**: a hostname, cert-manager TLS, and a list of path- (and optionally
method-) matched routes onto backends, with an optional CORS / rate-limit / WAF / JWT-authorizer
middleware chain. Its own XRD says so: *"a hostname with path routes onto backends… not an
emulator and not the AWS API Gateway wire protocol."*

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
| Routes / paths | **Covered** | as IngressRoute `PathPrefix`/`Path` matches (`Prefix`/`Exact`) |
| HTTP methods per route | **Covered** | `routes[].methods` → an IngressRoute `Method()` match; a request whose verb isn't listed doesn't match the route |
| Authorizers — JWT | **Partial (opt-in, plugin-gated)** | `spec.authorizer.jwt` validates a Bearer OIDC token against an issuer's JWKS (pair with a `UserPool`); off by default, requires a JWT Traefik plugin (see below). Lambda / IAM / Cognito-specific authorizers are **non-goals** |
| **Stages** | **Non-goal** | no stage concept — an API-Gateway control-plane construct the Ingress model doesn't back; use separate `HttpApi`s (e.g. per host) instead |
| **Deployments** (promote/rollback) | **Non-goal** | the composite renders a live route directly; promote/rollback is the GitOps/`cfn` change flow, not an in-API deployment lifecycle |
| Usage plans / API keys | **Non-goal** | per-API-key metering/quotas is an API-Gateway control-plane feature; the per-source `rateLimit` covers throttling. Front with a CDN/gateway product for keyed usage plans |
| Rate limiting / throttling | **Covered (basic)** | `spec.rateLimit` (`average`/`burst`) renders a Traefik rateLimit middleware — a per-source token bucket. Not per-API-key usage plans |
| **WAF (L7)** | **Partial (opt-in, experimental)** | `spec.waf: true` attaches a Traefik Coraza / OWASP CRS middleware. Off by default; requires the `coraza` Traefik plugin enabled on the cluster (see below) |
| Request/response mapping (VTL) | **Non-goal** | an L7 path proxy, not a transformation layer; VTL request/response mapping is not modeled (use the backend, or `GraphQLApi`'s VTL for GraphQL) |
| CORS | **Covered** | `spec.cors` (origins/methods/headers/credentials/max-age) renders a Traefik headers middleware — the API Gateway CORS-equivalent, preflight included |
| Custom domain | **Partial** | one IngressRoute host + TLS; no APIGW base-path mapping / multi-domain |
| Integrations | **Partial** | in-cluster `Function`/`Application` only; no Lambda-proxy / HTTP / AWS-service / VPC-link |

## The honest read for an adopter

If an app uses API Gateway REST as *"a hostname routing paths (and methods) to backends, with CORS,
throttling, and a JWT authorizer,"* `HttpApi` now covers that: **per-route HTTP methods, CORS,
rate limiting, and a JWT/OIDC authorizer** are all present (the authorizer opt-in and plugin-gated,
like the WAF).

What remains absent is the API-Gateway **control plane** — **stages, a deployment
promote/rollback lifecycle, per-API-key usage plans, and VTL request/response mapping** — and these
are **deliberate non-goals**, not unfinished work. They describe managing an API as a versioned,
metered product; open-infra's answer is different by design: a route is a live declarative resource
(promote/rollback is the GitOps or `cfn` change flow), throttling is per-source rather than
per-key, and transformation belongs in the backend (or, for GraphQL, in `GraphQLApi`'s VTL). This
note makes no parity claim to the contrary; the boundary is where "an HTTP front door" ends and "an
API product-management plane" begins.

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

## JWT authorizer (`spec.authorizer`)

`kind: HttpApi` can require a valid **JWT** on requests before they reach a backend — the API
Gateway JWT-authorizer equivalent — with `spec.authorizer.jwt`:

```yaml
authorizer:
  jwt:
    issuer: https://auth.example.com/realms/app   # e.g. a kind: UserPool's ISSUER_URL
    audience: [my-api]                             # optional; the aud claim must match
    required: true                                 # 401 without a valid token (default)
```

It renders a per-API Traefik middleware that validates the Bearer token against the issuer's JWKS
(`<issuer>/.well-known/jwks.json`) and attaches it to every route. **Pair it with a
[`kind: UserPool`](auth-migration.md)** as the issuer and the loop closes: the pool issues the
tokens, the authorizer verifies them.

Like the WAF, it is **opt-in and plugin-gated** — it renders a Traefik `plugin:` middleware, so it
enforces only once a JWT Traefik plugin is enabled in Traefik's static config (the same
`HelmChartConfig` shape as above). **Confirm the plugin's exact config keys against the version you
enable** before trusting enforcement — different JWT plugins name their fields differently (issuer,
JWKS URL, audience). Until the plugin is enabled, setting `spec.authorizer` renders a middleware
Traefik cannot resolve, so keep it off until then. Lambda / IAM / Cognito-specific authorizer types
are non-goals — JWT/OIDC is the one authorizer shape open-infra models.
