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
| Rate limiting / throttling | **Gap (absent)** | no Traefik rate-limit middleware emitted |
| Request/response mapping (VTL) | **Gap (absent)** | L7 path proxy only; no transformation layer |
| CORS | **Gap (absent)** | — |
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
