# Data-plane policy enforcement at the aws-shim: observed Cedar decisions over real SigV4

**What this is:** an honest, observed record that the aws-shim's fine-grained data-plane
authorization (Cedar-backed `kind: Policy` `spec.dataPlane`, see [`docs/policy-engine.md`](../docs/policy-engine.md))
actually decides a real request — a genuine AWS-SDK SigV4 call, made by the `aws` CLI against a
fully-deployed shim binary, denied or allowed by the engine. It is the first live milestone of
making the engine the platform authority: the engine, its shim wiring, and the loader were already
unit- and integration-tested; this is the deployed binary answering a real client.

**Rule:** no property is marked observed without a real request and its actual response captured
below; the isolated setup and what it does *not* prove are stated plainly.

**Date:** 2026-09-04.

> **Update 2026-09-04 — now rolled out and verified on the LIVE deployed front door.** The
> aws-shim is deployed (`open-infra-aws-shim`, ArgoCD-tracked) and the checks below were re-run
> against it, not a throwaway:
> - The canonical S3 probe ([`probe/aws-shim-s3.sh`](../probe/aws-shim-s3.sh)) **PASSED**:
>   byte-identical put/get, well-formed ETag, list, aws-chunked dechunking, `SignatureDoesNotMatch`
>   on a wrong secret, and the coarse write boundary (a `readers` principal denied `PutObject`,
>   still allowed `GetObject`).
> - **Data-plane deny, live:** a `powerusers` principal (coarse SAR allows the read) with a policy
>   `Deny s3:GetObject on Bucket::aws-shim-probe` got `AccessDenied` over SigV4; the shim logged
>   `"denied by an explicit forbid policy"`. With the policy removed (cache refreshed), the *same*
>   principal downloaded the object — the A/B control proving the 403 was the data-plane policy, not
>   the coarse gate. Verification artifacts (test user/key/policy/bucket) were removed; the shim
>   stays deployed.

## Setup (isolated, throwaway — the original spike)

The shim was deployed into a throwaway namespace — not the platform's opt-in `open-infra-aws-shim`
front door, which stays off — pointed at a deliberately-dead object-storage endpoint. A principal
was minted in the `powerusers` group (so the coarse SubjectAccessReview the shim runs first
*allows* object access), and a data-plane policy was attached to that principal:

```yaml
spec:
  dataPlane:
    appliesTo: ["User::pe-dp-user"]
    statements:
      - { effect: Allow, actions: ["s3:*"],        resources: ["*"] }
      - { effect: Deny,  actions: ["s3:GetObject"], resources: ["Bucket::secret"] }
```

The dead backend is the point: a request the engine *allows* proceeds and returns a backend error
(`InternalError`), while a request the engine *denies* returns `AccessDenied` before any backend
call — so a 403 unambiguously means the Cedar decision, not a storage result.

## Observed (real `aws s3api` calls over SigV4)

| # | Request | Response | What it shows |
|---|---|---|---|
| A | `get-object --bucket secret` | `AccessDenied` (403) | The explicit `Deny` on `Bucket::secret` overrides the `s3:*` `Allow` — **forbid overrides allow**, even though the coarse SAR (powerusers) permits the op. |
| B | `get-object --bucket public` | `InternalError` (dead backend) — **not** AccessDenied | The engine **allowed** it; the deny is scoped to `Bucket::secret` only — **per-resource scoping**. |
| C | `get-object` with a **wrong secret** | `SignatureDoesNotMatch` (403) | SigV4 authentication actually fires; naming a valid key id is not enough. |

Server-side, the shim recorded the decision for (A):

```json
{"level":"WARN","msg":"s3 denied by data-plane policy","user":"pe-dp-user","op":"get","bucket":"secret"}
```

### A/B control — the deny is the policy, not the coarse gate

With the data-plane policy **removed** (and the shim's 30s policy cache expired), the *same*
`powerusers` principal's `get-object --bucket secret` returned `InternalError` — **not**
`AccessDenied`. So the coarse SubjectAccessReview allowed the op all along; the 403 in (A) was the
data-plane policy and nothing else. This is the whole point of the layer: it can **tighten** within
a coarse grant (an explicit `Deny` RBAC cannot express), never widen it.

## What this does and does not prove

- **Proven, observed live:** a deployed shim binary authenticates a real SigV4 request, resolves
  the principal, and lets the Cedar engine decide — with forbid-overriding-allow and per-resource
  scoping, confirmed by both the client response and the server log, and isolated by an A/B control.
- **Not proven here:** a byte-faithful object round-trip on an *allowed* request (the backend was
  dead on purpose — that durability semantic is covered by [`probe/aws-shim-s3.sh`](../probe/aws-shim-s3.sh)).
  Per-service governance (an S3 policy leaving DynamoDB untouched) and the loader serving its
  last-good snapshot through a control-plane blip are covered by the engine's integration and unit
  tests, not re-staged as a live blip here.
- **Rollout:** the original run (above) was a throwaway; the front door is now deployed on the
  platform (see the dated update at the top). Enforcement bites only where a `kind: Policy`
  `dataPlane` block names a principal — deploying the shim makes the capability live; it governs
  nothing until a policy is authored.
