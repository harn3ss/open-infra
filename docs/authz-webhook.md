# Control-plane authorization webhook (design + spike, WIP)

> Status: **design + offline spike** on `feat/authz-webhook`. Nothing here is wired to any live
> API server. This is Phase 2 of making Cedar the platform-wide authorization authority
> ([`docs/policy-engine.md`](policy-engine.md)): the data plane (Phase 1) is built and
> live-verified; this extends the *same* engine and the *same* `kind: Policy` corpus to the
> Kubernetes control plane, through the API server's authorization-webhook interface.

## The interface (why a webhook, not admission)

Kubernetes lets the API server delegate an authorization decision to an external webhook: for a
request it cannot itself allow, or for every request when the webhook is first in the chain, it
POSTs a `SubjectAccessReview` (`authorization.k8s.io/v1`) — the principal (`user`, `groups`,
`extra`), and either `resourceAttributes` (verb, group, resource, subresource, namespace, name) or
`nonResourceAttributes` (path, verb) — and reads back `{allowed, denied, reason}`.

This is the **authorization** webhook, not an admission webhook, and the distinction is the whole
reason it can be the authority: admission fires only on writes, so it can never govern
get/list/watch; the authorization webhook is consulted for **every verb, reads included**. It sees
the same request shape RBAC sees, so a Cedar decision can be a true drop-in for an RBAC decision.

## One policy world

Control-plane statements ride the existing `kind: Policy`, in a `spec.controlPlane` block alongside
`spec.dataPlane` — never a parallel authz world. A statement is the same shape the data-plane engine
already compiles to Cedar, with a control-plane vocabulary:

```yaml
spec:
  controlPlane:
    appliesTo: ["Group::platform-admins", "ServiceAccount::open-infra-console/console-api"]
    statements:
      - { effect: Allow, actions: ["get","list","watch","create","update","delete"],
          resources: ["databases.openinfra.dev::*"] }
      - { effect: Deny,  actions: ["delete"], resources: ["databases.openinfra.dev::prod/*"] }
```

The `SubjectAccessReview` maps onto a `policyengine.Request` with no new evaluator:

| SAR field | Cedar |
|---|---|
| `user` + `groups` | principal + the groups a statement's `appliesTo` may name |
| `verb` (`get`, `create`, …) | **action** |
| `resource` + `group` | resource **type** — `databases.openinfra.dev` |
| `namespace`/`name` | resource **id** — `<namespace>/<name>` (also in context) |
| `subresource`, `apiGroup`, `apiVersion` | request **context** |
| `nonResourceAttributes` (`/healthz`) | resource type `NonResourceURL`, id = path |

So the engine's existing allow/deny/condition semantics — explicit `forbid` overriding, default-deny
— carry straight over. That is the point of Phase 1 first: the evaluator is already proven.

## Shadow first — measure divergence before deciding anything

RBAC must not leave the chain until Cedar's answer has been compared to RBAC's on **real** traffic
and every disagreement is understood. The webhook therefore ships in a **shadow** mode:

- Placed **first** in the authorization chain with `failurePolicy: NoOpinion`, it computes the Cedar
  decision for every request, **logs** `{request, cedarDecision, principal}`, and returns
  *no opinion* (`allowed:false, denied:false`) — so the real decision is still RBAC's, downstream.
- Divergence is then a log-join: where Cedar would `Deny` a request the audit log shows RBAC
  allowed (or vice-versa), that case is recorded and explained — **not tuned away**.
- Because it returns no-opinion and fails open to the next authorizer, a shadow webhook that is slow
  or down cannot break the cluster. This is the safe way to gather the evidence Phase 2 step 2 wants.

Only after the divergence set is empty-or-explained, and with explicit approval, does the webhook
switch to **enforce** mode (return the real decision) and RBAC leave the chain.

## The bootstrap problem

The authorizer must not need authorization from itself to start. Two rules make the startup
acyclic:

1. **A static allow ahead of the webhook** for the identities that must always pass: the
   `system:masters` break-glass group, the API server's own identity, and the webhook's own
   ServiceAccount (so it can read its policy corpus). These are expressed in the API server's
   authorization config *before* the webhook entry, not inside Cedar, so a broken or empty corpus
   can never lock everyone out.
2. **The corpus loads over a path the webhook does not gate.** The webhook reads `kind: Policy` via
   the API server; during the shadow/transition phase RBAC still authorizes that read, and in the
   end state the static allow for its own SA does. It serves last-known policy if the read blips
   (the same hardening the data-plane loader already has), so a control-plane read stall degrades to
   stale policy, never to "deny everything."

## Failure and availability posture

The authorizer sits in the **control-plane path**: its latency is the API server's latency and its
availability is a cluster-wide dependency. Stated decisions, to be evidenced before enforce mode:

- **Fail-closed by construction, with a hard floor.** In enforce mode a webhook error is a deny —
  except the static-allow floor above, which is evaluated by the API server, not the webhook, so an
  admin with `system:masters` can always recover a cluster whose authorizer is wedged. This is the
  emergency bypass, and it is deliberate.
- **HA.** Multiple replicas behind a Service; the API server retries; a rollout never has zero
  ready endpoints. It runs in-cluster but its manifest pins it away from the very workloads it
  gates where the platform allows.
- **Bounded latency.** Cedar evaluation is in-memory against a compiled policy set; the corpus is
  cached and refreshed, so a decision is a map lookup plus an evaluation, not an API round-trip.
- **TLS with the validated modules.** The webhook is a network service in the control-plane path,
  so its serving TLS uses the same FIPS-validated crypto as every other in-cluster service
  (a carry-forward requirement, not a new one).

## The migration surface is large and must be enumerated (observed)

Every grant RBAC makes implicitly becomes an explicit Cedar grant, or the cluster deadlocks the
moment RBAC leaves. Measured on the live cluster (read-only), the surface is concrete:

- **168** ServiceAccounts (each an implicit principal), **~130** ClusterRoleBinding subjects,
  **65** namespaced RoleBindings, against **364** ClusterRoles of grant vocabulary.
- **Cluster-admin / high-privilege holders** that must be granted explicitly first (deadlock risks):
  `system:masters` (break-glass), the `kube-apiserver` user (`system:kubelet-api-admin`),
  `velero/velero-server`, `longhorn-system/longhorn-support-bundle`, `kube-system/helm-traefik(-crd)`,
  `knative-serving/controller`, and the `crossplane:masters` group — plus the platform's own
  controllers (kubevirt, cdi, cert-manager, cnpg, mariadb-operator, metallb, nats, vault, minio) and
  the 14 Crossplane provider SAs.

This list is the true gate on removing RBAC from the chain (Phase 2 step 6): until each holder has an
explicit, reviewed Cedar grant, enforce mode is not safe. It also feeds the NIST/CIS mapping
([`policy-engine.md`](policy-engine.md) Phase 3), where the assurance that RBAC's minimal-privilege
posture used to inherit from the CIS benchmark becomes a Cedar-corpus check the project must author.

## Honest status

- [x] **Design** — this document; the SAR→Cedar model; shadow-first; bootstrap + failure posture.
- [x] **Implicit-principal enumeration** — observed on the live cluster (above), read-only.
- [x] **Webhook spike** — a server that accepts a `SubjectAccessReview`, maps it to a
      `policyengine.Request`, decides via the existing engine, and answers in shadow or enforce mode.
      Offline, unit-tested; **not wired to any API server**.
- [ ] **`kind: Policy` `spec.controlPlane`** — the XRD field + the drift-gate mirrors (a real schema
      change), and a K8s loader for it. The spike reads the block if present; the field is not yet on
      the XRD.
- [ ] **Live shadow run** — wiring the webhook into the API server authorization config on a
      throwaway/non-critical cluster first, then the real one, to record divergence. A consequential
      control-plane change, gated on explicit approval.
- [ ] **Enforce + RBAC removal** — only after divergence is understood, every implicit principal has
      an explicit grant, and the failure posture is evidenced.
