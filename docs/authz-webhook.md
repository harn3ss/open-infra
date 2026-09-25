# Control-plane authorization webhook (design + live)

> Status: **enforce LIVE** (merged to `main`, live-verified). This is Phase 2 of making Cedar the
> platform-wide authorization authority ([`docs/policy-engine.md`](policy-engine.md)): the data plane
> (Phase 1) is deployed and live-verified; this extends the *same* engine and the *same* `kind: Policy`
> corpus to the Kubernetes control plane, through the API server's authorization-webhook interface.
> The webhook is wired into the live k3s API server via the structured `AuthorizationConfiguration`
> (`Node → Webhook(cedar) → RBAC`) in **enforce** mode: Cedar is the authoritative authorizer for
> every SubjectAccessReview, deciding before RBAC. RBAC is **retained as a webhook-down fallback**
> (`failurePolicy: NoOpinion`), not removed — Cedar decides everything while the webhook is up; RBAC
> catches a webhook outage. Shadow mode (`AUTHZ_MODE=shadow`, log-only) remains available for
> measuring divergence on a cluster whose corpus has not been validated.

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
switch to **enforce** mode (return the real decision) — as it now has. RBAC is kept behind it as the
webhook-down fallback rather than removed (see the failure posture below); Cedar is nonetheless the
authority, deciding every request while the webhook is up.

## The bootstrap problem

The authorizer must not need authorization from itself to start. Three mechanisms make startup
acyclic and keep a broken corpus from locking out the cluster:

1. **A break-glass floor inside the webhook**, decided *before* the corpus is consulted, for the two
   identities that must always pass in enforce: the webhook's **own ServiceAccount** (auto-derived
   from the `sub` claim of its projected token — so its reads of its corpus sources are authorizable
   without the webhook, or it would deadlock on the first load) and the **`system:masters`** group
   (cluster-admin recovery through a broken/empty corpus). Scoped to exactly those — not the whole
   namespace. The `Node` authorizer sits first in the chain, so kubelet/node identities never consult
   the webhook at all.
2. **Corpus-gating.** The webhook enforces *only* once it has a non-empty corpus. With none loaded —
   a fresh cluster whose corpus is not applied yet, or a cold-start load blip — it returns no-opinion
   and **defers to RBAC** rather than denying everything. This is what makes `AUTHZ_MODE=enforce` safe
   as a committed default. A principal absent from a *non-empty* corpus is still default-denied; only
   an empty/unloadable corpus defers.
3. **Last-good serving on a read blip.** The corpus is cached; a transient read error serves the
   last-known-good snapshot (the same hardening the data-plane loader has), so a control-plane read
   stall degrades to stale policy, never to "deny everything."

## Failure and availability posture

The authorizer sits in the **control-plane path**: its latency is the API server's latency and its
availability is a cluster-wide dependency. The live posture:

- **Graceful degradation, not fail-closed.** The failure order is: Cedar decides (webhook up, corpus
  loaded) → **RBAC** decides (webhook down/timeout — `failurePolicy: NoOpinion`, or corpus not loaded —
  corpus-gating) → **break-glass** keeps `system:masters` + the webhook's own SA open through a broken
  corpus. RBAC is deliberately kept in the chain as this fallback rather than removed, so an authorizer
  outage degrades to RBAC instead of a cluster-wide lockout. (Pure RBAC removal — the fully fail-closed
  end state — is deferred until the webhook is HA; on a single replica it would brick the cluster on
  any webhook blip.)
- **Availability via the fallback, not replicas (single-node reality).** The webhook is a **single
  `hostNetwork` replica** on the control-plane node, serving loopback-only TLS (`127.0.0.1:8099`) with
  a `Recreate` rollout — deliberate: the authorizer is reached by the API server *without* depending on
  cluster networking/CNI (a CNI outage must not wedge authz), and a hostNetwork loopback port cannot be
  shared by two pods. So HA is **not** multiple replicas behind a Service; availability during a
  redeploy/outage comes from the RBAC fallback above. True multi-replica HA needs **more than one
  control-plane node** (this cluster has one) and is a tracked follow-up.
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
posture used to inherit from the CIS benchmark becomes a Cedar-corpus check the project must author —
now started as **`corpus-check`** (`console-api/cmd/corpus-check`, core in `internal/corpuscheck`):
it audits the generated corpus for `cluster-admin`-equivalent grants, wildcard-resource grants,
cluster-wide Secrets access, and privilege-escalation verbs, and can gate CI with `-strict`. Run
read-only against the live cluster it currently reports 17 `cluster-admin`-equivalent principals —
exactly the over-privilege signal the CIS benchmark used to give for free, now a generated artifact.

**AC-6 posture on those 17 (`*`-on-`*`).** They are **broad by design**, and the corpus is a faithful
mirror of their RBAC — it does not widen them. They are: `system:masters` / `crossplane:masters`
(admin groups); the GitOps engine (`argocd/argocd-application-controller`, which applies arbitrary
manifests); the Crossplane core (`crossplane-system/crossplane`, which composes arbitrary managed
resources); backup (`velero/velero-server`, which reads/writes every resource kind); chaos-mesh
(`chaos-controller-manager`/`-dashboard`/`-dns-server`, which injects faults cluster-wide); the
virtualization operators (`kubevirt-controller`/`-operator`, `cdi/cdi-operator`/`cdi-sa`); the Knative
and CNI plumbing (`knative-operator`, `kube-system/multus`); Helm install jobs (`kube-system/helm-traefik(-crd)`);
and the on-demand diagnostics collector (`longhorn-system/longhorn-support-bundle`). Reducing these is
**upstream-RBAC hardening**, not a corpus edit: scoping Cedar below a component's RBAC only takes effect
while the webhook is up (RBAC still grants the breadth on webhook-down) and risks breaking a component
on an operation it performs rarely, so any scope-down must be **traffic-observed** first, per principal.
The number is the metric to drive down over time (tracked); it is a documented, justified acceptance,
not a silent pass.

## Honest status

- [x] **Design** — this document; the SAR→Cedar model; bootstrap + failure posture.
- [x] **Implicit-principal enumeration** — observed on the live cluster (above), read-only.
- [x] **`kind: Policy` `spec.controlPlane`** — the XRD field is live with its drift-gate mirrors; the
      webhook's K8s loader unions every `kind: Policy spec.controlPlane` block with an optional compiled
      `control-plane-corpus` ConfigMap bundle (the lighter delivery for a full-cluster corpus).
- [x] **Corpus generator (`rbac-to-cedar`)** — translates the cluster's RBAC into per-principal grants
      mirroring what RBAC allows, recording faithfulness caveats where lossy; never invents a Deny.
      Hardened during the cutover: a subresource is keyed as a distinct `resource/subresource` type
      (not collapsed onto the base), and a namespace-less RoleBinding ServiceAccount subject defaults to
      the binding's namespace (both bugs had silently dropped real grants under enforce).
- [x] **Shadow run** — the divergence-measurement mode (log-only, no-opinion) is retained as
      `AUTHZ_MODE=shadow`; it was the pre-cutover baseline and stays available for validating a corpus.
- [x] **Webhook first-in-chain, ENFORCE — LIVE + verified.** Wired into the live k3s API server via the
      structured `AuthorizationConfiguration` (`Node → Webhook(cedar) → RBAC`); the webhook returns real
      Cedar decisions before RBAC. Live-verified: 0 legitimate denials in steady state, cluster healthy
      (nodes Ready, apiserver `readyz` ok, argocd Healthy). `hostNetwork` on the control-plane node,
      loopback-only TLS, `Recreate`, break-glass floor + corpus-gating (above). Manifest:
      `platform/security/manifests/authz-webhook-shadow.yaml` (`AUTHZ_MODE=enforce`). Applying the corpus
      is a deliberate, cluster-specific operator step (regenerated, not committed):
      ```
      KUBECONFIG=... go run ./cmd/rbac-to-cedar -configmap | kubectl apply --server-side -f -
      ```
- [ ] **Pure RBAC removal** — RBAC is deliberately retained as the webhook-down fallback; removing it
      entirely (fully fail-closed) is deferred until the webhook is HA, since on a single replica it
      would brick the cluster on any webhook blip.
- [ ] **Multi-replica HA** — needs more than one control-plane node (this cluster has one); the RBAC
      fallback covers the single-replica redeploy/outage gap in the meantime.
- [ ] **AC-6 scope-down of the 17 `*`-on-`*` grants** — documented + accepted as broad-by-design
      (above); reducing them is upstream-RBAC hardening driven by per-principal traffic observation, an
      ongoing effort, not a corpus edit.
