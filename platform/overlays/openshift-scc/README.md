# openshift-scc overlay

An **opt-in** kustomize overlay for **OpenShift / OKD**, whose `restricted-v2` SCC handles pod hardening
differently from vanilla Kubernetes Pod Security: it assigns each pod a UID/GID/fsGroup from the
**namespace's allocated range** and **rejects** any pod that hardcodes `runAsUser` / `runAsGroup` /
`fsGroup` to a literal outside that range.

open-infra's manifests set `runAsUser: 65532` (etc.) to satisfy *Kubernetes* PSA `restricted` — which is
correct there, but **rejected by OpenShift**. This overlay therefore does the **opposite** of the
[`restricted-psa`](../restricted-psa/README.md) overlay: it **removes** the range-constrained fields so
the SCC can inject them.

## Pick the overlay that matches your substrate

| Substrate | Overlay | runAsUser handling |
|---|---|---|
| RKE2 / SLES / hardened kubeadm (Kubernetes PSA `restricted`) | [`restricted-psa`](../restricted-psa/) | **sets** a literal (65532) to satisfy `runAsNonRoot` |
| OpenShift / OKD (`restricted-v2` SCC) | `openshift-scc` (this one) | **removes** it; the SCC injects a range UID |

Never apply both. Like its sibling, this directory is outside the root app-of-apps `include` glob, so
Argo never applies it automatically.

## What it does

Removes hardcoded `runAsUser` / `runAsGroup` / `fsGroup` (26 fields across 17 non-privileged workloads —
console, aws-shim, open-appsync, ca-issuer, iceberg-rest, trino, redis/valkey, airgap-registry/prefetch,
and every security reconciler/setup Job) via JSON6902 `remove` ops. It does **not** add
`allowPrivilegeEscalation`/`capabilities`/`seccompProfile` — the `restricted-v2` SCC defaults those.

**Verified** (2026-08-21): `kubectl kustomize … --load-restrictor LoadRestrictionsNone` renders, and no
non-exception workload retains any `runAsUser`/`runAsGroup`/`fsGroup` field in the output.

> **Not yet live-verified on OpenShift.** The OKD test cluster from the 2026-08-14 portability run was
> torn down, so SCC *admission* acceptance is not re-verified here — only that the offending fields are
> gone (which is the exact cause of the rejection that run found). Validate on a live OKD cluster before
> relying on it.

## Exceptions & upstream (same as the sibling overlay)

- Privileged host-level workloads — `audit-offsite-ship` (hostPath+root), `longhorn-host-prereq`,
  `airgap-node-registries` — are left as-is and need a **scoped custom SCC** on OpenShift (e.g. grant
  their ServiceAccount a `hostmount-anyuid`/custom SCC), not this overlay.
- Upstream **Crossplane** (hardcodes 65532) and **CloudNativePG** (10001) are Helm charts; on OpenShift
  grant their namespaces the `nonroot-v2` SCC or set chart values. Tracked as a follow-up.

## Apply (on OpenShift, after validation)

```bash
kubectl kustomize platform/overlays/openshift-scc --load-restrictor LoadRestrictionsNone | oc apply -f -
```
