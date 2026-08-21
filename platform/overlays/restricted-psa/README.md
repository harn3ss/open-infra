# restricted-PSA overlay

An **opt-in** kustomize overlay that adds a restricted-`PodSecurity`-conformant `securityContext` to
open-infra's own setup Jobs and reconciler CronJobs, for substrates that enforce the **restricted**
Kubernetes Pod Security Standard (RKE2/SLES with restricted PSA, hardened kubeadm).

> **OpenShift/OKD uses the sibling [`openshift-scc`](../openshift-scc/README.md) overlay instead**, not
> this one. OpenShift's `restricted-v2` SCC assigns UIDs from the namespace range and **rejects** a
> hardcoded `runAsUser`, so it needs the *opposite* treatment (drop `runAsUser`, not set it). Applying
> this overlay on OpenShift would fail admission. Never apply both.

It patches **only** — the base manifests are untouched, so the default (k3s) deploy is unaffected. This
directory is **outside** the root app-of-apps `include` glob (`platform/root-app.yaml`), so Argo never
applies it automatically; an operator opts in on a restricted substrate.

## Why an overlay (not base edits)

On the default substrate these workloads run fine on their images' own users; forcing `runAsNonRoot` +
`runAsUser` everywhere risks breaking a setup job that expects a particular uid or a writable path. So the
hardening is a separate, opt-in variant an operator applies **after** validating it on the target
substrate — never a silent change to the base.

## What it covers (13 workloads, verified)

Every open-infra setup Job / reconciler CronJob that lacked full restricted `securityContext` is patched
to add pod-level `runAsNonRoot: true` + `runAsUser: 65532` + `seccompProfile: RuntimeDefault` and, on each
non-conformant container/init-container, `allowPrivilegeEscalation: false` + `capabilities.drop: [ALL]`:

`console-iam-setup`, `audit-offsite-setup`, `vault-transit-setup`, `lakehouse-setup`, `aws-shim-iam-setup`,
`velero-setup`, `longhorn-backup-setup`, `longhorn-backup-creds-refresh`, `chaos-node-longhorn-reconciler`
(Job + CronJob), `ca-provisioner`, `encryptionkey-destroyer`, `encryptionkey-reconciler`.

**Verified** (2026-08-21, `kubectl apply --dry-run=server` into a `pod-security.kubernetes.io/enforce=restricted`
namespace): base workloads emit restricted-PSA violation warnings (APE, capabilities, runAsNonRoot,
seccompProfile); the overlay-rendered workloads emit **zero** violations.

> Scope of the proof: this verifies **admission conformance** (the pods are accepted under restricted PSA).
> It does **not** prove each job's binary runs correctly as uid 65532 on your substrate — validate the
> actual runtime once on the target cluster (a job that writes outside `/tmp` or needs a specific uid may
> need a per-job tweak here).

## Privileged exceptions (NOT patched — cannot be restricted)

Three host-level workloads legitimately need privileges and are left as-is; on a restricted substrate they
need a **namespace-level PSA exemption** (label their namespace `pod-security.kubernetes.io/enforce=privileged`)
or an alternative:

- `audit-offsite-ship` — `hostPath` mount of the node audit log (`/var/log/...`); reading the audit stream
  is inherently host-level.
- `longhorn-host-prereq` — `privileged` + `hostPID` DaemonSet that installs open-iscsi on the node.
- `airgap-node-registries` — `privileged` + `hostPath` DaemonSet that writes the node `registries.yaml`.

## Upstream Crossplane & CNPG (Helm — separate mechanism, #34)

Installed from Helm charts, so hardened via chart values / CRs, not this overlay:

- **Crossplane core + rbac-manager** — hardened **in place** via chart values in
  `platform/abstraction/crossplane.yaml` (`securityContextCrossplane`/`securityContextRBACManager` +
  `podSecurityContext*`), verified with `helm template` to render drop-ALL + seccomp + runAsNonRoot.
- **Crossplane provider/function pods** — need a `DeploymentRuntimeConfig` referenced via
  `runtimeConfigRef`; ready manifest + operator wiring notes in
  [`crossplane-provider-runtimeconfig.yaml`](crossplane-provider-runtimeconfig.yaml) (an operator step —
  wiring it supersedes the chart's package strings).
- **CloudNativePG** — the operator pod is **already restricted-conformant** as shipped (runAsNonRoot +
  `drop:[ALL]` + seccomp RuntimeDefault; verified on the live pod), so no change is needed for k8s PSA.

## Apply (on a restricted substrate, after validation)

```bash
# base manifests are up-tree, so relax the load restrictor
kubectl kustomize platform/overlays/restricted-psa --load-restrictor LoadRestrictionsNone | kubectl apply -f -
# or point a dedicated Argo Application at this path for the restricted cluster
```

`patches.yaml` is generated from the base workloads; if a base pod spec changes, regenerate it.
