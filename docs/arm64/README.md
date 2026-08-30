# ARM64 support

open-infra runs on arm64 (Apple Silicon / Graviton / Ampere). This page is the arm64 support
reference; the dated capability surveys in this directory (`survey-*.jsonl`) are the evidence behind it.

## What runs on arm64

- **Control plane and bootstrap.** The whole bootstrap path is arm64-clean: k3s, Cilium (full
  kube-proxy replacement), ArgoCD, crossplane + provider-kubernetes + the composition functions,
  KubeVirt/CDI, cert-manager, sealed-secrets, MetalLB, rbac-manager. `install.sh` runs to completion on
  an arm64 node. Runtime-confirmed on native aarch64 (Lima on Apple Silicon, and AWS Graviton).
- **Data-plane operators.** CloudNativePG (`kind: Database`), MinIO (`Bucket`/`FileShare`),
  NATS/JetStream (`Stream`/`Queue`), Redis/Valkey, and Longhorn all publish and run arm64.
- **First-party images.** The ten first-party Go/query images publish arm64 under explicit `-arm64`
  tags (`build-arm64.yml`), and `open-infra-mc` ships as a shared multi-arch `:latest`. The compositions
  arch-select the tag from the `openinfra-platform` EnvironmentConfig (`imageArchSuffix`), so the
  data-plane kinds — `DatabaseProxy`, `DataFlow`, `Migration`, `Replication`, `Query`, `GraphQLApi`,
  `Destruction` — run on arm64. Proven end-to-end on a standing Apple-Silicon node in the live cluster
  and on AWS Graviton.
- **Kinds.** `EncryptionKey`, `Destruction`, `Grant`, `Function`, and `HttpApi` are runtime-verified on
  arm64. The pure-orchestration kinds (`Policy`/`Role`/`User`/`Group`/`SecurityGroup`/
  `DataClassification`/`Volume`) render via provider-kubernetes (arm64-confirmed) but are recorded as
  capable-but-unverified where they were not each individually observed on an arm64 node — see the
  per-kind verdicts in `survey-2026-08-30.jsonl`.

## What does not run on arm64

- **First-party images are non-FIPS on arm64.** FIPS is primarily a **substrate** property (SLES/RKE2,
  amd64-validated); the arm64 images inherit nothing from it. They ship under `-arm64` tags stamped
  `openinfra.dev/fips=false`, and the default tags stay amd64, so a FIPS/amd64 deployment can never pull
  a non-FIPS arm64 image by accident. Full posture in
  [`../architecture-support.md`](../architecture-support.md).
- **Windows VMs are structurally amd64.** There is no arm64 Windows Server ISO, and the Windows path is
  amd64-hardwired (q35 + MBR BIOS + amd64 sysprep). `kind: VmImage` and Windows `kind: VirtualMachine`
  are therefore amd64-only. Linux VM guests use multi-arch containerDisks (KubeVirt selects the `virt`
  machine type) and are arm64-capable.

## Mixed amd64/arm64 clusters

The compositions route each kind to a node its image can run on. `openinfra.dev/arch: <arch>` on a
resource renders both the arch-selected image **and** a matching `kubernetes.io/arch` nodeSelector, so a
wrong-arch image cannot land on the wrong node; a Windows VM is forced to `arch: amd64` (structural), a
Linux VM stays flexible unless annotated. Upstream multi-arch sidecars (Debezium/NATS) stay unpinned, and
a user-supplied image is left unpinned (unknown arch). An arch-satisfiability admission policy refuses a
kind that no present node architecture can run.

Validated end-to-end on a live mixed cluster (an arm64 node alongside amd64 under one control plane):
annotate → the composition arch-selects the image and nodeSelector → the scheduler places the workload
on the matching-arch node → the arm64 engine runs and reaches its data-plane dependency over the cluster
network → correct result; and the mirror holds too (a wrong-arch image cannot land on the wrong node).
Stateful, storage-backed kinds on arm64 are covered separately from this stateless-path validation.

## Mixed-arch VMs: x86 guests on an arm64 control plane

To run the x86 VM catalog (all Windows, and any `architecture: amd64` guest) when the **control plane is
arm64** and the **workers include amd64**, two things line up — both shipped in the compositions and
`install.sh`:

1. **The VM declares its architecture.** The `vm` and `vmimage` compositions emit
   `spec.template.spec.architecture` on the KubeVirt VirtualMachine — `amd64` for Windows (structural)
   and the golden **installer** VM (the catalog is x86), `arm64`/`amd64` for Linux when a per-resource
   `openinfra.dev/arch` annotation targets one, and nothing for a plain Linux guest (it stays flexible
   on multi-arch containerDisks). This is the **admission** gate: `virt-api` on a non-amd64 control plane
   derives the allowed machine types from `spec.architecture`, so an x86 (`q35`) VM is rejected before
   scheduling unless it declares amd64 — even with a capable x86 worker present.
2. **KubeVirt has an amd64 runtime target.** On an arm64 control plane, `install.sh` patches the
   `KubeVirt` CR with `spec.configuration.architectureConfiguration.amd64` (`machineType: q35`,
   `emulatedMachines: [q35*, pc-q35*]`, `ovmfPath`), guarded on `uname -m = aarch64` so an all-amd64
   cluster is left at its default. The composition's `architecture: amd64` is what fixes admission (a q35
   amd64 VMI admits via KubeVirt's built-in amd64 machine defaults); this patch supplies the
   virt-launcher / qemu runtime (emulated machine + OVMF) the guest needs to actually **boot** on the
   amd64 worker.

**Longhorn placement.** VM root disks are provisioned by CDI/Longhorn and must land on the **amd64
worker** (the arm64 control plane can't run the x86 guest, and is usually too small for a Windows golden
anyway). On a fresh mixed cluster Longhorn starts with **no disks** (the
`node.longhorn.io/create-default-disk` gate), so:

- Label **only the amd64 worker(s)** for a Longhorn disk:
  `kubectl label node <amd64-worker> node.longhorn.io/create-default-disk=true`.
- Set the golden/VM StorageClass (or the Longhorn default) to **`numberOfReplicas: "1"`** — with a single
  disked node, a higher replica count leaves volumes stuck `Degraded`/unschedulable.

The end-to-end path — an arm64 control plane building the Windows golden and booting a `VirtualMachine`
on an x86 worker — is captured in
[`hybrid-arm64cp-x86worker-2026-08-29.md`](hybrid-arm64cp-x86worker-2026-08-29.md).

## Evidence

The dated capability surveys are kept as an audit trail (newest supersedes older where they overlap):

- `survey-2026-08-24.jsonl` — manifest-layer survey: which images publish an arm64 build.
- `survey-2026-08-27.jsonl` / `-08-28.jsonl` / `-08-29.jsonl` — runtime layer on native arm64, a mixed
  AWS Graviton cluster, and a standing Apple-Silicon node.
- `survey-2026-08-30.jsonl` — per-kind runtime sweep on the standing node.
- `hybrid-arm64cp-x86worker-2026-08-29.md` — the hybrid arm64-control-plane + x86-worker run.
- `openinfra-arm64.lima.yaml` — the reproducible arm64 Lima VM definition.
