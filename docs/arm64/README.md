# ARM64 capability survey (issue #41, Phase 1)

Whether open-infra runs on arm64 (Apple Silicon / Graviton / Ampere). This began as a **survey** (no
code change); a runtime retest and the `-arm64` image builds came later — read it top-to-bottom as a log.

> **Update (2026-08-29), superseding the original survey framing:** the arm64 image gap is **closed** —
> **#42** (multi-arch images) and **#43** (runtime retest on a restored network) are both **done**. The
> images ship arm64 (9 first-party images via distinct `-arm64` tags in `build-arm64.yml`; `open-infra-mc`
> as a shared multi-arch `:latest`), the compositions arch-select them, and it is **runtime-proven on a
> standing Apple-Silicon node in the live cluster** (see *#43 closed …* below). On FIPS: it is primarily a
> **substrate** property (SLES/RKE2, amd64); **arm64 images are non-FIPS and inherit nothing** from that
> validation — so publishing arm64 removes nothing FIPS-wise. (Separately, the amd64 Go images since build
> in Go-native FIPS mode, #46.) Full posture in [`../architecture-support.md`](../architecture-support.md).

## Method (and why it's split)

The survey has two layers, run cheapest-first:

1. **Manifest layer (done, `survey-2026-08-24.jsonl`).** For each first-party image and the
   control-plane images, `docker manifest inspect` from the amd64 dev host answers *does an arm64
   build even exist*. A missing arm64 manifest **is** a `did_not_schedule` result by #41's own
   definition ("no arm64 manifest entry / image pull refused / exec format error") — provable
   without an arm64 machine, and it costs kilobytes, not the gigabytes a full pull would.
2. **Runtime layer (originally deferred; since run — see the retest sections below).** A native arm64
   Linux VM (`openinfra-arm64.lima.yaml`) to confirm the `did_not_schedule` predictions with real
   `exec format error`s and to move the `not_attempted` (arm64-available-upstream) rows to `works` /
   `scheduled_but_failed`. This needs internet egress in the guest to pull images, so it was deferred
   while only a metered hotspot was available — then run on 2026-08-27/28/29 once the link was restored.

Outcome vocabulary is #41's, kept strictly distinct: `not_attempted` · `did_not_schedule` ·
`scheduled_but_failed` · `works`. The manifest layer can only ever produce `did_not_schedule`
(arm64 build absent) or `not_attempted` (arm64 build present, but not run here) — it never claims
`works`.

## Headline findings (manifest layer, 2026-08-24)

- **All 11 first-party images are amd64-only.** apply-sink, attest, audit-offsite, aws-shim,
  babelfish, ca-issuer, console, mc, open-appsync, query, tds-proxy — every one is a single-arch
  amd64 build (a plain `docker build`, which is what shipped). On an arm64-only cluster, all of
  them `did_not_schedule`. (This also corrects the issue's `exists:false` note for tds-proxy: the
  `:latest` tag exists — it is simply single-arch. The earlier check used the wrong image name.)
- **The control plane is arm64-clean.** crossplane (amd64/arm/arm64/ppc64le), Cilium (amd64/arm64),
  CloudNativePG (amd64/arm64), and KubeVirt virt-launcher (amd64/arm64/s390x) all publish arm64. So
  open-infra can **bootstrap** on arm64 — the blockers are purely our first-party data-plane images.
- **`mc` is not a coin flip — it breaks.** The mc-consumers `cp /usr/bin/mc` **from our
  `open-infra-mc` image** (amd64-only), not an arch-selected download, so every consumer (attest,
  audit-offsite, the crypto-erase destroyer, query, aws-shim, console-minio-user, lakehouse-setup)
  inherits the amd64-only constraint.
- **`kind: VirtualMachine`: Windows is structural, Linux is NOT.** KubeVirt is arm64. The **Linux**
  catalog entries (ubuntu/fedora/debian/centos) use **multi-arch containerDisks**
  (`quay.io/containerdisks/*` → amd64+arm64) and the composition hardcodes no x86 machine type for
  Linux (the `q35`/MBR/Hyper-V block is guarded by `{{ if $isWin }}`), so they should boot on arm64
  (KubeVirt selects the `virt` machine type). **This CORRECTS the original claim that "the entire
  catalog is x86" — that was a reasoning error; the containerDisk manifests were never checked, and
  Linux ones are multi-arch.** **Windows** is the genuine structural case: there is no arm64 Windows
  Server ISO, and its path is hardwired amd64 (q35 + MBR BIOS + `processorArchitecture="amd64"`
  sysprep). Storage is fine either way — Longhorn v1.12.0 is arm64.

## What maps to what

| Outcome | Components |
|---|---|
| `did_not_schedule` (proven from manifests) | all 11 first-party images; kinds **DatabaseProxy, DataFlow, Migration, Replication, Query, GraphQLApi** (first-party data plane); **Destruction** (destroyer is an mc-consumer); **VmImage / Windows VirtualMachine** (no arm64 Windows ISO — but **Linux** VirtualMachine guests are arm64-capable, see the correction above) |
| `not_attempted` (arm64 build present upstream; runtime not run here) | CertificateAuthority, DataClassification, Directory, EncryptionKey, FaultInjection, FileShare, Function, Grant, Group, HttpApi, Model, Policy, Role, SecurityGroup, Stream, User, Volume; the control-plane images |

Honest edges carried in the grid: `HttpApi` needs a runtime check that it doesn't share the
open-appsync/aws-shim data plane; `Stream`'s upstream images (Debezium/NATS/Benthos) should each be
arm64-confirmed at runtime; the `not_attempted` orchestration kinds are *likely* fine (crossplane +
provider-kubernetes are arm64) but are not claimed as `works` until run.

## Live phase (Phase 1b) — the committed environment

`openinfra-arm64.lima.yaml` is the reproducible arm64 VM definition (Lima, native aarch64 on Apple
Silicon). It is **not yet executed** — running it requires internet egress in the guest to pull
images. When run, it confirms the `did_not_schedule` set and resolves the `not_attempted` rows.

## Runtime layer — CONFIRMED on native arm64 (2026-08-25)

The runtime layer was executed on a native aarch64 VM (Lima on Apple Silicon; def in
`openinfra-arm64.lima.yaml`). The environment had no direct internet, so all pulls were routed
through a proxy chain (guest → Mac relay → an amd64 host's forward proxy → internet) — the arm64
images themselves are real, only the transport was proxied.

- **Bootstrap `works`.** k3s **v1.36.3+k3s1** installed and ran (its arm64 binary pulled cleanly),
  and **Cilium 1.16.6** (full kube-proxy replacement) brought the node **Ready** — the whole
  networking layer runs natively on arm64. `evidence_ref: runtime 2026-08-25 (arm64 Lima)`.
- **All 11 first-party images `did_not_schedule` — confirmed at runtime.** Each pod scheduled onto
  the arm64 node (so it is not a scheduling failure) and then kubelet failed the pull with
  `no match for platform in manifest: not found`. This is the manifest-layer `did_not_schedule`
  prediction, now proven live on real arm64 hardware — the images have no arm64 build.
  `evidence_ref: runtime 2026-08-25 (arm64 Lima)`.

- **The product's own installer `works` on arm64.** `install.sh` ran to completion on the arm64
  node — k3s + Cilium (already up) + **KubeVirt/CDI + ArgoCD** all installed and rolled out, and the
  app-of-apps `open-infra-platform` Application was created. 26 platform pods Running, 0 crash. So
  the entire control plane and the bootstrap path are arm64-clean.

- **The app-of-apps convergence to the upstream data planes was NOT completed — for an
  ENVIRONMENT reason, not an arm64 one.** ArgoCD could not fetch manifests: the survey's egress
  proxy (needed because the host had no direct internet) refuses non-443 `CONNECT`, and putting
  `HTTPS_PROXY` on the ArgoCD pods routes their internal gRPC/redis through it too. Cleanly
  threading the proxy through ArgoCD's per-repo git **and every Helm-repo** fetch is
  disproportionate plumbing, so the orchestration/data-plane kinds were left at their manifest-layer
  verdict (`not_attempted`, arm64 available upstream) rather than run. This is a survey-transport
  limitation; on a machine with normal internet it is a non-issue. It must NOT be read as an arm64
  failure of those kinds.

## Runtime retest — network RESTORED (2026-08-27, `survey-2026-08-27.jsonl`)

Issue #43 asked to re-run the runtime layer once the transport limitation was gone. It was re-run on
a native aarch64 Lima VM with **real internet** (vzNAT, no proxy). The proxy wall that capped the
2026-08-25 run is gone, so the orchestration and data-plane kinds finally got **real runtime
verdicts**. What flipped:

- **Bootstrap still `works` — and surfaced + fixed a real portability bug.** `install.sh` extracted
  the Cilium CLI into `/usr/local/bin` *without* `sudo`; on a clean non-root box that is
  `Permission denied` and `set -e` aborts the whole install (the node never gets a CNI). The amd64
  dev host hid it (writable `/usr/local/bin`). Fixed (`install.sh:231`, `| sudo tar …`) and validated
  live — Cilium then installed and the node went Ready.
- **app-of-apps: `not_attempted (proxy)` → `works_partial`.** ArgoCD repo-server fetched and rendered
  the platform manifests cleanly and the root applied its 150 managed resources (24 XRDs + 24
  Compositions + RBAC + CronJobs + the arch admission policy). The transport blocker is gone. Full
  one-shot convergence of all 19 child apps on a single NAT node churns on bootstrap sync-wave /
  CRD-and-namespace ordering — the known `gitops-raw-crd-dryrun` class, **environmental, not arm64**;
  the representative data-plane apps were deployed directly to get their verdicts.
- **Orchestration + composition engine: `not_attempted` → `works`.** Runtime-confirmed Running on
  arm64 (0 crashes): ArgoCD v3.5.2, Cilium v1.16.6, KubeVirt v1.8.4, CDI v1.65.0, MetalLB v0.14.8,
  cert-manager, sealed-secrets, snapshot-controller, **crossplane + provider-kubernetes v0.14.1 + all
  three composition functions + rbac-manager**. The 24 XRDs/Compositions install on arm64.
- **Data-plane operators: `not_attempted` → `works`.** CNPG operator `1.25.1` (kind: Database), MinIO
  (Bucket/FileShare, the object store), NATS `2.10.18` (Stream/Queue), Redis/Valkey — all Running on
  the arm64 node.
- **First-party images: unchanged — `did_not_schedule`.** All 11 re-inspected 2026-08-27 are still
  single-arch amd64. Confirmed live: the `audit-offsite` CronJob's pod hit `ImagePullBackOff:
  NotFound` on arm64. **The platform's own images remain the entire arm64 gap**; making them
  multi-arch is a separate CI decision tracked in #42 (subsequently DONE — the `-arm64` images are now published; see the Update at the top).

Net: with the network restored, everything that was transport-blocked runs on real arm64. The only
remaining arm64 failure is the first-party amd64-only images — exactly the gap the manifest layer
predicted, now proven from both directions. *(Subsequently closed: the `-arm64` images were published
later the same day, and the compositions now arch-select them from the `openinfra-platform`
EnvironmentConfig (`imageArchSuffix`, #112) — so setting `-arm64` makes the kinds run on arm64. See the
mixed-cluster validation below.)*

## Mixed amd64/arm64 cluster — front-to-back validation (2026-08-28, `survey-2026-08-28.jsonl`)

With the `-arm64` images published and the compositions arch-selecting them (`imageArchSuffix`, #112),
the last thing unproven was the whole chain on a **real, mixed** cluster — an arm64 node running
alongside amd64 under one control plane. A native **AWS Graviton** (m7g, aarch64) joined a running
k3s + Cilium cluster over a mesh and the end-to-end path was exercised:

| Layer | What it proves | Result |
|---|---|---|
| Substrate | arm64 node `Ready`, arm64 Cilium agent running, versions matched | ✅ |
| Cross-mesh data path | an arm64 pod resolves cluster DNS and reaches in-cluster Services (API, object store) by ClusterIP over the mesh | ✅ |
| Composition (render) | `openinfra.dev/arch: arm64` renders **both** the `-arm64` image **and** a `kubernetes.io/arch: arm64` nodeSelector (asserted by `test/render`) | ✅ |
| Composition (run) | that workload is **placed on the arm64 node** and its DuckDB engine **reads a real object from the in-cluster store** over the mesh, returning the correct result | ✅ |
| Isolation | an arm64-pinned workload goes **Pending** rather than ever landing on an amd64 node (`didn't match node selector`) | ✅ |
| Admission | the arch-satisfiability policy + binding + param ConfigMap + recomputing CronJob are live and evaluating | ✅ |

So the full chain holds: annotate → composition arch-selects image + nodeSelector → scheduler places on
the matching-arch node → the arm64 engine runs → it reaches its data-plane dependency over the mesh →
correct result; and the mirror (a wrong-arch image cannot land on the wrong node) holds too.

**Honest edges.** The per-node arch pin used for mixed clusters is validated but still **landing** (it is
not yet the default composition path). One case is **not built**: an explicit arch nodeSelector on
`VirtualMachine`, so a Windows VM is not yet *explicitly* pinned off arm64 nodes (today only KubeVirt's
`q35` implicitly fails there). **Stateful** kinds on arm64 (a `Database` PVC) were out of scope — the
arm64 node carried no distributed storage — so this validation covers **stateless** kinds that call back
to in-cluster services, not storage-backed ones.

## #43 closed — a standing arm64 node + the last runtime verdicts (2026-08-29, `survey-2026-08-29.jsonl`)

The Graviton was borrowed and is gone; the durable substitute #43's standing-caution called for is now in
place: an **Apple Silicon (M2 Max) node stands in the `.194` cluster** (`lima-openinfra-arm64`, a bridged
Lima VM with a real LAN IP, native-arm64 Cilium, `Ready`). On it, the two runtime verdicts #43 named were
settled and the outstanding flips were observed on real hardware:

- **`kind: HttpApi`: `not_attempted` → `works`.** Deployed live — the composition renders exactly one
  Traefik `Ingress` and **no pods**, so it is orchestration-only and does *not* share the
  open-appsync/aws-shim data plane (the concern that would have made it `did_not_schedule`). Its only
  runtime deps (Traefik, provider-kubernetes) are arm64-confirmed.
- **First-party images: `did_not_schedule` → `works`.** The "amd64-only, the entire arm64 gap" finding
  that ran through every prior survey is retired by #42. Proven on the node, not by reasoning:
  `open-infra-mc:latest` (now a multi-arch manifest) pulled its `linux/arm64` variant and ran
  (`ARCH=aarch64`, `mc RELEASE.2025-08-13`).
- **Confirmed unchanged:** `app-of-apps-convergence` stays `works_partial` (its tail is bootstrap
  sync-wave ordering — environmental, not arm64); the upstream data-plane operators still run on arm64.

**Honest residual:** the pure-orchestration kinds that render only Kubernetes objects
(Policy/Role/Group/User/Grant/SecurityGroup/…) inherit their arm64 answer from provider-kubernetes
(arm64-confirmed) but were not each individually deployed-and-observed on the node; they stay
`arm64_capable_unverified`, not silently upgraded. A full per-kind runtime sweep on the standing node is
available future work, outside #43's named scope.

## Consequences for phases 2 and 3 (not done here — survey only)

The manifest layer already gives phase 2 its honest majority: architecture per kind would be
`unsupported` (amd64) for the six first-party-data-plane kinds + **Windows** VmImage (Linux VMs are arm64-capable), and `untested`
for the orchestration kinds until the runtime layer runs. **Making these images multi-arch was a
separate CI decision (#42) — it has since been DONE: the `-arm64` images are now published (see the
Update at the top). It is not a FIPS decision — the images were never FIPS at the image layer.**

## Mixed-arch VMs: x86 guests on an arm64 control plane (#51, shipped)

open-infra assumes a single-arch cluster by default. To run the x86 VM catalog (all Windows, and any
`architecture: amd64` guest) when the **control plane is arm64** and the **workers include amd64**, two
things must line up — both now shipped, not hand edits:

1. **The VM declares its architecture.** The `vm` and `vmimage` compositions emit
   `spec.template.spec.architecture` on the KubeVirt VirtualMachine — `amd64` for Windows (structural)
   and for the golden **installer** VM (the catalog is x86), `arm64`/`amd64` for Linux when a
   per-resource `openinfra.dev/arch` annotation targets one, and nothing for a plain Linux guest (it
   stays flexible on multi-arch containerDisks). This matters at **admission**: `virt-api` runs on the
   control plane and derives the allowed machine types from `spec.architecture`; without it the arch is
   inferred as the CP's (arm64) and a `q35` VM is rejected *before scheduling* — even though a capable
   x86 worker is present and advertises `q35`.

2. **KubeVirt is told amd64 is a real target.** On an **arm64 control plane**, `install.sh` patches the
   `KubeVirt` CR with `spec.configuration.architectureConfiguration.amd64` (`machineType: q35`,
   `emulatedMachines: [q35*, pc-q35*]`, `ovmfPath`), so virt-api admits amd64 machine types. This is
   guarded on `uname -m = aarch64`, so an all-amd64 cluster's KubeVirt is left at its default.

**Longhorn placement on a mixed cluster.** VM root disks are provisioned by CDI/Longhorn and must land
on the **amd64 worker** (the arm64 CP can't run the x86 guest, and is usually too small for a Windows
golden anyway). On a fresh mixed cluster Longhorn starts with **no disks** (the
`node.longhorn.io/create-default-disk` gate), so:

- Label **only the amd64 worker(s)** for a Longhorn disk:
  `kubectl label node <amd64-worker> node.longhorn.io/create-default-disk=true`.
- Set the golden/VM StorageClass (or the Longhorn default) to **`numberOfReplicas: "1"`** — with a
  single disked node, a higher replica count leaves volumes stuck `Degraded`/unschedulable.

The end-to-end path (arm64 CP builds the Windows golden and boots a VirtualMachine on an x86 worker) was
proven with hand edits in the #45 run — see [`hybrid-arm64cp-x86worker-2026-08-29.md`](hybrid-arm64cp-x86worker-2026-08-29.md);
#51 is those edits made permanent in the compositions + `install.sh`.
