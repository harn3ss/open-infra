# ARM64 capability survey (issue #41, Phase 1)

Whether open-infra runs on arm64 (Apple Silicon / Graviton / Ampere). This began as a **survey** (no
code change); a runtime retest and the `-arm64` image builds came later — read it top-to-bottom as a log.

> **Update (2026-08-27), superseding the original survey framing:** the `-arm64` images have since been
> **published** — 10 first-party images via `build-arm64.yml` (see *Runtime retest — network RESTORED*
> below). On FIPS: it is a **substrate** property (SLES/RKE2, amd64), never an *image* one — the
> first-party images are plain `CGO_ENABLED=0` Go builds with **no image-level FIPS on any arch** — so
> publishing arm64 removes nothing FIPS-wise. See [`../architecture-support.md`](../architecture-support.md).

## Method (and why it's split)

The survey has two layers, run cheapest-first:

1. **Manifest layer (done, `survey-2026-08-24.jsonl`).** For each first-party image and the
   control-plane images, `docker manifest inspect` from the amd64 dev host answers *does an arm64
   build even exist*. A missing arm64 manifest **is** a `did_not_schedule` result by #41's own
   definition ("no arm64 manifest entry / image pull refused / exec format error") — provable
   without an arm64 machine, and it costs kilobytes, not the gigabytes a full pull would.
2. **Runtime layer (not yet run).** A native arm64 Linux VM (`openinfra-arm64.lima.yaml`) to
   confirm the `did_not_schedule` predictions with real `exec format error`s and to move the
   `not_attempted` (arm64-available-upstream) rows to `works` / `scheduled_but_failed`. This needs
   internet egress in the guest to pull images; deferred while only a metered hotspot is available.

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
later the same day — see the Update at the top. The kinds still need composition tag-selection to use
them by default.)*

## Consequences for phases 2 and 3 (not done here — survey only)

The manifest layer already gives phase 2 its honest majority: architecture per kind would be
`unsupported` (amd64) for the six first-party-data-plane kinds + **Windows** VmImage (Linux VMs are arm64-capable), and `untested`
for the orchestration kinds until the runtime layer runs. **Making these images multi-arch was a
separate CI decision (#42) — it has since been DONE: the `-arm64` images are now published (see the
Update at the top). It is not a FIPS decision — the images were never FIPS at the image layer.**
