# Architecture support

Which **CPU architectures** open-infra runs on. This is a living document: the support states below
are the *declared truth* in [`platform/arch/kind-architectures.yaml`](../platform/arch/kind-architectures.yaml),
and CI (`arch-check`) verifies that declaration against the real published image manifests, so this
page cannot quietly drift from what actually ships. It grows as more architectures and components are
verified.

> Architecture (CPU: amd64 / arm64) is separate from **substrate** portability (the Kubernetes
> distribution / OS). For running on non-k3s distributions see [`portability.md`](portability.md).

## Summary

| Architecture | Status | Notes |
|---|---|---|
| **amd64 (x86-64)** | **Supported** | The shipped, exercised architecture; the validated **FIPS substrate** (SLES 15 SP7 + RKE2 in FIPS mode) runs here. See *FIPS* below for what that does and does not cover. |
| **arm64 (aarch64)** | **Partial** | The control plane, installer, **and the first-party kinds** run natively on arm64 — the compositions arch-select the `-arm64` images per cluster (set `imageArchSuffix: -arm64`), verified end-to-end on **AWS Graviton** and **Apple Silicon**. Mixed amd64/arm64 clusters (per-node routing) are validated and landing. `babelfish`, Windows VMs, and the FIPS substrate stay amd64. See below. |

Nothing here is a certification claim — it is verified capability, with the evidence in
[`docs/arm64/`](arm64/).

## What runs on arm64 today

Verified on a native Apple Silicon (aarch64) node (evidence: [`docs/arm64/`](arm64/)):

- **The whole control plane + the installer.** `install.sh` runs to completion on arm64 — k3s,
  Cilium (kube-proxy replacement), KubeVirt/CDI, Argo CD, and the app-of-apps are all arm64-clean.
  So an arm64 cluster **boots and self-manages**.
- **Upstream-backed / orchestration kinds** — the kinds whose data plane is upstream software
  (crossplane compositions, cert-manager, CNPG, Longhorn, Vault, Samba, Knative, chaos-mesh, …),
  which publish arm64. These are marked `untested` below only because the survey's runtime pass did
  not exercise them end-to-end (an environment limitation, not an arm64 one); their images are
  arm64-available.

## arm64 first-party images and how the kinds select them

The first-party images are **built for arm64 and published under `-arm64` tags** (`build-arm64.yml`
— native arm64 runners; non-FIPS, see *FIPS*). Ten images ship arm64: console, mc, query, tds-proxy,
aws-shim, apply-sink, attest, audit-offsite, ca-issuer, open-appsync. `babelfish` is the exception (its
experimental C++/ANTLR source build stays amd64-only).

**The kinds run on arm64 — the compositions arch-select the tag per cluster.** An `openinfra-platform`
EnvironmentConfig carries `imageArchSuffix`; the compositions render `…:latest{{ imageArchSuffix }}`, so
the default (`""`) stays byte-identical amd64 `:latest`, and setting `-arm64` makes every first-party
kind pull its `-arm64` image. On an arm64 cluster:

```
kubectl patch environmentconfig openinfra-platform --type merge -p '{"data":{"imageArchSuffix":"-arm64"}}'
```

Verified end-to-end: a `kind: Query` renders and runs on `…/open-infra-query:latest-arm64` on real
**AWS Graviton** and **Apple Silicon** nodes. **Mixed** amd64/arm64 clusters need one more piece — a
per-node arch pin (a `kubernetes.io/arch` nodeSelector on the rendered workload plus a per-resource
`openinfra.dev/arch` override) so each kind lands on a node of its image's arch. That is **validated
end-to-end on a live mixed cluster** (an arm64 node joined a running cluster over a mesh; a Query
annotated `openinfra.dev/arch: arm64` rendered the `-arm64` image + an `arch: arm64` nodeSelector, was
placed on the arm64 node, and read an object from the in-cluster store) and is **landing** (see *Roadmap*).

| Kind | arm64 image | Runs on arm64? | Note |
|---|---|---|---|
| DatabaseProxy, DataFlow, Migration, Replication, Query, GraphQLApi | **published** (`-arm64`) | **yes** | composition arch-selects via `imageArchSuffix`; set it to `-arm64` on an arm64 cluster |
| Destruction (crypto-erase) | **published** (`mc:…-arm64`) | **yes** | same mechanism; its destroyer is an `mc` consumer |
| Database (engine=babelfish) | **amd64-only** | **no** | experimental C++/ANTLR source build; arm64 compile not undertaken |
| VirtualMachine — **Linux** guests (ubuntu/fedora/debian/centos) | multi-arch containerDisk | **capable — not yet live-booted** | the catalog uses **multi-arch KubeVirt containerDisks** (`quay.io/containerdisks/*` → amd64+arm64) and the composition hardcodes no x86 machine type for Linux (KubeVirt selects `virt` on arm64). Longhorn **v1.12.0** (arm64) backs the disks. Should boot on arm64; end-to-end boot not yet verified. |
| VirtualMachine — **Windows** / VmImage | n/a | **no (structural)** | there is **no arm64 Windows Server ISO**, and the Windows path is hardwired amd64 (`q35` + MBR BIOS + `processorArchitecture="amd64"` sysprep). Multi-arch images can't fix this. |

The full, authoritative, CI-checked per-kind list (three states: `supported` / `unsupported` /
`untested`) is [`platform/arch/kind-architectures.yaml`](../platform/arch/kind-architectures.yaml).

## How the platform behaves on an unsupported architecture

open-infra does **not** accept a claim it cannot satisfy and leave it silently Pending. A
ValidatingAdmissionPolicy computes, per kind, whether any architecture present in *your* cluster can
run it (`untested` is permitted, never blocked), and **refuses an unsatisfiable claim at admission**
with an honest error:

> `open-infra: kind VirtualMachine cannot run on any architecture present in this cluster — its
> declared arch support is unavailable on every node … Add a node of a supported arch, or use a
> different kind.`

So a mixed or arm64-only cluster fails *closed and legibly*, not with an obscure scheduling hang. Both
directions are exercised: the refusal on an arm64-only cluster (a kind declared amd64-only rejected at
admission), and the allow-path live on a mixed cluster (the policy, its binding, the satisfiability
ConfigMap, and the recomputing CronJob all active). See [`platform/arch/README.md`](../platform/arch/README.md).

## FIPS

**FIPS is a *substrate* property, and we have validated it on amd64 — not a property of our images.**
open-infra's FIPS posture comes from the platform underneath the workloads: **SLES 15 SP7 + RKE2 run
in FIPS mode** (kernel FIPS + FIPS crypto policy — the OS and the Kubernetes cryptographic modules),
which we have exercised end-to-end on **amd64 only** (see
[`security-and-compliance.md`](security-and-compliance.md) and [`docs/compliance/`](compliance/)).
There is no validated FIPS substrate for arm64.

The first-party application **images** are a separate matter, and the honest statement is stronger than
"amd64 is FIPS, arm64 is not": every first-party image is a plain `CGO_ENABLED=0` Go build (standard Go
crypto), so **none of them are independently FIPS-validated cryptographic modules on *any*
architecture — amd64 included.** FIPS 140-3 evaluation covers the OS and the Kubernetes crypto module,
not the orchestration layer. Concretely:

- **Run FIPS / regulated workloads on the amd64 + SLES/RKE2 FIPS substrate.**
- **arm64 is for portability, development, and non-regulated use** — its images (published under
  explicit `-arm64` tags, see *Roadmap*) carry no FIPS claim, and neither does an arm64 substrate.
- Because the images were never FIPS at the image layer, publishing arm64 images **loses nothing**
  there; the entire FIPS story is the amd64 substrate, which arm64 simply does not target.

Giving the amd64 image builds an *image-level* FIPS crypto path (the Go 1.24 native FIPS module,
`GODEBUG=fips140=on`) is a distinct hardening we have **not** done; it is tracked as its own item so the
claim is only ever made once it is true.

## Roadmap

- **arm64 first-party images (`-arm64` tags) — published.** Ten first-party images now build natively on
  arm64 and push under explicit `-arm64` tags (`build-arm64.yml`); the default tags stay amd64, so a
  FIPS/amd64 deployment can never pull a non-FIPS arm64 image by accident.
- **Composition arm64 tag-selection — done.** The compositions arch-select the first-party image tag
  from the `openinfra-platform` EnvironmentConfig (`imageArchSuffix`), so setting `-arm64` on an arm64
  cluster makes the data-plane kinds schedule and run on arm64. Verified end-to-end on AWS Graviton and
  Apple Silicon.
- **Mixed amd64/arm64 clusters (per-node arch routing) — validated, landing.** A per-node arch pin
  renders a `kubernetes.io/arch` nodeSelector matching the arch-selected image (with a per-resource
  `openinfra.dev/arch` override), so on a mixed cluster each kind lands on a node its image can run on
  and a wrong-arch image can't be scheduled onto the wrong node. Validated end-to-end on a live mixed
  cluster (an arm64 node joined over a mesh; positive/negative/isolation cases all held). Remaining: an
  explicit arch nodeSelector on **VirtualMachine** so a Windows VM is pinned off arm64 nodes, and rolling
  the pin across the remaining compositions.
- **Per-image FIPS crypto on the amd64 builds** (the Go 1.24 native FIPS module) — a separate hardening
  tracked as its own item; it would give the amd64 images an *image-level* FIPS claim, which today only
  the substrate carries. Not started.
- `VirtualMachine` **Windows** guests / `VmImage` stay amd64 — there is no arm64 Windows Server ISO and
  the Windows path is hardwired amd64. **Linux** VM guests are already arm64-capable (multi-arch
  containerDisks + no hardcoded x86 machine type); live-booting one on arm64 to move the row from
  *capable* to *proven* is the open item.
- Other architectures (e.g. ppc64le, s390x — the control plane's upstream images often publish them)
  are untested; add a column here and a row set to the registry when one is surveyed.

## Evidence

- [`docs/arm64/`](arm64/) — the survey: a grid-shaped result (`survey-2026-08-24.jsonl`), the
  method, and the reproducible arm64 VM definition.
- [`platform/arch/`](../platform/arch/) — the declared registry, the `arch-check` CI (declared vs
  actual), and the fail-closed admission policy.
