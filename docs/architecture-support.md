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
| **arm64 (aarch64)** | **Partial** | The control plane and installer run natively, and the first-party images are now **published for arm64** (`-arm64` tags). The kinds that use them don't run *by default* yet — the compositions still pin the amd64 `:latest` tag; see below. |

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

## arm64 first-party images (published) and the one wiring step left

The first-party images are now **built for arm64 and published under `-arm64` tags** (`build-arm64.yml`
— native arm64 runners; non-FIPS, see *FIPS*). Ten images ship arm64: console, mc, query, tds-proxy,
aws-shim, apply-sink, attest, audit-offsite, ca-issuer, open-appsync. `babelfish` is the exception (its
experimental C++/ANTLR source build stays amd64-only).

**But the kinds do not run on arm64 *by default* yet — one wiring step remains.** The compositions pin
the amd64 `:latest` tag, so on an arm64 node a kind's pod still pulls the amd64 image and fails
(`no match for platform in manifest`). The `-arm64` images are pullable directly today; making the kinds
select them automatically on arm64 nodes needs a per-cluster image-suffix mechanism (see *Roadmap*).

| Kind | arm64 image | Runs on arm64 by default? | Note |
|---|---|---|---|
| DatabaseProxy, DataFlow, Migration, Replication, Query, GraphQLApi | **published** (`-arm64`) | **not yet** | composition pins `:latest` (amd64); needs the `-arm64` tag selected on arm64 nodes |
| Destruction (crypto-erase) | **published** (`mc:…-arm64`) | **not yet** | same — its destroyer is an `mc` consumer |
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

So a mixed or arm64-only cluster fails *closed and legibly*, not with an obscure scheduling hang. See
[`platform/arch/README.md`](../platform/arch/README.md).

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
- **Composition arm64 tag-selection — the remaining step to make the kinds run on arm64.** The
  compositions pin `:latest` (amd64); a per-cluster image-suffix toggle (append `-arm64` on an arm64
  cluster) would let the data-plane kinds actually schedule and run on arm64. Not started.
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
