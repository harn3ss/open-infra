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
| **arm64 (aarch64)** | **Partial** | The control plane and the installer run natively; several first-party data-plane images are amd64-only, so the kinds that use them do not yet run. See below. |

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

## What does not run on arm64 (yet)

The blocker is specific and honest: **several first-party data-plane images are built amd64-only**
(a plain single-arch `docker build`), so a kind whose workload is one of them cannot pull on arm64
(`no match for platform in manifest`). Making those images multi-arch is a deliberate, FIPS-gated
decision tracked separately (see *FIPS* below).

| Kind | arm64 | Why |
|---|---|---|
| DatabaseProxy, DataFlow, Migration, Replication, Query, GraphQLApi | **unsupported** | first-party data-plane image is amd64-only |
| Destruction (crypto-erase) | **unsupported** | its destroyer is an `mc` consumer; the `mc` image is amd64-only |
| VirtualMachine, VmImage | **unsupported** | *structural, not a build flag* — an arm64 host cannot run the shipped **x86 guest OS catalog** (Ubuntu/Fedora/Debian/CentOS/Windows). KubeVirt itself is arm64. |

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

- **arm64 first-party images (`-arm64` tags)** flip most `unsupported` rows above to `supported`. They
  are standard-Go (non-FIPS) builds published under **explicit `-arm64` tags** — the default tags stay
  amd64, so a FIPS/amd64 deployment can never pull a non-FIPS arm64 image by accident. *(In progress.)*
- **Per-image FIPS crypto on the amd64 builds** (the Go 1.24 native FIPS module) — a separate hardening
  tracked as its own item; it would give the amd64 images an *image-level* FIPS claim, which today only
  the substrate carries. Not started.
- `VirtualMachine` / `VmImage` stay amd64 regardless until (and unless) an arm64 guest OS catalog is
  offered — multi-arch *images* do not help there.
- Other architectures (e.g. ppc64le, s390x — the control plane's upstream images often publish them)
  are untested; add a column here and a row set to the registry when one is surveyed.

## Evidence

- [`docs/arm64/`](arm64/) — the survey: a grid-shaped result (`survey-2026-08-24.jsonl`), the
  method, and the reproducible arm64 VM definition.
- [`platform/arch/`](../platform/arch/) — the declared registry, the `arch-check` CI (declared vs
  actual), and the fail-closed admission policy.
