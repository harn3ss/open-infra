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
| **amd64 (x86-64)** | **Supported** | The shipped, exercised architecture; the amd64 **FIPS-mode substrate** (SLES 15 SP7 + RKE2) was exercised here — FIPS *mode* on stock SP7 crypto, **not** the CMVP-certified module builds. See *FIPS* below for what that does and does not cover. |
| **arm64 (aarch64)** | **Partial** | The control plane, installer, **and the first-party kinds** run natively on arm64 — the compositions arch-select the `-arm64` images per cluster (set `imageArchSuffix: -arm64`), verified end-to-end on **AWS Graviton** and **Apple Silicon**. Mixed amd64/arm64 clusters are supported — every first-party kind + VMs carry a per-node arch pin, validated on a live mixed cluster. `babelfish`, Windows VMs, and the FIPS substrate stay amd64. See below. |

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
— native arm64 runners; non-FIPS, see *FIPS*). Nine images ship a distinct `-arm64` tag: console, query,
tds-proxy, aws-shim, apply-sink, attest, audit-offsite, ca-issuer, open-appsync. **`mc` is the one
exception**: it carries no FIPS claim (`fips=false` on every arch), so a shared tag can't hide a non-FIPS
build of a FIPS image — it therefore ships as a single **multi-arch `:latest`** (amd64+arm64) rather than a
distinct tag, so the static jobs that consume it (crypto-erase / audit off-siting / attestation) pull the
arch-matching binary from one image ref. `babelfish` stays amd64-only (experimental C++/ANTLR source build).

**The kinds run on arm64 — the compositions arch-select the tag per cluster.** An `openinfra-platform`
EnvironmentConfig carries `imageArchSuffix`; the compositions render `…:latest{{ imageArchSuffix }}`, so
the default (`""`) stays byte-identical amd64 `:latest`, and setting `-arm64` makes every first-party
kind pull its `-arm64` image. On an arm64 cluster:

```
kubectl patch environmentconfig openinfra-platform --type merge -p '{"data":{"imageArchSuffix":"-arm64"}}'
```

Verified end-to-end: a `kind: Query` renders and runs on `…/open-infra-query:latest-arm64` on real
**AWS Graviton** and **Apple Silicon** nodes. **Mixed** amd64/arm64 clusters carry a **per-node arch
pin**: every first-party composition (and VMs) renders a `kubernetes.io/arch` nodeSelector matching the
arch-selected image, plus a per-resource `openinfra.dev/arch` override, so each kind lands on a node of
its image's arch and a wrong-arch image can't be scheduled onto the wrong node. Validated end-to-end on a
live mixed cluster (an arm64 node joined a running cluster over a mesh; a Query annotated
`openinfra.dev/arch: arm64` rendered the `-arm64` image + an `arch: arm64` nodeSelector, was placed on the
arm64 node, and read an object from the in-cluster store).

| Kind | arm64 image | Runs on arm64? | Note |
|---|---|---|---|
| DatabaseProxy, DataFlow, Migration, Replication, Query, GraphQLApi | **published** (`-arm64`) | **yes** | composition arch-selects via `imageArchSuffix`; set it to `-arm64` on an arm64 cluster |
| Destruction (crypto-erase) | **published** (`mc` multi-arch `:latest`) | **yes** | its destroyer is a static CronJob (not a composition), so it can't arch-select a tag — the `mc` image it stages is multi-arch, so the arch-matching binary is pulled automatically |
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

**FIPS is a *substrate* property we have exercised in FIPS *mode* on amd64 — not a property of our
images.** open-infra's FIPS posture comes from the platform underneath the workloads: **SLES 15 SP7 +
RKE2 run in FIPS mode** (kernel FIPS + FIPS crypto policy — the OS and the Kubernetes cryptographic
modules), exercised end-to-end on **amd64 only** (see
[`security-and-compliance.md`](security-and-compliance.md) and [`docs/compliance/`](compliance/)).
To be precise: the nodes ran FIPS **mode** on **stock SP7 crypto packages** — the
11 version-locked RPMs are the running SP7 builds, **not the CMVP-certified SP6 module builds** (SUSE
does publish those SP6-certified modules for installation on SP7; that install step was not performed).
So the honest claim about that event is "operating in FIPS mode," never "running the
FIPS-140-3-validated module versions."

**The certified-module path is proven.** SUSE's SP6-certified crypto modules
install on SP7 (via the Certifications Module) and the OpenSSL FIPS provider goes **active** in FIPS
mode — validated end-to-end on **both amd64 (a SLES SP7 OptiPlex) and arm64 (a SLES SP7 Graviton)**, the
identical certified versions on each arch, so **arm64 carries no substrate-FIPS disadvantage**. The
provisioning method now installs + locks those certified modules. This was validated on
throwaway/temporary nodes; it is *not* a claim that a permanent production fleet is currently running the
certified modules.

One more precision, because CMVP validation is **operational-environment-specific**: the SUSE OpenSSL 3
module is **CMVP cert #5096** (module `fips.so` v1.1), and its tested/affirmed environments are specific
server platforms — AMD EPYC 7343, Intel Xeon Gold 5416S, **Ampere Altra Q80-30 (aarch64)**, IBM Telum
(SP6 tested; SP7 vendor-affirmed on Intel/AMD). The boxes used here (an OptiPlex with a consumer Intel
CPU, an AWS Graviton with an Arm Neoverse core) are **not** on that list. So what is proven is that the
**validated module binary installs and goes active in FIPS mode** on SP7 on both arches — not that these
particular boxes constitute a CMVP-listed validated configuration.

**The boundary, stated plainly:** a certified cryptographic module installed and running in FIPS mode is
**not** the same as *the platform* being certified. The FIPS 140-3 certificates cover the OS crypto
modules (and RKE2's Kubernetes crypto module); the **orchestration layer — Crossplane, the compositions,
and our first-party images — is out of scope of those substrate certificates** (the amd64 Go images do
carry a separate *image-level* FIPS-**mode** build — see below — which is itself not a certificate).
Built ≠ verified ≠ certified.

The first-party application **images** are a separate layer with their own FIPS posture:
the **amd64 Go-built images compile with the Go native FIPS 140-3 module** (`GOFIPS140=v1.0.0`, which
bakes `DefaultGODEBUG=fips140=on` into the binary, so `crypto/fips140.Enabled()` is true at runtime with
no env) and are stamped **`openinfra.dev/fips=true`**. The **arm64** images (built with `GOFIPS140` empty)
and the **non-Go** images — `query` (DuckDB), `babelfish` (C++/ANTLR), `mc` (upstream MinIO client) —
stay plain builds stamped **`openinfra.dev/fips=false`**. So the amd64/arm64 split is now a genuine
FIPS/non-FIPS split *at the image layer*.

The boundary, stated as plainly as the substrate one: **a Go module running in FIPS mode is not a CMVP
certificate.** The Go FIPS 140-3 module v1.0.0 is CMVP **in process**; building with `GOFIPS140=v1.0.0`
means the image's Go crypto runs that module in its FIPS-approved mode — it is **not** a granted
certificate, and it is **separate** from the SLES/RKE2 substrate validation (cert #5096 et al.). Built ≠
verified ≠ certified.

- **Run FIPS / regulated workloads on the amd64 + SLES/RKE2 FIPS substrate** — that is where the OS and
  Kubernetes crypto modules are FIPS-140-3-**validated**.
- The **amd64 image-level FIPS mode** (Go module) is an additional image-layer control, not a substitute
  for the substrate validation and not itself a certificate.
- **arm64 stays portability / non-regulated** — its images, and any arm64 substrate, carry no FIPS claim.

The amd64 Go image builds carry an *image-level* FIPS crypto path — the Go native FIPS 140-3 module
(`GOFIPS140=v1.0.0`, `fips140=on`): they build with it and are
stamped `openinfra.dev/fips=true` (verified — the binary carries `-tags=fips140v1.0` / `GOFIPS140=v1.0.0`).
The claim is scoped to exactly what it is: an image-level FIPS-**mode** build, not a CMVP certificate (the
Go module is CMVP *in process*) and not the substrate validation.

## Roadmap

- **arm64 first-party images (`-arm64` tags) — published.** Ten first-party images now build natively on
  arm64 and push under explicit `-arm64` tags (`build-arm64.yml`); the default tags stay amd64, so a
  FIPS/amd64 deployment can never pull a non-FIPS arm64 image by accident.
- **Composition arm64 tag-selection — done.** The compositions arch-select the first-party image tag
  from the `openinfra-platform` EnvironmentConfig (`imageArchSuffix`), so setting `-arm64` on an arm64
  cluster makes the data-plane kinds schedule and run on arm64. Verified end-to-end on AWS Graviton and
  Apple Silicon.
- **Mixed amd64/arm64 clusters (per-node arch routing) — done.** Every first-party composition
  (Query, DatabaseProxy, DataFlow, Replication, Migration, GraphQLApi) renders a `kubernetes.io/arch`
  nodeSelector matching the arch-selected image (with a per-resource `openinfra.dev/arch` override), so on
  a mixed cluster each kind lands on a node its image can run on and a wrong-arch image can't be scheduled
  onto the wrong node. Upstream multi-arch sidecars (Debezium/NATS) stay unpinned; a user-supplied image
  is left unpinned (unknown arch). **VirtualMachine** carries the same pin: a Windows VM is forced to
  `arch: amd64` (structural), a Linux VM stays flexible unless annotated. Validated end-to-end on a live
  mixed cluster (an arm64 node joined over a mesh; positive/negative/isolation cases all held) and
  render-tested.
- **Per-image FIPS crypto on the amd64 builds — done.** The amd64 Go images build with the
  Go native FIPS 140-3 module (`GOFIPS140=v1.0.0`) and carry `openinfra.dev/fips=true`; arm64 and the
  non-Go images (`query`/`babelfish`/`mc`) stay `false`. It is an image-level FIPS-*mode* build, not a
  CMVP certificate (the Go module is CMVP in-process).
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
