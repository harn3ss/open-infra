# ARM64 capability survey (issue #41, Phase 1)

Whether open-infra runs on arm64 (Apple Silicon / Graviton / Ampere). This is a **survey, not
remediation** — no CI/multi-arch change was made, so the FIPS/BoringCrypto validation story is
untouched. Anything that would need a multi-arch rebuild is a separate, human-gated decision.

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
- **`kind: VirtualMachine` is a structural failure, not a build flag.** KubeVirt itself is arm64,
  but an arm64 host cannot run x86 guests, and the entire shipped OS catalog (ubuntu/fedora/debian/
  centos/windows) is x86. No catalog entry boots on arm64.

## What maps to what

| Outcome | Components |
|---|---|
| `did_not_schedule` (proven from manifests) | all 11 first-party images; kinds **DatabaseProxy, DataFlow, Migration, Replication, Query, GraphQLApi** (first-party data plane); **Destruction** (destroyer is an mc-consumer); **VirtualMachine / VmImage** (x86 guest catalog) |
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

The orchestration kinds (the `not_attempted` rows) and the full upstream data-plane convergence
were not run in this pass; the manifest layer already shows them arm64-capable via upstream.

## Consequences for phases 2 and 3 (not done here — survey only)

The manifest layer already gives phase 2 its honest majority: architecture per kind would be
`unsupported` (amd64) for the six first-party-data-plane kinds + VirtualMachine, and `untested`
for the orchestration kinds until the runtime layer runs. **Making these images multi-arch is the
separate, FIPS-consequential CI decision #41 says must be its own issue — it is not done here.**
