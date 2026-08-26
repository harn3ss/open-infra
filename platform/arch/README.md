# Declared kind architecture (#41 Phase 2)

`kind-architectures.yaml` is the **declared** architecture support for every open-infra kind, in a
strict three-state vocabulary — `supported` / `unsupported` / `untested` — derived from the arm64
survey (`docs/arm64/`). It is the single source of truth that Phase 2 enforces and Phase 3 (the
console) will read.

## Kept honest by CI

A declared capability that drifts from reality is worse than none, so `arch-check.py` (workflow
`arch-check.yml`) verifies the registry against the **real published image manifests** on every
change to this directory and weekly:

- a kind declared `supported` for an arch must actually have that arch in its first-party image;
- a kind declared `unsupported` whose image has since **gained** that arch is flagged as stale.

Inconclusive (couldn't read a manifest) exits non-zero — it is never reported as a pass. Kinds
with no first-party image inherit their arch from upstream and stay `untested` until run on real
hardware.

## Enforcement (in progress)

The declared truth drives two enforcement mechanisms; the registry + CI check land first:

1. **Node affinity** — arch-`unsupported` kinds pin their data plane to a supported arch via
   `kubernetes.io/arch` node affinity (derived from this registry), so on a mixed-arch cluster the
   workload only schedules where it can run. *(Rolling this into every composition is the remaining
   Phase 2 enforcement work.)*
2. **Fail-closed admission** — a claim for a kind that cannot be satisfied on any available node is
   refused at admission with an honest error ("requires amd64; no amd64 node available") rather than
   accepted and left silently Pending — the fake green check the platform must not produce itself.
   *(Strongest form; tracked as the remaining Phase 2 enforcement work.)*

Making the first-party images multi-arch (which would flip several `unsupported` rows) is a
separate, FIPS-consequential CI decision tracked in its own issue.
