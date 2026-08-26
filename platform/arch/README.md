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

## Enforcement

1. **Fail-closed admission — DONE (proven on the reference cluster).** A claim for a kind that cannot
   run on any architecture present in the cluster is **refused at admission** with an honest error,
   instead of accepted and left silently Pending. `kind-satisfiable.yaml` reconciles per-kind
   satisfiability (this registry ∩ node `kubernetes.io/arch`; `untested` is permitted, never blocked)
   into a ConfigMap, and `arch-admission-policy.yaml` (a ValidatingAdmissionPolicy) denies on it.
   Verified: a kind marked unsatisfiable has its claim refused with the message; satisfiable kinds
   admit normally.
2. **Node affinity — remaining enhancement.** For the *mixed*-arch case (some supported + some
   unsupported nodes), arch-`unsupported` kinds should also pin their data plane to a supported arch
   via `kubernetes.io/arch` node affinity, so an admitted claim can't land on a node it can't run on.
   Fail-closed admission already covers the *no*-supported-node case; this covers the mixed case.

## Phase 3 (console) — decision

Per #41 (which flags the overlap and says *decide rather than duplicate*), the arch-aware **console
UX folds into #30** (the new-kind creation experience), not a separate build. It has a clean
foundation: the two ConfigMaps here are the single source the console reads (avoiding the three-place
drift the VM catalog has), and the fail-closed VAP already enforces at the API layer — so even a
console create of an unsatisfiable kind is refused server-side with the honest message. The console's
job in #30 is to render that as an explanatory disabled state (never silent omission), with `untested`
labelled and permitted.

Making the first-party images multi-arch (which would flip several `unsupported` rows) is a separate,
FIPS-consequential CI decision tracked as polyhedron #42.
