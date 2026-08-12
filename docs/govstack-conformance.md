# GovStack conformance — open-infra as the infrastructure layer

open-infra positions as the **cloud / hosting infrastructure layer** that GovStack building blocks run
on top of — not as an application building block. GovStack treats cloud/infrastructure as a
foundational specification, and that layer is a near-description of what open-infra already is:
Kubernetes-native, declarative config, CI/CD-driven, self-contained, self-hostable, with no mandatory
internet dependency.

> Scope note: this maps open-infra against the GovStack cross-cutting and cloud-infrastructure
> requirements. It is a conformance *self-assessment*, not an attested certification — formal
> conformance requires engaging the GovStack working groups and their program.

## Interfaces (OpenAPI)

GovStack requires building-block interfaces to be OpenAPI-described. open-infra's meaningful platform
API is the **declarative resource API** — the `openinfra.dev` custom resources a block provisions
infrastructure through. That surface is specified in
[`docs/openapi/openinfra-platform.openapi.yaml`](openapi/openinfra-platform.openapi.yaml), **generated
from the CRD schemas** (`platform/abstraction/*-xrd.yaml`) so it can never drift from the running API.
See [`docs/openapi/README.md`](openapi/README.md).

- Platform resource API — 25 kinds, standard Kubernetes list/create/get/delete endpoints. ✅ generated
- The BFF (`/api`) and the AWS-shim are secondary, human-facing surfaces; their OpenAPI is a follow-up.

**External dependency:** conforming these specs *to the GovStack Architecture Blueprint* (matching its
prescribed OpenAPI shapes) requires the Blueprint spec itself — a human must supply the exact
version/section to reconcile against. The specs above are open-infra's own, correct and drift-gated;
the Blueprint reconciliation is the open item.

## Requirement mapping

| GovStack requirement | open-infra | Status |
|---|---|---|
| Containerized, self-contained deployment | every unit an independent container image | ✅ |
| On-premises / self-hosted install (digital-registries block *requires* an on-site option) | full self-host via `install.sh` + GitOps | ✅ home turf |
| Fully automated, CI/CD deployment to a known state | app-of-apps GitOps, CI-gated | ✅ |
| Right-to-be-forgotten (GDPR cross-cutting) | `kind: Destruction` crypto-erase (arguably stronger than a typical block) | ✅ |
| Honest data handling / privacy-first | `kind: DataClassification` (honest-unknown) | ✅ |
| High availability, proven | control-plane HA profile (console 2 replicas + PDB + node spread + zero-downtime rollout); app-tier + managed-Postgres HA proven by the chaos harness | ✅ profile shipped; availability-under-fault proven by the app-availability + cnpgfailover oracles |
| CA / PKI building block (issue+revoke, OpenAPI, HA) | `kind: CertificateAuthority` on Vault PKI + `kind: EncryptionKey` | 🔨 in progress (gap A) |
| Interfaces conform to the Architecture Blueprint OpenAPI | platform OpenAPI generated (above) | 🟡 needs the external Blueprint to reconcile |
| Hardened deployment profile | opt-in `components.hardened`: enforce restricted PSS on the control plane + warn/audit elsewhere; Cilium default-deny + `kind: SecurityGroup` already shipped; console now non-root/RO-rootfs/seccomp/drop-ALL | ✅ profile shipped (opt-in) |
| Encryption stack live-verified | Vault Transit customer keys | 🟡 built; live-verify is Vault-operator-gated (gap E) |

## Reliability evidence (the differentiator)

The chaos harness is the conformance evidence almost no other candidate can show: a suite of
**fail-loud oracles on a singular verdict engine, each proven able to go red before it counts** (see
[`docs/chaos-oracle.md`](chaos-oracle.md)). It already proves, under injected fault:

- app availability under replica loss (tolerate SLO), managed-Postgres failover convergence, block/
  file/directory durability, VM liveness, stream no-loss, and multi-master mesh reconvergence.

This speaks directly to the HA / reliability non-functional requirements — availability is
*demonstrated under fault*, not asserted.

## Open items (the credibility gates for moving past the sandbox)

1. **A** — `kind: CertificateAuthority` (code buildable; issuance proof needs Vault initialized).
2. **B** — control-plane HA profile + a prove-red HA oracle.
3. **C** — reconcile the generated OpenAPI to the GovStack Architecture Blueprint *(needs the Blueprint)*.
4. **D** — the hardened deployment profile.
5. **E** — live-verify the encryption stack, then drop the EXPERIMENTAL flag *(needs a Vault operator to init + unseal)*.

The GovStack Sandbox is explicitly **not** production-ready — step one is conformance + credibility
(stand open-infra up under a Sandbox and run a use-case demo), not a live national deployment.
