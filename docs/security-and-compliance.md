# Security & Compliance

open-infra is built to a **control framework**, not just a feature list. This document states
its security posture honestly and maps its capabilities to the **NIST SP 800-53** control
families that underpin **FedRAMP** and most US federal authorizations.

## What "compliance" means here — read this first

open-infra is **software you self-host**, not a hosted cloud service. That distinction matters:

- **FedRAMP authorizes a running service offering**, operated by a specific organization,
  assessed by a 3PAO, and granted an ATO by an authorizing official. A *software project*
  cannot "be FedRAMP." Anyone who tells you otherwise is selling a badge, not a boundary.
- **What open-infra provides** is the *technical* control implementations and the *evidence*
  an operator needs, so that authorizing a deployment is a matter of configuration and
  paperwork rather than re-engineering.

So the honest claim is **"FedRAMP-aligned / control-mapped, independently unverified"** — and
we will never print "compliant" or "certified" without an assessment behind it. That honesty
*is* the credibility.

**Split of responsibility.** A large fraction of 800-53 is organizational, not technical —
personnel security, incident-response plans, security-awareness training, POA&Ms, the System
Security Plan itself. open-infra covers the **technical controls**; the **operator supplies
the organizational controls** and the authorization boundary documentation. The mapping below
labels which is which.

## Secure by default (NIST CM-7, Least Functionality)

The platform's default posture is to **surface and enable only what's essential**; privileged
or dangerous capabilities are opt-in:

- **Authentication is required.** The console enforces a session on every API and the
  embedded-Grafana proxy; `AUTH_MODE=none` exists only for throwaway dev clusters and raises
  both a startup warning and a **persistent, non-dismissable banner** on every page.
- **Fault injection is off by default.** The Chaos surface is hidden unless a deployment sets
  `CHAOS_UI_ENABLED=true` — a deliberately-break-things tool is not something a reviewer
  should find one click from Monitoring.
- **No anonymous data access.** Grafana's anonymous kiosk is reachable only through the
  authenticated console proxy, never directly.
- **Least-privilege service identities.** Query, the lakehouse/Trino engine, and the console
  each use a **scoped MinIO user** (bucket- or action-limited, no admin API), never the root
  credentials. Workload pods run non-root, read-only-rootfs, with capabilities dropped and no
  service-account token where they don't call the API.

A **hardened deployment profile** (see *Roadmap*) extends this: no Chaos Mesh install, RBAC
that withholds `FaultInjection`, no `AUTH_MODE=none`, and the experimental tier disabled.

## NIST 800-53 control-family mapping

Status legend: **Implemented** (shipped and exercised) · **Partial** (core in place, hardening
tracked) · **Operator** (the deployment must supply/configure it).

| Family | open-infra capability | Status |
|--------|------------------------|--------|
| **AC — Access Control** | `kind: User`/`Group` account management; RBAC enforced via Kubernetes impersonation; `kind: Policy`/`Role` with a permission boundary + impersonation ceiling; least-privilege service identities (scoped MinIO/query users, non-root pods) | Implemented |
| **AU — Audit & Accountability** | API-server audit log (`RequestResponse` for IAM/RBAC/`openinfra.dev` writes) shipped to Loki, person-attributed via `impersonatedUser`; console **Audit** view; console IAM actions logged with the acting human | Implemented (retention/off-site/tamper-evidence: Partial → Roadmap) |
| **IA — Identification & Authentication** | `AUTH_MODE` local / LDAP / OIDC; signed sessions; k8s-impersonated identities namespaced as `openinfra:<user>` | Implemented (OIDC backend + MFA delegated to the IdP: Partial/Operator) |
| **SC — System & Communications Protection** | Cilium NetworkPolicy (default-deny + `kind: SecurityGroup`); per-workload network sandboxes (Query egress allow-list); TLS via cert-manager; control-plane/mesh mTLS | Implemented (encryption-at-rest with customer keys: Roadmap) |
| **CM — Configuration Management** | Declarative GitOps baseline (Argo CD); change control through git review + sync; **drift checkers** (policy-boundary, Argo exclude-list) fail the build on divergence; secure-by-default least functionality | Implemented |
| **SI — System & Information Integrity** | Prometheus + Loki monitoring/alerting; container images Trivy-scanned + cosign-signed; convergence + chaos suites as integrity evidence | Implemented (file-integrity/SIEM export: Operator) |
| **CP — Contingency Planning** | Velero (cluster) + Longhorn (volume) backups to MinIO; RDS-style pre-delete snapshots + restore; the **nightly chaos suite** is contingency/resilience *test evidence* (partition, failover, clock-skew, convergence) | Implemented |
| **CA — Assessment & Continuous Monitoring** | Mechanical correctness: convergence harness + nightly chaos as continuous verification; drift tests as configuration assurance | Partial (evidence pipeline: Roadmap) |
| **MP — Media Protection** | Crypto-erase data destruction (NIST **SP 800-88**): per-volume/per-DB keys, deletion = destroy key + destruction certificate | Roadmap (#71) |
| **RA / PL / PS / IR / AT / …** | Risk assessment, planning, personnel, incident response, awareness training | **Operator** — organizational controls outside the platform |

For contractors handling **Controlled Unclassified Information (CUI)**, **NIST SP 800-171** is
the lighter-weight cousin; the AC/AU/IA/SC/CM/SI coverage above maps directly onto its
requirement families.

## Roadmap — the government feature track

Sequenced, longer-horizon work that deepens the posture (tracked in the issue backlog):

1. **Audit hardening** — Loki retention → long-term + off-site; hash-chain + signing + WORM
   (object-lock) for tamper-evidence (AU-9); decide on read-event capture.
2. **Encryption with customer-managed keys** — at-rest encryption keyed by the operator
   (SC-28), data-residency pinning.
3. **`kind: Grant`** — temporal, auto-expiring access grants (AC-2/AC-6 just-in-time).
4. **`kind: DataClassification`** — label data and enforce handling by classification.
5. **Crypto-erase** — NIST SP 800-88 destruction with a tamper-evident certificate (MP-6).
6. **Lineage + signed compliance attestation** — provenance and a signed control-coverage
   report generated from the live cluster.
7. **Hardened deployment profile** — one switch that disables the experimental tier, Chaos
   Mesh, and every opt-in dangerous capability, and tightens defaults for an authorization
   boundary.

## Maturity — don't over-trust the experimental tier

Security posture is only as good as the maturity of what it protects. open-infra tiers its
surface (see [README → Maturity & guarantees](../README.md#maturity--guarantees)): the PaaS
surface is **Stable**; the distributed-systems primitives (multi-master replication, CDC) are
**Experimental** until the graduation bar is met. A hardened deployment should run the Stable
surface and treat the Experimental tier as opt-in, not system-of-record.

## Reference environment vs. the platform

open-infra is developed and proven on a real cluster, and that cluster is a **homelab** —
disclosed honestly, because "it actually runs" is worth more than a diagram. The homelab is the
*reference environment*; it is **not** the security boundary. The guarantees and controls above
describe the **platform**; a production or authorized deployment supplies its own hardened
environment, organizational controls, and authorization boundary.
