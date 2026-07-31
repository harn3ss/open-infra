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

## NIST 800-53 control mapping

Control-level implementation statements for the families open-infra implements. This is a
**control-implementation summary, not an SSP** — an operator's System Security Plan (with its
authorization boundary, inherited controls, and organizational controls) is the authoritative
artifact; this shows what the platform provides toward it.

Status legend: **Implemented** (shipped and exercised) · **Partial** (core in place, hardening
tracked) · **Operator** (the deployment supplies/configures it) · **Roadmap** (planned).

### AC — Access Control

| Control | Implementation | Status |
|---------|----------------|--------|
| AC-2 Account Management | `kind: User` / `kind: Group` created, disabled, and deleted from the console (Security & Identity) or `kubectl`; a break-glass `root` account for recovery. | Implemented |
| AC-3 Access Enforcement | Every console action runs as the signed-in user via Kubernetes **impersonation** (`Impersonate-User`/`-Group`); Kubernetes RBAC is the decision point. BFF-native endpoints are gated by a `SubjectAccessReview` first. | Implemented |
| AC-5 Separation of Duties | Built-in roles (admin / poweruser / readonly) plus `kind: Policy`/`Role` separate identity management, workload management, and read-only access. | Implemented |
| AC-6 Least Privilege | Policies/Roles grant only within the `openinfra.dev` workload-kind permission **boundary** (never secrets or RBAC); an **impersonation ceiling** caps what the console SA may impersonate; service identities are scoped (per-bucket MinIO users, non-root read-only-rootfs pods, no SA token where unused). | Implemented |
| AC-6(9) Audit Use of Privileged Functions | IAM/RBAC/`openinfra.dev` writes are captured at `RequestResponse` in the audit log. | Implemented |
| AC-14 Permitted Actions w/o Auth | None in the hardened posture; `AUTH_MODE=none` (dev only) disables auth and raises a persistent banner. | Implemented (secure default) |
| AC-17 Remote Access | Console over TLS; public exposure via outbound-only Cloudflare Tunnel (no inbound ports) or WireGuard. | Implemented / Operator |

### AU — Audit & Accountability

| Control | Implementation | Status |
|---------|----------------|--------|
| AU-2 Event Logging | API-server audit policy logs create/update/patch/delete on IAM, RBAC, and `openinfra.dev` resources; read and lease noise is dropped. | Implemented |
| AU-3 Content of Audit Records | Records carry actor (`impersonatedUser`), verb, resource, timestamp, and response code; privileged writes are captured at **`RequestResponse`** (full request + response body). | Implemented |
| AU-6 Audit Review & Analysis | Console **Audit** view, filterable by user / resource / time, merging the API-server log with console IAM actions. | Implemented |
| AU-8 Time Stamps | `requestReceivedTimestamp` on every record. | Implemented |
| AU-9 Protection of Audit Information | Shipped to Loki off the writable node; hash-chain + signing + WORM object-lock for tamper-evidence is **roadmap**. | Partial |
| AU-11 / AU-4 Retention & Capacity | Loki retention today; long-term + off-site retention is **roadmap**. | Partial |
| AU-12 Audit Record Generation | k3s API-server audit log + console `iam:` logs → promtail → Loki. | Implemented |

### IA — Identification & Authentication

| Control | Implementation | Status |
|---------|----------------|--------|
| IA-2 User Authentication | `AUTH_MODE` local (built-in accounts) and LDAP / Active Directory; OIDC is reserved (not yet implemented). | Implemented (OIDC: planned) |
| IA-2(1)(2) MFA | Delegated to the backing directory (LDAP/AD, or an OIDC IdP when added). | Operator |
| IA-4 Identifier Management | `kind: User`; console identities are namespaced `openinfra:<user>` so they can never collide with real cluster users. | Implemented |
| IA-5 Authenticator Management | Local passwords hashed in a Secret; break-glass `root`; directory-backed modes delegate authenticator lifecycle. | Implemented / Operator |

### SC — System & Communications Protection

| Control | Implementation | Status |
|---------|----------------|--------|
| SC-7 Boundary Protection | Cilium CNI with **default-deny** NetworkPolicy + `kind: SecurityGroup`; per-workload egress sandboxes (a Query pod may reach only DNS / MinIO / Trino). | Implemented |
| SC-8 Transmission Confidentiality/Integrity | TLS on ingress via cert-manager; control-plane and Chaos Mesh use mTLS; managed SQL-Server (Babelfish) enforces `Encrypt=mandatory`. | Implemented |
| SC-12 / SC-13 Key Management & Crypto Use | cert-manager issues and rotates certificates; **Sealed Secrets** keep secrets encrypted at rest in git. | Implemented |
| SC-23 Session Authenticity | HMAC-signed session cookie, `HttpOnly` + `Secure` + `SameSite=Lax`, plus a required CSRF header on all mutations. | Implemented |
| SC-28 Protection at Rest | Relies on the underlying storage today; **customer-managed-key** encryption is **roadmap**. | Partial |
| SC-5 Denial-of-Service Protection | Cloudflare edge when publicly exposed; dependency DoS CVEs remediated via SI-2. | Partial / Operator |

### CM — Configuration Management

| Control | Implementation | Status |
|---------|----------------|--------|
| CM-2 Baseline Configuration | The entire platform is a declarative GitOps baseline, reconciled continuously by Argo CD. | Implemented |
| CM-3 Configuration Change Control | Changes land via git (review) and apply only through Argo sync; `selfHeal` reverts out-of-band drift. | Implemented |
| CM-4 Impact Analysis | CI (`test.yml`: Go race tests + UI typecheck/build) and drift checkers gate changes before merge. | Implemented |
| CM-5 Access Restrictions for Change | Git plus Kubernetes RBAC restrict who can change configuration. | Implemented / Operator |
| CM-6 Configuration Settings | Settings are declarative manifests, not imperative host state. | Implemented |
| CM-7 Least Functionality | Secure-by-default: auth required, fault injection off unless `CHAOS_UI_ENABLED=true`, per-component install toggles, anonymous Grafana reachable only through the authenticated proxy. | Implemented |
| CM-8 Component Inventory | The Argo app-of-apps is the authoritative, versioned component inventory. | Implemented |

### SI — System & Information Integrity

| Control | Implementation | Status |
|---------|----------------|--------|
| SI-2 Flaw Remediation | Trivy scans every built image and uploads results to GitHub code-scanning; Dependabot opens grouped weekly version-update PRs and security PRs on demand; CI (including the UI gate) verifies them. | Implemented |
| SI-3 Malicious Code Protection | Images are Trivy-scanned and **cosign-signed** (keyless / Sigstore); the Babelfish image is patched to 0 fixable CVEs. | Implemented |
| SI-4 System Monitoring | Prometheus metrics + Loki logs + Alertmanager; platform and per-GPU dashboards. | Implemented |
| SI-7 Software / Information Integrity | Cosign signatures on images; GitOps means running state derives from reviewed, signed git. | Implemented |
| SI-10 Information Input Validation | IAM policy statements validated against the resource/verb boundary; CRD schemas validate resource input at admission. | Implemented |

### CP — Contingency Planning

| Control | Implementation | Status |
|---------|----------------|--------|
| CP-9 System Backup | Velero (cluster objects) + Longhorn (volume snapshots) to MinIO; RDS-style pre-delete snapshots for databases and VMs. | Implemented |
| CP-10 Recovery & Reconstitution | Restore from Velero/Longhorn backups and snapshots; KubeVirt live migration for VM node-loss recovery. | Implemented |
| CP-4 Contingency Plan Testing | The **nightly chaos suite** (partition, primary failover, clock-skew, convergence) is automated contingency-test evidence. | Implemented |

### Partial, roadmap, and operator-supplied

- **CA — Assessment & Continuous Monitoring** — the convergence harness and nightly chaos are
  continuous verification; a formal control-evidence pipeline is **roadmap**. *(Partial)*
- **MP-6 Media Sanitization** — crypto-erase per NIST **SP 800-88** (per-volume/DB keys;
  deletion destroys the key and writes a destruction certificate) is **roadmap** (#71).
- **RA / PL / PS / IR / AT / CA process controls** — risk assessment, planning, personnel
  security, incident response, and awareness training are **organizational** controls the
  operator supplies; the platform provides evidence sources (audit, monitoring), not the
  programs themselves.

For contractors handling **Controlled Unclassified Information (CUI)**, **NIST SP 800-171** is
the lighter-weight cousin; the AC/AU/IA/SC/CM/SI statements above map directly onto its
requirement families.

## Continuous assurance — flaw remediation (SI-2, SI-3, SI-7)

Flaw remediation is not a one-time scan here; it is a **closed loop** that runs on every
change and on a schedule, which is what an assessor looks for under SI-2:

1. **Detect.** Every image CI builds is scanned by **Trivy**, and results are uploaded to
   GitHub **code-scanning** (the Security tab). Vulnerable dependencies surface as alerts
   with severity, the affected package, and the fixed version.
2. **Track.** **Dependabot** opens grouped version-update PRs weekly and security PRs on
   demand across all ecosystems (Go modules, the console npm tree, GitHub Actions). Nothing
   relies on someone remembering to check.
3. **Verify.** CI gates every dependency PR — Go race tests plus a **UI typecheck + build**
   job — so a bump that breaks the build or types cannot merge. (That gate was added after a
   TypeScript major slipped through unverified; the loop now closes that hole.)
4. **Remediate.** The fix merges through the normal reviewed-git → Argo path. Worked example:
   `CVE-2026-56852` (an infinite-loop DoS in `golang.org/x/text`) was surfaced by Trivy and
   remediated by a dependency bump, verified green, the same day.

Two guardrails keep the loop from doing harm: fragile major upgrades (e.g. the `@rjsf`
form-library family, whose packages must move in lockstep) are **held** for a deliberate
migration rather than auto-merged; and image **provenance** is established by **cosign**
keyless signatures (SI-3 / SI-7), so what runs is traceable to reviewed, signed source.

Scope, honestly: this covers **dependency and container-image** flaws. Host/OS patching, and
application-level penetration testing, are the operator's responsibility (host OS patching is
outside the platform; the images themselves are rebuilt and re-scanned on each release — the
Babelfish image, for instance, ships at 0 fixable CVEs).

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
