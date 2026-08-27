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

The **hardened deployment profile** (opt-in `components.hardened`, shipped) extends this: no Chaos Mesh
install, RBAC that withholds `FaultInjection`, no `AUTH_MODE=none`, restricted Pod Security enforced on
the console namespace, and the experimental tier disabled.

## NIST 800-53 control mapping

Control-level implementation statements for the families open-infra implements. This is a
**control-implementation summary, not an SSP** — an operator's System Security Plan (with its
authorization boundary, inherited controls, and organizational controls) is the authoritative
artifact; this shows what the platform provides toward it.

Status legend: **Implemented** (shipped and exercised) · **Partial** (core in place, hardening
tracked) · **Operator** (the deployment supplies/configures it) · **Roadmap** (planned).

The government control machinery (issue #71) was exercised end-to-end on the reference cluster on
2026-08-18 — see [`govt-track-verification-2026-08.md`](compliance/govt-track-verification-2026-08.md)
for exactly what was verified (audit off-siting integrity, Grant self-revoke, DataClassification,
attestation store), the three latent bugs that pass found and fixed, and what stays gated (customer-key
encryption and crypto-erase are Vault-gated and remain **not-live-verified**).

### AC — Access Control

| Control | Implementation | Status |
|---------|----------------|--------|
| AC-2 Account Management | `kind: User` / `kind: Group` created, disabled, and deleted from the console (Security & Identity) or `kubectl`; a break-glass `root` account for recovery. | Implemented |
| AC-2(2) Temporary / Emergency Accounts | `kind: Grant` gives time-bounded, self-revoking access; each grant requires **second-party approval** before it confers anything (a grant is AwaitingApproval until a different admin approves it). | Implemented |
| AC-3 Access Enforcement | Every console action runs as the signed-in user via Kubernetes **impersonation** (`Impersonate-User`/`-Group`); Kubernetes RBAC is the decision point. BFF-native endpoints are gated by a `SubjectAccessReview` first. | Implemented |
| AC-5 Separation of Duties | Built-in roles (admin / poweruser / readonly) plus `kind: Policy`/`Role` separate identity management, workload management, and read-only access; `kind: Grant` approval **requires a distinct approver** — the BFF rejects self-approval and the composition renders no binding when `approvedBy == requestedBy`. | Implemented |
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
| AU-9 / AU-9(2) / AU-9(3) Protection of Audit Information | The audit log is shipped off the writable node in a **hash chain** to a **WORM (Object Lock, COMPLIANCE) bucket** — undeletable by anyone, including root, until retention expires — and verified back into a broken/reordered/edited-detects result surfaced in the console. An optional external S3 sink keeps a copy on a separate system (AU-9(2)). See [`audit-offsite.md`](audit-offsite.md). | Implemented (external off-site copy is operator-configured; under **cluster-wide** restricted PSA the `monitoring` namespace needs a `privileged` exemption — the ship job reads a `0600` audit file via root+hostPath) |
| AU-11 / AU-4 Retention & Capacity | Loki retention for the queryable view; the off-site WORM segments carry a default ~7-year COMPLIANCE retention (configurable) that cannot be shortened. | Implemented |
| AU-12 Audit Record Generation | API-server audit log (host path is [substrate-configurable](portability.md)) + console `iam:` logs → promtail → Loki. | Implemented |

### IA — Identification & Authentication

| Control | Implementation | Status |
|---------|----------------|--------|
| IA-2 User Authentication | `AUTH_MODE` local (built-in accounts) and LDAP / Active Directory; OIDC is reserved (not yet implemented). | Implemented (OIDC: planned) |
| IA-2(1)(2) MFA | Delegated to the backing directory (LDAP/AD, or an OIDC IdP when added). | Operator |
| IA-4 Identifier Management | `kind: User`; console identities are namespaced `openinfra:<user>` so they can never collide with real cluster users. | Implemented |
| IA-5 Authenticator Management | Local passwords hashed in a Secret; break-glass `root`; directory-backed modes delegate authenticator lifecycle. The experimental [AWS-SDK shim](aws-shim.md) adds SigV4 access keys as a `kind: User` sub-resource (one Secret per key, revocable); the shim **recomputes and constant-time-compares** the signature ("verify, don't just parse") — naming a key without holding its secret is rejected, and it reuses the same impersonated `SubjectAccessReview`, never a parallel auth path. | Implemented / Operator |

### SC — System & Communications Protection

| Control | Implementation | Status |
|---------|----------------|--------|
| SC-7 Boundary Protection | Cilium CNI with **default-deny** NetworkPolicy + `kind: SecurityGroup`; per-workload egress sandboxes (a Query pod may reach only DNS / MinIO / Trino). | Implemented |
| SC-8 Transmission Confidentiality/Integrity | TLS on ingress via cert-manager; control-plane and Chaos Mesh use mTLS; managed SQL-Server (Babelfish) enforces `Encrypt=mandatory`. | Implemented |
| SC-12 / SC-13 Key Management & Crypto Use | cert-manager issues and rotates certificates; **Sealed Secrets** keep secrets encrypted at rest in git; **`kind: EncryptionKey`** holds customer-owned keys in a Vault Transit KMS with rotation. | Partial (cert-manager + Sealed Secrets exercised; the customer-key Vault KMS is opt-in and **not yet live-verified** — gated on an operator initializing/unsealing Vault) |
| SC-23 Session Authenticity | HMAC-signed session cookie, `HttpOnly` + `Secure` + `SameSite=Lax`, plus a required CSRF header on all mutations. | Implemented |
| SC-28 / SC-28(1) Protection at Rest (customer keys) | Opt-in `encryption` component: encrypted Longhorn StorageClass (LUKS), and MinIO SSE-KMS / etcd KMS wiring keyed by a customer-owned Vault Transit key — open-infra never holds the key material. See [`encryption.md`](encryption.md). | Partial (opt-in; built and reviewed, **not yet live-verified** — Vault-gated) |
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
| CP-4 Contingency Plan Testing | The **nightly chaos suite** runs a seeded **lottery** (2–4 composed multi-master faults → proven byte-identical reconvergence) every night; a wider set of recover-mode contingency tests (HA-DB failover, CDC-pipeline resume, directory / fileshare / volume / VM recovery) runs on-demand. Every scenario — its fault-injection point, its invariant, and its last-verified date + method — is published in the auto-generated **[chaos-scenarios.md](chaos-scenarios.md)** gallery. | Implemented (nightly: multi-master; wider plane: on-demand) |

### Partial, roadmap, and operator-supplied

- **CA — Assessment & Continuous Monitoring** — the nightly lottery + convergence harness give
  continuous verification of multi-master recovery, and the [chaos-scenarios.md](chaos-scenarios.md)
  gallery is the per-scenario evidence record (chain, fault, invariant, last-verified date + method,
  auto-regenerated on each nightly). Continuous coverage is **strong for multi-master** and
  **point-in-time for the wider plane** (on-demand); folding the whole plane into the counted nightly,
  plus a formal control-evidence export, is **roadmap**. *(Partial)*
- **MP-6 Media Sanitization** — crypto-erase per NIST **SP 800-88**: `kind: Destruction` destroys a
  customer key (per-volume/DB) and writes a destruction certificate to the WORM store. **Live-verified**
  end-to-end by `probe/encryption-vault.sh` (provision → byte-identical round-trip → crypto-erase to
  unrecoverable), a re-runnable gate; bringing Vault up remains operator-gated (the customer holds the
  unseal keys). *(Verified; opt-in + operator-gated)*
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

Delivered so far:

- **`kind: Grant`** — temporal, auto-expiring access grants with a second-party **approval workflow**
  (AC-2(2)/AC-5/AC-6 just-in-time). See [`iam.md`](iam.md#kind-grant--temporal-just-in-time-access).
- **Audit off-siting** — hash-chained, WORM (object-lock) tamper-evident copy of the audit log,
  verifiable from the console, with an optional external sink (AU-9/AU-9(2)/AU-9(3)/AU-11). See
  [`audit-offsite.md`](audit-offsite.md).
- **`kind: DataClassification`** — a data-categorization scheme (RA-2) with a compliance auditor that
  checks tagged workloads against their class's handling requirements. See
  [`data-classification.md`](data-classification.md).
- **Encryption with customer-owned keys** — `kind: EncryptionKey` on a Vault Transit KMS, an encrypted
  Longhorn StorageClass, and the MinIO/etcd wiring runbook (SC-12/13/28/28(1)). Opt-in, off by
  default. See [`encryption.md`](encryption.md).
- **Crypto-erase** — `kind: Destruction` destroys a customer key (NIST SP 800-88), making all data it
  wrapped unrecoverable, and writes an immutable destruction certificate to the WORM audit store
  (MP-6). Opt-in. See [`destruction.md`](destruction.md).
- **Data lineage** — provenance of data movement (source→stream→sink), derived from the
  DataFlow/Migration/Replication/Stream topology (SI-12 / AU). See [`lineage.md`](lineage.md).
- **Signed compliance attestation** — live NIST control coverage with cluster evidence, viewable in
  the console, snapshotted immutably to the WORM audit store, and GPG-signable out-of-band with the
  release key (CA-2 / CA-7). See [`compliance-attestation.md`](compliance-attestation.md).
- **Hardened deployment profile** — opt-in `components.hardened`: enforces restricted Pod Security on
  the console namespace, disables the experimental tier and Chaos Mesh, withholds `FaultInjection`, and
  forbids `AUTH_MODE=none`, on top of the Cilium default-deny + `kind: SecurityGroup` network fence
  (CM-7 / AC-6).

## Maturity — don't over-trust the experimental tier

Security posture is only as good as the maturity of what it protects. open-infra tiers its
surface (see [README → Maturity & guarantees](../README.md#maturity--guarantees)): the PaaS
surface is **Stable**; the distributed-systems primitives (multi-master replication, CDC) are
**Experimental** until the graduation bar is met. A hardened deployment should run the Stable
surface and treat the Experimental tier as opt-in, not system-of-record.

## Reference environment vs. the platform

open-infra is developed and proven on a real cluster, and that cluster is a **residential computer lab** —
disclosed honestly, because "it actually runs" is worth more than a diagram. The residential computer lab is the
*reference environment*; it is **not** the security boundary. The guarantees and controls above
describe the **platform**; a production or authorized deployment supplies its own hardened
environment, organizational controls, and authorization boundary.

### Running on an operator-provided certified substrate

open-infra targets **operator-provided** Kubernetes substrates and is not bound to the reference lab or
to a specific CNI/CSI. Storage classes are configurable per resource (`spec.storageClass` on the
stream, migration, dataflow, directory, fileshare, and VM-image kinds, and `spec.database.storageClass`
on managed databases), so those planes deploy on whatever CSI the operator brings rather than requiring
a particular one. (VM root disks and standalone `Volume`s remain on Longhorn — live-migration needs its
RWX `longhorn-migratable` class — so a Longhorn-free substrate runs the data-plane and database kinds,
not VM live-migration or standalone block volumes.)

The platform has been **exercised end-to-end on a certified-track substrate** — SUSE Linux Enterprise
Server 15 SP7 + RKE2, **under FIPS mode** (kernel FIPS + FIPS crypto policy on every node) — including
the Crossplane control plane, the Stream/Function chain (CDC → JetStream → Knative), and multi-master
replication, with chaos-oracle fault injection (network partition, capture/sink kill) and enforced
PodSecurity `restricted` admission. The chaos run was **17 green / 2 red / 1 inconclusive**: the two
reds were both multi-master reconvergence edges — a flapping partition and a reproducible 2-master
member-kill seed that did not reconverge within the window — and the inconclusive was an app-availability
run whose replicas never came up (a setup artifact, not a product fault). **Both reds were subsequently
re-run on a clean, unhardened, homogeneous fleet and reconverged byte-identical every time (3/3 each)** —
so they were artifacts of the hardened-substrate environment and the root-cause deep-dive's overloaded
control-plane node (its convergence runner exhausted etcd on one box), not defects in the multi-master
engine itself. That is the expected result of exercising something that is still **Experimental**
(multi-master reconvergence, below); the same run also surfaced real issues that were fixed in-window — a
sandbox seed-vs-Postgres startup race and the data-plane `storageClass` portability gap. The substrate was additionally scanned against recognized baselines
— the OS with the DISA STIG OpenSCAP profile and the Kubernetes distribution with the CIS Kubernetes
benchmark — establishing an assessor-legible hardening posture (a baseline, with a documented
remediation path; full hardening is the deployer's). The scan results (DISA STIG 63 pass / 154 fail,
PCI-DSS v4 109/132, HIPAA 29/99, ANSSI-BP-028-high 146/193; CIS Kubernetes 53 pass / 9 fail / 46 warn,
all as-provisioned) and their remediation analysis are recorded in
[`docs/compliance/rke2-sles-fips-scan-2026-08.md`](compliance/rke2-sles-fips-scan-2026-08.md). A follow-on
re-scan after the STIG remediation was applied (2026-08-22) improved **every** framework — DISA STIG
194/25, PCI-DSS v4 166/76, HIPAA 92/36, ANSSI-BP-028-high 209/131 — showing the deployer-hardening step
generalizes across baselines rather than closing STIG alone. The full
OpenSCAP and kube-bench reports are retained in a dated evidence bundle (captured 2026-08-16, integrity
manifest [`rke2-sles-fips-evidence.MANIFEST.sha256`](compliance/rke2-sles-fips-evidence.MANIFEST.sha256),
SHA-256 `7baa8c10…`), available for assessor review. This is a validation **event**, not a certification of open-infra:
Common Criteria / FIPS 140-3 evaluations cover the **operating system and the Kubernetes cryptographic
module**, not the orchestration layer, and remain the deployer's to maintain via a subscribed,
in-evaluation-configuration substrate. This validation event is **amd64-only** — there is no arm64
FIPS substrate — and the first-party application images are standard `CGO_ENABLED=0` Go builds that
carry **no image-level FIPS claim on any architecture**. Run FIPS/regulated workloads on the amd64 +
SLES/RKE2 substrate; arm64 images (`-arm64` tags) are for portability and non-regulated use. See
[`architecture-support.md`](architecture-support.md). Consistent with the maturity note above, multi-master
reconvergence stays **Experimental** — a substrate exercise like this exists partly to find its edges.
