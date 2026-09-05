# NIST 800-53 control mapping — platform-wide Cedar authorization

Companion to the decision that Cedar becomes the platform-wide authorization authority, replacing
Kubernetes RBAC as base grantor. This maps that mechanism change to 800-53 / 800-53A.

**Rails:** built ≠ verified ≠ certified; theorized ≠ observed; honest-unknown over guessed-green. A
control whose evidence has not been regenerated under Cedar is an **open control**, not a pass.
800-53 prescribes **outcomes** (approved authorizations are enforced), not mechanisms — so a mechanism
change is not automatically a regression, but the **evidence** for each affected control must be
re-established against the new mechanism.

## Current state (must anchor every claim below — established by inspection, 2026-09-05)

- **Cedar is NOT yet the live control-plane authority.** The Cedar authorization webhook
  (`cmd/authz-webhook`) is deployed in **shadow** mode (authorization-mode `Node,RBAC,Webhook`,
  webhook last, no-opinion) with an **empty corpus**. RBAC remains the base grantor. So on the control
  plane, Cedar today enforces nothing observable.
- **Data-plane Cedar** (aws-shim `spec.dataPlane`) is **opt-in and OFF by default**; no live platform
  traffic is governed by it.
- Therefore every Cedar "gain" below is presently **capability**, not **live-observed enforcement**.
  This is the honest gate: the net 800-53 effect is positive only once #109 Phase 2 (webhook enforcing,
  RBAC divergence measured) and Phase 3 (corpus checker on a cadence, committed evidence) land.

### Task 3 — currently-unknown facts, established by reading the artifacts

1. **Do scan profiles contain Kubernetes-level benchmark content, or purely OS STIG?**
   **Both** (`docs/compliance/rke2-sles-fips-scan-2026-08.md`): (a) **DISA STIG for SLES 15**
   (`xccdf_org.ssgproject.content_profile_stig`, OpenSCAP) — OS layer; and (b) **CIS Kubernetes
   Benchmark on RKE2** (kube-bench, `rke2-cis`) — 53 pass, 46 WARN, the WARN concentrated in the
   **policies** section (RBAC / network-policy / PSS, manual-review by design). **This is the inherited
   authorization assurance:** the CIS-K8s RBAC controls supply the authorization-surface evidence today
   at no argumentative cost. When Cedar replaces RBAC as base grantor, those CIS RBAC controls' premise
   no longer holds and the evidence must be manufactured (the corpus checker below is the replacement).
   *Scope note:* this scan is the **RKE2+SLES production-gov substrate**; the k3s dev cluster is not
   CIS-benchmarked. The Cedar decision is platform-wide, so it bears on the substrate's inherited story.
2. **Corpus checker exists** (`console-api/internal/corpuscheck/corpuscheck.go`, `cmd/corpus-check`):
   flags cluster-admin-equivalent grants, wildcard-resource, cluster-wide secret reads, and escalation
   verbs — the machine-checkable equivalent of the CIS RBAC controls. **Built; not yet run on a
   cadence producing committed evidence.** `rbactocedar` (`cmd/rbac-to-cedar`) converts RBAC to Cedar
   grants for it to check.
3. **Claimed-control inventory / overclaim audit:** coordinated with the standing gov/FedRAMP
   overclaim audit (`docs/security-and-compliance.md`), not duplicated here.

## Task 1 — controls where Cedar is a genuine capability GAIN

Status legend: **[cap]** capability exists · **[obs]** live-observed · **[evi]** evidence artifact
committed · **[ext]** externally assured. Nothing below is [obs]+ on the control plane yet (shadow/empty).

| Control | What pure RBAC cannot do | What Cedar expresses | Status | Evidence needed to reach [obs] |
|---|---|---|---|---|
| **AC-3 Access Enforcement** | RBAC is additive-only: no deny that a grant can't route around | Explicit `forbid` that overrides any `permit` (formally: forbid-overrides) | **[cap]** (forbid-overrides is proven in `policyengine` unit tests + live on the data-plane shim per `evidence/data-plane-policy-enforcement.md`); **control-plane [cap] only** — shadow | Webhook in **enforce** mode denying a request an RBAC role would allow, recorded |
| **AC-6 Least Privilege** | Least privilege only by *absence* of grants; cannot assert "denied even though a role permits" | default-deny + explicit `forbid` on privileged actions | **[cap]** | A privileged action (e.g. cluster-wide secret read) denied by a `forbid` while a bound role would permit it — observed on the control plane |
| **AC-6(9)/(10) privileged functions** | No first-class notion of privileged-function gating beyond verb/resource | `forbid` scoped to privileged actions + conditions | **[cap]** | Same, for a named privileged function |
| **AC-2 Account Management** | Principals are RBAC subjects; SA/user/group mapping is implicit | Users/Groups/Roles/ServiceAccounts as typed Cedar principals; assumed-role sessions as `Role` principals (#111) | **[cap]** partial — the principal model exists (kind: User/Group/Role, aws-shim SigV4 + assumed-role); the **corpus** that would evidence account-management decisions is empty | A populated corpus + the access-review report (already shipped, AC-2/AC-6) cross-referenced to Cedar principals |
| **AC-17 Remote Access** | RBAC has **no request-context** notion (no source IP / time) | Conditions on request context (source, MFA assertion, tags) | **[cap] data-plane only** — the aws-shim plumbs request context (source IP, etc.); the **control-plane webhook does not yet populate condition attributes** | Condition attributes plumbed into the webhook's request context + a source-conditioned decision observed |
| **IA-2 / MFA sub-controls** | No authorization gating on an MFA assertion | `forbid unless context.mfa` — **authorization gating** on an MFA claim | **[cap]** for the *gating half* only. **Boundary:** Cedar gates *on* an MFA assertion; it does **not** perform authentication or establish MFA — that is the authentication surface, out of scope per #109. Record precisely: Cedar satisfies "deny privileged action absent MFA claim," not "MFA is enforced at login" | An MFA-gated `forbid` observed + the auth surface shown to supply the claim |
| **AU-2/AU-3/AU-12 Audit** | Split story: RBAC decisions in the apiserver audit log, shim decisions separately | A single uniform decision log across control plane + data plane (one evaluator) | **[cap]** — uniformity is a design property; today the two planes still log separately (apiserver audit → Loki; shim → its own). The webhook would have to emit a decision record per call for the uniform-log claim to hold | Webhook emitting per-decision audit records into the same pipeline (Loki), shown alongside apiserver audit |
| **AC-4 / SC-7 adjacency** | — | Only insofar as authz decisions bear on information-flow claims | **[cap] narrow** — do NOT claim network-enforcement controls here (kind: SecurityGroup / NetworkPolicy is a different plane, #120) | n/a — explicitly not overreaching |

## Task 2 — controls where the assurance burden SHIFTS (the honest cost)

| Control | The shift | Current honest state | What closes it |
|---|---|---|---|
| **CM-6 Configuration Settings** (load-bearing) | CIS-K8s Benchmark supplies a documented RBAC baseline for free; a Cedar corpus has **no published benchmark** | **OPEN.** No authored Cedar configuration baseline positioned as the CM-6 artifact yet | An authored, documented Cedar corpus baseline as the CM-6 artifact, + a statement of which CIS controls it replaces and which CIS controls' premise no longer holds |
| **CA-2 Control Assessments** | Was: CIS-K8s scan. Now: depends on the corpus checker running | **by-inspection only** — `corpus-check` exists but is not wired to run + emit evidence | corpus-check run against the live corpus, output committed under `evidence/` |
| **CA-7 Continuous Monitoring** | Same, on a cadence | **OPEN** — no cadence | corpus-check on a schedule (CronJob), evidence artifacts over time |
| **CM-3 / CM-4 Change Control / Impact Analysis** | Policy changes become security-relevant config changes to the whole platform | **partial [cap]** — the `kind: Policy` git path is declarative, version-controlled, diffable (a real strength: every change is a reviewable PR); missing = a documented impact-analysis step for policy changes | Document the policy-change review/impact process; a policy-simulator (planned) strengthens it |
| **SA-11 Developer Testing** | — | **[cap]+cite** — Cedar's evaluator is formally verified (a genuine assurance asset for the *evaluator*). It says **nothing** about corpus correctness | Cite the Cedar formal-verification work for the evaluator; corpus correctness is the corpus checker's job (CA-2/CA-7) |
| **SI-2 / RA-5 adjacency** | The authorizer becomes a security-relevant component in the control-plane path | **noted** — the webhook's own vulnerability posture must be tracked (image scanning, patching) like any in-path service | Webhook image in the standard scan/patch cadence |
| **CP / SC availability** | The authorizer's availability is now a platform-wide dependency; its latency is the control plane's latency | **OPEN** — #109 Phase 2 step 5 (availability + failure behaviour) is a stated-decision-with-evidence still owed; must be fail-closed-by-construction, TLS on validated modules | Documented + evidenced availability/failure decision from #109 Phase 2 |

## Open controls (the true gate on #109 Phase 2 step 6 — removing RBAC)

The moment RBAC leaves the apiserver authorization chain, these lose their current evidence and must
already be re-evidenced under Cedar, or they become **unevidenced**:

1. **CM-6** — no Cedar CM-6 baseline artifact yet (CIS-K8s RBAC baseline no longer applies).
2. **CA-2 / CA-7** — corpus checker not yet run-on-cadence with committed evidence.
3. **AC-3 / AC-6** — control-plane enforcement is shadow; no observed Cedar denial on the control plane.
4. **AC-17 / IA-2 conditions** — the webhook does not yet populate request-context condition attributes.
5. **AU-2/3/12 uniform log** — the webhook does not yet emit decision records.
6. **CP/SC availability** — the authorizer availability/failure decision is not yet evidenced.

Until this list is cleared, platform-wide Cedar authorization is an **honest unknown** with respect to
800-53 and must be described that way in any external-facing material. Removing RBAC (#109 Phase 2
step 6) before this list is closed would convert inherited-and-real assurance into unevidenced claims.

## Assessor-facing narrative

800-53 prescribes outcomes — that approved authorizations are enforced — not a specific mechanism.
Kubernetes RBAC is one mechanism; it is additive-only and cannot express an ungrantable deny, request
conditions, or default-deny as a first-class property. Cedar can. So replacing RBAC with Cedar is a
**capability gain** against AC-3/AC-6/AC-17/IA-2, not a regression.

The honest cost: part of today's authorization assurance is **inherited** from the CIS Kubernetes
Benchmark (a published, third-party, machine-checkable RBAC baseline scanned via kube-bench). Cedar has
no published benchmark. Under full replacement, that assurance splits: the **evaluator** half holds up
and arguably strengthens (Cedar is formally verified — SA-11), but the **configuration** half becomes
the project's own to author (a CM-6 Cedar baseline) and to check continuously (a corpus checker, built
but not yet on a cadence — CA-2/CA-7). The net 800-53 posture improves **only after** that
project-owned assurance is manufactured and evidenced. Until then this mapping records capability, not
control satisfaction — deliberately, per the project's built ≠ verified ≠ certified rail.

## References
- `console-api/cmd/authz-webhook`, `console-api/internal/controlplaneauthz` (the webhook)
- `console-api/internal/corpuscheck`, `cmd/corpus-check`, `cmd/rbac-to-cedar` (Phase-3 tooling, built)
- `docs/policy-engine.md`, `docs/authz-webhook.md`, `docs/security-and-compliance.md`
- `docs/compliance/rke2-sles-fips-scan-2026-08.md` (the STIG + CIS-K8s scan)
- `evidence/data-plane-policy-enforcement.md` (data-plane forbid-overrides, live)
