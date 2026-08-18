# Government feature track — live verification (2026-08-18)

The government control machinery (issue #71) shipped and was code-reviewed, but several controls had
never been *exercised end-to-end on a running cluster* — "built" is not "verified." This is a dated
record of a live verification pass on the reference cluster: what was exercised, what it found, and
what remains gated. It is verification evidence, **not** a certification (see
[`security-and-compliance.md`](../security-and-compliance.md) for the honesty framing).

## Summary

| Control / feature | Result | Evidence |
|---|---|---|
| Audit off-siting (AU-9) — ship | **Verified** | 2172 hash-chained segments shipped to the WORM bucket over 7 days (`head` advancing per run) |
| Audit off-siting (AU-9) — verify / integrity | **Verified (after fix)** | Full re-derivation: `intact:true`, 2172 segments / 6,303,408 records, `shadowVersions:0`; anchor advanced #25 → #2171 |
| Temporal access — `kind: Grant` (AC-2) | **Verified (after fix)** | A Grant rendered its `ClusterRoleBinding` (`openinfra:<user>` → role); a 1-minute Grant self-revoked on time — binding and CR both removed by the reconciler |
| DataClassification — taxonomy (AC-4/SC-28 marking) | **Verified (render)** | A class rendered its mirror ConfigMap (`openinfra-dataclass-*`) that the auditor reads |
| Signed compliance attestation (CA-2/CA-7) — generate + store | **Verified (after fix)** | A run generated the live NIST 800-53 attestation and stored `attestations/2026-08-18` to the WORM bucket |
| Encryption with customer keys (SC-12/13/28) | **Not verified — gated** | Vault is not deployed on this cluster; `probe/encryption-vault.sh` needs an operator to init/unseal Vault |
| Crypto-erase — `kind: Destruction` (MP-6) | **Not verified — gated** | Same Vault gate; shares the encryption probe |
| Data lineage (SI-12) | **Partial** | Parsing now unit-tested (`lineage_test.go`, incl. the `siteA/siteB` pin); a live end-to-end `/api/lineage` exercise (BFF/session-gated) is still open |

## Bugs the verification found (all were silently broken on the running cluster)

1. **Audit-offsite `verify` OOM-killed for 7 days.** The integrity job re-derived the whole chain by
   loading every segment's records into memory (6.3M audit lines across log rotations); it exceeded its
   256Mi limit — and even a one-off 1Gi run OOM'd. The integrity anchor had stalled at seq #25
   (2026-08-10) while `ship` advanced to #2171: no integrity check had succeeded in a week, on an
   enforced-default AU-9 control. **Fixed** by streaming the verification one segment at a time
   (`auditchain.StreamVerifier`, O(1) memory); the fixed job then proved the chain intact (above).

2. **Grant self-revoke wedged for 12h.** A reconcile job hit `activeDeadlineSeconds`, its pod stuck in
   `Terminating`, and `concurrencyPolicy: Forbid` counted that job as "active" — so every subsequent
   minute's sweep was skipped and no Grant expired. **Fixed** with `concurrencyPolicy: Replace` +
   `ttlSecondsAfterFinished` (the sweep is idempotent, so a stuck run is superseded on the next tick).
   This is the "async teardown" risk the docs flagged, made real and closed.

3. **Attestation store broken for 39h+.** The `fetch-mc` init copies `mc` from the `minio/mc` image,
   which now ships the binary without world-read, so under the pod-default uid 65532 the copy failed
   "Permission denied" — breaking the store step and every attestation snapshot silently. **Fixed** by
   running that isolated binary-copy init as root (the store container stays hardened, non-root).

## What remains

- **Encryption + crypto-erase** stay **Experimental / not-live-verified**: they require an operator to
  deploy and init/unseal Vault, then run `probe/encryption-vault.sh`. That single gated session drops
  both experimental flags. This is a deliberate human gate (unseal-key custody), not a defect.
- **Data lineage** parsing is now unit-tested — the four per-kind parsers were extracted from the
  handler and covered in `lineage_test.go` (commit a0d2cdd), with the `siteA/siteB` shape pinned so the
  dropped-edge regression can't return. A live end-to-end `/api/lineage` exercise against real CRs
  (BFF/session-gated) remains the open item.
- The three fixes above are deployed live and in git; the audit-offsite fix also ships in its rebuilt
  image so the scheduled hourly verify stops OOMing.
