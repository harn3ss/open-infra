# Signed compliance attestation

The capstone of the government feature track: turn "we implement these controls" from a claim in a
doc into a **signed, verifiable statement backed by live evidence from the running cluster**.

## What it is

An attestation is a snapshot of NIST 800-53 control coverage with the *evidence gathered from the
cluster at that moment* — how many temporal grants exist, how many data classifications and
classified workloads, how many customer-owned keys (and how many provisioned), how many crypto-erase
destructions completed with certificates, how many data flows are tracked, and the off-site audit
chain's recorded head **and when it was last verified**. (The attestation reports that head + verify
time as evidence; it does not itself re-verify the chain — the console's Audit → Integrity check does
that live, and because the off-siter leaves its anchor un-advanced on tamper, a stale verify time in
the attestation is itself a signal.) It is assembled by one component (`internal/attest`) used both by:

- the console **Security & Identity → Attestation** page (and `/api/compliance/attestation`) — the
  live, on-screen report; and
- `cmd/attest` — the same assembler, run by a CronJob, written to disk for signing.

Because both use the same assembler, what you read on screen is what gets signed.

## The immutable trail (opt-in)

Enable `components.attestation` and a daily CronJob writes each attestation (JSON + Markdown),
date-stamped, to the **WORM audit store** under `attestations/<date>/` with COMPLIANCE retention —
an undeletable record of what controls were in place, with what evidence, over time. It requires
audit off-siting (the WORM bucket) and reuses that scoped, put+retain MinIO identity.

## Signing (operator / CI — the release key stays out of the cluster)

Signing is deliberately **not** done in the cluster: the GPG private key that signs open-infra's
Terraform-provider releases must not live in k8s. You sign an attestation the same way you sign a
release — with that key, off-cluster — and publish the detached signature.

```sh
# Pull a stored attestation (or generate one live from the console endpoint / cmd/attest):
mc cp audit/openinfra-audit/attestations/2026-08-11/attestation.json .

# Sign with the release key (the same key + fingerprint as provider releases):
gpg --local-user <release-key-id> --detach-sign --armor attestation.json
#   → attestation.json.asc

# Publish attestation.json + attestation.json.asc (e.g. attach to a compliance record / release).
```

Verification, by anyone with the published public key:

```sh
gpg --import openinfra-release-pubkey.asc      # the same public key that verifies provider releases
gpg --verify attestation.json.asc attestation.json
```

A good signature over an attestation that carries the cluster's live evidence is the deliverable:
it ties a specific control-coverage claim, with counts, to a specific point in time, signed by the
key holder.

## Honesty

- **Presence is not certification.** The attestation reports which control *mechanisms* are present
  and their live evidence; it does not assert accreditation. See
  [`security-and-compliance.md`](security-and-compliance.md) for the full control mapping and the
  "what compliance means here" framing.
- The evidence is **counts and status**, gathered read-only from Kubernetes — no secrets, no key
  material. The signature attests to *that snapshot*, not to a runtime guarantee.
- The stored snapshots are immutable (WORM); the signature is applied out-of-band, so its trust rests
  on the release key's custody — exactly as for a signed release.

## Control mapping

- **CA-2 / CA-7** — assessment & continuous monitoring: evidence generated from the live system.
- **AU / SI-12** — the immutable, dated trail of attestations.
- Reuses the provider release-signing key (integrity / non-repudiation of the artifact).
