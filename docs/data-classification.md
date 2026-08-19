# Data classification — categorize data, then check its handling

Government data handling starts with **categorization** (NIST SP 800-53 **RA-2**): decide how
sensitive a piece of data is, then require controls proportionate to that level. open-infra models
this with `kind: DataClassification` (the taxonomy) plus a compliance auditor (the check).

## Defining a classification

A `DataClassification` names a sensitivity level and the handling requirements data at that level
must meet:

```yaml
apiVersion: openinfra.dev/v1
kind: DataClassification
metadata: { name: restricted, namespace: platform }
spec:
  level: restricted            # public | internal | confidential | restricted (low→high)
  description: "CUI / regulated customer data"
  requires:
    encryptionAtRest: true
    networkRestricted: true    # a SecurityGroup / NetworkPolicy must cover it
    noPublicExposure: true     # no LoadBalancer / public ingress
    backup: true
    residencyNodeLabel: openinfra.dev/residency   # must be pinned to labelled nodes
    retentionDays: 2555
```

It is deliberately **admin / security-team managed** — a categorization scheme is set centrally, so
it is excluded from what a `kind: Policy` can grant. It compiles to a labelled ConfigMap in the
console namespace that the auditor reads.

## Tagging data

Label the workload that holds or serves the data:

```yaml
metadata:
  labels:
    openinfra.dev/classification: restricted
```

Deployments and StatefulSets carrying the label are brought under their class's requirements.

## Checking compliance

The console **Security & Identity → Data Classification** page (and `/api/compliance/classification`,
admin-gated) evaluates every tagged workload against its class and reports per-rule **pass / fail /
unknown** — a detect-and-report control, like AWS Config rules. What it checks today, from the typed
Kubernetes API:

| Requirement | How it is checked |
|---|---|
| `noPublicExposure` | no `LoadBalancer` Service selects the workload's pods |
| `networkRestricted` | a `NetworkPolicy` selects the workload's pods |
| `residencyNodeLabel` | the pod template's `nodeSelector` pins to the required node label |
| `encryptionAtRest` | every persistent data volume sits on an **encrypted** StorageClass (parameter `encrypted=true`, e.g. the Longhorn LUKS class) — **fail** if any is not, **unknown** (never a false pass) for a stateless workload or an unreadable class/PVC |
| `backup` | **unknown** — there is no standing per-workload backup *policy* resource to interrogate (the backup subsystem is on-demand snapshot / final-snapshot-before-delete, not scheduled per-workload protection) |

Requirements a class does not ask for are skipped; requirements that cannot yet be verified are
reported `unknown` rather than passed silently. As the encryption and backup features land, their
checks move from `unknown` to real verification.

**Coverage today.** The auditor evaluates labelled **Deployments and StatefulSets**. Managed
databases (CloudNativePG `Cluster`s), `Volume`s, `FileShare`s, and object buckets are not yet
evaluated — label those and they will simply not appear in the report until their evaluators are
added. This is a reporting scope, stated so it is not mistaken for full coverage.

## Control mapping

- **RA-2** Security Categorization — the levels + the taxonomy.
- **MP-3** Media Marking — the classification label is the marking.
- **AC-4 / SC-28** — the handling requirements (network restriction, no public exposure, residency,
  encryption at rest) the levels express and the auditor checks.
