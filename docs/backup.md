# Backup — `kind: BackupVault` + `kind: BackupPlan`

open-infra offers AWS Backup–shaped, declarative backups: a **vault** is an isolated
destination for recovery points, and a **plan** schedules retained backups of selected
resources into a vault. They compile to [Velero](https://velero.io) objects — the engine
that already powers the cluster-wide backup in `platform/backup/` — so a plan protects the
workloads your `kind: Application` / managed database / `kind: VirtualMachine` render:
Kubernetes objects **and** persistent-volume data (filesystem backup) to object storage.

Both kinds ride the opt-in **`backup`** component (the Velero install). They are
**experimental**.

## How it maps

| AWS Backup | open-infra | Velero |
|---|---|---|
| Backup vault | `kind: BackupVault` | a `BackupStorageLocation` (`openinfra-vault-<name>`), prefix-isolated in the MinIO `velero` bucket |
| Backup plan | `kind: BackupPlan` | one `Schedule` per rule (`<plan>-<rule>`) |
| Plan rule (schedule + lifecycle + target vault) | `spec.rules[]` (`schedule` + `retentionDays` + `targetVault`) | `Schedule.spec.schedule` + `template.ttl` + `template.storageLocation` |
| Resource assignment (by tag/ARN) | `spec.selection` (namespaces + label selector + resource types) | `template.includedNamespaces` / `labelSelector` / `includedResources` |

A vault is a **separate kind** from a plan (not a field on it) because the vault owns the
`BackupStorageLocation` and has its own lifecycle: several plans can target one vault, so the
storage location is created once and referenced — exactly as an AWS plan references a vault.

## Example

```yaml
apiVersion: openinfra.dev/v1
kind: BackupVault
metadata: { name: prod, namespace: team-a }
spec:
  description: production database backups
---
apiVersion: openinfra.dev/v1
kind: BackupPlan
metadata: { name: db-backup, namespace: team-a }
spec:
  rules:
    - { name: daily,  schedule: "0 3 * * *", retentionDays: 7,  targetVault: prod }
    - { name: weekly, schedule: "0 4 * * 0", retentionDays: 90, targetVault: prod }
  selection:
    includedNamespaces: [team-a]
    labelSelector: { app: payments }           # only objects with this label
    includedResources: [clusters.postgresql.cnpg.io, persistentvolumeclaims]
```

With no `selection`, a plan backs up **all** namespaces except the system/backup ones
(`kube-system`, `velero`, `minio`) — the same excludes the cluster-wide `daily` schedule
uses, so a plan never tries to back up the backup store itself.

## Honest scope

- Retention is the per-rule **TTL**: Velero deletes a backup when it expires. This is **not**
  AWS Vault Lock (immutable WORM / compliance retention) — the vault isolates recovery points
  by storage prefix, it does not make them immutable.
- Recovery is via Velero restore (`velero restore create --from-backup <plan>-<rule>-<timestamp>`);
  a declarative `kind: Restore` is not yet modelled.
- Velero backs up what it can see in the cluster (objects + PV data via filesystem backup);
  it is not a per-AWS-service snapshot API. For database point-in-time recovery, see the
  managed-database `pointInTimeRecovery` knob, which is a separate, finer mechanism.
