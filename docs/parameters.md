# Parameters (`kind: Parameter`)

`kind: Parameter` is a hierarchical, optionally-encrypted parameter store — the AWS SSM Parameter
Store equivalent. Each parameter's value is held in Vault's KV-v2 `params` mount under its path and
materialized (with every other parameter in the namespace) into a per-namespace
`openinfra-parameters` Secret that applications read at boot.

It rides the opt-in **`encryption`** component (Vault). Enable it with `components.encryption: true`.

```yaml
apiVersion: openinfra.dev/v1
kind: Parameter
metadata: { name: db-host, namespace: shop }
spec:
  path: /app/db/host
  value: postgres.shop.svc.cluster.local
  type: String          # or SecureString
```

## How apps consume it

The reconciler flattens each path into an `UPPER_SNAKE` env key — `/app/db/host` → `APP_DB_HOST` —
and writes all of a namespace's parameters into one `openinfra-parameters` Secret. Reference it from
an `Application` or `Function` via the existing `spec.secrets` field; it is injected with `envFrom`:

```yaml
apiVersion: openinfra.dev/v1
kind: Application
metadata: { name: web, namespace: shop }
spec:
  image: ghcr.io/acme/web:1.2.3
  secrets: [openinfra-parameters]   # APP_DB_HOST (and the rest) become env vars
```

## Hierarchy, types, and tiers

- **Hierarchy** is the path convention. In Vault the tree lives at `params/<namespace>/<path>`, so an
  SSM `GetParametersByPath`-style read is a KV list under a prefix.
- **`type`** is `String` or `SecureString`. Both are stored in Vault (encrypted at rest) and
  materialized into a Kubernetes Secret; the type is advisory metadata surfaced in the console.
- **`tier`** (`Standard` / `Advanced`) mirrors SSM's tiers as metadata.

## Reconciliation

A CronJob (`parameter-reconciler`, every 5 minutes) logs in to Vault with its own ServiceAccount
(no stored credential), writes each value to the KV tree, and rebuilds the namespace Secret.
Changing a value takes effect on the next reconcile; a rolling restart of the consuming workload
picks up the new environment. Its Vault policy is scoped to the `params/*` mount only.

**Status:** built; not yet live-verified end-to-end on a cluster. Values are currently set inline on
the CR (`spec.value`); a `valueFrom` secret reference is a planned follow-on for populating a
`SecureString` without the value passing through the CR spec.
