# Parameters (`kind: Parameter`)

`kind: Parameter` is a hierarchical, optionally-encrypted parameter store — the AWS SSM Parameter
Store equivalent. Each parameter's value is held in OpenBao's KV-v2 `params` mount under its path and
materialized (with every other parameter in the namespace) into a per-namespace
`openinfra-parameters` Secret that applications read at boot.

It rides the opt-in **`encryption`** component, whose key service is [OpenBao](openbao.md). Enable it
with `components.openbao: true` and `components.encryption: true`.

```yaml
apiVersion: openinfra.dev/v1
kind: Parameter
metadata: { name: db-host, namespace: shop }
spec:
  path: /app/db/host
  value: postgres.shop.svc.cluster.local
  type: String          # or SecureString
```

## Value by reference (populate out-of-band)

`value` is **optional**. Omit it to declare a parameter — its `path`, `type`, and other metadata —
*without* putting the value in the manifest, and populate the value out-of-band into the same OpenBao
path instead (`params/<namespace><path>`, key `value`). The reconciler materializes it into the
namespace Secret once present; until then the parameter is simply absent from the Secret (eventually
consistent, never an empty env var). This is the AWS SSM model — the value lives only where
`ssm:GetParameter` reads it and never travels through a mirrored or GitOps-tracked manifest.

```yaml
apiVersion: openinfra.dev/v1
kind: Parameter
metadata: { name: db-password, namespace: shop }
spec:
  path: /app/db/password
  type: SecureString        # value omitted — put it in OpenBao at params/shop/app/db/password (key: value)
```

An inline `value` and value-by-reference can be mixed freely within a namespace.

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

- **Hierarchy** is the path convention. In OpenBao the tree lives at `params/<namespace>/<path>`, so an
  SSM `GetParametersByPath`-style read is a KV list under a prefix.
- **`type`** is `String` or `SecureString`. Both are stored in OpenBao (encrypted at rest) and
  materialized into a Kubernetes Secret; the type is advisory metadata surfaced in the console.
- **`tier`** (`Standard` / `Advanced`) mirrors SSM's tiers as metadata.

## Reconciliation

A CronJob (`parameter-reconciler`, every 5 minutes) logs in to OpenBao with its own ServiceAccount
(no stored credential), writes each value to the KV tree, and rebuilds the namespace Secret.
Changing a value takes effect on the next reconcile; a rolling restart of the consuming workload
picks up the new environment. Its OpenBao policy is scoped to the `params/*` mount only.

**Status:** the CR, composition, and reconciler are verified live (the reconciler runs and attempts a
login to the key service); the KV write + Secret materialization were verified on a **fresh** install
(when the key service was still HashiCorp Vault), where the setup Job provisions the `params` mount and
the reconciler's auth role as part of the `encryption` component. The setup Job provisions them on an
existing install too: after its first run it logs in as `vault-config`, its configuration identity, on
every sync ([encryption.md](encryption.md#bringing-the-key-service-up-operator-one-time)); an install
whose setup Job has no `vault-config` identity yet needs the bootstrap token once (the commands are in
`platform/security/vault.yaml`). Values are set inline on the CR (`spec.value`) today; a `valueFrom`
secret reference is a planned follow-on.
