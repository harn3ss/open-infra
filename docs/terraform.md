# Terraform

> AWS equivalent: the AWS Terraform provider. Declare open-infra resources in HCL instead of
> `kind:` manifests, and manage them alongside the rest of your estate.

The provider is published as
[**`harn3ss/openinfra`**](https://registry.terraform.io/providers/harn3ss/openinfra/latest).
Source lives in a separate repository,
[harn3ss/terraform-provider-openinfra](https://github.com/harn3ss/terraform-provider-openinfra).

```hcl
terraform {
  required_providers {
    openinfra = {
      source  = "harn3ss/openinfra"
      version = "~> 0.1"
    }
  }
}

provider "openinfra" {
  # Defaults to in-cluster credentials, else $KUBECONFIG / ~/.kube/config.
  # kubeconfig = "~/.kube/config"
  # context    = "my-cluster"
}
```

## When to reach for it

open-infra resources are Kubernetes CRDs, so `infra.yaml` through GitOps is the primary path
and stays the one that gives you drift correction and review. Terraform earns its place when:

- **open-infra is one part of a wider estate.** One plan covers your DNS, TLS, cloud accounts
  *and* your on-prem databases, instead of two systems that disagree about what exists.
- **You want a plan before an apply.** `terraform plan` shows the diff; a `kubectl apply`
  does not.
- **You already speak HCL** and would rather not hand-write CRD YAML.

It is *not* a replacement for GitOps. Argo CD reconciles continuously; Terraform reconciles
when you run it. Pick per resource, not per platform — and don't manage the same object with
both, or they will fight.

## What's addressable

Every kind, with full CRUD and `terraform import` via `namespace/name`:

| Resource | Kind |
|---|---|
| `openinfra_application` | `Application` — container workload |
| `openinfra_database` | `Application` with `spec.database` (postgres/mysql/mongo/babelfish) |
| `openinfra_virtual_machine` | `VirtualMachine` |
| `openinfra_function` | `Function` |
| `openinfra_volume` | `Volume` |
| `openinfra_file_share` | `FileShare` |
| `openinfra_security_group` | `SecurityGroup` |
| `openinfra_model` | `Model` |
| `openinfra_query` | `Query` |
| `openinfra_migration` | `Migration` |
| `openinfra_replication` | `Replication` |
| `openinfra_dataflow` | `DataFlow` |
| `openinfra_stream` | `Stream` |
| `openinfra_directory` | `Directory` |
| `openinfra_fault_injection` | `FaultInjection` |
| `openinfra_vm_image` | `VmImage` |

Plus a **data source for every kind**, which returns `spec` and `status` as JSON strings:

```hcl
data "openinfra_virtual_machine" "dc" { name = "windowsdc" }

output "vm_os" {
  value = jsondecode(data.openinfra_virtual_machine.dc.spec).os
}
```

That's deliberate. Mirroring fifteen evolving schemas in a *read* path would guarantee silent
drift — a field added here would simply be unreadable there. JSON stays correct as the
platform changes. Typed resources are for the things you *author*.

## Example

```hcl
resource "openinfra_database" "orders" {
  name   = "orders"
  engine = "postgres"
}

resource "openinfra_stream" "orders_cdc" {
  name = "orders-cdc"

  source = {
    engine   = "postgres"
    host     = "orders-db-rw"
    database = "orders"
    username = "app"
    tables   = ["public.orders"]

    # The password is never in the resource — only a reference to the Secret
    # open-infra generated when it created the database.
    password_secret_ref = { name = "orders-db-app" }
  }
}

resource "openinfra_function" "on_order" {
  name  = "on-order"
  image = "ghcr.io/harn3ss/on-order:latest"

  # Deliver the stream's change events as HTTP POSTs.
  trigger = { stream = openinfra_stream.orders_cdc.name }
}
```

More in
[`examples/full-stack.tf`](https://github.com/harn3ss/terraform-provider-openinfra/blob/main/examples/full-stack.tf).

## Things worth knowing

**`ready` is usually `false` right after apply.** Terraform returns as soon as the API server
accepts the object; the platform reconciles asynchronously. That's the same contract as the
console — creation is fast, readiness is not. Don't gate a dependent resource on it.

**Refresh is conservative.** `Read` pulls back only scalar attributes your config already
sets, and skips nested blocks entirely, because XRD defaults inside a nested block (a
source's `port: 5432`) would otherwise show up as a permanent phantom diff. The consequence:
an out-of-band change to a field you don't manage in HCL is not detected. The next apply
that touches the resource corrects it.

**Identity is deliberately absent.** `kind: User` and `kind: Group` (`iam.openinfra.dev`) have
no Terraform resources. Managing who may log in from the same config that manages
infrastructure invites an accident with no undo. Use the console or `kubectl` — see
[`iam.md`](iam.md).

**Some resources are jobs, not desired state.** Changing a `openinfra_query`'s `sql` runs a
new query rather than altering the old one, so it forces replacement. Applying an
`openinfra_fault_injection` deliberately breaks running workloads — scope its `target`
carefully.

## Keeping the two repos in sync

> ⚠️ The provider mirrors these CRD schemas **by hand**, and nothing enforces it. A field
> missing there cannot be expressed in HCL — silently absent, not an error.

If you change `platform/abstraction/*-xrd.yaml`, update the provider in the same breath.
Almost every change is one line in its `internal/provider/kinds.go` table; its
[CONTRIBUTING.md](https://github.com/harn3ss/terraform-provider-openinfra/blob/main/CONTRIBUTING.md)
has the mapping.

## See also

- [`quickstart.md`](quickstart.md) — the `infra.yaml` + GitOps path.
- [`console.md`](console.md) — the web console.
- [`architecture.md`](architecture.md) — what the CRDs compile to.
