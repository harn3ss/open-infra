# Cost Explorer

> AWS equivalent: **Cost Explorer** — except inverted. Instead of showing the bill
> you *are* paying, open-infra shows the bill you're **not** paying: *"what AWS would
> have charged to run this cluster."*

The console **Billing → Cost Explorer** page prices your live cluster against AWS
public on-demand list rates and shows the monthly/annual estimate next to your actual
cost (**$0** — it's your hardware).

## What it prices

It's a **read-only estimate** computed from live cluster state — nothing is
provisioned. The BFF (`/api/cost`) reads:

| Category | From | AWS rate (default) |
|---|---|---|
| **Compute** (EC2/Fargate) | node allocatable vCPU + memory | Fargate: $0.04048/vCPU-hr + $0.004445/GB-hr |
| **GPU** (accelerated EC2) | node `nvidia.com/gpu` capacity | g4dn.xlarge class: $0.526/GPU-hr |
| **Block storage** (EBS) | sum of PVC requested capacity | gp3: $0.08/GB-month |
| **Load balancers** (ALB) | `Service`s of type `LoadBalancer` | ALB base: $16.43/month |

Compute is priced against **node capacity** ("what renting these boxes as EC2 would
cost"), so the estimate doesn't depend on whether workloads set resource requests. A
secondary **by-namespace** breakdown uses running pod requests to show *where* the
compute goes. Hours/month = 730.

## Tuning the prices

The rates are us-east-1 on-demand list prices, overridable per-deployment via env on
the console (so you can match your region or negotiated rates):

```
COST_VCPU_HOUR   COST_GB_HOUR   COST_GPU_HOUR   COST_EBS_GB_MONTH   COST_LB_MONTH
```

## Limits

- Estimate only — excludes data transfer, S3 object storage, and RDS/support premiums.
- Not a metering/chargeback system (no historical trend, no per-hour sampling). For
  real cost *allocation* accounting, a Kubecost integration is the heavier alternative.

## See also

- [`console.md`](console.md) — the console UI.
- [`architecture.md`](architecture.md) — the full AWS-equivalents mapping.
