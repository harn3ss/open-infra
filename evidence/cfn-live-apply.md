# CFN engine live apply path: real create, real rollback, real drift (retiring the fake applier)

**What this is:** an honest, observed record that the CloudFormation engine's stateful phases
(deploy/rollback/drift) drive **real objects into a real API server** and behave correctly there —
not against the fake applier the unit tests use. Until this, CFN phases 2–5 were exercised only by a
test double, so across the matrix "supported" meant "translates," not "deploys and runs" (#119).

**Rule:** a fact is marked observed only if a real object went through the real `kubectlApplier` into
the live cluster and the stated behaviour was seen. A pass against the fake applier does not count and
is now marked in-code as translation-layer-only (`cfn/deploy_test.go`).

**Date:** 2026-09-04; spread broadened 2026-09-07 (Function, ECS/Application, EC2/VM added live).
**Cluster:** the live control plane. **Test:** `cfn/live_integration_test.go` (build tag `integration`),
run with `KUBECONFIG` set (`KUBECONFIG=… go test -tags integration -run TestLive ./cfn`).

## The three facts a fake applier structurally cannot test — observed

| Fact | What was driven | Observed |
|---|---|---|
| **Real create** | `AWS::S3::Bucket` → `kind: Bucket` (MinIO) | created, admitted, reconciled to **ready** on the real cluster (`TestLive_RealCreate`) |
| **Real failed-create, ZERO orphans** | a valid Bucket, then a second resource the API server **rejects at apply** | deploy → `CREATE_FAILED`, and the first, successfully-created Bucket was **rolled back (deleted)** — no orphan left behind (`TestLive_FailedCreateZeroOrphans`) |
| **Real drift** | a deployed Bucket, edited out-of-band with `kubectl patch` | the engine reported **in-sync before** the edit and **drift after** it, against the live object (`TestLive_DriftDetection`) |

The failed-create is the load-bearing one: rollback-leaves-zero-orphans is precisely the property a
double cannot exercise, because it never runs real admission/validation. It is now proven live.

## Spread of kinds exercised live (breadth honestly bounded)

`cfn deploy` has been observed driving real objects to ready across more than one backing family this
cycle — but **not the whole matrix**, and one kind's live success does not imply another's:

- **deploy-verified (observed applying + ready live):**
  - `AWS::S3::Bucket` → `kind: Bucket` (MinIO)
  - `AWS::IAM::Policy` / `AWS::IAM::ManagedPolicy` → `kind: Policy` (Crossplane composition)
  - `AWS::SSM::Parameter` → `kind: Parameter` (Vault-backed, reached ready)
  - `AWS::Lambda::Function` → `kind: Function` (Knative) — created + **ready** (`TestLive_Function_RealCreate`, 2026-09-07)
  - `AWS::ECS::TaskDefinition` + `AWS::ECS::Service` → `kind: Application` (Deployment) — created + **ready** as a genuinely **multi-container Pod** (primary `app` + sidecar `log`) behind a real **Service** (`TestLive_ECS_MultiContainer`, 2026-09-07)
  - `AWS::EC2::Instance` (catalog OS `ubuntu-22.04`) → `kind: VirtualMachine` (KubeVirt) — created + **VMI phase `Running`** observed on the cluster (`TestLive_EC2_VM`, 2026-09-07)

  That is **six** distinct backing families now observed live — MinIO, Crossplane, Vault, Knative, a
  Deployment+Service, and KubeVirt — spanning stateless, stateful, and VM workloads.
- **plan-verified only (translates; NOT yet observed applying live):** the remaining `cfn/mapping.go`
  entries — Queue (NATS), a **database** Application (CNPG-backed, distinct from the Deployment-backed
  ECS Application above), Table (FerretDB), the AppSync collation, Cognito/UserPool, etc. These stay
  explicitly plan-verified until each is driven live; admission/defaulting/reconcile differ by kind, so
  a green apply for one family says nothing about another.

## The type-vs-payload caveat (recorded, per #119)

A green `plan` (translation succeeds) is **not** a green `deploy`. A template can reference only
`supported` types and still fail apply because a *property* didn't map or an admission policy rejects
the result. `plan-verified` and `deploy-verified` are therefore different statuses, tracked
separately above. Real-world confidence for a kind is not upgraded on the basis of translation alone.

## What remains open (named, not hidden)

- The kinds listed "plan-verified only" above are the next live-apply targets; each stays caveated
  until observed.
- A structural apply-blocker for any kind that translates but cannot be made to apply live would be a
  real finding (a "supported" type that doesn't deploy) — none found yet; the search continues per
  kind as they are exercised.
