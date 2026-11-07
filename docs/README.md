# open-infra documentation

open-infra is two audiences' product:

- **People who use it** — developers and teams who build on AWS. They use the console, the AWS CLI and
  SDKs (through the [aws-shim](aws-shim.md)), CloudFormation and Terraform, and never need to know
  that Kubernetes runs underneath.
- **People who run it** — whoever installs, upgrades and operates the platform. Their guides are
  Kubernetes-shaped on purpose: they work with the cluster directly.

A guide for users that tells you to run `kubectl` is a bug: report it. Some user guides end with a
short *Operators* note; skip it unless you run the platform.

## Using open-infra

**Start here:** [Web console](console.md) · [AWS-SDK shim](aws-shim.md) (the AWS CLI and SDKs) ·
[CloudFormation](cloudformation.md) · [Terraform](terraform.md) · [Migrating from AWS](aws-migration.md) ·
[AWS coverage](aws-coverage.md) · [The customer surface](customer-surface.md)

| Area | Guides |
|---|---|
| Identity and access | [Console sign-in](auth.md) · [IAM](iam.md) · [Policy engine](policy-engine.md) · [Cognito-fronted AppSync auth](auth-migration.md) |
| Compute | [Virtual machines (EC2)](virtual-machines.md) · [Auto Scaling groups](auto-scaling-groups.md) · [Functions (Lambda)](serverless.md) · [Scheduled jobs](scheduled-jobs.md) · [Workflows (Step Functions)](state-machines.md) |
| Networking and delivery | [Security groups](security-groups.md) · [Static sites (CloudFront)](static-sites.md) · [API Gateway coverage](api-gateway-coverage.md) · [Email (SES)](email.md) |
| Data | [Databases (RDS)](databases.md) · [Streaming](streaming.md) · [Data flows](dataflow.md) · [Query (Athena + Glue)](query.md) · [Replication](replication.md) · [Migrations (DMS)](migrations.md) · [Lineage](lineage.md) · [Data classification](data-classification.md) |
| Storage and protection | [Snapshots](snapshots.md) · [Backup](backup.md) · [Encryption (KMS)](encryption.md) · [Crypto-erase](destruction.md) · [Private CA](certificate-authority.md) · [Parameters (SSM)](parameters.md) |
| Machine learning | [GPU and managed inference](gpu.md) · [Training jobs](training-jobs.md) · [Tuning jobs](tuning-jobs.md) · [Processing jobs](processing-jobs.md) · [Batch transform](batch-transform.md) · [Model registry](model-registry.md) · [Model monitoring](model-monitor.md) · [Feature store](feature-store.md) |
| Cost and compliance | [Cost Explorer](cost.md) · [Config rules](config.md) · [Tracing](tracing.md) |

## Running open-infra

| Area | Guides |
|---|---|
| Install and configure | [Quickstart](quickstart.md) · [Architecture](architecture.md) · [Architecture support (arm64)](architecture-support.md) · [Substrate portability](portability.md) · [Air-gapping](airgapping.md) |
| Security and audit | [Security and compliance](security-and-compliance.md) · [Audit off-siting](audit-offsite.md) · [Signed attestation](compliance-attestation.md) · [Control-plane authorization webhook](authz-webhook.md) · [Function admission](function-admission.md) · [GovStack conformance](govstack-conformance.md) |
| Reliability and testing | [Chaos engineering](chaos.md) · [Chaos scenarios](chaos-scenarios.md) · [Chaos oracle](chaos-oracle.md) · [Nightly chaos suite](chaos-suite.md) · [Convergence harness](convergence-harness.md) · [CI](ci.md) |

Some user guides (GPU, encryption) also have an operator setup section; it is marked as such.
