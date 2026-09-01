# Migrating from AWS: CloudFormation/CDK and Amplify

This is the honest migration story for the two pieces of AWS "surrounding glue" that sit around
an application: the **infrastructure-as-code** it is deployed with (CloudFormation / CDK) and
the **frontend hosting** it may use (Amplify). It says what ports cleanly, what ports with
caveats, what does not port, and what is deliberately out of scope. It is not a parity claim —
open-infra is not CloudFormation and not Amplify.

## CloudFormation / CDK

open-infra has a **CloudFormation engine** (`cfn`) — see
[`docs/cloudformation.md`](cloudformation.md) for the full reference. It reads a CloudFormation
template (and CDK output, which is CloudFormation JSON), maps each resource onto an open-infra
kind, and can plan, deploy, update, and tear down a stack. CDK is in scope only through its
synthesized template: `cdk synth` produces CloudFormation, and that is what `cfn` consumes —
open-infra does not run the CDK construct programming model itself.

**What the engine's coverage actually is** is exactly its committed mapping table, not "all of
CloudFormation." The honest boundaries:

- **Ports cleanly** — Lambda (container-image) → `Function`, Step Functions → `StateMachine`,
  AppSync → `GraphQLApi`, IAM Role/Policy/User/Group → the IAM kinds, KMS → `EncryptionKey`.
- **Ports with caveats (lossy)** — S3/SQS/SNS/RDS map through an `Application`'s sub-blocks,
  EC2 → `VirtualMachine`, EBS/EFS → `Volume`/`FileShare`. The caveats are printed, never hidden.
- **Breaks / refused (fail-loud, never a silent partial)** — `AWS::DynamoDB::Table` is **gated**
  (no managed data layer yet; see below), `AWS::Cognito::*` is unsupported (open-infra consumes
  OIDC/JWT, it does not host a user pool — see [`docs/auth-migration.md`](auth-migration.md)),
  nested stacks, Lambda-backed custom resources, and the general AWS resource catalog are
  unsupported. Each produces a `REJECTED` verdict naming the reason.
- **Create fidelity is narrower than the mapping** — a resource type that *maps* does not always
  *create*, because AWS resource content often has no faithful open-infra form (IAM's
  `service:Action` permission namespace vs open-infra's `kind:verb` RBAC; KMS key policies; a
  `Fn::GetAtt` to another resource's ARN). Those refuse rather than approximate. Read the
  *Create fidelity* section of the engine doc before assuming a template deploys.

**For AppSync specifically**, there is also a management-plane path independent of the CFN
engine: the [aws-shim](aws-shim.md) translates a specific set of AppSync management verbs —
`CreateResolver` / `UpdateResolver` / `DeleteResolver` / `GetResolver` / `CreateDataSource` /
`DeleteDataSource` — into a patch on `kind: GraphQLApi`. Everything else re-expresses as
open-infra kinds directly, or as Terraform via the
[Terraform provider](https://registry.terraform.io/providers/harn3ss/openinfra).

**The honest summary for an adopter:** an existing CloudFormation/CDK stack does not "just run."
The infrastructure it describes ports to open-infra to the exact extent the committed mapping
table covers it; everything else is either re-expressed as kinds/Terraform by hand or is refused
loudly. The value is migration-in and dev-stack standup from templates you already have — not
CloudFormation-as-a-service.

## Amplify hosting + build jobs

**Decision: an Amplify-equivalent frontend-hosting-and-build story is out of scope for
open-infra, and is documented as deployer-external.**

Amplify bundles three things: static frontend hosting (CDN + TLS for a built SPA), a managed
build/CI pipeline (git push → build → deploy), and a backend-provisioning layer. open-infra is
the **backend/infrastructure** layer — it provisions the APIs, functions, data, and identity a
frontend talks to. It deliberately does not try to be a static-site host or a frontend CI system:

- **Static frontend hosting** (a built `dist/` behind a CDN) is a solved, commoditized problem
  that an adopter's existing tooling handles better — their own object storage + CDN (including
  the `Application` `storage.buckets` for the artifacts if they want them on-cluster), or any
  static host. open-infra does not ship a managed CDN/edge product to compete with that.
- **The build pipeline** (git → build → deploy) is the adopter's CI (GitHub Actions, GitLab CI,
  etc.), which builds the SPA and pushes it wherever they host it, and applies open-infra kinds
  (or `cfn` / Terraform) for the backend. There is no open-infra-managed build service, and none
  is planned.

So a Cognito+AppSync+DynamoDB app migrating in would: express its **backend** as open-infra kinds
(or via `cfn` where the template maps), and keep its **frontend hosting + build** on its own
static-hosting + CI. Nothing here implies Amplify parity; the frontend-hosting half is explicitly
not an open-infra responsibility.

## What still blocks a full AppSync-app migration

Recorded honestly so no one reads this as "ready":

- **The DynamoDB data layer** — the biggest technical risk. open-infra has no managed DynamoDB
  table kind today; AppSync resolvers can target a Dynamo-shaped data source whose coverage is
  a documented subset (Get/Put/Delete/Scan — see the data-layer characterization), and closing
  the remaining gaps is separate work. Until that lands, a DynamoDB-backed app does not fully port.
- **Cognito user-pool management** — open-infra consumes Cognito/OIDC JWTs but does not host or
  manage a user pool; the auth-migration path (external IdP vs open-infra IAM + OIDC) is covered
  in its own note.
