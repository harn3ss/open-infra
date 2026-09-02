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
  (no standalone table *kind* for the engine to map onto — the shim has a DynamoDB front door, but
  the engine maps to kinds; see below), `AWS::Cognito::*` is unsupported by the engine (it doesn't
  map onto `kind: UserPool` yet, though open-infra now hosts a pool — see
  [`docs/auth-migration.md`](auth-migration.md)), nested stacks, Lambda-backed custom resources, and
  the general AWS resource catalog are unsupported. Each produces a `REJECTED` verdict naming the reason.
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

## Terraform (via open-transform): the neutral-resource mapping

Beyond CloudFormation, an AWS **Terraform** estate can be assessed for portability by
[open-transform](https://github.com/harn3ss/open-transform) (`otf assess -target openinfra`),
which reports what does and does not have an open-infra target. A feasibility pass over real
AWS VPC/EKS modules surfaced four resource classes worth a **decided** disposition — recorded
here so the answer is deliberate, not "unsupported":

| AWS resource | open-infra | disposition |
|---|---|---|
| `aws_iam_role` | **`kind: Role`** | **Supported** — a Role is a named bundle of Policies compiled to an aggregated ClusterRole (see [iam.md](iam.md)). This is a first-class target; a migration should map to it. |
| `aws_vpc` / `aws_subnet` | `kind: SecurityGroup` | **Deliberate non-goal** — Kubernetes is one flat pod network; isolation is by workload identity, not address range. Model it with Security Groups; do not recreate the VPC. Full rationale in [security-groups.md](security-groups.md#why-there-is-no-vpc-or-subnet-a-deliberate-non-goal). |
| `aws_sqs_queue` | *(no standalone kind)* | **Acknowledged gap, deferred.** NATS JetStream is the messaging substrate, but it is exposed only through `kind: Stream` (which is **CDC-sourced** — it tails a database change log, not a standalone app-to-app queue) and `Function` triggers. A first-class SQS-shaped queue kind is not built (low frequency: one occurrence in the assessed estate); revisit if demand grows. |
| `aws_s3_bucket` | *(sub-block, no kind)* | **Known** — buckets appear as fields inside other kinds (e.g. an `Application`'s `storage.buckets`), not as a standalone kind. Tracked separately. |

The point of the disposition is that a report of "untranslatable" should carry the *right
next step* — "map to `kind: Role`," "model isolation with Security Groups," — rather than a
bare "unsupported." Mapping the neutral `role`/`queue` classes to these targets is
open-transform's job, not the platform's.

## What still blocks a full AppSync-app migration

Recorded honestly so no one reads this as "ready":

- **The DynamoDB data layer** — the aws-shim ships a **DynamoDB front door**: CreateTable,
  GetItem / PutItem / DeleteItem / UpdateItem, Query, full Scan, and the batch item APIs
  (BatchGetItem / BatchWriteItem) — see [`docs/aws-shim.md`](aws-shim.md). What remains: there is
  **no standalone table *kind*** (a Dynamo table isn't yet a first-class declarative resource), and
  the open-appsync *VTL-resolver* data-source path covers only single-item CRUD + Query/Scan (no
  batch/transactional writes on that path). A Dynamo-backed app works against the shim surface, but
  not yet as a declared table kind.
- **Cognito self-service management** — open-infra now **hosts a user pool**
  ([`kind: UserPool`](auth-migration.md) — Keycloak, hosted sign-up/sign-in UI, OIDC issuance), so
  the identity-provider half is covered. What is still absent is a programmatic self-service
  user-pool *management* API (user CRUD via an API); see [`docs/auth-migration.md`](auth-migration.md).
- **API Gateway REST control plane** — `kind: HttpApi` covers routing paths, per-route methods,
  CORS, throttling, and a JWT authorizer. What it does not model is the REST-v1 control plane —
  stages, a deployment promote/rollback lifecycle, and per-API-key usage plans (deliberate
  non-goals); see [`docs/api-gateway-coverage.md`](api-gateway-coverage.md).
- **X-Ray-style trace fan-out** — distributed tracing ships (Grafana Tempo + the OTel SDK in the
  first-party services, opt-in; see [`docs/tracing.md`](tracing.md)). Traces are captured — what is
  not an X-Ray clone is automatic AWS-service-map discovery.
