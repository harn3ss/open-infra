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
  EC2 → `VirtualMachine`, EBS/EFS → `Volume`/`FileShare`, DynamoDB → `kind: Table` (name + key
  schema on the aws-shim's data layer; functions only where the shim's DynamoDB front door is
  enabled — no capacity/indexes/streams), Cognito → `kind: UserPool`, ECS → `kind: Application`.
  The caveats are printed, never hidden.
- **Breaks / refused (fail-loud, never a silent partial)** — nested stacks, Lambda-backed custom
  resources, and the general AWS resource catalog are unsupported. Each produces a `REJECTED`
  verdict naming the reason.
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

## Amplify hosting + build

Amplify bundles three things: static frontend hosting (CDN + TLS for a built SPA), a managed
build/CI pipeline (git push → build → deploy), and a backend-provisioning layer.

- **Static frontend hosting** is ported: **`kind: StaticSite`** serves a built `dist/` from MinIO
  with an SPA fallback and TLS (see [static-sites.md](static-sites.md)).
- **The managed build pipeline** (git → build → deploy) is a **decided build** (git repo + build
  command → sandboxed build Job → publish the output to the StaticSite bucket, on push). Until it
  lands, the build half is the adopter's own CI pushing artifacts to the StaticSite bucket.
- **Backend provisioning** is the core of open-infra — the APIs, functions, data, and identity the
  frontend talks to, expressed as open-infra kinds (or via `cfn`/Terraform where the template maps).

So a Cognito+AppSync+DynamoDB+Amplify app migrating in expresses its backend as open-infra kinds and
hosts its frontend on `StaticSite`; the git-push-to-build step is the one piece still being built.

## Elastic Beanstalk → `kind: Application`

Elastic Beanstalk is a managed app-deployment layer (provision instances, deploy a build, load-balance,
auto-scale, roll updates). open-infra is container-native, so an EB environment is **re-expressed as a
`kind: Application`** — there is no `BackupPlan`-style new kind to add, just a mapping. Build a container
image for the app (EB's managed platforms — Python/Node/Java/Go/Docker — all become an image) and:

| Elastic Beanstalk | `kind: Application` |
|---|---|
| Environment (app version + platform + config) | one `Application` (Deployment + Service + Ingress + HPA) |
| Platform / solution stack | the container `spec.image` (bring the runtime in the image) |
| `aws:autoscaling:asg` MinSize/MaxSize | `spec.scaling` (`min`/`max`/`targetCPUPercent` → HPA) |
| Instance type (`aws:ec2:instances`) | `spec.cpu` / `spec.memory` (requests/limits) — not an instance SKU |
| Environment properties (env vars) | `spec.env` (and `spec.secrets` for secret-backed values) |
| Environment CNAME / URL | `spec.domain` (Traefik Ingress + cert-manager TLS) |
| Enhanced health / health-check URL | the container's own readiness/liveness probes (a failing container is not routed) |
| Rolling / immutable deploys | the Deployment's rolling update (an image change rolls the pods) |
| RDS attached to the environment | a managed DB via `spec.database` (CNPG/MariaDB/babelfish) |
| Worker environment (SQS-backed) | a `kind: Function` with `spec.trigger`/`spec.queues`, or an `Application` consuming a `kind: Queue` |

**Does not map:** `.ebextensions` / platform hooks (bake the equivalent into the image or an init
container), EB-managed OS patching (the image + cluster handle it), and EB's instance-SKU sizing (open-infra
sizes by `spec.cpu`/`spec.memory` requests + quotas, not a named instance type). The estate's EB
environments each become one `Application` manifest; the `kind: Application` schema (and its ECS-mapping
notes) is in `platform/abstraction/xrd.yaml`.

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

## Declared non-goals (boundary decisions)

Some AWS services are **deliberately out of scope** — not unfinished work. Where an estate depends
on one, the honest answer is the boundary + the substitute, not a half-built lookalike:

| AWS service | Disposition | Substitute / rationale |
|---|---|---|
| **Route 53** (authoritative DNS) | **Non-goal** | DNS stays external/BYO (registrar / Cloudflare / sslip.io). A single cluster can't mirror globally-anycast authoritative DNS; the platform doesn't try. |
| **GuardDuty** (threat detection) | **Non-goal** | The raw signals are present — the API-server audit log in Loki, `kind: FlowLog`, DNS — for a **BYO SIEM**. The platform ships no managed detection/ML layer. |
| **Organizations** (multi-account) | **Non-goal** | Tenancy is **namespaces + RBAC + Cedar**, not an account hierarchy. Mapping: namespace ≈ account, a namespace subtree ≈ an OU, a Cedar/RBAC deny-ceiling ≈ an SCP. No account layer is built. |
| **SES managed deliverability** (DKIM/SPF/DMARC, reputation, suppression) | **Non-goal** | `kind: EmailSender` sends SES-shaped mail over a relay; deliverability (which needs DNS control, itself BYO) stays the operator's responsibility on their relay + DNS. |
| **Babelfish HA** (SQL-Server-compatible engine) | **Experimental, no HA** | Single-instance StatefulSet on Longhorn with start/stop + snapshot/restore (durability = Longhorn + Velero). It is not under CloudNativePG, so streaming-replication HA would mean a re-platform — out of scope while the engine is experimental. |
| **Redshift** (managed MPP warehouse) | **Covered by `kind: Query` (`engine: trino`); residuals non-goal** | The MPP warehouse / federation core IS provided — `kind: Query` runs **Trino over Iceberg/MinIO** (idle-stops), with Athena/Glue front doors. The Redshift-specific managed-warehouse *residuals* — workload management (WLM), result caching, materialized views, concurrency scaling — are **not** built: they are provider-managed tuning, not core capability, and poor ROI for the estate's single cluster. Map a Redshift workload to `kind: Query engine: trino`; revisit a specific residual only if a concrete workload proves it load-bearing. |
| **CloudFront** (managed CDN) | **Non-goal** | The edge stays BYO (Cloudflare/Fastly). A single cluster can't mirror a globally-anycast CDN's PoPs — same reasoning as Route 53. Mapping: a distribution → the BYO-CDN's config; origin → an `Ingress`/`kind: StaticSite`; OAC → origin auth; invalidation → the CDN's own API. (In-cluster caching, if ever needed for a single-region deployment, would be a Varnish/nginx layer in front of Traefik — not a CloudFront equivalent.) |

These are decisions, not gaps: revisit the boundary (as with the CNI/VPC and API Gateway calls)
if the estate's dependence proves load-bearing enough to justify crossing it.

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
