# CloudFormation templates — `cfn plan`

open-infra can read an AWS CloudFormation template and tell you, resource by resource,
whether it can provision it on open-infra — and exactly what it cannot. It can then
provision the supported ones as a live, tracked stack. This is the `cfn` engine.

The same engine is also fronted by the **AWS CloudFormation API** on the aws-shim, so an
unmodified `aws cloudformation` client / CDK can drive it (CreateStack, change sets, drift,
DeleteStack) — there, a stack provisions under the *caller's* own authority via impersonation,
the way AWS does it. See [`docs/aws-shim.md`](aws-shim.md#cloudformation-the-cfn-engine-as-a-doorway-caller-authority-via-impersonation-probe-proven).
The CLI below is the operator-run path (it uses your kubeconfig's ambient identity).

For the broader migration picture — CDK, Amplify hosting, and what is deliberately
out of scope — see [`docs/aws-migration.md`](aws-migration.md).

To drive the front door from a workstation, point the whole AWS client at the shim, not just one
command:

```sh
export AWS_ENDPOINT_URL=https://s3.<your open-infra domain>   # every service, not one command
export AWS_CA_BUNDLE=$PWD/openinfra-root-ca.crt                 # the platform root CA
aws cloudformation deploy --template-file template.yaml --stack-name app --parameter-overrides …
```

`--endpoint-url` would redirect only CloudFormation: `deploy --s3-bucket` (needed for templates over
51,200 bytes) and `package` would upload to AWS's own S3. A stack's EC2 instances need no endpoint in
the template either — the guest's environment names the shim
([virtual-machines.md](virtual-machines.md#aws-endpoints-inside-the-guest)).

- **`cfn plan`** (read-only) parses a template, maps every resource onto an open-infra
  kind, resolves the intrinsic functions and the dependency order, and prints a verdict.
  It provisions nothing.
- **`cfn deploy`** provisions a stack live: it applies the resources in dependency order,
  records the stack, and rolls back on failure — fail-closed, never a partial stack.
- **`cfn changeset`** (read-only) diffs a template against the current stack — what would
  be Added, Modified, Removed, or left Unchanged.
- **`cfn update`** applies that change set, rolling back to the exact prior stack if any
  step fails. An EC2 instance whose update changes something it reads only when it starts
  (its `InstanceType`, `UserData`, disks, metadata options, instance profile) is stopped and
  started, as AWS does for an update with "some interruptions": the update completes once
  the instance runs on the new spec, and keeps its private address. A change a running
  instance takes live (its security groups, its public address and ports) restarts nothing.
  A stopped instance stays stopped; the change applies when it next starts. If the update
  then fails, its rollback restarts the instance onto its prior spec.
- **`cfn destroy`** tears a stack down in reverse dependency order, honoring
  `DeletionPolicy`.

`cfn` does not yet drift-check a stack against the live cluster; that is the last phase.

## The cardinal rule

The engine never silently drops or approximates a resource it cannot faithfully model.
CloudFormation is a contract: if a template asks for something open-infra has no honest
equivalent for, the right answer is to say so and refuse — not to provision "something
close" and let you discover the gap in production. So the verdict is conservative by
design, and every refusal names its reason.

## Verdicts

`cfn plan <template>` prints one of three verdicts and sets its exit code to match:

| Verdict | Exit | Meaning |
|---|---|---|
| `PROVISIONABLE` | 0 | Every resource maps to a faithful kind; all intrinsics resolved; dependencies order cleanly. |
| `PROVISIONABLE_WITH_CAVEATS` | 0 | As above, but at least one resource maps only **partially** (the mapping is lossy). The caveats are listed; read them before relying on the result. |
| `REJECTED` | 1 | At least one blocker. **Nothing** would be provisioned. Every blocker is listed with its exact reason. |

A blocker is any of: an unsupported or gated resource type, an unsupported intrinsic
function (e.g. a macro/SAM `Fn::Transform`), an `Fn::ImportValue` whose export was not
supplied, a required parameter with no value, a reference to something that does not
exist, or a dependency cycle.

Some outcomes depend on the cluster, which the CLI cannot see. `-object-encryption` plans for a
cluster that encrypts every new bucket by default (`components.objectEncryption`); without it, a
bucket's `BucketEncryption` is a blocker. The aws-shim's front door reads this from the platform, so
`ValidateTemplate`, change sets and deploys there need no flag.

### The fidelity summary

A provisionable plan ends with a **fidelity summary**: every property of *this* template that
open-infra accepts but does not emulate as AWS does, per resource — no-ops (e.g.
`PublicAccessBlockConfiguration`, already the MinIO default), properties with no counterpart (e.g.
the parts of an AWS managed policy that name services open-infra does not run), and approximations (e.g. a CloudFront distribution's
certificate is issued in-cluster, not requested from ACM, and there is no edge cache). Read it as
the boundary of what a test on open-infra proves: anything listed behaves differently from AWS or is
not exercised, so a pass here never claims more than it tested. `-json` returns the same list as
`Fidelity` (and each resource's `Caveats`).

The summary also lists the resource attributes open-infra does not act on: `UpdatePolicy`,
`UpdateReplacePolicy` (resources are updated in place, never replaced), `CreationPolicy`
`AutoScalingCreationPolicy`, and `Metadata` `AWS::CloudFormation::Authentication`. A `CreationPolicy`
`ResourceSignal` **is** waited for, and `Metadata` (with `AWS::CloudFormation::Init`) is returned by
`DescribeStackResource` for `cfn-init` to read — see [Resource signals](#resource-signals-and-wait-conditions).
Any line in the summary makes the verdict `PROVISIONABLE_WITH_CAVEATS`. Through the aws-shim front door,
the summary is also the stack's `StackStatusReason` in `DescribeStacks` and the reason on the stack's
first event of each create or update.

Plan runs every resource's translator, so the summary covers each property. It cannot when a
required parameter has no value, when the template uses a `Transform`, or when the stack has a
custom resource or an API Gateway REST API (their attributes resolve only during deploy). The summary
then says so in a line of its own, and `GateSkipped` in `-json` gives the reason.

The aws-shim front door shows the same summary: in `DescribeChangeSet`'s `StatusReason` (what
`aws cloudformation describe-change-set` and `deploy` show) and in `ValidateTemplate`'s `X-Openinfra-Fidelity` response header (its `Description` is the template's, as on AWS).

Anything that would quietly grant more than the template asked for is refused rather than listed:
a security-group port that does not resolve (it would mean every port), a security-group list that
does not resolve to groups, an instance published on the LAN with no security group, a security group
named from outside the stack that does not exist, an encrypted root volume (VM root disks are not
encrypted), a disabled KMS key, an AppSync root
field with no `@aws_*` auth directive (open-appsync would serve it unauthenticated), a `PRIVATE` AppSync
API, and an SNS subscription's `FilterPolicy` (unless the SNS front door applies it) or other delivery settings.

A `Ref` to an in-stack resource whose value is fixed before deploy — a bucket's, table's or
function's name (its explicit name, or the name its open-infra kind is created with) and a topic's
ARN — resolves at plan time, so UserData, environment variables and policies that use it are applied
as written. Other `Ref`s and most `Fn::GetAtt` values exist only after deploy; stack Outputs that use
them are filled from the deployed resources (see *Deploying a stack*).

### Queues, topics, parameters and keys: in the APIs that serve them

Through the aws-shim front door, a stack's `AWS::SQS::Queue`, `AWS::SNS::Topic` (and its
subscriptions), `AWS::SSM::Parameter`, and `AWS::KMS::Key` / `AWS::KMS::Alias` are created **in the
store the shim's SQS, SNS, SSM and KMS front doors serve** — the queue is the one `ReceiveMessage`
reads, the topic the one `Publish` delivers from — so the application uses them through those APIs, by
the names and ARNs the stack reports:

| Resource | `Ref` | `Fn::GetAtt` |
|---|---|---|
| `AWS::SQS::Queue` | the queue URL | `Arn`, `QueueName`, `QueueUrl` |
| `AWS::SNS::Topic` | the topic ARN | `TopicArn`, `TopicName` |
| `AWS::SNS::Subscription` | the subscription ARN | — |
| `AWS::SSM::Parameter` | the parameter name | `Type`, `Value` |
| `AWS::KMS::Key` | the key id | `Arn`, `KeyId` |
| `AWS::KMS::Alias` | the alias name | — |
| `AWS::SQS::QueuePolicy`, `AWS::SNS::TopicPolicy` | the policy's id | — |

These resolve at plan time, so a Lambda environment variable or UserData that names the queue gets
its URL. Each step is authorized as the matching front door authorizes it, for the caller (a stack can
create no queue its deployer could not create with `sqs:CreateQueue`). Delete and Retain behave as for
any resource: a deleted queue, topic, parameter or alias is removed; a deleted key is **scheduled for
deletion** with the template's `PendingWindowInDays` (default 30), as CloudFormation deletes one. A
stack refuses to take over an object of the same name that another stack — or no stack — created.

An `AWS::SQS::QueuePolicy` or `AWS::SNS::TopicPolicy` is the `Policy` of each queue or topic it names (an
in-stack one by `Ref`, or any existing one by URL or ARN), and it decides the deliveries the shim makes to
it — the SNS fan-out policy that lets a topic `sqs:SendMessage` to the queue, an EventBridge rule's sends,
a CloudWatch alarm's publish — exactly as the SQS and SNS APIs apply a `Policy` (see *SQS* and *SNS* in
[`aws-shim.md`](aws-shim.md)). One policy may cover several queues (`Queues: [A, B]`, a statement's
`Resource: [A.Arn, B.Arn]`): as on AWS, each statement applies to the queues its `Resource` names; one
naming a queue the policy is not attached to refuses. Setting it is checked as `SetQueueAttributes` / `SetTopicAttributes` on each
queue or topic; deleting it removes the policy (unless another policy has replaced it since); an update of the
queue or topic keeps it. A policy that grants a user or role, is public, or uses a condition other than
`aws:SourceArn` / `aws:SourceAccount` refuses at plan: callers are authorized by IAM here, not by resource
policies.

A FIFO queue (`FifoQueue: true`) is a FIFO queue in the SQS store, with `ContentBasedDeduplication`,
`DeduplicationScope` and `FifoThroughputLimit` its attributes; an unnamed one gets CloudFormation's `.fifo`
suffix. Its dead-letter queue must be FIFO too, and it cannot subscribe to a topic (the topics here are
standard).

A subscription's `FilterPolicy` and `FilterPolicyScope` are applied by the SNS front door (see *SNS* in
[`aws-shim.md`](aws-shim.md)); a policy it cannot apply refuses at plan.

What the APIs here do not serve is refused rather than half-created: FIFO topics, per-queue
or per-topic encryption keys, SNS protocols other than `sqs` and `lambda`, SSM
parameter `Policies` and the Advanced tier, and KMS keys other than symmetric `ENCRYPT_DECRYPT`.
`AWS::SSM::Parameter`'s `Name` is optional, as on AWS: an unnamed parameter gets CloudFormation's
generated `<stack>-<logical id>-<suffix>` name. A stack's KMS key is also the `kind: EncryptionKey` an
encrypted EBS volume or RDS instance names; that volume key is separate key material, so disabling or
deleting the key through the KMS API does not lock or erase those volumes (deleting the stack does).

The CLI (`cfn deploy`), which has no such stores, keeps the kind mappings in the tables below — those
resources are not visible through the AWS APIs.

A stack's `AWS::Lambda::Function` is invocable by the `FunctionName` or `Arn` the stack reports, through
the Lambda API, an SNS lambda subscription, an EventBridge target or an API Gateway integration, like a
function the Lambda API serves: the shim finds a function by name in the stack namespace as well
(see *Lambda* in [`aws-shim.md`](aws-shim.md)). Because a function name is unique in an account, a stack
refuses to create a function whose name a function outside the stack already has.

## Usage

```console
$ cfn plan -param Stage=dev webapp.yaml
Verdict: PROVISIONABLE_WITH_CAVEATS

Resources:
  [part] Assets      AWS::S3::Bucket                   -> Application(storage.buckets)
      caveat: no standalone bucket kind — a bucket is provisioned via an Application's storage.buckets (MinIO)
  [ok  ] Api         AWS::Lambda::Function             -> Function
  [ok  ] Workflow    AWS::StepFunctions::StateMachine  -> StateMachine
  [part] ProdAlarms  AWS::SNS::Topic                   -> Queue  [skipped: condition IsProd is false]
  [ok  ] AppKey      AWS::KMS::Key                     -> EncryptionKey
  [gate] AppRole     AWS::IAM::Role                    -> Role
      ⚠ maps at plan only — NOT deployable (no create translator): kind: Role is a first-class assumable identity (trust policy + attached data-plane Policies; sts:AssumeRole on the aws-shim, #111), but there is no CFN create translator — author the Role + its trust natively.

Provisioning order:
  AppKey -> Assets -> AppRole -> Api -> Workflow

Provisionable, but review the caveats above — some mappings are lossy.
NOT DEPLOYABLE AS-IS: 1 resource(s) map at plan but have no create translator; `cfn deploy` is all-or-nothing and will refuse this stack until they are removed or expressed natively.
```

Templates may be JSON or YAML, and the YAML short forms (`!Ref`, `!GetAtt`, `!Sub`,
`!Join`, `!If`, …) are understood. Parameters are supplied with `-param NAME=VALUE`
(repeatable); `-stack-name` seeds `AWS::StackName`; `-json` emits the plan as JSON for
tooling.

## What maps to what

The mapping table below is the engine's contract. A resource type is only listed once
it has a backing open-infra kind and a faithful (or explicitly lossy) mapping. Anything
not in the table is **unsupported by default** — the engine does not guess.

### Coverage at a glance

Counted from the engine's own mapping table and translator dispatch, per namespace, with the aws-shim
front door that serves each namespace's API (so a stack's resource can be found through it). The
per-type registry, the exceptions to the front-door gate and the breadth gaps are in
[`aws-coverage.md`](aws-coverage.md).

<!-- BEGIN shimgen:cfn-namespaces — generated by probe/shimgen.py from the coverage registry (probe/registry/); do not edit -->
| Namespace | A stack can create | Plan maps, cannot create | Refused | Front door here |
|---|---|---|---|---|
| `AWS::ApiGateway` | 11 | 0 | 0 | `apigateway` |
| `AWS::AppSync` | 5 | 0 | 0 | `appsync` |
| `AWS::AutoScaling` | 0 | 0 | 2 | none |
| `AWS::CertificateManager` | 1 | 0 | 0 | `acm` |
| `AWS::CloudFormation` | 4 | 0 | 0 | `cloudformation` |
| `AWS::CloudFront` | 6 | 0 | 0 | `cloudfront` |
| `AWS::CloudWatch` | 1 | 0 | 0 | `monitoring` |
| `AWS::Cognito` | 2 | 0 | 0 | `cognito-idp` |
| `AWS::DynamoDB` | 1 | 0 | 0 | `dynamodb` |
| `AWS::EC2` | 17 | 7 | 1 | `ec2` |
| `AWS::ECR` | 1 | 0 | 0 | `ecr` |
| `AWS::ECS` | 3 | 0 | 0 | `ecs` |
| `AWS::EFS` | 0 | 1 | 0 | none |
| `AWS::ElasticLoadBalancing` | 0 | 0 | 1 | none |
| `AWS::ElasticLoadBalancingV2` | 0 | 0 | 4 | none |
| `AWS::Events` | 2 | 0 | 0 | `events` |
| `AWS::IAM` | 5 | 1 | 0 | `iam` |
| `AWS::KMS` | 2 | 0 | 0 | `kms` |
| `AWS::Lambda` | 2 | 2 | 0 | `lambda` |
| `AWS::Logs` | 1 | 0 | 0 | `logs` |
| `AWS::RDS` | 1 | 0 | 0 | `rds` |
| `AWS::Route53` | 0 | 0 | 3 | none |
| `AWS::S3` | 2 | 0 | 0 | `s3` |
| `AWS::SNS` | 3 | 0 | 0 | `sns` |
| `AWS::SQS` | 2 | 0 | 0 | `sqs` |
| `AWS::SSM` | 1 | 0 | 0 | `ssm` |
| `AWS::SecretsManager` | 1 | 0 | 0 | `secretsmanager` |
| `AWS::StepFunctions` | 1 | 0 | 0 | `states` |
<!-- END shimgen:cfn-namespaces -->

The tables below are written by hand; CI checks them against the same registry (a type listed as
supported must be supported, one listed in the create-translator table must have a create translator).

### Supported — a faithful backing kind

| CloudFormation | open-infra |
|---|---|
| `AWS::Lambda::Function` | `kind: Function` |
| `AWS::AppSync::GraphQLApi` | `kind: GraphQLApi` |
| `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy` | `kind: Policy` |
| `AWS::IAM::User` | `kind: User` |
| `AWS::KMS::Key` | `kind: EncryptionKey` |

### Partial — a backing kind exists, but the mapping is lossy

These provision, but not every property translates, or the resource is provisioned as
part of another kind rather than on its own. The caveat is always printed.

| CloudFormation | open-infra | Caveat |
|---|---|---|
| `AWS::S3::Bucket` (+ `AWS::S3::BucketPolicy`) | `kind: Bucket` | a standalone MinIO bucket with versioning + lifecycle + object lock; an in-stack `BucketPolicy` collates in as `spec.policy` (public `*` principals only) |
| `AWS::SQS::Queue`, `AWS::SNS::Topic` | `kind: Queue` | a standalone NATS JetStream stream (SQS=work queue, SNS=fan-out topic); through the aws-shim front door, a queue/topic in the SQS/SNS API's store instead (see *Queues, topics, parameters and keys*) |
| `AWS::KMS::Alias` | the KMS API's alias store | through the aws-shim front door only (refused elsewhere) |
| `AWS::SQS::QueuePolicy`, `AWS::SNS::TopicPolicy` | the queue's / topic's `Policy` in the SQS / SNS API's store | through the aws-shim front door only (refused elsewhere); grants to services, narrowed by source — grants to users or roles refuse |
| `AWS::StepFunctions::StateMachine` | `kind: StateMachine` | the supported Amazon States Language subset translates byte-for-byte; `EXPRESS`, AWS-ARN Task resources, `.waitForTaskToken`/`.sync` callbacks and non-Lambda service integrations refuse |
| `AWS::IAM::Group` | `kind: Group` | maps at plan only — no create translator: a Group's permissions are its attached AWS policies, from which its `clusterRole` cannot be derived (author the Group natively) |
| `AWS::RDS::DBInstance` | an `Application`'s `database` | engine/size mapping is lossy |
| `AWS::EC2::Instance` | `kind: VirtualMachine` | AMI/instance-type → os/cpu/memory is lossy |
| `AWS::EC2::Volume` | `kind: Volume` | Longhorn block volume |
| `AWS::EFS::FileSystem` | `kind: FileShare` | SMB share on Longhorn |
| `AWS::AppSync::DataSource` / `Resolver` / `FunctionConfiguration` / `GraphQLSchema` | part of `kind: GraphQLApi` | **faithfully** translated as part of one GraphQLApi's spec (SDL / VTL / JS byte-for-byte) — not lossy, just not standalone; a bare one (no in-stack API) refuses |
| `AWS::DynamoDB::Table` | `kind: Table` | registers name + key schema (+ TTL) on the aws-shim's FerretDB data layer; functions only where the aws-shim DynamoDB front door is enabled (opt-in). No capacity/throughput, secondary indexes, streams, or per-table SSE — those **block** |
| `AWS::Cognito::UserPool` / `UserPoolClient` | `kind: UserPool` | a hosted OIDC pool (Keycloak realm); MFA, Lambda triggers, and schema do not transfer |
| `AWS::ECS::Service` (+ its `TaskDefinition`) | `kind: Application` | a Service and its referenced TaskDefinition collate into one Application (Deployment+Service+Ingress+HPA); LB/subnet/multi-container config does not transfer |
| `AWS::CloudFront::Distribution` (+ `OriginAccessControl` / `CloudFrontOriginAccessIdentity` / `ResponseHeadersPolicy` / `CachePolicy` / `OriginRequestPolicy`, and its `AWS::CertificateManager::Certificate`) | `kind: StaticSite` | a **narrow static-site subset** — one private S3 origin, SPA fallback, response headers, TLS on the Aliases; **no edge cache**. Everything else refuses. See [CloudFront](#cloudfront-a-static-site-subset) below |
| `AWS::ApiGateway::RestApi` (+ `Resource` / `Method` / `Deployment` / `Stage` / `Model` / `RequestValidator` / `Authorizer` / `ApiKey` / `UsagePlan` / `UsagePlanKey`) | the aws-shim `apigateway` REST v1 surface | **create-deployable via the in-cluster doorway.** The whole API collates into one provisioning plan on its `RestApi` and is materialized by driving the `apigateway` REST v1 API in order (resource tree → methods + integrations → deployment → stages, plus models/validators/authorizers and in-stack keys/usage plans); every other `AWS::ApiGateway::*` type composes into it. A **CLI** deploy (no in-cluster doorway) refuses rather than guessing — the custom-resource stance. The collation is **closed-world**: each `AWS::ApiGateway::*` resource and nested block (`Integration`, `IntegrationResponses`, `MethodResponses`, `ApiStages`) names what it honors, and anything else refuses — a resource `Policy`, `EndpointConfiguration: PRIVATE`/`VpcEndpointIds`, an OpenAPI `Body`, `DisableExecuteApiEndpoint: true`, `ApiKeySourceType: AUTHORIZER`, a Lambda (`TOKEN`/`REQUEST`) authorizer and its `AuthorizerUri`, method `AuthorizationType` `AWS_IAM`/`CUSTOM`, `AuthorizationScopes`, an `AuthorizerId`/`RequestValidatorId` that is not in-stack, integration `Credentials`/`VPC_LINK`/`PassthroughBehavior` other than `WHEN_NO_MATCH`/`SelectionPattern`, a stage `CanarySetting`, a deployment's `StageDescription`. Operation-only settings are accepted and listed in the fidelity summary (checked at plan time for the API Gateway resources): usage-plan `Throttle`/`Quota` (not enforced), stage `MethodSettings`/`AccessLogSetting`/`TracingEnabled`/cache settings, integration `TimeoutInMillis`, integration-response `ResponseParameters`. CloudFormation booleans are read strictly (`ApiKeyRequired: !Ref Param` is honored; `Enabled: "false"` disables a key; a value that is not a boolean refuses). Custom domains / WAF / gateway responses are not modeled; stack **update** of a REST-v1 stack is refused (destroy + recreate). For a declarative v2 API use `kind: HttpApi`. |

### Custom resources (`AWS::CloudFormation::CustomResource` / `Custom::*`)

A Lambda-backed custom resource is **supported** (#269): at deploy, the in-stack `kind: Function`
named by `ServiceToken` is **invoked synchronously** at the resource's point in dependency order with
the CloudFormation custom-resource event (`RequestType` `Create`/`Delete`, `ResourceProperties`), and
its returned **`Data`** resolves later resources' `Fn::GetAtt`. This is the faithful AWS behaviour,
with one open-infra adaptation: the handler **returns** `{"Status":"SUCCESS"|"FAILED","Data":{…}}`
synchronously rather than PUT-ing it to a pre-signed S3 `ResponseURL` (open-infra has no S3 callback
surface). A `FAILED` status fails the deploy (all-or-nothing rollback). On stack teardown the Function
gets a `Delete` event. **Fail-closed:** `ServiceToken` must `!Ref`/`!GetAtt` an **in-stack**
`AWS::Lambda::Function` — an out-of-stack / AWS-ARN ServiceToken has no invoke target and refuses.
**Carve-outs (v1):** a stack **UPDATE** that touches a custom resource refuses (destroy + recreate —
a custom resource has no diffable state); custom resources are not drift-tracked (no live object); and
the invoke needs the **in-cluster** deploy path (the aws-shim CloudFormation doorway), so the local
`cfn` CLI refuses a custom-resource stack.

### Nested stacks (`AWS::CloudFormation::Stack`)

**Through the aws-shim CloudFormation front door, a nested stack is a stack of its own**, as on AWS.
Its child template is read from its `TemplateURL` in the shim's own S3 as the caller (see [Templates in
S3](#templates-in-s3-templateurl)); the URL may be a literal or a `Fn::Sub` / `Fn::Join` of parameters and
pseudo parameters, as `aws cloudformation package` writes them. The child is created when the parent
reaches it in dependency order, under the caller's authority (the caller needs `CreateStack` on it as well),
and is named `<parent>-<logical id>-<suffix>` (lowercase, within 63 characters). It has its own record,
events and Outputs, and `DescribeStacks` / `ListStacks` report its `ParentId` and `RootId`. In the parent,
the resource's physical id and `Ref` are the child's `StackId`, and `Fn::GetAtt <Stack>.Outputs.<Key>`
reads the child's Output: resources created after the child, and the parent's Outputs, get the value.
Nested stacks may nest further.

A child that fails is rolled back as a stack, and the parent's create rolls back with it, deleting the
child (`Embedded stack … was not successfully created: …`). Deleting the parent deletes its nested stacks
first, as stacks; each is then kept as a deleted stack like any other. A nested stack is deleted only with
its parent: `DeleteStack` on it directly is refused, and so is `UpdateTerminationProtection` (its root's
applies). `UpdateStack` on a nested stack directly runs, as AWS allows.

Refused rather than approximated: `NotificationARNs` (stack notifications are not sent); a `Parameters`
value that is not a string, number or boolean (AWS takes only those — join a list with `Fn::Join`); a
`TemplateURL` or parameter value that has not resolved when the child is created. `Tags` are accepted as
a caveat (stack tags are not propagated). An **update of the parent that would add, remove or change a
nested stack** — its parameters, or its template as read from the `TemplateURL` now — is refused with
nothing changed; an update that leaves every nested stack as it is runs, its resources reading the
children's current Outputs.

**The `cfn` CLI flattens nested stacks instead** (#268): it resolves each child `TemplateURL` as a **local
file** (relative to the parent) and inlines the child into the parent as one combined template
(`FlattenNested`), which then deploys as a single open-infra stack. The child's resources are prefixed
with the stack's logical id, the parent-supplied `Parameters` are substituted, and the parent's
`Fn::GetAtt <Stack>.Outputs.<Key>` resolves to the child's Output expression. **Fail-closed** (a flattened
template is never a mis-wired one): the flattener refuses what it can't rewrite correctly — `Fn::Sub` in a
child, child `Conditions`/`Mappings`, a nested-nested stack, an intrinsic (non-literal) `TemplateURL`, an
unmappable `Ref`/`GetAtt`, an id collision, or an unbound child `Parameter`.

### Templates in S3 (`TemplateURL`)

AWS takes a template inline (`TemplateBody`, up to 51,200 bytes) or as an S3 object (`TemplateURL`, up
to 1 MB) — `aws cloudformation deploy --s3-bucket` uploads anything larger, and a nested stack names its
child template that way. The aws-shim front door accepts a `TemplateURL` that names an object in **its
own S3**: virtual-hosted (`https://<bucket>.<s3 host>/<key>`) or path-style
(`https://<s3 host>/<bucket>/<key>`), on the front door's own endpoint, an S3 hostname it serves, or an
AWS S3 hostname (`*.s3.amazonaws.com`, for which it stands in); a pre-signed URL's query string is
ignored. The URL is only parsed into a bucket and key — **never fetched over the network**, so it cannot
be used to reach anything else — and the object is read with the **caller's** permissions, exactly as
the S3 front door would authorize a `GetObject`. Any other URL is refused. Set `AWS_ENDPOINT_URL` (not
just `--endpoint-url`) when using `aws cloudformation deploy --s3-bucket`, so the upload goes to the same
S3 the front door reads.

### CloudFront: a static-site subset

A CloudFront distribution in front of a private S3 bucket — the standard single-page-app hosting
template — translates to a [`kind: StaticSite`](static-sites.md): an nginx server that syncs the bucket
from MinIO and serves it behind a Traefik Ingress with cert-manager TLS. open-infra has **no edge tier**
(no points of presence, no cache), so only the static-site shape translates, and every distribution
feature outside it refuses at plan with its reason.

The template's bucket stays a `kind: Bucket` (its versioning, lifecycle and policy translate as usual)
and the StaticSite's `spec.bucket` names that same MinIO bucket. The StaticSite mints its own scoped
MinIO reader — that is the OAC/OAI analog — so the bucket stays private, and the `BucketPolicy`
statements that grant CloudFront read are realized by the site instead of being stored as a MinIO
bucket policy (MinIO can't resolve a CloudFront principal). The OAC/OAI, the response-headers, cache
and origin-request policies, and the ACM certificate provision nothing on their own: each validates its
own properties and is read by the distribution that references it.

| Template | StaticSite |
|---|---|
| one `Origins` entry: an S3 REST origin (`S3OriginConfig`) whose `DomainName` is an in-stack bucket (`!GetAtt Bucket.RegionalDomainName` / `DomainName`, or `${Bucket}.s3[.<region>].amazonaws.com`) | `spec.bucket` (the bucket's `BucketName`, else its logical id) |
| `OriginAccessControlId` (an in-stack `AWS::CloudFront::OriginAccessControl`, type `s3`) or `S3OriginConfig.OriginAccessIdentity` (an in-stack `CloudFrontOriginAccessIdentity`), and the bucket-policy grant to `cloudfront.amazonaws.com` (with `aws:SourceArn` naming the distribution) or to the identity's `CanonicalUser` / IAM ARN | the site's own scoped MinIO credentials; the grant is not stored |
| `Aliases` | `spec.domain` (first) + `spec.domains` (the rest), each with an Ingress rule and a SAN on the certificate |
| `ViewerCertificate.AcmCertificateArn` (typically an in-stack `AWS::CertificateManager::Certificate`, which must cover the Aliases) | `spec.tls: true` — cert-manager issues the site's certificate (see [Site certificates](#site-certificates-acm-domain-validation)) |
| `CustomErrorResponses` 403 and/or 404 → `/index.html` with `ResponseCode: 200` | `spec.spa: true` (history fallback) |
| `CustomErrorResponses` 403/404 → one error page with a 404 response | `spec.spa: false` + `spec.errorDocument` |
| `DefaultRootObject` | `spec.indexDocument` |
| `DefaultCacheBehavior.ResponseHeadersPolicyId` — an in-stack `AWS::CloudFront::ResponseHeadersPolicy` (`SecurityHeadersConfig`, `CustomHeadersConfig`) or the AWS managed `SecurityHeadersPolicy` id | `spec.responseHeaders` (added by nginx to every response, errors included) |
| `Fn::GetAtt <Distribution>.DomainName` | the first Alias — the hostname the site is served on |
| `DefaultCacheBehavior.ViewerProtocolPolicy` | `spec.viewerProtocolPolicy` — a plain-HTTP request is answered as CloudFront answers it: `redirect-to-https` a 301 to the `https://` URL, `https-only` a 403, `allow-all` the content |
| `DefaultCacheBehavior.Compress: true` | `spec.compress` — compressible types (text, JSON, JavaScript, CSS, SVG, fonts, …) of 1,000 bytes or more are gzip-compressed for a client that sends `Accept-Encoding: gzip` (gzip only, no Brotli) |

**Accepted, not emulated — printed as caveats:** caching (`CachePolicyId` / `OriginRequestPolicyId`,
`CachedMethods`, TTLs, `ForwardedValues`, `ErrorCachingMinTTL`) — every request is served
from the synced copy of the bucket, which re-syncs every 30 seconds (an upload goes live within about
30s; `aws cloudfront create-invalidation` and `wait invalidation-completed` work, and the invalidation is
Completed once the site has re-synced — see [aws-shim.md](aws-shim.md#cloudfront-a-stacks-distribution-its-invalidations-and-reads-probe-proven));
`PriceClass`,
`HttpVersion`, `IPV6Enabled`, `Comment`, `Tags`; `Logging` (nginx logs to the pod's stdout); origin
timeouts, `OriginShield`, `OriginCustomHeaders`; `MinimumProtocolVersion` (Traefik's TLS defaults
apply); ACM's DNS/email validation records (the operator validates domains once, below); OAC request signing. Two behaviours differ
from an S3 origin by nature: object metadata set at upload (`Content-Type`, `Cache-Control`,
`Content-Encoding`) is not served — nginx infers `Content-Type` from the file extension — and a missing
object is a 404 at the origin (an S3 origin without `s3:ListBucket` says 403), so 403 and 404 mappings
collapse into one missing-object behaviour. `Ref <Distribution>` is a stable synthetic distribution id
(`E…`), the id the CloudFront invalidation calls take.

**Refused:** a distribution without `Aliases` (open-infra has no `*.cloudfront.net` hostname to serve
on), a second origin or `OriginGroups`, a custom origin (`CustomOriginConfig` — an S3 website endpoint,
a load balancer, an API), `OriginPath`, path-pattern `CacheBehaviors`, Lambda@Edge
(`LambdaFunctionAssociations`) and CloudFront Functions (`FunctionAssociations`), signed URLs / cookies
(`TrustedKeyGroups` / `TrustedSigners`), `FieldLevelEncryptionId`, `RealtimeLogConfigArn`, a geo
restriction, `WebACLId`, continuous deployment (`ContinuousDeploymentPolicyId` / `Staging`), write
methods in `AllowedMethods`, `Enabled: false`, a wildcard Alias, a dedicated-IP certificate
(`SslSupportMethod: vip`), a response-headers `CorsConfig` or `RemoveHeadersConfig` (and the managed CORS
policies), a header the server sets itself (`Content-Type`, `Server`, …), error responses for codes
other than 403/404, an origin bucket with Object Lock, and a bucket-policy CloudFront grant that no
in-stack distribution holds (or that names a distribution or identity outside the stack). An ACM
certificate no included distribution uses refuses too — it has no open-infra consumer.

#### Site certificates (ACM domain validation)

ACM issues a trusted certificate only for a domain whose ownership it validated. Here the operator
validates domains once, at install: `certificates.validatedDomains` in `config.yaml` lists the domains
the site owns. For them `install.sh` keeps an ACM-style certificate authority, the ClusterIssuer
`openinfra-acm`: an intermediate that the platform root signs and that is name-constrained to exactly
those domains, so it can vouch for no other name. Then:

- A distribution whose every Alias is one of those domains or under one gets its certificate from
  `openinfra-acm`. A client that trusts the platform root trusts the site, as browsers trust ACM's
  certificates. The root's certificate is public: `curl -fsSk https://s3.<your open-infra domain>/v1/ca-bundle`
  downloads it (see [the aws-shim guide](aws-shim.md)).
- An Alias outside them is refused at plan and deploy: on AWS that certificate would stay
  `PENDING_VALIDATION` and the distribution could not use it.
- With no validated domains, sites keep a self-signed certificate (ClusterIssuer `openinfra-issuer`),
  which a client trusts only if told to. The plan says which applies.

Each validated domain must be inside the platform root's own name constraints (`cluster.local`, `svc`,
`sslip.io`, or a domain added in `platform/networking/cluster-ca-root.yaml`). Give sites a domain of their
own (for example `sites.<LAN-IP-with-dashes>.sslip.io`) rather than the one platform endpoints use, so
no stack can name a platform hostname. Offline, `cfn plan -validated-domains d1,d2` plans for such an
environment.

> `AWS::DynamoDB::Table` graduated from gated to **partial** once the aws-shim's DynamoDB
> data layer gained atomic transactions + TTL and a declarative `kind: Table`. `kind: Table`
> registers the table's name + key schema (immutable, exactly as in DynamoDB) with the shim,
> so items are writable without a runtime `CreateTable`. It is a thin front onto a data-plane
> capability, not a standalone managed database — reach for `kind: Application`'s `database`
> when you need capacity, indexes, or streams.

## Intrinsic functions

Resolved: `Ref`, `Fn::GetAtt`, `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::Split`,
`Fn::FindInMap`, `Fn::Base64`, `Fn::Cidr`, `Fn::GetAZs`, `Fn::ImportValue`, and the
condition functions `Fn::If` / `Fn::Equals` / `Fn::And` / `Fn::Or` / `Fn::Not`, plus the
`AWS::*` pseudo-parameters. `Conditions` are evaluated, so a resource gated on a false
condition is reported as skipped and left out of the provisioning order.

- **Pseudo-parameters** are the install's AWS identity (`platform/aws-shim/aws-identity.yaml`, see
  [the account, region and partition](aws-shim.md#the-account-region-and-partition)):
  `AWS::AccountId` is its 12-digit account, `AWS::Region` its region, `AWS::Partition` is `aws` and
  `AWS::URLSuffix` `amazonaws.com`, and `AWS::StackId` is the stack's StackId, the ARN the front door
  returns. A custom resource's event carries the same StackId. The `cfn` CLI reads `ACCOUNT_ID` and
  `AWS_REGION` from its environment, so set them as the shim has them.

- **`Fn::Cidr`** — real IPv4 subnet math: `[ipBlock, count, cidrBits]` carves `count`
  sequential `/(32-cidrBits)` blocks from `ipBlock` (IPv6 blocks, or a count/bits that
  overflow the block, are refused).
- **`Fn::GetAZs`** — a deterministic region-derived stand-in (`<region>a/b/c`), enough for
  `Fn::Select` over the list to resolve. open-infra is a single cluster, not multi-AZ, so
  these are plan-time names; the translate layer maps subnet/AZ placement to the cluster's
  own topology.
- **`Fn::ImportValue`** — resolves a cross-stack export from the exports supplied to the
  engine (`-import NAME=VALUE`, repeatable). A stateless CLI has no account-global export
  registry, so the operator supplies the exporting stacks' output values. An export that is
  **not** supplied records a blocker (the honesty rail holds — never a faked value), so a
  multi-stack deploy passes each upstream export explicitly.

Refused (each records a blocker): `Fn::Transform` (macros / SAM), and any other intrinsic
the engine does not implement. A template that relies on one of these is `REJECTED` rather
than provisioned with the value quietly wrong.

## Deploying a stack

```console
$ cfn deploy -namespace my-app -stack-name tickets kms-stack.yaml
Deploying stack "tickets" into namespace "my-app"…

Stack tickets [CREATE_COMPLETE]
  PrimaryKey   openinfra.dev/v1/EncryptionKey -> tickets-primarykey
  BackupKey    openinfra.dev/v1/EncryptionKey -> tickets-backupkey

Stack "tickets" is CREATE_COMPLETE (2 resources).
```

`deploy` is fail-closed by construction:

1. **Plan gate** — it runs the same `plan`. A `REJECTED` template is refused before
   anything is applied. Parameter values are checked here as CloudFormation checks them, with
   its messages: a value for a parameter the template does not declare (`Parameters: [X] do not
   exist in the template`), a parameter with no value and no `Default` (`… must have values`), a
   value outside its `AllowedValues`, `AllowedPattern` (a full match), `MinLength` / `MaxLength`
   or `MinValue` / `MaxValue` (or its `ConstraintDescription`, when it has one), and a `Number`
   that is not a number. Through the aws-shim, an `AWS::EC2::Subnet::Id`,
   `AWS::EC2::SecurityGroup::Id` (or `GroupName`) or `AWS::EC2::VPC::Id` value — or a `List<…>`
   of them — must name a `kind: Subnet`, `SecurityGroup` or `Vpc` that exists (`Parameter
   validation failed: parameter value … does not exist`), and an update's `UsePreviousValue` key
   must be a parameter of the stack's previous template. `AWS::EC2::KeyPair::KeyName` is not
   looked up (open-infra has no key pairs; an instance's `KeyName` is a caveat).
2. **Translate gate** — every included resource must have a create translator *and* every
   one of its properties must translate. A single property the engine cannot honor refuses
   the whole deploy. Nothing is applied until everything translates — there is no partial
   stack.
3. **Ordered apply** — resources are created in dependency order, each recorded in a
   persisted stack record and labeled with its stack. As on AWS, a resource is created once
   everything it depends on is complete, and resources that do not depend on each other are
   created alongside each other: a resource's wait (the cluster reporting it ready, the signals
   its `CreationPolicy` waits for) runs while the resources after it that do not depend on it
   are created. So a `WaitCondition` with no `DependsOn` waits while the instance whose
   `UserData` signals it is created. An `AWS::EC2::Instance` is complete once its VM is
   running, as on AWS: one whose VM never starts fails the stack at the timeout, and one whose
   VM stays in an error state (`ErrorUnschedulable`, an image that cannot be pulled) fails it
   after three minutes.
   The `cfn` CLI keeps the record as a `cfn-stack-<name>` ConfigMap in the target namespace.
   The aws-shim front door keeps it as a Secret in the shim's own namespace, readable only by
   the shim and cluster admins, because the record holds every resource's resolved properties,
   including what a `NoEcho` parameter was fed into.
   A stack's `AWS::DynamoDB::Table` is AWS's table through the aws-shim: one whose name is
   already a table's is refused (`Table already exists`), and the table is deleted with its
   items by a stack delete, an update that removes it, or a rolled-back create (unless
   `DeletionPolicy: Retain`), so a stack re-created with the same name starts empty. The `cfn`
   CLI, which has no access to the table data, deletes only the `kind: Table` claim.
4. **Rollback** — if any create or readiness wait fails, what is still being created is
   cancelled (`CREATE_FAILED`, "Resource creation cancelled"), everything created in that deploy
   is deleted in reverse order (a custom resource gets its Function's `Delete` event), and the
   stack ends `ROLLBACK_COMPLETE`, as on AWS — or `ROLLBACK_FAILED` when something could not be
   deleted. Either way the stack stays until it is deleted. A failed create leaves no orphans. A
   `DeletionPolicy: Retain` resource is kept, as AWS keeps it on rollback. One example is the
   shared default `EncryptionKey`, which may already key a sibling stack's disks.

The stack record lists every resource a create plans before it applies the first one. An
update records the resources it adds before it adds them. So if the process running an
operation dies partway through, the operation can still be rolled back from the record
alone. The aws-shim CloudFormation front door does this automatically
([aws-shim.md](aws-shim.md#cloudformation-the-cfn-engine-as-a-doorway-caller-authority-via-impersonation-probe-proven)).

A target `-namespace` and a `-stack-name` are required; `deploy` never guesses a
namespace. Use `-no-wait` to skip the readiness gate, `-timeout SECS` to bound it.

### Resource names

Each resource is named after its stack, `<stack>-<logical id>` in lowercase, as CloudFormation names a
resource the template leaves unnamed. Past 40 characters the name keeps its first 31 and ends in a
hash of the stack and logical id, so it stays unique and within Kubernetes limits. A bucket with no
`BucketName` gets the S3 name AWS gives it, `<stack>-<logical id>-<suffix>`: lowercase, shortened to fit
63 characters, ending in a 12-character suffix that differs for a later stack of the same name; `Ref`
returns it. One template can therefore be deployed as several stacks
(`dev`, `prod`) in one namespace. Logical ids that differ only in case (`MyDB`, `Mydb`) are two
resources, as on AWS: each gets a name ending in a hash of its exact id. Explicit names are used as
given: a Lambda's `FunctionName` names its Function (and `Ref` returns it), and a `BucketName`,
`TableName`, `QueueName`, `TopicName` or SSM parameter `Name` is the name clients use. Two resources
of one stack that would be one object (an explicit `FunctionName` equal to another Function's
generated name) are refused at the gate.

Before applying a resource, deploy and update check that no object of that kind and name exists that
is not this stack's. Another stack's object, or one no stack created, is never overwritten: the
operation fails and rolls back. A resource's first create is create-only, so two operations racing
for one name cannot both take it. An explicit physical name is checked the same way: a `BucketName`,
`QueueName`/`TopicName`, `TableName` or SSM `Name` another object in the namespace already has is
refused, as AWS refuses a create whose name is taken (otherwise a `dev` and a `prod` stack would share
one bucket). An object a deleted stack retained (`DeletionPolicy: Retain`, including one a rolled-back
create kept) still carries that stack's name but is no longer part of it. As on AWS, a new stack of the
same name, or an update that adds the resource again, creates a new resource rather than taking the
retained one back (so its rollback or delete can never remove the data the template asked to keep): the
new object is named around the retained one (its generated name ends in a hash), and the stack records
that name, so later updates and the delete use it. An explicit physical name the retained object still
has (its `BucketName`) is refused, as AWS refuses a bucket name that is taken; give the new resource
another name, or delete the retained one. A name that cannot change (an explicit `FunctionName`) is
refused the same way. The shared namespace default `EncryptionKey` of stacks created before per-stack
default keys is applied by every stack that uses it, retained or not.

A stack's data never carries over to a new stack of the same name. As on AWS, a generated bucket name
ends in a suffix of its own stack instance, so a re-created stack gets a new, empty bucket. A bucket's owner
record also names the claim instance that created it (its composite's creation time): a claim that is a new
instance takes over a bucket only when it is empty, and is refused while the earlier instance's data is
still in it.

A stack created before stack-qualified names keeps the names it recorded: an update never renames a
resource, which would create a second object and orphan the first. Resources an update adds to such
a stack are stack-qualified. Likewise a bucket created before generated bucket names keeps its S3 name (its
claim's name); a bucket an update adds gets a generated one.

### Stack outputs

When a create or update completes, the template's `Outputs` are evaluated against the
deployed stack and stored with it — `cfn deploy` prints them, and the aws-shim
CloudFormation front door returns them from `DescribeStacks` (`OutputKey` / `OutputValue` /
`Description` / `ExportName`). A conditioned-off Output is not an Output of the stack.

Everything the template itself determines resolves: literals, parameters, pseudo-parameters,
mappings, conditions, `Fn::Sub` / `Fn::Join` / `Fn::Select` / …, `Fn::ImportValue`, and a custom
resource's returned `Data` (and its `Ref`, the `PhysicalResourceId` its handler returned). Every
translated type's `Ref` and documented `Fn::GetAtt` attributes resolve too (`cfn/resource_attrs.go`):

- **ARNs** are built from the stack's `AWS::Partition`, `AWS::Region` and `AWS::AccountId` — the
  install's account and region, the ones the aws-shim reports — so an ARN a template builds with `!Sub` is
  the same string an Output reports (a bucket's `Arn`, a queue's `Arn`, a topic's `TopicArn`, a table's
  `Arn`, a function's `Arn`, a role's `Arn`, a managed policy's `Ref`, a key's `Arn`, a state machine's
  `Ref`, an ECS service's `Ref`, a certificate's `Ref`).
- **Names and URLs** are the ones the service uses: a queue's `Ref` / `QueueUrl` is
  `<SQS_QUEUE_URL_BASE>/<account>/<name>` (the same URL the SQS front door reports for it; a VM guest
  reading the stack's outputs through AWS's CloudFormation name gets it as
  `https://sqs.<region>.amazonaws.com/<account>/<name>`, which its resolver sends to the shim — see
  [aws-shim.md](aws-shim.md)), a parameter's
  `Ref` is its name, a bucket's `DomainName` / `RegionalDomainName` / `WebsiteURL` are AWS's shapes for
  its name. A queue, topic, subscription, parameter, key or alias in the SQS/SNS/SSM/KMS store (see
  *Queues, topics, parameters and keys*) resolves to exactly what that store holds — a stack key's `Ref`
  is the key id the KMS API lists. A secret, log group, EventBridge rule or bus, ECR repository or alarm
  (created through its own front door) resolves to the name and ARN it was created under: a secret's
  `Ref` / `Id` is its ARN (the one `GetSecretValue` takes), a repository's `RepositoryUri` is the
  in-cluster registry host and its name.
- **Ids another stack passes back in** — a VPC's, a subnet's, a security group's — are the resource's
  open-infra name. That is what the translators accept from a parameter or `Fn::ImportValue` (a raw
  `vpc-`/`subnet-`/`sg-` id is opaque to them), so a network stack's exports are usable by the stacks that
  import them. A resource that provisions nothing of its own (an internet gateway, a route table, a
  CloudFront policy) gets a stable synthetic id in AWS's shape (`igw-…`, `rtb-…`).
- **Live values** come from the deployed resources' status: an Elastic IP's `Ref` / `PublicIp` and an
  exposed instance's `PublicIp` are the VM's LAN IP (`status.lanIp`), and an Elastic IP allocated on its
  own (see below) is the address it holds; an instance's `PrivateIp` is the VM's pod IP (`status.ip`); an
  RDS instance's `Endpoint.Address` / `Endpoint.Port` are its in-cluster database Service; a user pool's
  `ProviderURL` is its issuer; a WaitCondition's `Data` is its signals'.
- **An instance's DNS names**: `PrivateDnsName` is AWS's form for the VM's address,
  `ip-a-b-c-d.ec2.internal` (`ip-a-b-c-d.<region>.compute.internal` outside us-east-1); nothing serves
  that zone here, so it names the instance but does not resolve. `PublicDnsName` is
  `ec2-<LAN IP with dashes>.<suffix>` on the install's public DNS suffix (`networking.publicDnsSuffix` in
  `config.yaml`; point it at a zone that resolves such names on your LAN, such as a wildcard DNS
  service). Without a suffix, or for an instance with no public address, it is `""`, which is what AWS
  reports for an instance without a public DNS name.

A LAN IP is assigned shortly after the VM is created, so a completing stack waits for it
(up to ten minutes, within `-timeout`) before recording its Outputs. An instance with an encrypted
root starts later: its OS image is copied onto the encrypted disk first. While such an instance is
still copying, or has copied and is starting, the wait goes on, up to 45 minutes in all; once its copy
is done, the instance has ten minutes to report its address. It stops waiting a minute before the
operation as a whole would run out of time (an hour through the aws-shim front door), so the stack's
final record is still written.

An Output that names an attribute open-infra does not provide is **refused at plan time** — the stack is
refused before anything is created, naming the attributes the type does have — as AWS refuses a template
whose `Fn::GetAtt` names an attribute the type lacks. An Output that is supported but still does not
resolve after deploy (a LAN IP never assigned, an instance that is not exposed) **fails the create or
update**, which rolls back, with the reason as the stack's status reason: no stack completes with an
Output missing, and an Output is never filled with a placeholder or an invented value.

An Output with an `Export.Name` is a cross-stack export. Through the aws-shim front door,
exports are registered per namespace: `ListExports` lists them, `Fn::ImportValue` in any
template the front door evaluates resolves against them, a stack that would export a name
another stack already exports is refused, and a stack — or an update — that would remove an
export another stack imports is refused. The `cfn` CLI has no export registry; pass upstream
exports with `-import NAME=VALUE`.

### Resource signals and wait conditions

A resource with a `CreationPolicy` `ResourceSignal` is not complete when it exists but when its
instances say so, as on AWS: after it is applied and Ready, the stack waits for `Count` (default 1)
`SUCCESS` signals with distinct `UniqueId`s within `Timeout` (an ISO 8601 duration, default `PT5M`, at
most 12 hours). A `FAILURE` signal, or the timeout, fails the resource and rolls the stack back.
`AWS::CloudFormation::WaitCondition` waits the same way — for its `Handle`'s signals (`Count`, `Timeout`
in seconds) or for its own `CreationPolicy` — and its `Fn::GetAtt Data` (usable in Outputs) is the
signals' data as a JSON object keyed by `UniqueId`. A `WaitConditionHandle`'s `Ref` is a URL on the
aws-shim (signed for that stack and handle) that a guest `PUT`s AWS's signal JSON to
(`{"Status":"SUCCESS","UniqueId":"…","Data":"…","Reason":"…"}`); its base is `CFN_SIGNAL_BASE_URL`, by
default the shim's in-cluster TLS address that guests already use for their credentials.

Signals arrive two ways: the handle URL, and `SignalResource` (what `cfn-signal --stack --resource`
calls). An instance of the stack may signal it with nothing more than its instance role — on AWS
`cfn-signal` needs no extra permission, so a template written for AWS grants none. Anyone else needs
update rights on the stack (a User) or a policy allowing `cloudformation:SignalResource` on it (a role).
`DescribeStackResource` returns a resource's `Metadata`, which is what `cfn-init` reads for
`AWS::CloudFormation::Init`; the guest runs `cfn-init` itself against the shim's endpoint, as it would
against AWS's. Guests resolve `cloudformation.<region>.amazonaws.com` to the shim, so
`cfn-init --stack … --resource … --region …` needs no `--url`.

`cfn-init`, `cfn-signal` and `cfn-hup` run with no credentials (no `--role`, no keys) work too, as on
AWS. They sign their calls `Authorization: CFN_V1 <document>:<signature>` with the instance's signed
identity document ([virtual machines](virtual-machines.md#signed-instance-identity-document)). The shim
first checks the document:
- the signature is the platform's;
- the document has not expired;
- the account and region are this shim's.

The call is then the instance's, with the authority CFN_V1 has on AWS:
- **Actions:** `SignalResource`, `DescribeStackResource` and `DescribeStackResources` only.
- **Stacks:** only the stack that launched the instance. Its record must list the VM, the VM's composite
  must be bound to it with the document's instance id, and the instance must be running.

These are all refused, with the same answer for a stack that does not exist and a stack that is not the
instance's:
- another instance's document;
- another stack;
- a VM deleted and re-created under the same name, which has a new instance id;
- a stopped VM;
- a call through the LAN Ingress.

aws-cfn-bootstrap's calls are `GET` requests with their parameters in the query string and
`ContentType=JSON`. Those three actions answer in JSON for them, as AWS does, whether the call is signed
CFN_V1 or with SigV4 (`--role`). The bootstrap's `requests` checks TLS against the guest's system trust
store, which holds the platform's AWS endpoints CA. On cloud images that is the distro's
`python3-requests`, which cloud-init itself uses. Only the aws-shim front door receives signals: a `cfn deploy` of a stack that waits for
them is refused rather than waiting for something that cannot arrive.

### Stack events and the rest of the API

Through the aws-shim front door, every transition is recorded as AWS records it — the stack's
`CREATE_IN_PROGRESS` ("User Initiated"), each resource's `CREATE_IN_PROGRESS` / `CREATE_COMPLETE`, a failed
resource's `CREATE_FAILED` with its reason, the rollback, the stack's final status; updates and deletes
likewise — and `DescribeStackEvents` returns them newest first, as the create progresses. Also served:
`ListStackResources` and `DescribeStackResources` (each resource's CloudFormation type, physical id —
its `Ref` — and own status), `DescribeStackResource`, `ListChangeSets`, `ListImports` and
`SignalResource`. A resource that provisions nothing of its own — an internet gateway and its
attachment, a route table, a route and their associations, an Elastic IP folded onto its instance, a
volume attachment, a wait condition handle, a bucket policy — is listed too, with its `Ref` as its
physical id (`igw-…`, `rtb-…|0.0.0.0/0`, the address, the handle's URL; one with no `Ref` of its own gets
the `<stack>-<LogicalId>-<suffix>` id AWS generates), and with the status of the resources it is part of
(a route its VPC's, an attachment its instance's and volume's); its events follow theirs. A wait
condition handle exists from the moment the create begins, as on AWS. Change sets list them too — an `Add`, `Modify` (its resolved properties differ) or `Remove`, by its type and physical id — and an update that changes only them is an update: the stack records the new template and parameters and their events, and ends `UPDATE_COMPLETE`, with nothing applied, since nothing of theirs exists. A resource an update removes is no longer listed (its `DELETE_COMPLETE` event stays in the history). `DescribeStacks` lists every template parameter (a default as such; `NoEcho` as
`****`) and the template's `Description`. `ValidateTemplate` checks a template without parameter values,
as AWS does: a parameter with no default is not an error there. A change set is found by its ARN alone (what `deploy` prints), lists each change by its CloudFormation type, and once executed reports `ExecutionStatus` `EXECUTE_COMPLETE` (or `EXECUTE_FAILED`); only an `AVAILABLE` change set can be executed.

### Create fidelity is narrower than the plan mapping

The plan table above answers "is there a backing kind?". Creating a resource asks a
harder question: does every *property* translate faithfully? Often it does not, and where
it does not the engine refuses rather than guess. A resource type that plans as
`supported` is therefore not automatically create-able. Concretely, at create time:

- The set of types with a create translator is a subset of the plan-supported types. A
  supported type without a translator is refused at deploy with "no create translator".
  **`cfn plan` surfaces this directly** so the gap is never a deploy-time surprise: a resource
  that maps but cannot be created is marked `[gate]` and flagged `⚠ maps at plan only — NOT
  deployable`, its `Deployable` field is `false` in the JSON, and any stack containing one is
  reported `PROVISIONABLE_WITH_CAVEATS` (never a clean `PROVISIONABLE`) with an explicit
  `NOT DEPLOYABLE AS-IS` line. Because deploy is all-or-nothing, one such resource makes the whole
  stack undeployable until it is removed or expressed natively.
- AWS resource *content* frequently has no faithful open-infra form — IAM's
  `service:Action` permission namespace is a different universe from open-infra's
  `kind:verb` RBAC, KMS key policies have no per-key equivalent, and a `Fn::GetAtt` to
  another resource's ARN has no value here. Each of these blocks the deploy loudly.
- Where a property maps but loses something (a KMS `KeyPolicy`, a Lambda `Role`), the loss
  is printed as a **caveat**, never silently dropped.

Today's create translators (live-verified on the cluster):

| CloudFormation | open-infra | Notes |
|---|---|---|
| `AWS::KMS::Key` | `kind: EncryptionKey` | Description, `EnableKeyRotation`→rotation, `KeySpec`→key type; `KeyPolicy` is a caveat (access is via open-infra IAM). **Through the aws-shim front door**: also a key in the KMS API's store (`KeyPolicy` applied there), under the id its `Ref` resolves to. |
| `AWS::KMS::Alias` | the KMS API's alias store | `AliasName`, `TargetKeyId` (an in-stack key or a key id/ARN). Through the aws-shim front door only. |
| `AWS::Lambda::Function` (`PackageType: Image` only) | `kind: Function` | `Code.ImageUri`→image, `Environment`→env, `MemorySize`→memory, `Timeout`→timeout, `Role`→`spec.role`, the [execution role](serverless.md#execution-role) the function's code runs as: an in-stack `AWS::IAM::Role` by `!GetAtt <Role>.Arn`, or a role ARN of the stack's account. Refused, as Lambda refuses them: a `Role` by `!Ref` (a name, not an ARN), an in-stack role whose trust does not name `lambda.amazonaws.com`, a role of another account. A zip/Runtime Lambda has no image and is refused. |
| `AWS::StepFunctions::StateMachine` | `kind: StateMachine` | The ASL `DefinitionString`/`Definition` maps byte-for-byte (open-infra runs the same Amazon States Language). `RoleArn`, `Logging`/`TracingConfiguration` are caveats. **Refused** (not silently broken): a definition whose Task `Resource` fields are AWS ARNs — open-infra Tasks reference a Function as `function:<name>`, so remap them first; also `EXPRESS` type, `DefinitionS3Location`, and `DefinitionSubstitutions`. |
| `AWS::EC2::Volume` | `kind: Volume` | `Size`→size, `MultiAttachEnabled`→shared (RWX), **`Encrypted`→LUKS at rest keyed by a customer `kind: EncryptionKey`** (a `KmsKeyId` must reference an in-stack `AWS::KMS::Key`; with no `KmsKeyId` the volume is keyed by the stack's default EncryptionKey `<stack>-ebs-default` — the `aws/ebs` analog, created on first use, one per stack so destroying one stack's key crypto-erases only that stack's volumes; a stack created while the namespace shared one `ebs-default` keeps using it). The resource completes once the volume is **bound** — usable, as EBS reports `available`; for an encrypted volume that is after its passphrase is materialized ([`encryption.md`](encryption.md#longhorn-volumes-shipped-sc--just-use-it)). `AvailabilityZone`/`VolumeType`/`Iops`/`Throughput` are caveats (one flat cluster, Longhorn). **Refused**: a `KmsKeyId` that names an out-of-stack or AWS-managed key (no mappable equivalent) and `SnapshotId` (an EBS snapshot id has no open-infra VolumeSnapshot to restore from). |
| `AWS::Cognito::UserPool` (+ `UserPoolClient`) | `kind: UserPool` | `UserPoolName`→realm — a hosted OIDC pool (Keycloak). An in-stack `UserPoolClient` **collates** into the pool (its `ClientName`→`spec.clientId`; the pool provisions one app client). The realm's own defaults cover password policy / schema / verification, so those are caveats — as is the client's OAuth config (flows/scopes/callback URLs/GenerateSecret). **Refused**: `MfaConfiguration` (ON/OPTIONAL) and `LambdaConfig` triggers (behavior-bearing auth with no faithful mapping); more than one client per pool; a client whose `UserPoolId` isn't in the stack. |
| `AWS::IAM::User` | `kind: User` | `UserName`→displayName, `Groups`→group membership (the AWS best-practice shape — permissions come from a Group's ClusterRole). **Refused**: `ManagedPolicyArns` / inline `Policies` / `PermissionsBoundary` — AWS policy documents (`service:Action` over ARNs) have no faithful k8s-RBAC form; dropping them would silently strip permissions. Password/LoginProfile are set separately (caveat). |
| `AWS::IAM::Role` (a service role: EC2 instance role, Lambda execution role, …) | `kind: Role` (`spec.trust`) | A **service role's** trust is an `AssumeRolePolicyDocument` that Allows `sts:AssumeRole` for AWS service principals, recorded as IAM's `CreateRole` records it. **`ec2.amazonaws.com`** → the **`vm`** principal: assumable by a `kind: VirtualMachine` that names it as `spec.instanceRole` (the container-credentials path, no static keys). **`lambda.amazonaws.com`** → `Service::lambda.amazonaws.com`: a **Lambda execution role**, assumed by a `kind: Function` that names it as `spec.role` ([execution role](serverless.md#execution-role)). **`ecs-tasks.amazonaws.com`** → `Service::ecs-tasks.amazonaws.com`: an **ECS task role**, assumed by a `kind: Application` that names it as `spec.assumeRole` ([task roles](iam.md#task-roles-applications)). **`states.amazonaws.com`** → `Service::states.amazonaws.com`, assumed by a state machine that names it. **Any other service** → `Service::<service>`: the role exists with its policies and its trust, as on AWS, but no open-infra service assumes a role on that trust, so it grants nothing — a caveat says so. An **AppSync service role** (trusting `appsync.amazonaws.com`) translates with **no trust entry**: the role exists, as on AWS, with its policies attached, but nothing assumes it — open-appsync reaches its data sources with the engine's own connection — so it grants nothing, and a caveat says its policies do not limit the resolvers. **Refused**: a non-service trust principal (account/ARN, SAML/OIDC, a mix with one of those) — no template-derivable trust. **Inline `Policies` are translated** into companion `kind: Policy` objects (`spec.dataPlane`, `appliesTo: Role::<name>`) that govern the role's assumed sessions — the narrow data-plane subset (`s3:`/`sqs:`/`ecr:`/… actions on recognizable ARNs, the same importer `AWS::IAM::Policy` uses); any statement the data plane can't honor fail-closes the whole Role. **ECR statements** map to `Repository::<name>` from `arn:aws:ecr:<region>:<account>:repository/<name>` (wildcards kept, e.g. `repository/team/*`), and `ecr:GetAuthorizationToken` on `Resource: "*"` stays `*` — so an instance role that grants `ecr:GetAuthorizationToken` + `ecr:BatchGetImage` + `ecr:GetDownloadUrlForLayer` on its repository can `aws ecr get-login-password \| docker login` and `docker pull` that repository from the guest, and nothing else ([ECR](aws-shim.md#ecr-minio-backed-oci-registry-two-plane-json-protocol-probe-proven)). An in-stack bucket/queue/table/function/topic referenced by `!GetAtt X.Arn`, or inside an `Fn::Sub` as `${X.Arn}` or `${X}` (`!Sub "${AppBucket.Arn}/*"`, `!Sub "arn:aws:s3:::${AppBucket}/*"`), resolves to that resource; `${AWS::Region}`/`${AWS::AccountId}`/`${AWS::Partition}` and parameters resolve as anywhere else. A reference that still doesn't resolve to a real resource refuses the Role rather than granting on a non-resource. **`ManagedPolicyArns`**: the AWS managed policies an instance role commonly attaches are attached as companion `kind: Policy` objects carrying the access open-infra serves — `AmazonEC2ContainerRegistryReadOnly` and `AmazonEC2ContainerRegistryPullOnly` (ECR pull), `AmazonS3ReadOnlyAccess` (`s3:Get*`/`s3:List*`), `AmazonSSMManagedInstanceCore` (its parameter reads and the SSM agent's Run Command channel — the instance becomes a managed instance `aws ssm send-command` reaches; Session Manager has no endpoint) and `CloudWatchAgentServerPolicy` (metrics and logs) — each with a caveat naming what of it is not attached. Any other managed or customer-managed policy ARN stays a caveat (not attached); express that access as inline statements. |
| `AWS::IAM::InstanceProfile` | *(implicit)* | The AWS container that binds a role to an instance. open-infra binds the role directly on the VM (`kind: VirtualMachine` `spec.instanceRole`), so the profile provisions nothing on its own — an `EC2::Instance`'s `IamInstanceProfile` is resolved **through** it to the role. A no-op (accepts `Roles`/`Path`/`Name`/`Tags`) so a stack carrying it is not blocked. It reads back through IAM (`get-instance-profile`, `list-instance-profiles`, `list-instance-profiles-for-role`) by its `Ref`, with the ARN its `Fn::GetAtt Arn` gives. |
| `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy` | `kind: Policy` (`spec.dataPlane`) | The **data-plane** subset of an AWS policy document — `s3:*`/`dynamodb:*`/`lambda:*` actions on recognizable S3/DynamoDB/Lambda ARNs — imports into a real, enforced `kind: Policy` `spec.dataPlane` (Cedar-backed, applied at the aws-shim front doors; see [`policy-engine.md`](policy-engine.md)), attached to the policy's `Users`/`Roles`. The `kind: Policy` is created in the stack's namespace, and a policy there governs only that namespace's principals: a `User` or `Role` is an in-stack `AWS::IAM::User`/`AWS::IAM::Role` (by `Ref`), or one that must already exist in the stack's namespace — deploy refuses while it does not, as AWS refuses a policy naming a missing user. A **`Groups` attachment refuses**: groups are IAM home identities a stack's policy cannot govern, so a guardrail attached that way would apply to no one; attach it natively in the IAM home namespace. ARNs map (`arn:aws:s3:::reports/*`→`Bucket::reports`, a table ARN→`Table::metrics`), `Allow`/`Deny` carry through faithfully. A `ManagedPolicy` translates the same way **when it carries inline `Groups`/`Users`/`Roles`**; a standalone one (attached elsewhere via `ManagedPolicyArns`) has no principal here and blocks. A **`Roles` attachment now translates** to `dataPlane.appliesTo: [Role::<name>]` and governs the assumed `sts:AssumeRole` session (the shim authenticates assumed-role sessions, #111; the engine governs `Role::` principals) — a declared caveat records that each named `kind: Role` must exist and carry a trust policy natively for a session to assume it. `ManagedPolicyName`/`Description`/`Path` are dropped metadata (caveats). **Refused** (never a silent partial — a dropped `Deny` or condition is a security hole, a dropped `Allow` a scope change): any action for a service with no data plane (`ec2:*`, `iam:*`), an unrecognizable ARN, a `Condition` on any key beyond `aws:SourceIp` (IpAddress/NotIpAddress), `aws:username` (StringEquals exact, or StringLike/StringNotLike `*`-wildcard — `?` is refused), `aws:CurrentTime` (Date{Greater,Less}Than[Equals] — the value must be a Cedar-parseable datetime like `2025-01-01T00:00:00Z`), the authenticated-principal flag, or MFA (`aws:MultiFactorAuthPresent` Bool/BoolIfExists/Null, `aws:MultiFactorAuthAge` Numeric* and their IfExists forms) — those import; any other key/operator or a multi-valued condition is refused (author it natively), a statement with no mappable `Resource`, and a policy attached to no principal. Enforced only where the shim front doors are enabled (opt-in); it never governs the k8s control plane (that stays RBAC + the boundary). |
| `AWS::ECS::Service` + `TaskDefinition` (+ `Cluster`) | `kind: Application` | **A collation** — a Service and its referenced TaskDefinition merge into one Application (Deployment+Service+Ingress+HPA). The primary container (the LB-named one, else the first with a port) → `image`/`port`/`env`; **additional containers → Application `sidecars`** (image/port/env). `DesiredCount`→a fixed replica count. A `Cluster` and a bare TaskDefinition are no-ops. **Refused**: a `Command`/`EntryPoint` override (any container), task `Volumes`, or a Service whose TaskDefinition isn't in the stack. **`TaskRoleArn`** (a role name or ARN) → the app's task role, `spec.assumeRole` ([task roles](iam.md#task-roles-applications)): the role of that name in the stack's account, which must trust `ecs-tasks.amazonaws.com` (a role ARN of another account is caveated: the app assumes the stack account's role of that name); an in-stack role by `!Ref`/`!GetAtt` is not resolved yet (a caveat — set `assumeRole` natively). Caveats: LoadBalancers / NetworkConfiguration / LaunchType, task Cpu/Memory / `ExecutionRoleArn`, and per-sidecar CPU/memory/health checks (open-infra exposes via `domain`, sizes via quotas/HPA). |
| `AWS::DynamoDB::Table` | `kind: Table` | KeySchema+AttributeDefinitions→hashKey/rangeKey (S/N/B), `TimeToLiveSpecification`→ttlAttribute, **`GlobalSecondaryIndexes`→globalSecondaryIndexes** (name + key schema; backed by a real Mongo index — a Query with the index's name filters on its attributes; GSI Projection/throughput are caveats). `ProvisionedThroughput`/`BillingMode` are caveats (no capacity model); functions only where the aws-shim DynamoDB front door is enabled. **Refused**: local secondary indexes, `StreamSpecification`, `SSESpecification`, PITR/import — behavior-bearing with no faithful form. |
| `AWS::AppSync::GraphQLApi` + `GraphQLSchema` + `DataSource` + `Resolver` (+ `FunctionConfiguration`) | `kind: GraphQLApi` | **A collation** — the API reads its in-stack Schema (SDL→schema), DataSources, and Resolvers (unit + pipeline). A resolver's VTL carries **byte-for-byte** (Request/ResponseMappingTemplate→request/response), and `APPSYNC_JS` maps to the `appsync-js` runtime. Data-source types: `AMAZON_DYNAMODB`/`HTTP`/`NONE`/`OPENSEARCH`/`EVENTBRIDGE`, and `AWS_LAMBDA` when `LambdaConfig.LambdaFunctionArn` references the stack's own `AWS::Lambda::Function` (`!GetAtt Fn.Arn` — the data source invokes the `kind: Function` it becomes). On a Lambda data source a resolver or `FunctionConfiguration` may leave out its mapping templates — a **Direct Lambda Resolver** (AppSync's Context is the event; the return value is the field's) — and `MaxBatchSize` (0–2000) batches it (BatchInvoke; see [open-appsync](../open-appsync/README.md#lambda-resolvers-direct-and-batched)). Caveats: `AuthenticationType` (open-appsync enforces via `@aws_*` schema directives + apiKeysSecret) and a dynamodb source's `mongoURI` (a deploy-time endpoint). **Refused**: a Lambda data source naming a function outside the stack, a resolver with a mapping template left out on a non-Lambda source (AWS requires both there), `MaxBatchSize` on a non-Lambda source or on a `PIPELINE` resolver (a pipeline batches in its functions), a relational source with no DSN, any S3-location template, and a child pointing at an API not in the stack. |
| `AWS::S3::Bucket` | `kind: Bucket` | A standalone MinIO bucket (the object-storage analog of `kind: Volume`). `BucketName`→bucket, `VersioningConfiguration`→versioning, `LifecycleConfiguration`→lifecycle rules (Id / Prefix / `ExpirationInDays` / `NoncurrentVersionExpiration.NoncurrentDays`), `ObjectLockConfiguration`→objectLock (WORM). An in-stack **`AWS::S3::BucketPolicy`** targeting this bucket **collates** in as `spec.policy` (applied verbatim via `put-bucket-policy`) — **public `*` principals only**; a Statement with an AWS-IAM-ARN principal **refuses** (MinIO can't resolve the ARN, so the policy would store but not enforce as written — same class as the db-stats/dataflow refuse-rather-than-apply rule). `BucketEncryption` maps where object encryption is on (`components.objectEncryption`: every new bucket gets default AES256 encryption under the platform MinIO's key; an `aws:kms` key is not used — the platform key is), and **refuses** where it is off — refusing beats an unencrypted bucket that looks encrypted. **Refused**: `CorsConfiguration` (a MinIO ceiling — see the ceilings table), a lifecycle `Transitions`/`ExpirationDate`/tag-or-size filter, and website/notifications/replication/public-access. `Tags`→`tags`, the bucket's S3 tags (`GetBucketTagging` returns them); a tag S3 refuses (an `aws:` key, more than 50, over-long) refuses, and one whose value is not known at plan time is dropped with a caveat. A stack delete refuses a bucket that still holds data (see [Tearing down a stack](#tearing-down-a-stack)). |
| `AWS::S3::BucketPolicy` | `kind: Bucket` (`spec.policy`) | **Collated** into its in-stack `AWS::S3::Bucket` — it has no standalone form. The `PolicyDocument` is serialized to compact JSON and applied verbatim via `put-bucket-policy`. **Public `*` principals only** (`"*"`, `{"AWS":"*"}`, `{"AWS":["*"]}`) — an AWS-IAM-ARN principal refuses (govern identity-scoped access via a data-plane `kind: Policy` instead). **Refused**: a `BucketPolicy` whose `Bucket` names/Refs a bucket not in this stack (a policy over an unmanaged bucket is not translatable). |
| `AWS::RDS::DBInstance` | `kind: Application` (data-only, `database`) | `Engine`→engine (postgres/aurora-postgresql→postgres; mysql/mariadb/aurora-mysql→mysql; sqlserver-\*→babelfish), `DBName`→name, `MultiAZ`→highAvailability, **`StorageEncrypted`→LUKS keyed by a customer `kind: EncryptionKey`** (postgres only in v1; `KmsKeyId` must reference an in-stack `AWS::KMS::Key`). Caveats: `AllocatedStorage`/`DBInstanceClass` (no per-DB capacity knob), master credentials (open-infra provisions them, injects `DATABASE_URL`), backup/network config. **The `mysql` engine is MariaDB** (MySQL wire-compatible, not MySQL itself) — a loud caveat warns that server-specific collations such as **`utf8mb4_0900_ai_ci`** (the MySQL 8.0 default) do **not** transfer and must be remapped (e.g. `utf8mb4_unicode_ci`) before importing a dump; there is no real MySQL 8 engine. **Refused**: `StorageEncrypted` on a non-postgres engine or without a mappable `KmsKeyId`, and an unmappable engine (oracle). |
| `AWS::SQS::Queue` | `kind: Queue` | `QueueName`→the stream, `MessageRetentionPeriod`→retentionHours. A NATS JetStream **WorkQueue** (each message to one consumer). **Refused**: `FifoQueue` (JetStream ordering/dedup differs) and `KmsMasterKeyId`. Visibility/delay/DLQ-redrive are consumer-side caveats. **Through the aws-shim front door**: a queue in the SQS API's store — standard, or FIFO with `FifoQueue` (`ContentBasedDeduplication`/`DeduplicationScope`/`FifoThroughputLimit` its attributes) — whose `VisibilityTimeout`/`DelaySeconds`/`MessageRetentionPeriod`/`MaximumMessageSize`/`ReceiveMessageWaitTimeSeconds`/`RedrivePolicy` are its queue attributes (see *Queues, topics, parameters and keys*). |
| `AWS::SNS::Topic` | `kind: Queue` (fanout) | `TopicName`→the stream. A NATS JetStream **Limits** stream (fan-out — every consumer reads each message). An inline **`lambda` `Subscription` to an in-stack Function maps** — the subscribing `kind: Function` gets the topic in `spec.queues` and reads the stream (see `AWS::SNS::Subscription` below). **Refused**: every other inline `Subscription` protocol (`sqs`/`http`/`email`/`sms`/…), `FifoTopic`, `KmsMasterKeyId`. **Through the aws-shim front door**: a topic in the SNS API's store; inline `sqs` and `lambda` subscriptions are delivered by that front door. |
| `AWS::SNS::Subscription` | `kind: Function` (`spec.queues`) | **Collated** into the subscribing Function — no standalone form. **Only `Protocol: lambda` to an in-stack `AWS::Lambda::Function` maps**: the topic's stream name is folded into that Function's `spec.queues`, so the Function consumes the topic's JetStream stream directly (open-infra's "subscribe a consumer to the topic" mechanism, in place of SNS push delivery). The `TopicArn` must `!Ref`/`!GetAtt` an in-stack `AWS::SNS::Topic` and the `Endpoint` an in-stack Function; both standalone `AWS::SNS::Subscription` resources and inline `Subscription` entries on a topic are honored the same way. **Refused**: an out-of-stack topic or endpoint (nothing we manage), an `sqs` subscription (open-infra builds no topic→queue bridge — instead give the consumer `spec.queues: [<topic>]` so it reads the topic stream directly), and `http`/`https`/`email`/`email-json`/`sms`/`application`/`firehose` (no open-infra outward push-delivery surface). **Through the aws-shim front door**: a subscription in the SNS API's store — `sqs` to a queue ARN and `lambda` to an in-stack Function or a function ARN, delivered by that front door; `RawMessageDelivery`, `FilterPolicy` and `FilterPolicyScope` map (applied by that front door). |
| `AWS::SecretsManager::Secret` | a Secrets Manager secret (the shim's store) | Created through the Secrets Manager front door, as the caller, so the app reads it with `GetSecretValue` by the ARN `Ref` returns (the ARN's six-character suffix is derived from the stack, so `Ref` is known before deploy; a secret deleted and re-created by the same stack keeps its ARN). `SecretString`, or `GenerateSecretString` (generated once at create — `SecretStringTemplate` + `GenerateStringKey` included; an update does not regenerate it), `Description`, `Tags`. A changed `SecretString` is a new version. A stack delete removes the secret at once (no recovery window). **Refused**: a `KmsKeyId` other than the default managed key, `ReplicaRegions`, and a secret with no value. |
| `AWS::Logs::LogGroup` | a CloudWatch Logs log group (the shim's store) | `LogGroupName`, `RetentionInDays` (an AWS-allowed value; removing it in an update keeps events forever again), `Tags`. **Refused**: `KmsKeyId`, `DataProtectionPolicy`. A `LogGroupClass` other than `STANDARD` and `FieldIndexPolicies` are caveats. |
| `AWS::Events::Rule`, `AWS::Events::EventBus` | an EventBridge rule / custom bus (the shim's store) | A rule's `ScheduleExpression` and/or `EventPattern` on the default or a named bus, `State`, and Targets with a constant `Input`: an in-stack Lambda function (invoked in the stack's own namespace) or a Lambda/SQS ARN. A target is authorized as `PutTargets` authorizes it — the caller must be able to invoke it. An in-stack SQS queue is a target where the front door serves SQS (the queue is then in the SQS API's store, targeted by its ARN). **Refused**: SNS, Step Functions and the other target types; a rule or target `RoleArn`, `InputPath`, `InputTransformer`, `DeadLetterConfig`, per-service target parameters; an in-stack SQS queue on a deploy path that does not serve SQS (it would be a `kind: Queue` stream EventBridge cannot deliver to). `RetryPolicy` is a caveat. A bus's partner `EventSourceName`, `Policy`, `KmsKeyIdentifier` and `DeadLetterConfig` refuse. |
| `AWS::ECR::Repository` | an ECR repository (the in-cluster registry) | `RepositoryName`, `ImageTagMutability` (`MUTABLE`/`IMMUTABLE`, changeable in an update), `EmptyOnDelete` (without it, deleting a repository that holds images fails the stack delete, as on AWS). `Fn::GetAtt RepositoryUri` is the registry host + name. `EncryptionConfiguration` `AES256` maps only where object storage is encrypted at rest. Scanning, lifecycle policies, an Allow-only repository policy and `Tags` are caveats (not implemented). **Refused**: `KMS` encryption, a repository policy with a `Deny`, tag-mutability exclusion filters. |
| `AWS::CloudWatch::Alarm` | a CloudWatch alarm (the shim's evaluator) | A single-metric alarm — `Namespace`, `MetricName`, `Dimensions`, `Statistic` or a `pNN` `ExtendedStatistic`, `Period`, `EvaluationPeriods`, `DatapointsToAlarm`, `Threshold`, the four static comparison operators, `TreatMissingData` — firing SNS `AlarmActions` (none when `ActionsEnabled` is false) — a topic by ARN, or an in-stack topic where the front door serves SNS. A dimension may name an in-stack instance (`Value: !Ref <instance>` or its `InstanceId`): the value is the instance's id; no `AWS/EC2` metrics are published for an instance, so its metrics reach the alarm only through `PutMetricData` (a caveat). `Unit` and `EvaluateLowSampleCountPercentile` are caveats. **Refused**: metric-math alarms (`Metrics`, `ThresholdMetricId`), anomaly-band operators, `OKActions` and `InsufficientDataActions`, and an in-stack topic action on a deploy path that does not serve SNS. |
| `AWS::Lambda::Permission` | (none) | A permission for an AWS service principal (`events`, `sns`, `s3`, `apigateway`, …) to invoke an in-stack Function provisions nothing: the integration that invokes it is authorized when it is created, against its creator's own `lambda:InvokeFunction`. **Refused**: an account or role principal, function URL permissions, an action other than `lambda:InvokeFunction`, a function outside the stack. |
| `AWS::EC2::VolumeAttachment` | `kind: VirtualMachine` `spec.volumes` | Attaches an in-stack `AWS::EC2::Volume` (or a `kind: Volume` a parameter names) to an in-stack instance: the VM starts with it as a virtio disk after its data disks, and is created after the volume. The `Device` name is not used; an attachment added to or removed from a running instance takes effect at its next restart. **Refused**: an instance outside the stack, an EBS volume id. |
| `AWS::Route53::RecordSet`, `AWS::Route53::HostedZone`, `AWS::Route53::RecordSetGroup` | — | **Refused**: open-infra serves no tenant-owned authoritative DNS zone (cluster DNS is cluster-scoped, LAN names come from the site's DNS), so a record would be accepted and never answered. Publish the name in the site's DNS, or use the Elastic IP / StaticSite domain the stack outputs. |
| `AWS::SSM::Parameter` | `kind: Parameter` | The SSM Parameter Store equivalent — a value under a hierarchical path in OpenBao KV-v2, materialized into the namespace's Secret. `Name`→`path`, `Value`→`value`, `Type` (`String`/`SecureString`; `SecureString` is held encrypted at rest). A `StringList` stores its plain comma-separated string (no list-typed parameter — caveat). `Description`/`AllowedPattern`/`DataType`/`Tags` are advisory metadata with no equivalent (caveats). **Refused**: a lifecycle `Policies` (expiration/notification) — an OpenBao-backed parameter does not auto-expire, so silently dropping one would keep a value that should have expired. Consume it by adding `openinfra-parameters` to an Application/Function `spec.secrets`. **Through the aws-shim front door**: a parameter in the SSM API's store (Standard tier) — `Name` is optional (CloudFormation's generated name), `Policies` refuse. |
| `AWS::EC2::VPC` | `kind: Vpc` | An isolated kube-ovn network domain. The VPC-level `CidrBlock` is informational (subnets carry the CIDRs), and DNS/tenancy/`Tags` are caveats. |
| `AWS::EC2::Subnet` | `kind: Subnet` | Real OVN isolation. `CidrBlock`→`cidr` (required), a `VpcId` `!Ref` to an in-stack `AWS::EC2::VPC`→`vpc`, `MapPublicIpOnLaunch`→`private` (a public subnet is not private). `AvailabilityZone`/IPv6/`Tags` are caveats (one flat cluster, no AZ). |
| `AWS::EC2::SecurityGroup` (+ `SecurityGroupIngress` / `SecurityGroupEgress`) | `kind: SecurityGroup` | A default-deny allow-rule set. Inline rules **and** standalone `AWS::EC2::SecurityGroupIngress`/`Egress` resources `!Ref`-ing this group collate into `spec.ingress`/`egress`, **fail-closed**: only TCP/UDP on a single port, a range of up to 16 ports (expanded to its exact port list), or all-ports, with a `CidrIp` source or a `SourceSecurityGroupId` `!Ref` to an in-stack SG, translate. A non-TCP/UDP protocol (incl. `-1`), a port range wider than 16 ports, an out-of-stack SG id, or an IPv6 CIDR **refuses the whole resource** (never a looser rule than written), as does a standalone rule with more than one source or destination, or one naming its group by `GroupName`. `VpcId`/`GroupName`/`Tags` don't map. |
| `AWS::EC2::VPCEndpoint` | `kind: VpcEndpoint` | A private, in-VPC DNS alias to the one aws-shim front door for the service. `ServiceName`→`service`, `VpcEndpointType` carried for fidelity, a `VpcId` `!Ref` to an in-stack `AWS::EC2::VPC`→`vpc`. `PolicyDocument`/`RouteTableIds`/`SubnetIds`/`SecurityGroupIds`/`PrivateDnsEnabled` are caveats (every service routes to the shim; access is governed by IAM/Cedar there, not per-endpoint). It reads back through `describe-vpc-endpoints` by its `Ref`. |
| `AWS::EC2::Instance` | `kind: VirtualMachine` | `ImageId` names an open-infra **catalog OS** in place of the AMI — a recognized PUBLIC image SSM-parameter path (ubuntu/debian/fedora/windows) maps; **a raw `ami-` id or an out-of-catalog OS refuses with the catalog listed** (the one refusal, inside an otherwise create-faithful translator — not a type-level ceiling). `InstanceType`→CPU/memory (common types; an unknown type is a caveat, not a guess), `UserData`→cloud-init (`#!` scripts; `#cloud-config` isn't merged — caveat), root `BlockDeviceMapping`→`diskSize`; an **`Encrypted` root**→`spec.rootDisk` (LUKS on `longhorn-encrypted`, keyed like an encrypted data disk — `KmsKeyId` `!Ref`s an in-stack `AWS::KMS::Key`, or omit it for the stack's default key; the OS image is copied onto it before first boot, so the instance starts a few minutes later, and it is RWO). `SubnetId`→places the VM in a `kind: Subnet` (real OVN isolation; a raw `subnet-` id refuses). `SecurityGroupIds` / the primary `NetworkInterfaces[0]` attach `kind: SecurityGroup`s via `spec.securityGroups` and set the subnet; `AssociatePublicIpAddress`→`spec.expose` (a raw `sg-` id refuses). An interface wrapped in `Fn::If` is the one its condition picks (its `GroupSet` attaches); one attached by `NetworkInterfaceId` (its groups are not in the template), or with a property the translator does not read, refuses — never a VM without the security groups the template gave it. **Extra EBS `BlockDeviceMappings`→`spec.dataDisks`** (blank persistent virtio disks attached in order; udev rules keyed by each disk's serial **alias the AWS names** onto them — the Nitro names `/dev/nvme0n1` (root), `/dev/nvme1n1`, … (data disks in mapping order, then attached volumes) and each mapping's `DeviceName` with its sd/xvd twin (`/dev/sdf` and `/dev/xvdf`), partitions included — so a lift-and-shift UserData script that formats/mounts `/dev/nvme1n1` or `/dev/sdf` runs **unmodified**; the kernel names stay `/dev/vd*`; an **`Encrypted` device maps to a LUKS data disk** (`longhorn-encrypted`) keyed by a customer `kind: EncryptionKey` — `KmsKeyId` must `!Ref` an in-stack `AWS::KMS::Key` — which is **RWO**, so it pins a `highAvailability` VM's live migration; `Encrypted` without a mappable key refuses). A data mapping with **`DeleteOnTermination: false`** is a `kind: Volume` of its own, attached through `spec.volumes` (by its `DeviceName`, after the instance's other data disks) and kept, as AWS keeps the volume, by everything that removes the instance — a stack delete, a rolled-back create, an update that removes it — then no longer part of the stack (with the stack's default key, when that encrypts it); an instance a stack already created with the mapping as a data disk keeps that disk. **`IamInstanceProfile`→`spec.instanceRole`**: resolved through its in-stack `AWS::IAM::InstanceProfile` to the `AWS::IAM::Role`, binding the VM to that `kind: Role` (the Linux guest gets its rotating credentials from EC2 instance metadata at `169.254.169.254`). As on AWS, the deployer needs `iam:PassRole` on that Role (admins hold it; [iam.md](iam.md#passing-a-role-iampassrole)). **`MetadataOptions`→`spec.metadataOptions`** (`HttpTokens`, `HttpPutResponseHopLimit`, `HttpEndpoint` map 1:1; `HttpProtocolIpv6` / `InstanceMetadataTags` enabled are caveats — the IPv6 endpoint and instance tags are not served). **`KeyName`→`spec.sshKey`**: the public key of a key pair the account holds (`aws ec2 import-key-pair` or `create-key-pair`, on the aws-shim's EC2 front door), authorized for the image's login user on first boot; a `KeyName` the account does not hold refuses (`InvalidKeyPair.NotFound`). **`Ref` / `InstanceId`** are the `i-` id the guest's instance metadata reports (the VM's `status.instanceId`), the id the EC2 and SSM APIs take. `Tags`, the `InstanceType` and the `KeyName` are kept as the VM's AWS view, which the EC2 API reports (`describe-instances`, `tag:` filters, Run Command targets). Caveats: AZ, and the dropped EBS perf knobs (`VolumeType`/`Iops`/`Throughput`). |
| `AWS::EC2::EIP` (+ `AWS::EC2::EIPAssociation`) on an in-stack instance | `kind: VirtualMachine` `spec.expose` + `spec.ports` | **Folded onto the associated VM's LAN IP** — the open-infra analog of a static address on a single-gateway site. An EIP associated with an in-stack `AWS::EC2::Instance` (its own `InstanceId`, or an `EIPAssociation` with `InstanceId` + `AllocationId: !GetAtt <EIP>.AllocationId` / `EIP: !Ref <EIP>`) sets the instance's `spec.expose` (a MetalLB LoadBalancer IP carrying SSH 22 / RDP 3389) and **derives `spec.ports` from the instance's in-stack SecurityGroups** — an AWS EIP reaches every port its security groups admit: each TCP/UDP ingress rule with a `CidrIp` source publishes its port (a range of up to 16 ports expands; the access port is not duplicated). Not published, each with a caveat: all-ports rules, wider ranges, `IpProtocol: -1`, portless protocols, rules sourced from another SecurityGroup (in-cluster peers, not LAN clients), and groups outside the stack. The EIP and the association provision nothing standalone. Caveats on the VM: the address is a **LAN IP, not a public internet IP**; it is stable for the life of the VM but held by its LoadBalancer Service, so a replaced VM may draw a different IP (an AWS allocation outlives its instance); `Ref` / `Fn::GetAtt <EIP>.PublicIp` are assigned at apply. **Embedding the address** (an instance's `UserData` that `Fn::Sub`s in `${Eip}`, the usual AWS shape: an EIP with no `InstanceId` plus an `EIPAssociation`): through the aws-shim's front door the EIP is then an allocation of its own, created before the resources that embed it, and the stack's create waits for its address before translating them, so the `UserData` carries the address itself, as on AWS; the instance's VM shares that address (`spec.elasticIp`) and the stack releases it on delete. An update can embed the address of an allocation the stack already holds; one that adds the EIP and embeds it in the same update is refused (add it first). Without allocations (the `cfn` CLI) such a `UserData` is not applied (a caveat), as any unresolved reference. A stack **Output** reading them returns the VM's LAN IP (`status.lanIp`; see [Stack outputs](#stack-outputs)); `Fn::GetAtt <EIP>.AllocationId` resolves everywhere to a stable synthetic `eipalloc-` id. `Tags`/`NetworkBorderGroup` and an association's `PrivateIpAddress` are dropped (caveats). **An address kept in its own stack**: through the aws-shim's front door, an EIP associated with nothing in its stack is an allocation of its own — a LAN address the shim holds for that stack (a MetalLB address on a holder Service named by the `AllocationId`). Another stack associates it with its instance by passing that `AllocationId` (a parameter, or `Fn::ImportValue` of an export) to an `AWS::EC2::EIPAssociation`: the instance's VM gets that address (`spec.elasticIp`), so it follows the instance across re-creates and stays with the allocation when the app stack is deleted. As on AWS, the caller needs `ec2:AssociateAddress` on it, an allocation already associated with another instance is refused (`Resource.AlreadyAssociated`), and deleting the allocation's stack while the address is associated fails (`DELETE_FAILED`, `InvalidIPAddress.InUse`) until the app stack lets go. The fixture's `eip.yaml` is this shape. **Refused**: an EIP associated with nothing in the stack where no allocations are kept (the `cfn` CLI), an out-of-stack `InstanceId`, an `AllocationId` that is not one open-infra holds (an AWS account's), an address-form `EIP` from another stack (associate it by `AllocationId`), an association by `NetworkInterfaceId` (no standalone ENI is modeled — associate by `InstanceId`), an association naming its address by both `AllocationId` and `EIP`, more than one EIP on one instance or one EIP on two (a VM has one LAN IP), a specific/BYOIP address (`Address`, `PublicIpv4Pool`, `IpamPoolId`, `TransferAddress`), and an EIP used as a NAT gateway's `AllocationId` (see the ceilings table). A published instance that names **no SecurityGroup** gets the stack's default `kind: SecurityGroup` (`<stack>-vpc-default`) — as a VPC's default group, it admits inbound only from its own members, so nothing on the LAN reaches the address, and all outbound. |
| `AWS::EC2::InternetGateway`, `AWS::EC2::VPCGatewayAttachment`, `AWS::EC2::SubnetRouteTableAssociation`, `AWS::EC2::RouteTable`, `AWS::EC2::Route` | *(implicit)* | **Structural no-ops** that provision nothing on their own, so a template carrying them is not blocked. On open-infra the border device is a `kind: NatGateway` (which plays the Internet-Gateway role on a flat /24); route tables are a pure container (routes are VPC-scoped on `kind: Vpc` `spec.routes`, not a standalone table). Only the **default route** `0.0.0.0/0` (or `::/0`) → an in-stack `InternetGateway` is accepted as implicit; **any other `Route`** — a non-default CIDR, or a target that isn't an in-stack InternetGateway (NatGateway/peering/instance/raw id) — **refuses fail-closed** (its next-hop IP isn't template-derivable), so author it on `kind: Vpc` `spec.routes` (`cidr` → the NatGateway `internalIp`). Each no-op is still closed-world (a `VpnGatewayId` attachment refuses). An `AWS::EC2::SubnetNetworkAclAssociation` **refuses**: `AWS::EC2::NetworkAcl` does not translate, so the ACL it names cannot be in the stack, and dropping the association would leave the subnet without its rules — author them on `kind: Subnet` `spec.acls`. The gateway, route table, route and association read back through `describe-internet-gateways` and `describe-route-tables` by their `Ref`s (the ids `DescribeStackResources` lists), while their VPC exists; `describe-network-acls` reads each VPC's default network ACL and each subnet's `spec.acls`. |

### Ceilings — map at plan, refuse at deploy *by design*

These types have a backing kind (so `cfn plan` maps them) but **cannot be created faithfully**, and
refuse at deploy rather than invent data or silently drop a guarantee. This is a deliberate ceiling,
not unfinished work:

| CloudFormation | Why it can't be created faithfully |
|---|---|
| `AWS::IAM::Role` (non-EC2 trust), `AWS::IAM::Group` | The **EC2 instance-trust** Role case is create-deployable (see the create-translators table: `ec2.amazonaws.com`→`spec.trust: [vm]`). What has **no create translator** is a Role trusting anything **else** — an account/ARN, a SAML/OIDC federated principal, a mix — whose trust has no template-derivable open-infra form, and the `Group` resource itself (a `Group`'s control-plane grant can't be derived from its attached AWS policies). Those map at plan (`[gate]`) and are authored natively. For **any** Role, its permission policies are imported separately as `kind: Policy` `spec.dataPlane` and listed in `spec.policies` — a Role resource carries only trust here. (A bare `IAM::User` identity maps; permissions attach via a Group's ClusterRole or a data-plane `IAM::Policy`.) |
| `AWS::EC2::NatGateway` (and an `AWS::EC2::EIP` used as its `AllocationId`) | `kind: NatGateway` (with its `kind: ElasticIp`) needs a VPC binding and an `internalIp` that AWS auto-assigns and the template never carries — inventing one would fabricate the route anchor. An EIP that is a NAT gateway's address refuses for the same reason (it is the border device's address, not an instance's). Author `kind: NatGateway` + `kind: ElasticIp` (naming its `natGateway` + `target`) natively. An EIP on an **instance** is create-deployable — it folds onto the VM's LAN IP (see the create-translators table), as does an instance's `AssociatePublicIpAddress`→`spec.expose`. |
| `AWS::Lambda::Version`, `AWS::Lambda::Alias` | A published **Version** is a **Knative revision** — auto-created on each deploy of a `kind: Function`, with its name assigned *at apply*, so there is no translate-time revision to pin. An **Alias** is a weighted Knative **traffic tag** on a `kind: Function` (`spec.aliases`: `name`+`revision`+`weight`; the aws-shim `Invoke` doorway routes a `Qualifier` to the `<alias>-<function>` tag, #257) — but an AWS alias points at a published numbered Version (which has no translate-time analog) and its `RoutingConfig` weights two such versions, so the alias→revision binding isn't template-derivable. Both map at plan (`[gate]`) and refuse at deploy; **declare rollout/canary traffic natively via `kind: Function` `spec.aliases`** (render-tested), and shift it by updating the Function. |
| `AWS::EFS::FileSystem` | EFS is elastic (no provisioned size); `kind: FileShare` requires a `size`. There is no size to map from, and inventing one is a guess. |
| `AWS::S3::Bucket` `CorsConfiguration` | MinIO does **not** support per-bucket CORS via the S3 API — `PutBucketCors` (and `mc cors set`) returns `MalformedXML` on this release. MinIO configures CORS **globally** via the `MINIO_API_CORS_ALLOW_ORIGIN` env, not per bucket. The property refuses loudly (rather than silently dropping a rule the author expects to enforce); set CORS at the MinIO deployment instead. (The bucket's other properties still map — only `CorsConfiguration` refuses.) |

## Updating a stack

`cfn changeset` shows what an update would do, without touching anything:

```console
$ cfn changeset -namespace my-app -stack-name tickets kms-stack-v2.yaml
Change set for "tickets":
  ~ Modify   PrimaryKey   EncryptionKey/primarykey
  + Add      ArchiveKey   EncryptionKey/archivekey
  - Remove   BackupKey    EncryptionKey/backupkey
```

The diff is between the new template and the specs recorded when the stack was last
applied — the CloudFormation model (diff against the current stack), not against live
cluster drift (that is `cfn drift`, below). `cfn update` then applies it: Adds and
Modifies in dependency order (each readiness-gated; an added resource's wait runs alongside what
does not depend on it, as on create), then Removes in reverse dependency order. A change to only a resource's `DeletionPolicy` or `DeletionProtection` is a Modify too
(the object is unchanged; the record takes the new deletion behavior), so protection can be turned
off and a resource retained before it is removed from the template, as on AWS. An object a removed
resource shares with one that stays (the stack's default `EncryptionKey`) is kept.

Update is fail-closed and rolls back to the **exact** prior stack. If any step fails,
everything the update added is deleted and every resource the prior stack had is
re-applied — restoring modified specs and re-creating removed ones — so a failed update
leaves the stack exactly as it was, with no orphans and no half-applied change. The stack
ends `UPDATE_COMPLETE` or `UPDATE_ROLLBACK_COMPLETE`.

## Tearing down a stack

```console
$ cfn destroy -namespace my-app -stack-name tickets
Destroying stack "tickets" in namespace "my-app"…

Stack "tickets" is DELETE_COMPLETE.
```

`destroy` deletes the stack's resources in reverse dependency order (the reverse of how
they were created), waits for each to actually be gone, then removes the stack record. It
honors CloudFormation's `DeletionPolicy`:

- **`Delete`** (the default) — the resource is deleted.
- **`Retain`** — the resource is left in the cluster and reported as now unmanaged; the
  stack record is still removed.
- **`RetainExceptOnCreate`** — kept like `Retain` by a stack delete and by an update that removes
  it, but deleted when the operation that created it rolls back.
- **`Snapshot`** — refused. open-infra has no generic pre-delete snapshot for an arbitrary
  kind, and deleting a resource that asked to be snapshotted first would be silent data
  loss, so `destroy` fails loud and deletes nothing rather than honor it dishonestly.

An RDS instance with `DeletionProtection: true` is protected as on AWS: `destroy`, and an update that
would remove it, are refused until an update turns the protection off.

An S3 bucket is deleted as AWS deletes one. Through the aws-shim front door, a stack delete stops at a
bucket that still holds objects, prior versions or delete markers: the stack goes `DELETE_FAILED` with
`BucketNotEmpty`, and the bucket and its data stay. Empty the bucket (every version, for a versioned
one), or give it `DeletionPolicy: Retain`, and delete the stack again. An empty bucket is removed with
its claim, so `HeadBucket` answers 404 once the stack is gone. An update that drops a bucket deletes it
when empty and otherwise leaves it in place, outside the stack, as AWS's update cleanup does. The `cfn`
CLI deletes the claim and leaves the bucket to the bucket reaper, which removes it only when empty.

Deletes are not reversible, so `destroy` does not roll back: if a delete fails, the stack
is left `DELETE_FAILED` with the resources that remain, and it stops.

## Detecting drift

`cfn drift` compares the recorded stack against what is actually running and reports any
resource that changed or was deleted out of band:

```console
$ cfn drift -namespace my-app -stack-name tickets
Stack "tickets" has DRIFTED from the cluster:
  ~ PrimaryKey   EncryptionKey/primarykey changed on the cluster: description
  - BackupKey    EncryptionKey/backupkey deleted out of band
  = ArchiveKey   EncryptionKey/archivekey in sync

Drift is reported, not reconciled — resolve it by updating the stack or the cluster deliberately.
```

It compares only the fields the stack **declares** — a default the CRD or composition
filled in that the stack never set is not drift, so it does not drown real drift in noise.
Drift is **surfaced, never reconciled**: a stack record that says one thing while the
cluster runs another is exactly the disagreement open-infra exists to catch, so `cfn drift`
names it and stops. It exits 0 when in sync and 1 when drift is found, so it drops into a
check. It is read-only.

## What this does not do yet

- The stateful lifecycle is complete — `plan`, `deploy`, `changeset`, `update`, `destroy`,
  and `drift`. What bounds the engine now is **coverage, not lifecycle**:
  - `PROVISIONABLE` at plan time means the template maps cleanly onto kinds — not that
    every property will translate at create time (see *Create fidelity* above), and not a
    guarantee of a running stack. Treat plan as a compatibility check.
  - The set of types with a create translator is small and grows deliberately: a type is
    added only once it has a backing kind and a faithful mapping. Change sets, nested
    stacks, and cross-stack references beyond the committed tables are out of scope.
- The mapping and translator tables are the honest surface of what the engine covers — the
  claim is exactly those tables, not full CloudFormation compatibility.
