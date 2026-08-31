# CloudFormation templates — `cfn plan`

open-infra can read an AWS CloudFormation template and tell you, resource by resource,
whether it can provision it on open-infra — and exactly what it cannot. This is the
`cfn` engine.

Today the engine is **read-only**: `cfn plan` is a dry-run. It parses a template,
maps every resource onto an open-infra kind, resolves the intrinsic functions and the
dependency order, and prints a verdict. It does **not** yet create, update, or delete a
real stack — stateful deployment is a later phase, deliberately gated behind this
dry-run so the mapping is trustworthy before anything is provisioned.

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
function (e.g. `Fn::ImportValue`), a macro/SAM `Transform`, a required parameter with
no value, a reference to something that does not exist, or a dependency cycle.

## Usage

```console
$ cfn plan -param Stage=dev webapp.yaml
Verdict: PROVISIONABLE_WITH_CAVEATS

Resources:
  [part] Assets      AWS::S3::Bucket                   -> Application(storage.buckets)
      caveat: no standalone bucket kind — a bucket is provisioned via an Application's storage.buckets (MinIO)
  [ok  ] Api         AWS::Lambda::Function             -> Function
  [ok  ] Workflow    AWS::StepFunctions::StateMachine  -> StateMachine
  [part] ProdAlarms  AWS::SNS::Topic                   -> Application(queues)  [skipped: condition IsProd is false]
  [ok  ] AppKey      AWS::KMS::Key                     -> EncryptionKey
  [ok  ] AppRole     AWS::IAM::Role                    -> Role

Provisioning order:
  AppKey -> Assets -> AppRole -> Api -> Workflow

Provisionable, but review the caveats above — some mappings are lossy.
```

Templates may be JSON or YAML, and the YAML short forms (`!Ref`, `!GetAtt`, `!Sub`,
`!Join`, `!If`, …) are understood. Parameters are supplied with `-param NAME=VALUE`
(repeatable); `-stack-name` seeds `AWS::StackName`; `-json` emits the plan as JSON for
tooling.

## What maps to what

The mapping table below is the engine's contract. A resource type is only listed once
it has a backing open-infra kind and a faithful (or explicitly lossy) mapping. Anything
not in the table is **unsupported by default** — the engine does not guess.

### Supported — a faithful backing kind

| CloudFormation | open-infra |
|---|---|
| `AWS::Lambda::Function` | `kind: Function` |
| `AWS::StepFunctions::StateMachine` | `kind: StateMachine` |
| `AWS::AppSync::GraphQLApi` | `kind: GraphQLApi` |
| `AWS::IAM::Role` | `kind: Role` |
| `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy` | `kind: Policy` |
| `AWS::IAM::User` | `kind: User` |
| `AWS::IAM::Group` | `kind: Group` |
| `AWS::KMS::Key` | `kind: EncryptionKey` |

### Partial — a backing kind exists, but the mapping is lossy

These provision, but not every property translates, or the resource is provisioned as
part of another kind rather than on its own. The caveat is always printed.

| CloudFormation | open-infra | Caveat |
|---|---|---|
| `AWS::S3::Bucket` | an `Application`'s `storage.buckets` | no standalone bucket kind (MinIO-backed) |
| `AWS::SQS::Queue`, `AWS::SNS::Topic` | an `Application`'s `queues` | mapped to NATS JetStream |
| `AWS::RDS::DBInstance` | an `Application`'s `database` | engine/size mapping is lossy |
| `AWS::EC2::Instance` | `kind: VirtualMachine` | AMI/instance-type → os/cpu/memory is lossy |
| `AWS::EC2::Volume` | `kind: Volume` | Longhorn block volume |
| `AWS::EFS::FileSystem` | `kind: FileShare` | SMB share on Longhorn |
| `AWS::AppSync::DataSource` / `Resolver` / `FunctionConfiguration` / `GraphQLSchema` | part of `kind: GraphQLApi` | sub-parts of one API's spec, not standalone resources |

### Gated and unsupported

`AWS::DynamoDB::Table` is **gated** — it is refused today, pending a decision on a
wide-column/key-value data layer. `AWS::Cognito::*` (open-infra consumes OIDC/JWT
identity rather than hosting a user pool), `AWS::CloudFormation::Stack` (nested stacks),
`AWS::CloudFormation::CustomResource`, `AWS::ECS::*`, and every `Custom::*` type are
**unsupported** for now. All of these produce a `REJECTED` verdict with the reason
stated.

## Intrinsic functions

Resolved: `Ref`, `Fn::GetAtt`, `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::Split`,
`Fn::FindInMap`, `Fn::Base64`, and the condition functions `Fn::If` / `Fn::Equals` /
`Fn::And` / `Fn::Or` / `Fn::Not`, plus the `AWS::*` pseudo-parameters. `Conditions` are
evaluated, so a resource gated on a false condition is reported as skipped and left out
of the provisioning order.

Refused (each records a blocker): `Fn::ImportValue`, `Fn::GetAZs`, `Fn::Cidr`,
`Fn::Transform`, and any other intrinsic the engine does not implement. A template that
relies on one of these is `REJECTED` rather than provisioned with the value quietly
wrong.

## What this does not do yet

- It does not deploy. There is no create/update/delete of a live stack, no change sets,
  no drift detection, no rollback. `cfn plan` reads and reports; it never touches the
  cluster.
- `PROVISIONABLE` means the template maps cleanly onto kinds — not that the mapped stack
  has been provisioned and verified end to end. Treat it as a compatibility check, not a
  guarantee of a running stack.
- The mapping table is the honest surface of what the engine covers. It will grow the
  same way every capability here graduates: a type is added only once it has a backing
  kind and a faithful mapping.
