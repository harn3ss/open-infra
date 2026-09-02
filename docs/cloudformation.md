# CloudFormation templates — `cfn plan`

open-infra can read an AWS CloudFormation template and tell you, resource by resource,
whether it can provision it on open-infra — and exactly what it cannot. It can then
provision the supported ones as a live, tracked stack. This is the `cfn` engine.

For the broader migration picture — CDK, Amplify hosting, and what is deliberately
out of scope — see [`docs/aws-migration.md`](aws-migration.md).

- **`cfn plan`** (read-only) parses a template, maps every resource onto an open-infra
  kind, resolves the intrinsic functions and the dependency order, and prints a verdict.
  It provisions nothing.
- **`cfn deploy`** provisions a stack live: it applies the resources in dependency order,
  records the stack, and rolls back on failure — fail-closed, never a partial stack.
- **`cfn changeset`** (read-only) diffs a template against the current stack — what would
  be Added, Modified, Removed, or left Unchanged.
- **`cfn update`** applies that change set, rolling back to the exact prior stack if any
  step fails.
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

`AWS::DynamoDB::Table` is **gated** — the engine maps to open-infra kinds, and there is
no standalone Dynamo table *kind* to map onto (the aws-shim has a DynamoDB front door,
but that is a runtime API, not a declarative kind). `AWS::Cognito::*` is unsupported
because the engine has no mapping onto `kind: UserPool` yet (open-infra *does* now host a
user pool — see [`docs/auth-migration.md`](auth-migration.md) — the engine just doesn't
target it). `AWS::CloudFormation::Stack` (nested stacks),
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

## Deploying a stack

```console
$ cfn deploy -namespace my-app -stack-name tickets kms-stack.yaml
Deploying stack "tickets" into namespace "my-app"…

Stack tickets [CREATE_COMPLETE]
  PrimaryKey   openinfra.dev/v1/EncryptionKey -> primarykey
  BackupKey    openinfra.dev/v1/EncryptionKey -> backupkey

Stack "tickets" is CREATE_COMPLETE (2 resources).
```

`deploy` is fail-closed by construction:

1. **Plan gate** — it runs the same `plan`. A `REJECTED` template is refused before
   anything is applied.
2. **Translate gate** — every included resource must have a create translator *and* every
   one of its properties must translate. A single property the engine cannot honor refuses
   the whole deploy. Nothing is applied until everything translates — there is no partial
   stack.
3. **Ordered apply** — resources are created in dependency order, each recorded in a
   persisted stack record (a `cfn-stack-<name>` ConfigMap) and labeled with its stack, and
   each waited for until it is ready.
4. **Rollback** — if any create or readiness wait fails, everything created in that deploy
   is deleted in reverse order and the stack is marked `CREATE_FAILED`. A failed create
   leaves no orphans.

A target `-namespace` and a `-stack-name` are required; `deploy` never guesses a
namespace. Use `-no-wait` to skip the readiness gate, `-timeout SECS` to bound it.

### Create fidelity is narrower than the plan mapping

The plan table above answers "is there a backing kind?". Creating a resource asks a
harder question: does every *property* translate faithfully? Often it does not, and where
it does not the engine refuses rather than guess. A resource type that plans as
`supported` is therefore not automatically create-able. Concretely, at create time:

- The set of types with a create translator is a subset of the plan-supported types. A
  supported type without a translator is refused at deploy with "no create translator".
- AWS resource *content* frequently has no faithful open-infra form — IAM's
  `service:Action` permission namespace is a different universe from open-infra's
  `kind:verb` RBAC, KMS key policies have no per-key equivalent, and a `Fn::GetAtt` to
  another resource's ARN has no value here. Each of these blocks the deploy loudly.
- Where a property maps but loses something (a KMS `KeyPolicy`, a Lambda `Role`), the loss
  is printed as a **caveat**, never silently dropped.

Today's create translators (live-verified on the cluster):

| CloudFormation | open-infra | Notes |
|---|---|---|
| `AWS::KMS::Key` | `kind: EncryptionKey` | Description, `EnableKeyRotation`→rotation, `KeySpec`→key type; `KeyPolicy` is a caveat (access is via open-infra IAM). |
| `AWS::Lambda::Function` (`PackageType: Image` only) | `kind: Function` | `Code.ImageUri`→image, `Environment`→env, `MemorySize`→memory, `Timeout`→timeout; a zip/Runtime Lambda has no image and is refused; `Role` is a caveat. |

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
Modifies in dependency order (each readiness-gated), then Removes in reverse dependency
order.

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
- **`Snapshot`** — refused. open-infra has no generic pre-delete snapshot for an arbitrary
  kind, and deleting a resource that asked to be snapshotted first would be silent data
  loss, so `destroy` fails loud and deletes nothing rather than honor it dishonestly.

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
