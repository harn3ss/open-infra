# Changelog

All notable changes to open-infra are recorded here. Versions follow
[semantic versioning](https://semver.org). The `openinfra.dev` resource kinds are
the product's public contract.

## Unreleased

### Fixed — Lambda functions with a role and a stored package run as on Lambda
- **Layers with the function's own identity:** a function with an execution role or a stored deployment
  package gets its layers (`code.layers`) from the aws-shim with its own token, as Lambda fetches a
  function's layers itself.
  - The shim serves a function only the layers it names, and only objects its account may read.
  - Before, layers needed the code in S3 with static keys, so such a function could not render at all.
- **The role's credentials as Lambda hands them over:** before the handler loads, the Node.js, Python and
  .NET runtimes set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` (with
  `AWS_CREDENTIAL_EXPIRATION`), renewed before they expire. Code that reads credentials as it loads now works.
- **An expired session is answered `ExpiredToken`**, as AWS answers it (`ExpiredTokenException` in the JSON
  protocols). An SDK then renews its credentials, so an SDK v2 client made at load re-reads the renewed
  environment.
- **The Lambda API:**
  - `UpdateFunctionCode` replaces a function's code source, so a function whose code came from S3 no longer
    ends up with two;
  - `UpdateFunctionConfiguration --runtime` moves a function off a runtime image of its own;
  - `CreateFunction` no longer publishes the function on the gateway: on Lambda a function is reachable over
    HTTP only through a function URL;
  - `GetFunction` and `GetFunctionConfiguration` report a failed update as `LastUpdateStatus: Failed`, with
    its reason and reason code, while the function stays `Active` on the configuration that still serves.
- A function picks up the new runtimes at its next revision.

### Fixed — a member account's IAM user deploys a stack from its own bucket
- **The cause:** a CloudFormation deploy reads a Lambda function's packaged code (`Code` `S3Bucket`/`S3Key`)
  after the request returns, as the caller. That read lost the caller's account. A member account's IAM
  user was decided there as no principal at all, and its stack failed with S3's AccessDenied on
  `GetObject`, though the same user could download the object with `aws s3 cp`. A nested stack's
  `TemplateURL` was read the same way.
- **Now:** both reads act in the caller's own account, as the S3 API does. The reason for a refused read is
  in the shim's log.

### Security — the console's IAM pages manage the account you are in
- **The flaw:** the console's IAM pages always read and wrote the management account's IAM, whatever account
  the session was in. A session switched into a member account's role was asked for IAM actions on that
  account's resources, which its role's policies may allow, and then acted on the management account's
  instead. It could create management users, mint keys for them, or reset their passwords. The switch into
  another account's role only worked from the Switch role fix below, so this path was open only in between.
- **Now, as in the AWS console:** in a member account's role session the IAM pages manage that account's
  users, groups, roles, policies, access keys, login profiles and MFA devices, in the account's own IAM, and
  nothing of the management account's:
  - its access keys record the account and act in it;
  - its policies page lists its own policies and the AWS-managed ones;
  - a user, group or role can attach only those;
  - a policy is an AWS policy document, as IAM's `CreatePolicy` takes it.

### Fixed — deleting a user deletes its access keys
- The console's Delete user left the user's access keys in the credential store. A user later created with
  the same name could then sign requests with them. As the AWS console does, deleting a user now deletes its
  access keys (and MFA devices) first; if they cannot be removed, the user is not deleted.

### Fixed — the console's Switch role reaches another account's role
- **The cause:** the console's permission check for Switch role never passed the role's trust policy to
  IAM policy evaluation. For another account's role that evaluation needs the role's own policy too, so it
  refused every switch across accounts, whatever the trust said. A management account administrator was
  refused a member account's `OrganizationAccountAccessRole`.
- **Decided as `sts:AssumeRole`, as on AWS and as the CLI's `sts assume-role` already was:**
  - the role's trust policy is evaluated as the role's resource policy;
  - another account's role needs both its trust and the caller's own policy allowing `sts:AssumeRole`;
  - within one account, a trust naming the caller is enough on its own, and only an explicit Deny refuses it.
- **Tightened with it:**
  - in another account's trust, a bare user name is that account's own user, never a caller of the same
    name from another account;
  - the root user cannot switch roles, as on AWS.

### Fixed — nodes pull runtime images from the in-cluster registry again
- **The cause:** a node's pull credential was minted by hand into a Secret. When the ECR token key moved
  into OpenBao, that credential stopped verifying. Every node was then refused at the token endpoint (401),
  and a function on a `code.runtimeImage` could fail its next cold start on any node without the image.
- **A node's own identity now gets it, as on AWS:**
  - the node agent presents its ServiceAccount token to the shim's `/ecr/node-credential` and gets the node
    puller's pull-only credential;
  - it asks again only when that credential stops verifying or nears its end, on a different day per node.
    So a key rotation mends itself, and a node's runtime restarts only then;
  - only the node agent may have the credential: another ServiceAccount is refused.
- **Registries follow a signing-key change:** when the token certificates change, the shim rolls the
  registries that verify tokens against them, so they trust the new key without a restart by hand.

### Fixed — a cold start no longer counts against a Lambda function's timeout
- **As on Lambda:** a function's `Timeout` counts from when the invoke reaches its runtime, not from when
  the request arrived. Before, a function called from zero spent its own timeout waiting for an instance:
  a 3-second echo called cold failed `Task timed out after 3.00 seconds` before its handler ran.
- **How:**
  - the Node.js, Python and .NET runtimes enforce the function's timeout themselves and answer Lambda's
    timeout error at it, with `Status: timeout` in the log tail;
  - the platform's own deadline is the timeout plus a 90-second start-up allowance. The revision ceiling
    rises to 990 seconds and the gateway's idle timeout to 1050 seconds.
- **Unchanged:** a function on its own image (`spec.image`) is still timed from the request's arrival.
- **A runtime image of your own** (`code.runtimeImage`, built from `lambda-runtime/`) enforces the function's
  timeout once rebuilt from this version. Until then its invocations end at the platform's deadline: the
  timeout plus the allowance.

### Fixed — S3 in a member account
- **A member account's administrator owns its buckets:** `CreateBucket` and `DeleteBucket` are decided by
  IAM (`s3:CreateBucket`, `s3:DeleteBucket`) and the bucket is then made or deleted by the S3 service itself,
  as the Lambda API makes a function. Before, a member account's `AdministratorAccess` user was refused
  `CreateBucket`.
- **A bucket kept by its account is still its own:** a bucket whose claim's setup succeeded is that
  account's, even when the claim is newer than the bucket (an earlier claim made it, or an operator recorded
  it). Before, such a bucket fell to the management account, so its own account's administrator was refused
  `GetObject`, and Lambda `CreateFunction` from it (`S3Bucket`/`S3Key`, the only way to deploy a package over
  50 MB) failed.
- **Proven:** `probe/aws-shim-s3-account.sh`. A member account's administrator makes, writes, reads and
  deletes a bucket and deploys a function from it; the management account and an invoke-only user of the
  account are refused with `AccessDenied`.

### Fixed — EC2 `DescribeSecurityGroups` reports a group as it is enforced
- **Its rules, exactly:** a group that defines a direction answers exactly its rules, and none when it
  has none. Before, a group with no outbound rules was reported with AWS's default allow-all rule, even
  when it allowed nothing: the wrong answer in the unsafe direction.
- **Its VPC:** a group with `vpc` answers its `VpcId`, and the `vpc-id` filter finds it.
- **The rest:** an undefined direction (unrestricted) is one allow-all rule, inbound as well as outbound;
  protocol `ALL` is `-1` with no port range.
- **Proven:** `probe/aws-shim-lambda-vpc.sh` reads the VPC's groups back through `describe-security-groups`.

### Documented — where Lambda finds a member account's functions
- **A member account's functions are its own:** Lambda Invoke (and every path that invokes by name) finds a
  member account's functions in its own namespaces — its home first — whether the Lambda API, a stack or a
  migration tool wrote them, authorized by the caller's `lambda:InvokeFunction` on the function's ARN.
  `docs/aws-shim.md` said only where the management account's are.
- **Proven:** `probe/aws-shim-lambda-account-invoke.sh`. A member account's user allowed two named functions
  invokes both; it is refused a third and `GetFunction` with `AccessDeniedException`; an unsigned or wrongly
  signed Invoke is refused and never runs.

### Added — a Lambda function in a VPC, egress-isolated the AWS way
- **Lambda `VpcConfig`:** `create-function` / `update-function-configuration --vpc-config` and
  CloudFormation's `VpcConfig` put a function in subnets and security groups of one VPC, with Lambda's
  checks:
  - every subnet and group must exist, all in one VPC;
  - at most 16 subnets and 5 groups;
  - an execution role allowed to manage network interfaces.
  The configuration answers `VpcConfig` with its `VpcId`; an empty one takes the function out.
- **Outbound is its security groups':**
  - a group's outbound rules are the function's allow-list;
  - the VPC's resolver and the Lambda service (its package, its role's credentials) are always reachable,
    as on AWS.
  A CloudFormation security group's `VpcId` now maps.
- **DNS that cannot leak a name:**
  - the function's only DNS is the VPC resolver; a DNS packet to any other address is dropped by the network;
  - Route 53 Resolver DNS Firewall (domain lists, rule groups, rules, VPC associations) applies there, and a
    blocked name is answered without being looked up.
- **Recorded:**
  - Route 53 Resolver query logging writes one record per query in AWS's format;
  - EC2 `create-flow-logs` (`TrafficType REJECT`) writes one record per refused flow, per network interface;
  - `describe-network-interfaces` lists the function's Lambda interfaces.
  Both logs go to CloudWatch Logs groups, readable without the function's own logs.
- **On any runtime:** a function on an unsupported runtime image in a VPC is egress-denied except for the
  VPC resolver and the Lambda service, so its security groups alone decide what else it reaches.
- See [docs/lambda-vpc.md](docs/lambda-vpc.md) for exactly what the posture allows, denies and records, and
  where it differs from AWS.

### Added — every Node.js and Python runtime AWS Lambda still creates functions on
- **New runtimes:** `nodejs16.x`, `nodejs18.x`, `python3.8`, `python3.9`, `python3.10`, `python3.11` and
  `python3.14` join the runtimes the Lambda API, CloudFormation and `kind: Function` accept. A stack on
  `nodejs18.x` that real CloudFormation deploys now deploys here too.
- **AWS's dates apply:** each deprecated runtime is refused from AWS's block-create date (2027-07-29) and
  block-update date (2027-08-31), as Lambda refuses it, and the console offers it disabled.
- **The deprecated ones are end of life upstream.** They run as AWS provides a deprecated runtime, as-is,
  with no more interpreter security fixes. Their images' known vulnerabilities show in the image scan.
- **Each has its own image.** `nodejs16.x` uses the AWS SDK v2, as AWS's did. `nodejs18.x` uses SDK v3
  3.967.0, the last release that supports Node.js 18.

### Fixed — a .NET function no longer dies when a probe connects as it starts
- **Before:** `HttpListener.Start` throws an `ArgumentNullException` when a connection is already waiting
  as it first accepts, which is a .NET bug. A readiness probe hitting a starting .NET function could kill
  its runtime.
- **Now:** the runtime starts the listener again. Under a stream of connections during start, 30 of 30
  starts served, after 34 retries.

### Added — Lambda runtimes follow AWS's deprecation dates
- **Each runtime carries AWS's three dates:** deprecation, block create and block update.
  - From deprecation, the console offers it disabled.
  - From block create, the Lambda API and CloudFormation refuse a new function on it, with Lambda's message.
  - From block update, they also refuse a change to one, unless the change moves it to a supported runtime.
- **A function on a deprecated runtime is invoked as before.**
- **Today:** `nodejs20.x` is deprecated, so the console offers it disabled. The API and CloudFormation
  still take it until 2027-07-29 (create) and 2027-08-31 (update), as AWS does. `dotnet8` is deprecated
  from 2026-11-10.

### Fixed — clearing a function's variables, and deleting its last alias, last
- **Before:** `update-function-configuration` with no variables, like deleting a function's last alias or
  version, answered success and the old values came back: Crossplane copies a claim's spec to its composite
  by merging, which cannot remove a field, and then copies it back.
- **Now:** an empty list is written, which both keep.

### Added — `aws lambda invoke --log-type Tail` (#407)
- **A synchronous invoke with `LogType: Tail`** answers the invocation's log in `X-Amz-Log-Result`, which
  the CLI prints as `LogResult`: the last 4 KB of Lambda's `START`, what the handler printed during that
  invocation, `END` and `REPORT` lines.
- **On the Node.js, Python and .NET runtimes** each invocation's output is its own, even when invocations
  run at once. A function on its own image gets the `START`, `END` and `REPORT` lines only.
- **The request ID** of an invoke is now a UUID, as Lambda's is, and the handler's `awsRequestId` is the same.

### Added — the `nodejs24.x` Lambda runtime
- **CloudFormation, the Lambda API and `kind: Function`** (`spec.code.runtime: nodejs24`) accept
  `nodejs24.x`, Node.js 24, the current Node.js LTS and AWS Lambda's newest Node.js runtime.
- **Its image,** `open-infra-lambda-nodejs24`, is built, signed and scanned like the others, with the same
  pinned AWS SDK v3 clients.
- **`nodejs20.x` is still accepted** for new functions. Node.js 20 reached its upstream end of life on
  2026-04-30, so when to stop accepting it is an operator decision; existing functions keep running either
  way.

### Fixed — a Lambda handler's context carries what Lambda's does (#406)
- **Before:** the invoked function ARN was always empty, the function version was always `$LATEST`, a
  caller's `ClientContext` was dropped, Node.js's `callbackWaitsForEmptyEventLoop` was missing, and
  `AWS_EXECUTION_ENV` lacked Lambda's `.x` for Node.js (`AWS_Lambda_nodejs22`).
- **Now, on the Node.js, Python and .NET runtimes:**
  - the invoked ARN is the one the caller used, with its version or alias qualifier;
  - the version is the one that runs;
  - `ClientContext` reaches the context (`client`, `custom`, `env`);
  - Node.js has `callbackWaitsForEmptyEventLoop` (`true`, Lambda's default);
  - `AWS_EXECUTION_ENV` is `AWS_Lambda_nodejs<N>.x`.
- **Difference:** on Node.js the response is sent as soon as a callback-style handler calls back, as
  Lambda does when `callbackWaitsForEmptyEventLoop` is `false`.

### Fixed — an asynchronous Lambda invoke delivers the payload as sent
- **Before:** an `Event` invocation reached the handler as an API Gateway proxy event, with an added
  `_http` field, and a non-object payload wrapped in `{"body": …}`. A function error counted as delivered.
- **Now:** the handler gets the payload as sent, as Lambda passes it. A function error is a failed attempt:
  it is retried, then dead-lettered.
- **On by default:** the aws-shim now connects to the platform's NATS (the `nats` component, on by default),
  so `Event` invokes and EventBridge's Lambda targets work on a default install. They were refused (503)
  because the shim was never given `NATS_URL`.

### Added — Lambda versions and aliases, as on AWS
- **Operations:** `PublishVersion`, `ListVersionsByFunction`, `CreateAlias`, `GetAlias`, `UpdateAlias`,
  `DeleteAlias` and `ListAliases`; `Publish` on `CreateFunction` and `UpdateFunctionCode`; and
  `DeleteFunction` with a version `Qualifier`. Each is decided as `lambda:<Operation>` on the function.
- **A version** keeps the code and configuration the function had when it was published; changing the
  function changes `$LATEST` only. Publishing during an update answers `ResourceConflictException` until the
  new code runs, as Lambda does.
- **An alias** names `$LATEST` or a version and may send a share of its invocations to one other version.
- **Invoking** `<function>:<version>` or `<function>:<alias>` runs that version, synchronously or as an
  `Event`, and `X-Amz-Executed-Version` names the version that ran. A qualified read answers with the
  version's own configuration.
- **`kind: Function`:** `spec.versions` is new. `spec.aliases` now takes Lambda's shape (`name`,
  `functionVersion`, `additionalVersionWeights`) in place of the earlier weighted traffic tags (`name`,
  `revision`, `weight`); no function on the platform used those. A function without published versions
  renders as before.
- **Not yet:** a CloudFormation stack's `AWS::Lambda::Version` and `AWS::Lambda::Alias` still map at plan
  and are refused at deploy.

### Fixed — `aws cloudformation deploy` of a stack whose resources read a custom resource's Data
- **Before:** the change set behind `aws cloudformation deploy` refused a new stack in which a resource
  reads a custom resource's `Data` (`Fn::GetAtt`). That value is known only once the handler has run, so
  the change set reported it as unresolved.
- **Now:**
  - the change set builds it as `{{changeSet:KNOWN_AFTER_APPLY}}`, as AWS shows such values;
  - it still checks every other property;
  - executing it creates the stack resource by resource, as `create-stack` does.

### Fixed — a CloudFormation security group with no inbound rules denies inbound, as on AWS (#374)
- **Before:** an `AWS::EC2::SecurityGroup` with no `SecurityGroupIngress` was translated with no ingress
  at all, so its members, VMs included, were left open inbound.
- **Now:**
  - **Inbound:** such a group defines an empty ingress and denies all inbound.
  - **Protocols:** `IpProtocol` takes `-1` (every protocol, so AWS's default egress rule deploys) and the
    numbers `6` and `17`. An ICMP rule is left out with a caveat (stricter than AWS) rather than refusing
    the whole group.
  - **`kind: SecurityGroup`:** gains protocol `ALL`, for every protocol on every port.
  - **A port-less rule keeps its protocol.** A rule with no ports means every port of its protocol, as an
    AWS rule does: `tcp 0-65535` is TCP only. It used to render as every protocol, so a "TCP, all ports"
    rule also let UDP and ICMP through. None of the six live groups with such a rule has members, so no
    running workload is affected.

### Fixed — RDS ModifyDBInstance applies what it accepts (#377)
- **Before:** `ModifyDBInstance` returned success for a class, storage, password or version change and
  applied none of them. A password rotation looked done while the old password kept working.
- **Now it applies:**
  - `DBInstanceClass` → new pod resources;
  - `AllocatedStorage` → grows the volume;
  - `MasterUserPassword` → the old password stops working;
  - `DeletionProtection`.
- **It refuses every other parameter**, an engine-version upgrade and a storage decrease, rather than
  accepting them.
- **`RebootDBInstance`** restarts an instance.
- **`EngineVersion`** is now the exact PostgreSQL image that runs (17.4), reported by
  `DescribeDBInstances`, which said "16" before. A version, port, backup retention or managed master
  password it does not provide is refused at create.

### Fixed — an RDS final snapshot restores after its instance is gone (#390)
- **Before:** the RDS front door's final snapshot could not be restored, so deleting an instance with one
  could lose its data:
  - the snapshot was an in-volume Longhorn snapshot, which dies with the volume;
  - the instance was deleted without waiting for the snapshot;
  - restore refused once the source instance was gone.
- **Now:**
  - **Snapshots are Longhorn backups**, which outlive the volume. They are owned by their snapshot, so
    `DeleteDBSnapshot` removes them.
  - **A delete with a final snapshot** answers `deleting` and removes the instance only once the snapshot
    has completed. If the snapshot fails, the instance is kept.
  - **A snapshot records its instance's settings** and keeps a copy of its master credential, so
    `RestoreDBInstanceFromDBSnapshot` needs no source instance.
  - A duplicate snapshot identifier is refused with `DBSnapshotAlreadyExists`.
  - `DescribeDBSnapshots` reports the snapshot's engine, storage and master username.

### Added — `iam:PassedToService`, so AWS's service FullAccess policies pass roles to their own service (#403)
- **A PassRole limited to a service passes roles to that service alone, as on AWS.** For example,
  `AWSLambda_FullAccess` passes roles to `lambda.amazonaws.com` only.
  - **Before:** such a statement was dropped. Its holder needed a hand-written PassRole policy to give a
    function an execution role.
  - **Now:** it works from the Lambda API, CloudFormation and the console. The same holder still cannot
    give a role to a VM.
  - **Each pass names its service:** a function → `lambda.amazonaws.com`, an application →
    `ecs-tasks.amazonaws.com`, a VM → `ec2.amazonaws.com`, a state machine → `states.amazonaws.com`.
  - The IAM compiler compiles such a grant into the service's own verb, `passrole:<service>`, which that
    service's pass-role admission check accepts beside `passrole`.
- **`iam:AWSServiceName` is recorded as not applicable:** no front door serves `CreateServiceLinkedRole`.

### Fixed — an Allow that needs MFA no longer reaches the control plane without it
- The IAM compiler now treats an MFA condition as a condition: such an Allow is dropped from the compiled
  control-plane grants, and such a Deny applies always.
  - **Before:** it compiled an Allow conditioned on `aws:MultiFactorAuthPresent` into an unconditional
    grant, so a CloudFormation stack or console write made as the caller could act without MFA.
  - No policy in use carried such a condition.

### Added — custom resources respond to their ResponseURL, and inline handlers get cfn-response (#404)
- **A Lambda-backed custom resource's event carries a `ResponseURL`, as on AWS,** and the deploy takes
  the response the handler PUTs there. The URL is a one-time URL on the aws-shim.
  - **Inline code that loads `cfn-response` (Node.js) or `cfnresponse` (Python)** gets open-infra's module
    beside it, as AWS provides its own for `Code.ZipFile`. A custom-resource handler copied from the AWS
    docs deploys unchanged; its `Data` resolves `Fn::GetAtt`, and a `FAILED` response rolls the stack
    back. Such code used to be refused.
  - A handler that returns its response still works.
  - **Node.js runtime:** handlers get Lambda's `context.done`, `context.succeed`, `context.fail` and
    `logStreamName`; `/var/task` is on `NODE_PATH`, as on Lambda. The Python context gains
    `log_stream_name`.
  - **Invocation:** custom resources are now invoked as Lambda's `Invoke`, so a handler's error is
    reported as the function's error.

### Added — the Lambda API creates and changes functions (#364)
- **`CreateFunction`, `UpdateFunctionCode`, `UpdateFunctionConfiguration` and `DeleteFunction` work
  through the aws-shim**, so `aws lambda create-function` and the SDKs' deploy calls run as on AWS.
  - **Authorization:** each is `lambda:<Operation>` on the function's ARN.
  - **The execution role** must be your account's, one you may pass (`iam:PassRole`) and one Lambda can
    assume (it trusts `lambda.amazonaws.com`), with AWS's errors when it is not.
  - **The code:** a .zip (`--zip-file`) or an S3 object, read with your permissions and stored as Lambda
    stores it; or an image.
  - **Refused, naming the parameter:** layers, VPC configuration, published versions and tags, which a
    function here does not have.
  - **Answers** report `CodeSha256`, `CodeSize`, `Description` and `RevisionId`, as AWS's do.
  - [`docs/serverless.md`](docs/serverless.md#creating-and-changing-functions-with-the-lambda-api).

### Fixed — a Lambda invoke runs to the function's own Timeout (#372)
- **The fixed 60-second cut is gone.** The aws-shim used to cut every invoke, synchronous or asynchronous,
  at 60 s. A longer-running function answered `ResourceNotFoundException` ("could not be reached"), and an
  asynchronous one could run again.
  - **Now:** an invoke waits for the function's `timeout` (up to 900 s; Knative's 300 s when unset), plus a
    cold-start allowance.
  - **Past the timeout:** it ends as Lambda ends it: a function error with `Sandbox.Timedout` "Task timed
    out after N.NN seconds". Knative's 504 at the revision timeout reads the same way.
  - **Async deliveries** are kept in progress while the function runs, so one is never redelivered mid-run.
  - **Tested:** `probe/aws-shim-lambda-timeout.sh`.

### Added — CloudFormation deploys .zip Lambdas (#402)
- **A Lambda with a .zip package, the default `PackageType`, deploys from CloudFormation** onto `kind:
  Function` `spec.code`, as AWS runs it.
  - **`Runtime`:** `nodejs20.x`, `nodejs22.x`, `python3.12`, `python3.13` or `dotnet8`. Any other runtime
    is refused, with that list.
  - **`Handler`**, plus the package given one of two ways:
    - `Code.ZipFile`: inline code, written to `index.js` (CommonJS) or `index.py`, as CloudFormation does;
    - `Code.S3Bucket`/`S3Key` (+ `S3ObjectVersion`): what `aws cloudformation package`, SAM after its
      transform, and CDK produce.
  - A template copied from the AWS docs, or synthesized by CDK, now deploys as written.
  - [`docs/cloudformation.md`](docs/cloudformation.md#lambda-zip-functions).
- **Packages are stored as Lambda stores them.** An S3 package is read at deploy with the deploying caller's
  `s3:GetObject`, and a refusal is Lambda's AccessDenied.
  - **Where it's kept:** a platform bucket that no account reaches through the S3 API, named on the
    Function by its SHA-256 (`spec.code.source.package`).
  - **How the function gets it:** the function's pods fetch it from the aws-shim at cold start with their
    own identity and get only their own function's package. No keys, so it combines with an execution role.
  - **Updates:** a stack update re-reads an S3 object only when its location changes, as CloudFormation
    does.
- **Refused:** `Layers`, inline code that loads `cfn-response` (a custom-resource handler returns its
  response here), `ZipFile` for a non-Node.js/Python runtime, and an inline handler not named `index.<name>`.
  - **The `cfn deploy` CLI** deploys inline code as a ConfigMap and refuses an S3 package, pointing to the
    front door.
- **Proven live:** `probe/aws-shim-cfn-lambda-zip.sh` passes. Inline Node.js code and an
  `aws cloudformation package` Python package deploy and answer `aws lambda invoke`; `nodejs18.x` is
  refused, naming the supported runtimes; and a deployer that may not read the package gets Lambda's
  AccessDenied.

### Changed — the platform's keys live in OpenBao (#359)
- **Every client of the key service uses OpenBao.** KMS, Secrets Manager, Parameter Store secure values,
  `kind: EncryptionKey`, encrypted volumes, the private CAs, KES and the STS sealing key reach OpenBao's
  active member over TLS 1.3, trusting the platform CA, which OpenBao's publisher copies into their
  namespaces (ConfigMap `openbao-ca`, named by `VAULT_CACERT`); OpenBao admits only them. The `encryption`
  component now needs `components.openbao`, and `install.sh` warns when it is missing.
- **Moving an install's keys from Vault.** [`scripts/vault-to-openbao.sh`](scripts/vault-to-openbao.sh)
  copies Vault's storage into OpenBao, so every key, version and ciphertext stays as it was. The keys are
  unavailable for a few minutes, from sealing Vault until the clients switch; Vault keeps a sealed copy as
  the rollback. The move checks every key version before and after, gives the operator new recovery keys
  that only they hold, and leaves OpenBao with no root token.
- **The platform's CAs sign through OpenBao, and their roots go offline.** This applies with
  `openbao.platformCAs: true`.
  - **Issuers.** `openinfra-ca`, `openinfra-aws-endpoints` and `openinfra-acm` keep their names. They sign
    through intermediates whose keys OpenBao generated and never exports, or, for the validated-domain CA,
    through the same CA, imported.
  - **Roots and clients.** Every certificate chains to the same roots as before, so clients trust nothing
    new.
  - **Taking the roots offline.** [`scripts/openbao-offline-roots.sh`](scripts/openbao-offline-roots.sh)
    moves the root keys into a file encrypted with the operator's passphrase and checks the file against the
    cluster before deleting the keys. It also restores them for the one ceremony that needs them: a new
    intermediate (`scripts/openbao-pki.sh rotate`, with no client impact).
  - **Checking it.** `probe/platform-root-ca.sh` checks either shape ([`docs/openbao.md`](docs/openbao.md),
    "The platform's CAs").

- **The aws-shim's signing keys are in OpenBao.** With `components.openbao`, three Transit keys under
  `openinfra/transit` sign what the shim issues: `instance-identity` (EC2 instance identity documents),
  `cognito` (user pools' tokens) and `ecr-token` (ECR credentials and registry tokens). Each is RSA-2048,
  never exportable, and created by the setup Job.
  - **The shim's access.** It signs through role `aws-shim-identity`, which may only sign with these keys and
    read their public halves.
  - **Certificates and JWKS.** Each version's certificate is made from the version itself, so every replica
    serves the same one, and the Cognito JWKS uses RFC 7638 thumbprints as kids.
  - **Rotation.** Rotation is the key's own: a replaced version verifies for as long as what it signed is
    relied on (1 hour, 30 days, 12 hours).
  - **The old keys.** The keys kept in Secrets before are retired by the shim: their public halves go into
    ConfigMaps, and the Secrets are deleted ten minutes later. Earlier tokens keep working; nobody signs in
    again.
  - **Failure.** If OpenBao cannot be reached, nothing is signed, and the shim never falls back to a key in a
    Secret.
  - **Fix: the shim without OpenBao.** The aws-shim now starts without OpenBao: its OpenBao CA mount is
    optional.

### Added — OpenBao, the platform's key and secrets service, ready to turn on (#359)
- **Three members, unsealed from outside the cluster.** `components.openbao` runs OpenBao 2.7 as three
  members sharing integrated Raft storage, each on a different physical machine the operator names
  (`openbao.nodes`) and on a solid-state disk. An OpenBao on a machine outside the cluster unseals them
  when they start (a transit seal); [`scripts/openbao-unseal-host.ps1`](scripts/openbao-unseal-host.ps1)
  sets one up on a Windows PC and operates it (unseal, status, a new cluster token, certificate renewal,
  backup and restore). A member that starts while that host is down stays sealed until it answers: there
  is no static key, dev mode or unsealed fallback.
- **Its site values stay out of git.** `install.sh` records the unseal host's address and CA, accepting
  the CA only when its SHA-256 fingerprint is `openbao.unsealHost.caFingerprint`, and labels the member
  nodes. The cluster's token for the unseal host is a Secret the operator creates from the host's output.
- **TLS 1.3, members only, audited.** The API serves TLS 1.3 with a certificate from the platform CA,
  renewed without a restart; only the members reach one another until a client is admitted; every request
  and response is audited, with sensitive fields HMAC'd, into Loki. `openbao` is a platform namespace: no
  account can make it its home.
- **Rehearsed on a live cluster.** Losing the active member, losing the unseal host, a rolling change and
  a certificate renewal ([`docs/openbao.md`](docs/openbao.md), `probe/openbao-ha.sh`).
### Changed — temporary access and groups are IAM policy alone (#360)
- **A grant attaches IAM policies for its window.** `kind: Grant` names the policies it attaches
  (`spec.policies`: AWS managed policies such as `aws-readonlyaccess` or `aws-poweruseraccess`, or your
  own) to a user or to every member of a group. Once someone other than the requester approves it, the
  subject holds those policies at every door — the AWS APIs, the console and Kubernetes — from the
  approval for its duration (at most 24 hours, refused at admission beyond that), and not a moment
  longer: each request checks the window. The console's **Grants** pages request, approve and revoke
  grants with a policy picker. A grant naming `spec.clusterRole` (the old ClusterRole elevation) is
  refused.
- **A group is only a container of policies.** A `kind: Group` binds nothing in Kubernetes;
  `spec.clusterRole` (the old permission tier) is refused at admission and by the console, with the
  managed policy to attach instead.
- **No hand-written user authority.** No manifest and no composition binds a user or group by hand any
  more (the one exception is the management account's break-glass root); a CI check fails on any
  binding of an `openinfra:*` user or group outside the RBAC the IAM compiler generates.
### Security — tenants get no Kubernetes access, and every customer capability is AWS-shaped
- **The operator surface is the management account's alone.** The platform's own Kubernetes objects
  (`openinfra-operator:*`: Secrets, pods with their logs and exec, ServiceAccount tokens, RBAC, nodes,
  namespaces) are refused to every principal of a member account — its administrators, its roles' sessions
  and its root — whatever its policies, through the console's resource API and watch stream. A member
  account's `AdministratorAccess` used to reach its own namespaces' raw objects. A member account's root
  is its account's root user, never the console's break-glass identity: it no longer reaches requests no
  IAM action maps, nor watches the whole cluster.
- **`AssumeRole` asks the caller's own policy where AWS does.** A role whose trust names only an account
  (`arn:aws:iam::<account>:root`, as OrganizationAccountAccessRole's does) is assumed only by a principal
  whose own policy allows `sts:AssumeRole` on it, and a role in another account only with that permission
  whatever its trust names; an explicit Deny refuses it everywhere. The trust alone used to decide, so
  any user of a trusted account could assume such a role.
- **The customer surface, inventoried.** [`docs/customer-surface.md`](docs/customer-surface.md) lists every
  resource type, property, console route, console screen and AWS API a customer can reach, each AWS-shaped,
  a platform extra, or the operator's alone, generated from the code. CI fails when a capability has no
  AWS-shaped entry, when a console route's action is not one AWS documents, when a gated route does not
  refuse a principal with no policy, when an aws-shim front door has no deny case, and when a proven
  service's probes assert no denial.

### Security — email is sent only as an authenticated, authorized identity (#277)
- **The SES SMTP interface.** The aws-shim serves SMTP submission the way Amazon SES's
  `email-smtp` endpoint does — STARTTLS on 587, TLS Wrapper on 465 — signed in with **SES SMTP
  credentials**: an IAM user's access key id and the SMTP password derived from its secret with AWS's
  algorithm. Every message is `SendRawEmail` as that user, authorized by IAM policy on every address it
  is sent as, with SES's replies (`530`, `535 Authentication Credentials Invalid`, `554 Access denied`,
  `554 Message rejected: Email address is not verified`). Failed sign-ins are rate-limited.
- **The platform relay takes mail from the aws-shim alone.** A NetworkPolicy admits only the shim's pods
  to the relay (and to the capturing sink on test clusters): no workload can submit mail directly, so no
  workload can send as an identity it was never granted.
- **`kind: EmailSender` mints SES SMTP credentials.** Each claim gets an IAM user allowed
  `ses:SendRawEmail` as its From address only, an access key, and the derived password, in its
  `<name>-smtp` secret (`SMTP_USERNAME` / `SMTP_PASSWORD`), pointing at the SMTP interface. Apps that sent
  to the relay unauthenticated must sign in with these credentials.
- **A member account's verified identities.** A member account sends as the identities its
  `kind: Account` lists in `spec.ses.verifiedIdentities`, and leaves the SES sandbox with
  `spec.ses.productionAccessEnabled`; its identity listings and `GetAccount` answer accordingly.

## v3.3.0 — 2026-10-29

Where v3.2.0 made the managed services *real*, v3.3.0 makes them **resilient and operable at estate
scale**. The serverless surface gains the Lambda execution model in full — Burstable sizing, a tenant
concurrency cap that returns a true 429, and a broad runtime catalog (current and EOL) you can even
override with your own image. Managed SQL Server learns to restore from native `.bak` backups. The
AWS-SDK shim grows API Gateway **REST v1** depth and, more importantly, learns to **degrade one service
instead of falling over** — a single read-only caller can no longer take the shared front door down.
Storage gains **measured, fail-closed disk-class placement** so databases and VM roots land on the right
media. Everything is additive and opt-in wherever it touches cost; nothing in the existing surface
changes.

### Security & resilience — the shared front door holds
- **A single tenant can no longer take the AWS-SDK shim down.** A large or unbounded DynamoDB `Scan`
  could exhaust the shared front door's memory and OOM it for *every* tenant. `Select=COUNT` now counts
  server-side without building a result set, `Limit` is honoured, an unbounded scan is capped into pages
  with a continuation token (an unmodified SDK paginates), and the process runs under a heap ceiling
  sized to its container — so one read can never spend the whole pod's memory.
- **A backend outage degrades only its own service.** If a service's datastore is unreachable the shim
  answers an honest error for *that* service (and adds a startup probe), instead of crashlooping the
  whole front door and taking the other two dozen services down with it.
- **Supply chain.** The Lambda runtime, `mc` and `nats` images were rebuilt to clear all outstanding
  high/critical image CVEs (a stale bundled XML parser, compression and networking libraries); the
  Python runtime drops `pip` and floors its dependencies to patched releases.

### Serverless — the Lambda execution model
- **Burstable sizing + a real concurrency cap.** A Function can run Burstable (request a floor, burst to
  its limit), and a tenant carries a concurrency/memory budget; at the cap the shim returns a true
  **429 throttle** (not a queued 503), the way Lambda does.
- **A broad runtime catalog.** Added **nodejs22** and **python3.13**; **ESM** handlers (`.mjs` /
  `type: module`) load on the Node runtime; and for legacy estates, **EOL escape-hatch** runtimes
  (including .NET Core 3.1) plus **`spec.code.runtimeImage`** to bring your own runtime image. The Node
  runtime ships the AWS SDK version-matched to AWS Lambda; both shims start on their oldest supported
  release; EOL base images pre-pull onto image-pull nodes.
- **Operability.** Superseded revisions now free their Services (GC), the Knative control plane runs HA
  with explicit resources, the maximum execution timeout is raised to 900s, and a memory-evicted pod
  reconciles cleanly. The **console** gains a **Code tab** for Functions — read the handler source,
  runtime settings, and download the package, like the AWS Lambda console.

### Managed databases — SQL Server restore
- **Restore a managed SQL Server from a native `.bak`** on bring-up, including **striped multi-file**
  backups (RDS-style backup-to-S3), with a capacity preflight, sized restore staging, and **readiness
  that stays NotReady until the restore actually completes** — a failed or long-running restore surfaces
  as a NotReady claim with its reason, never a silently-healthy-but-empty database. A completed restore
  is not re-downloaded on a pod restart.
- **Recovery model defaults to SIMPLE** so a restored database's transaction log can't grow unbounded.

### AWS-SDK shim — API Gateway REST v1
- **REST v1 gains request validation** (a shared JSON-schema tier), **API keys + usage plans**, and
  CloudFormation deploy of REST v1 resource types — closing the gap to the HTTP API v2 surface.
- **ECR** serves the OAuth2 token flow so `containerd` / `docker` image pulls authenticate correctly.

### Storage — disk-class placement
- **Databases and VM root disks now land on the right media, fail-closed.** Nodes are labelled with a
  **measured** disk class, a bulk-HDD class is available, and a DB or VM-root claim that cannot be placed
  on qualifying storage is **refused** rather than scheduled onto the wrong disk.

### Virtual machines
- **Firmware knob** — `spec.firmware` selects **BIOS or UEFI**, with optional **Secure Boot** and an
  ephemeral **vTPM**, so UEFI / Secure-Boot guests can be represented. It is **fail-closed on a migrated
  disk**: an adopted root disk must declare its boot mode (a UEFI-installed disk will not boot under
  BIOS) and the composition refuses to guess. Added a **windows-server-2016** golden image.

### IAM & policy
- **AWS `NotAction` / `NotResource` now translate** to Cedar complement axes (`notActions` /
  `notResources`) across the policy importer, CloudFormation, the shim, and native `kind: Policy`
  authoring — unblocking the AWS managed policies written with `NotAction`. Fail-closed by construction:
  a statement sets actions *or* notActions (never both), and an unmappable exclusion is **refused**, not
  silently widened. `Role.policies` is now optional.

### Configuration
- **`kind: Parameter` supports value-by-reference** — `value` is now optional, so a parameter can point
  at a managed source instead of carrying a literal.

### Compliance & audit
- **Opt-in per-tenant pod-budget guardrail** (a per-namespace ResourceQuota, generate-only so it never
  fails a workload closed) and **operator-tunable audit retention** (an `audit-config` ConfigMap plus an
  optional self-trim lifecycle on the audit bucket).

## v3.2.0 — 2026-10-12

Where v3.1.0 widened the AWS **surface** (twenty-five shim doorways), v3.2.0 deepens the **managed
services behind it** — the native `openinfra.dev` resources now *behave* like the AWS services they
mirror, not just answer like them. **DynamoDB** gains a durable backend with **point-in-time
recovery**; **Lambda** runs your **Zip/handler code** on managed runtimes; databases gain
**Aurora-style replicas, autoscaling and point-in-time restore** plus a new **real Microsoft SQL
Server** engine; **Step Functions** gets **Parallel/Map/Express**; and **CloudFormation** and **IAM**
translate more of a real stack. New declarative surfaces — **AWS Backup, AWS Config, Amplify-style
static-site builds, VPC endpoints** — round it out. Everything is **additive, and opt-in wherever it
touches cost or proprietary software**; nothing in the existing surface changes.

### Managed databases — RDS / Aurora / DynamoDB / SQL Server
- **Real Microsoft SQL Server** as a managed engine (`spec.database.engine: sqlserver`) — actual SQL
  Server 2022 over TDS 1433, alongside the existing SQL-Server-*compatible* `babelfish`. **Opt-in and
  EULA-gated**: it provisions nothing (and pulls no image) until you set `acceptEula: true`, and
  `edition` selects the licence — Developer (free, **non-production**) by default, Evaluation, or
  Express. A StatefulSet on Longhorn; `kind: DatabaseProxy (engineFamily: sqlserver)` fronts it. Live-verified.
- **Point-in-time recovery for Postgres** — continuous WAL archiving to object storage
  (`database.pointInTimeRecovery`), the foundation for **backtrack restore**: recover a managed Postgres
  to any instant in its window (to a new database you cut over to).
- **Aurora-shaped scaling** — `database.replicas` (the Aurora replica-count knob), a read-only
  **reader endpoint**, and **replica autoscaling** via KEDA.
- **DynamoDB got real.** A durable backend — **DocumentDB on CloudNativePG** with WAL archiving —
  brings **continuous backups + genuine `RestoreTableToPointInTime`**, `DeleteTable`, `BillingMode` /
  `ProvisionedThroughput` round-tripping, **DynamoDB Streams** (ordered change records + the
  `dynamodbstreams` API) and **local secondary indexes**. Each surface is proven by a live SDK probe.
- **DatabaseProxy** exposes `transactionMultiplexing`, wiring the proven RDS-Proxy per-transaction path.

### Serverless — Lambda (kind: Function)
- **Run your Lambda code, not just a container.** `spec.code` ingests a **Zip/handler** onto a managed
  runtime base image — **python3.12, nodejs20, and .NET 8** — with **Lambda layers**, **reserved
  concurrency**, and **weighted aliases/versions** (Knative traffic splitting). Alias
  invoke-by-qualifier is served through the shim.

### API Gateway — HTTP and REST
- **HTTP APIs (`kind: HttpApi`):** external HTTP origin backends (the `HTTP_PROXY` integration),
  **multiple custom domains + base-path mapping**, and **request validation** — required parameters and
  **body validation against Models** via the apigw-validator tier.
- **REST APIs (v1)** through the shim: a full control + data plane, **non-proxy VTL request/response
  mapping**, `IntegrationResponse` templates, and a **`COGNITO_USER_POOLS` method authorizer**.

### CloudFormation
- More of a real template deploys: **`Fn::Cidr`, `Fn::GetAZs`, `Fn::ImportValue`** intrinsics;
  **Lambda-backed custom resources** (invoked at deploy, with `Data` resolved into `Fn::GetAtt`);
  **nested-stack flattening** (child templates inlined into one stack); **`AWS::EC2::SecurityGroup`**
  (and standalone ingress/egress collation) and **`AWS::EC2::VPCEndpoint`** translation; and
  `AWS::Lambda::Version/Alias` recognized as plan-only ceilings.

### Step Functions
- The owned ASL engine gains **`Parallel` and `Map`** state types and **Express workflows** with
  **`StartSyncExecution`** (served via a dedicated sync Service).

### IAM & policy
- Cedar policy import now covers the **`aws:username`** (StringEquals/StringLike) and **`aws:CurrentTime`**
  (Date* time-window) condition keys, persisted through the CR.
- **IAM import translates all shim-enforced services**, not just s3/dynamodb/lambda.
- **KMS** key policies import as `kind: Policy` (`CreateKey` Policy / `PutKeyPolicy`), per-key access proven live.

### Backup, Config & compliance
- **`kind: BackupVault` + `BackupPlan`** — declarative **AWS Backup** over Velero (prefix-isolated
  vaults, scheduled plans).
- **`kind: ConfigRule`** — **AWS Config**-style rules over **Kyverno** (audit mode: records, does not
  enforce), delivered with a new **opt-in `compliance` component**.

### Web & networking
- **`kind: StaticSite`** — **Amplify-style managed builds** (clone → sandboxed build → publish → serve).
- **`kind: VpcEndpoint`** — a private in-VPC entry to the AWS front door.
- **ECR** moves to **per-repo data-plane token auth** (a Docker bearer-token server over the
  MinIO-backed registry).
- **SES** `SendEmail` / `SendRawEmail` front door over the SMTP relay (opt-in).
- **lan-expose:** a multi-VLAN return-path so clients off the EIP subnet reach FIPs, and NetworkPolicy
  ipBlock drift reconciliation.

### Security & hardening
- **CVE fixes:** `golang.org/x/net` → v0.60.0 (CVE-2026-78669) across all first-party binaries; UI
  `source-map-js` / `fast-uri` (Dependabot); Lambda runtime images now pull OS security updates and drop
  the unused npm CLI (pure build-tooling CVE surface).
- **authz:** corpus-miss defers unknown ServiceAccounts to RBAC (no reconcile deadlock) and a Crossplane
  group-wildcard unblocks new kinds; `function-auto-ready` added to the go-templating-only compositions.
- **audit off-siting:** a rotating-prefix re-sweep (durable anti-treadmill verify) plus memory/deadline
  fixes to the verify-full job.

### Docs
- The README now leads with a **banner** — *AWS on the surface, your hardware underneath*.
- Migration guidance: an **Elastic Beanstalk → `kind: Application`** recipe, with **CloudFront** (BYO-CDN)
  and **Redshift** (covered by `kind: Query` / Trino) recorded as non-goals; the AWS-parity boundary
  decisions documented.

## v3.1.0 — 2026-10-02

The AWS-SDK shim now fronts **twenty-five probe-proven services** (up from twelve at v3.0.0), each proven
by a real-AWS-SDK compatibility probe over the one SigV4 + one-policy-world (RBAC + Cedar) path. This
release adds thirteen doorways since v3.0.0 — the AWS **orchestration and data** surfaces (CloudFormation,
Step Functions, ECS, ECR, EKS, Glue, Athena) alongside the **identity, serverless, and messaging** doorways
(IAM, Cognito, API Gateway, CloudWatch metrics + alarms, Kinesis, SSM) — plus supply-chain hardening. It is
**additive**: the shim is opt-in and OFF by default, and nothing in the native `openinfra.dev` surface
changes.

### AWS compatibility (shim)
- **EKS doorway (opt-in; SigV4 service `eks`).** The shim fronts **EKS** — the twenty-fifth probe-proven
  service — as a connection-information doorway, not a cluster-provisioning emulation: the open-infra cluster
  IS the cluster. `DescribeCluster` returns the real endpoint and certificate authority so an
  `aws eks update-kubeconfig` flow yields a working kubeconfig; `ListClusters`/`DescribeCluster` are served
  and cluster-lifecycle verbs (`CreateCluster`/`DeleteCluster`/node groups) are **refused honestly** rather
  than faked, because the platform does not create throwaway clusters on demand. Proven by
  `probe/aws-shim-eks.sh` (exit 0 live). See [`docs/aws-shim.md`](docs/aws-shim.md).
- **Athena doorway (opt-in; SigV4 service `athena`).** The shim fronts **Athena** — the twenty-fourth
  service — over **Trino** against the lakehouse. `StartQueryExecution`/`GetQueryExecution`/
  `GetQueryResults`/`StopQueryExecution` run real SQL over the Iceberg tables; `StartQueryExecution` returns
  immediately and the execution absorbs Trino's **scale-from-zero cold start** asynchronously (it cooperates
  with the Trino autostop rather than pinning replicas). Proven by `probe/aws-shim-athena.sh` (exit 0 live).
  See [`docs/aws-shim.md`](docs/aws-shim.md).
- **Glue Data Catalog doorway (opt-in; SigV4 service `glue`).** The shim fronts **Glue** — the twenty-third
  service — mapping the Glue Data Catalog (`GetDatabases`/`GetTables`/`GetPartitions` and their create/delete
  verbs) onto the **Iceberg REST catalog** that backs the lakehouse, so the catalog an Athena/Trino query
  reads is the same one Glue describes — one catalog, not a parallel copy. Proven by
  `probe/aws-shim-glue.sh` (exit 0 live). See [`docs/aws-shim.md`](docs/aws-shim.md).
- **ECR doorway (opt-in; SigV4 service `ecr`).** The shim fronts **ECR** — the twenty-second service — over a
  **MinIO-backed OCI registry**. `GetAuthorizationToken`, `CreateRepository`/`DescribeRepositories`/
  `DeleteRepository`, and the image-manifest verbs back a registry a standard `docker login` + push/pull
  works against; authorization is at repository granularity. Proven by `probe/aws-shim-ecr.sh` (exit 0 live,
  self-cleaning). See [`docs/aws-shim.md`](docs/aws-shim.md).
- **ECS doorway (opt-in; SigV4 service `ecs`).** The shim fronts **ECS** — the twenty-first service — over the
  CloudFormation engine, **under caller authority**: `RunTask`/`CreateService`/`UpdateService`/
  `DescribeServices`/`DescribeTasks` land real workloads on the platform, and `DescribeServices` reads the
  workload's readiness **through the caller's own identity**, not the shim's service account, so a caller
  cannot read a service it is not authorized to see. Proven by `probe/aws-shim-ecs.sh` (exit 0 live). See
  [`docs/aws-shim.md`](docs/aws-shim.md).
- **CloudFormation doorway (opt-in; SigV4 service `cloudformation`).** The shim fronts **CloudFormation** —
  the twentieth service — over open-infra's owned CFN engine: `CreateStack`/`UpdateStack`/`DeleteStack`,
  `CreateChangeSet`/`ExecuteChangeSet`, `DescribeStacks`/`DescribeStackResources`, and
  `DetectStackDrift`/`DescribeStackDriftDetectionStatus`. A stack is applied **under the caller's authority**
  (impersonation), and each resource's physical name is the deterministic `k8sName(logicalId)`, so
  `aws cloudformation deploy` of a supported template is real end to end. The engine translates the subset it
  can honor faithfully and refuses the rest rather than silently dropping resources. Proven by
  `probe/aws-shim-cloudformation.sh` (exit 0 live). See [`docs/aws-shim.md`](docs/aws-shim.md).
- **Step Functions doorway (opt-in; SigV4 service `states`).** The shim fronts **Step Functions** — the
  nineteenth service — over an owned **Amazon States Language** engine (`kind: StateMachine` + `Execution`):
  `CreateStateMachine`, `StartExecution`/`DescribeExecution`/`GetExecutionHistory`, and a cooperative
  `StopExecution`. Each execution carries a **per-execution STS role authority** into its Task states, so a
  state machine's tasks act with exactly the execution role's permissions — not the engine's. Proven by
  `probe/aws-shim-stepfunctions.sh` (exit 0 live, including a Wait-survives-restart case). See
  [`docs/aws-shim.md`](docs/aws-shim.md).
- **Cognito user pools doorway (opt-in; SigV4 service `cognito-idp`).** The shim now fronts **Cognito user
  pools** — the seventeenth probe-proven service. `CreateUserPool`/`CreateUserPoolClient`, `SignUp`/
  `ConfirmSignUp`, the `Admin*` user-lifecycle ops, `InitiateAuth`/`AdminInitiateAuth` (`USER_PASSWORD_AUTH` +
  `REFRESH_TOKEN_AUTH`), `GetUser`, `GlobalSignOut`, and each pool's JWKS + OIDC discovery endpoints. The token
  contract is real: `InitiateAuth` returns genuine **RS256 JWTs** (id/access/refresh) signed by the shim's RSA
  key and **verifiable against the pool's JWKS** — an API Gateway JWT authorizer (the #169 doorway) pointed at
  the pool admits them end to end. Passwords are bcrypt; the configured **password policy is genuinely
  enforced**; **`GlobalSignOut` genuinely invalidates** already-issued tokens (a per-user cutoff). The
  control-plane (admin) surface and the pool's end-user auth are kept as distinct trust domains. SRP, MFA,
  identity pools, and the hosted UI are refused rather than faked. Proven by `probe/aws-shim-cognito.sh` (exit 0
  live); a boto3 sign-in example lives in [`examples/cognito-app/`](examples/cognito-app/). See
  [`docs/aws-shim.md`](docs/aws-shim.md).
- **IAM management API + AWS-policy-JSON→Cedar translation (opt-in; SigV4 service `iam`).** The shim now
  exposes the AWS IAM management verbs — `CreateRole`/`GetRole`/`DeleteRole`/`ListRoles`,
  `CreatePolicy`/`GetPolicy`/`DeletePolicy`/`ListPolicies`, `AttachRolePolicy`/`DetachRolePolicy`/
  `PutRolePolicy`/`ListAttachedRolePolicies`, `CreateUser`/`GetUser`/`DeleteUser`/`ListUsers`,
  `CreateAccessKey`/`DeleteAccessKey`/`ListAccessKeys`/`UpdateAccessKey`, `SimulatePrincipalPolicy` — over the
  platform's existing `kind: Role`/`Policy`/`User` entities, with **one policy world, no second engine**: a
  `CreatePolicy` translates the AWS PolicyDocument through `policyengine.ImportAWS` into the SAME Cedar
  statements the data plane enforces. An assumed IAM role is now an **independent principal whose authority is
  exactly its attached policies**, evaluated closed/default-deny (a role with no policy can do nothing) — the
  faithful AWS model. Translation fidelity is guarded: a policy with any part the translator can't honor
  faithfully — including `NotAction`/`NotResource` — is **refused** (`MalformedPolicyDocument`), never stored
  as a grant that differs from the JSON. `SimulatePrincipalPolicy` proves the translation both directions, and
  `CreateAccessKey` yields a key that genuinely authenticates. The **live `AssumeRole`→S3 round-trip** (the
  end-to-end confused-deputy detector) is verified: an STS-assumed session does exactly what its policy grants
  and is denied everything it does not, authorized on the role — not the shim's backend credentials. The
  eighteenth probe-proven service, `probe/aws-shim-iam.sh` exit 0 live. (`sts:AssumeRole` is enabled via a
  Vault `sts/signing-key`, written by the security setup Job on bootstrap.) See
  [`docs/aws-shim.md`](docs/aws-shim.md).
- **Kinesis Data Streams doorway (opt-in).** The shim now fronts a sixteenth service — **Kinesis Data
  Streams** — the ordered, sharded, replayable streaming primitive, deliberately distinct from the unordered
  SQS / no-retention SNS doorways. `CreateStream`/`DescribeStream`/`ListStreams`/`DeleteStream`,
  `PutRecord`/`PutRecords` (per-record partial failure + the 1 MiB limit), `GetShardIterator`/`GetRecords`/
  `ListShards`, and retention changes. A record is assigned to a shard by a stable `PartitionKey` hash and
  gets a strictly monotonic per-shard `SequenceNumber`; records replay within the retention window
  (`TRIM_HORIZON` re-reads from the start); `GetRecords` reports `MillisBehindLatest`. Backend is Postgres +
  a retention reaper (not JetStream), for exact ordering/sequence/replay semantics. Authorization is at
  **stream granularity** (cross-tenant read denied; read separable from write). Resharding and enhanced
  fan-out are refused. Proven by `probe/aws-shim-kinesis.sh` (exit 0 live); a producer/consumer example lives
  in [`examples/kinesis-pipeline/`](examples/kinesis-pipeline/). See [`docs/aws-shim.md`](docs/aws-shim.md).
- **CloudWatch metrics + alarms doorway (opt-in).** The shim now fronts a fifteenth service — **CloudWatch
  metrics and alarms** (the other half of CloudWatch; Logs shipped in v3.0.0) — over the AWS query protocol.
  `PutMetricData`/`GetMetricStatistics`/`GetMetricData`/`ListMetrics` with faithful period aggregation
  (Average/Sum/Minimum/Maximum/SampleCount + percentiles), where a metric's identity is namespace + name +
  **dimensions**. The crux: alarms **genuinely evaluate** — an in-process evaluator transitions
  OK/ALARM/INSUFFICIENT_DATA per EvaluationPeriods/DatapointsToAlarm/TreatMissingData/ComparisonOperator and
  **fires SNS AlarmActions** on entry to ALARM (an alarm that never evaluates is worse than absent, so a
  non-SNS action target is refused at PutMetricAlarm). Backend is Postgres + the owned evaluator (not
  Prometheus), for exact AWS semantics. Authorization is at **namespace granularity** (cross-tenant metric
  read is denied). Dashboards and metric-math expressions are refused. Proven by `probe/aws-shim-cloudwatch.sh`
  (exit 0 live). See [`docs/aws-shim.md`](docs/aws-shim.md).
- **API Gateway (HTTP API v2) doorway (opt-in).** The shim now fronts a fourteenth service — **API Gateway
  HTTP APIs** — completing the AWS serverless triad (API Gateway → Lambda → DynamoDB). Two planes: the
  apigatewayv2 **control plane** (restJson1 over REST paths — apis/routes/integrations/stages/authorizers,
  authorized by the one policy world with `apigateway:<Op>` Cedar actions) and the **data plane**, a real
  runtime HTTP→Lambda proxy that builds the API Gateway v2 proxy event (payload format 2.0 default + 1.0),
  matches routes with AWS precedence (`{id}`, `{proxy+}`, `$default`), and turns the Lambda's
  `{statusCode,headers,body}` back into the HTTP response. **JWT authorizers** (validated against the OIDC IdP
  registry, fail-closed) gate the application's end users — a trust domain kept distinct from the platform
  principals — and **CORS** is first-class. REST API v1, non-Lambda integrations, and REQUEST/Lambda
  authorizers are refused honestly. Proven by `probe/aws-shim-apigateway.sh` (exit 0 live). A canonical
  handler lives in [`examples/apigw-lambda/`](examples/apigw-lambda/). See [`docs/aws-shim.md`](docs/aws-shim.md).
- **SSM Parameter Store doorway (opt-in).** The AWS-SDK shim now fronts a thirteenth service —
  **SSM Parameter Store** (`AmazonSSM.<Op>`, JSON 1.1) — over the same SigV4 + one-policy-world path as
  the rest. It backs the hierarchical parameter tree (versions, labels, `String`/`StringList`/
  `SecureString`) on the shared Postgres; `SecureString` values are genuinely encrypted under the shim's
  KMS doorway (Vault Transit key `kms-aws-ssm`, parameter name bound as AEAD data) — plaintext never sits
  in Postgres. `WithDecryption` is a two-permission action (`ssm:GetParameter` + `kms:Decrypt`), and Cedar
  authorizes at per-parameter / per-path-prefix granularity. Standard tier only; Advanced tier / parameter
  policies / a custom SecureString `KeyId` are refused honestly rather than faked. Proven by
  `probe/aws-shim-ssm.sh` (exit 0 live). See [`docs/aws-shim.md`](docs/aws-shim.md).

### Supply chain & hardening
- **First-party tool images, digest-pinned.** The setup Jobs no longer pull mutable public `:latest` tool
  images: the MinIO client and NATS tooling are now first-party images (`open-infra-mc`, `nats-box`) pinned by
  digest, so a bootstrap's tool versions are fixed and reproducible rather than whatever `:latest` resolved to
  that day.
- **Bucket/queue readiness gated on setup success, not apply.** A `kind: Bucket`/`kind: Queue` claim now
  reports Ready only once its setup Job has genuinely succeeded (a durable-secret readiness gate), closing a
  false-green where a claim read Ready at apply time before its backing resource existed.
- **API Gateway integrations fenced by the caller's invoke authority.** An API Gateway integration target is
  now checked against the caller's own `lambda:InvokeFunction` authority, so a caller cannot wire a route to a
  function it is not permitted to invoke — a confused-deputy fence on the serverless data plane.
- **SQS store pinned to durable storage.** The aws-shim SQS CNPG store is pinned to Longhorn rather than
  ephemeral local-path, so queued messages survive a node's loss.

## v3.0.0 — 2026-09-25

open-infra now speaks the **AWS wire protocol** as a first-class surface. The opt-in AWS-SDK shim fronts
**twelve services, each proven by a real-AWS-SDK compatibility probe**, over one SigV4 +
one-policy-world (RBAC + Cedar) path — so you can point your existing AWS **SDK, CLI, Terraform, or
CloudFormation** at open-infra, or keep declaring intent in `infra.yaml`. This is a milestone bump: the
product's center of gravity now includes AWS-wire compatibility alongside its concept-parity native
surface. The shift is **additive** — the AWS shim is opt-in and OFF by default, and nothing on the
existing stable surface changes — so despite the major version there are no breaking changes to the
`openinfra.dev` kinds. Maturity tiers are unchanged and stated per capability (see the README).

### Observability
- **Distributed tracing (experimental).** open-infra now ships the AWS X-Ray-shaped signal to sit
  alongside its metrics (Prometheus) and logs (Loki): a Grafana **Tempo** backend (OTLP + Zipkin
  receivers, a Grafana datasource with trace-to-logs correlation), **Knative request tracing** wired
  to Tempo (per-`Function` spans through the activator/queue-proxy), and OpenTelemetry instrumentation
  of the first-party Go services (the console BFF, the aws-shim, and open-appsync) — an `otelhttp`
  server handler plus W3C `traceparent` propagation, so a request stitches shim → engine end to end.
  Service export is opt-in via `OTEL_EXPORTER_OTLP_ENDPOINT` (the manifests point it at Tempo; unset
  it to disable). Traces are queryable in Grafana → Explore. See [`docs/tracing.md`](docs/tracing.md).

### Messaging
- **`kind: EmailSender` (opt-in, experimental).** Transactional email — the AWS SES-shaped primitive.
  A claim provisions a sending identity (a From address) and emits a `<name>-smtp` connection secret
  (`SMTP_HOST` / `SMTP_PORT` / `SMTP_FROM` / `SMTP_FROM_NAME`) that apps consume via `spec.secrets` →
  `envFrom`, like the `<name>-minio` convention. Backed by a shared in-cluster SMTP relay, both riding
  the `mail` component. Honest about the hard part: reliable internet delivery needs a smarthost plus
  SPF/DKIM/DMARC on the sending domain (operator-configured), so the relay forwards to an optional
  `RELAYHOST` and defaults to best-effort direct delivery. An AWS-SDK SES shim verb is a documented
  follow-on. See [`docs/email.md`](docs/email.md).

### Configuration
- **`kind: Parameter` (opt-in, experimental).** A hierarchical, optionally-encrypted parameter store —
  the AWS SSM Parameter Store equivalent. Each value is held in Vault's KV-v2 `params` mount under its
  path and materialized (with the rest of the namespace's parameters) into a per-namespace
  `openinfra-parameters` Secret, flattened to `UPPER_SNAKE` env keys (`/app/db/host` → `APP_DB_HOST`),
  which apps read via the existing `spec.secrets` → `envFrom`. A least-privilege reconciler (Vault
  Kubernetes-auth, scoped to the `params/*` mount) writes the tree and rebuilds the Secret. Rides the
  `encryption` component. See [`docs/parameters.md`](docs/parameters.md).

### Compute & hosting
- **`kind: StaticSite`.** Static frontend hosting for a built SPA — the S3-static-website + CDN-origin
  primitive. One claim provisions a MinIO bucket for the assets (with a `<name>-minio` upload secret),
  an nginx server that continuously syncs the bucket and serves it with single-page-app
  history-fallback, and a Traefik Ingress with cert-manager TLS. Upload your `dist/` to the bucket and
  it goes live; the server re-syncs on an interval. Per-PR preview environments are documented as a CI
  recipe (render one `StaticSite` per pull request, tear it down on close) rather than a controller.
  See [`docs/static-sites.md`](docs/static-sites.md).

### Security
- **Field-level authorization in the AppSync engine now enforces (fix).** `open-appsync` authorizes a
  resolver's `auth:` requirement by running a `SubjectAccessReview` for the caller against the platform's
  RBAC — but the engine pod ran as the namespace `default` ServiceAccount, which cannot create
  SubjectAccessReviews, so every `auth:`-guarded field failed closed for all callers. The engine now runs
  under a dedicated ServiceAccount bound (via a small root-app-applied reconciler that also provisions it
  per namespace) to a minimal `create subjectaccessreviews` ClusterRole. Only APIs that actually use
  `auth:` take the dedicated SA; auth-less APIs are unchanged. The Crossplane provider still creates no
  RBAC — that boundary is intact.
- **`kind: HttpApi` gains CORS and rate limiting.** `spec.cors` (origins / methods / headers /
  credentials / max-age) renders a Traefik headers middleware — the API Gateway CORS-equivalent,
  preflight included — and `spec.rateLimit` (`average` / `burst`) renders a Traefik rateLimit
  middleware (a per-source token bucket, the usage-plan/throttle-equivalent). Both are built-in
  Traefik middlewares (no plugin) and compose with the WAF into one ordered `router.middlewares`
  chain (CORS → rate limit → WAF). Closes part of the API Gateway REST-v1 gap; stages, deployments,
  authorizers, per-API-key usage plans, and VTL mapping remain out of scope. See
  [`docs/api-gateway-coverage.md`](docs/api-gateway-coverage.md).
- **In-cluster WAF for `kind: HttpApi` (opt-in, experimental).** `spec.waf: true` attaches a
  per-API Traefik Coraza / OWASP Core Rule Set middleware to the API's Ingress — an L7 web
  application firewall, which a network `kind: SecurityGroup` (L3/L4) cannot provide. Off by
  default; positioned as defense-in-depth for apps not fronted by a CDN WAF (the documented edge
  path stays BYO-Cloudflare). It requires the `coraza` Traefik plugin to be enabled on the cluster,
  an operator step documented in [`docs/api-gateway-coverage.md`](docs/api-gateway-coverage.md)
  rather than shipped live (a bad plugin reference would fail Traefik startup).

### Identity
- **`kind: UserPool` (experimental).** A managed, customer-facing OIDC identity provider — the
  token-*issuing* counterpart to the platform's own IAM, and the open-source path to an AWS Cognito
  User Pool. It deploys Keycloak (a realm is the pool, a client is an app client), serves sign-up /
  sign-in and OIDC discovery, and emits a connection secret (`ISSUER_URL` / `REALM` / `CLIENT_ID` /
  `CLIENT_SECRET` / `ADMIN_*`). Because open-infra already *consumes* OIDC/Cognito JWTs, pointing a
  consumer's `OIDC_ISSUER` at a pool's `ISSUER_URL` makes `@aws_oidc` / `@aws_cognito_user_pools`
  enforcement verify its tokens with no code change. Admin-gated (not grantable by a `kind: Policy`).
  Experimental: the first slice runs Keycloak in dev mode on an embedded database persisted to a
  PVC — a real issuer, not yet a hardened, HA, Postgres-backed deployment. See
  [`docs/auth-migration.md`](docs/auth-migration.md).

### AWS compatibility
- **The AWS-SDK shim graduates to twelve probe-proven services.** Point an unmodified AWS SDK, CLI,
  Terraform, or CloudFormation at open-infra and it answers as AWS — SigV4-authenticated against your
  open-infra IAM, enforced by the *same* RBAC + Cedar permission boundary the console uses (one policy
  world, never a parallel auth), against **durable backends** (not an emulator). New this release, each
  built one at a time and each proven by a **real-AWS-SDK compatibility probe** (byte/behaviour assertions
  plus the auth negatives, not merely a `200`):
  - **SQS** — Postgres-backed: visibility timeout, per-receive receipt handles, DLQ redrive, long polling
    (FIFO refused, standard queues only).
  - **SNS** — durable fan-out to SQS queues, wrapped + raw delivery (`sqs` protocol only;
    FilterPolicy / `.fifo` / http refused).
  - **KMS** — HashiCorp Vault Transit: envelope encryption (`GenerateDataKey`), EncryptionContext bound as
    AEAD, the key lifecycle state machine, rotate-safe rotation, and crypto-erase (symmetric only; grants
    and key policies refused).
  - **Secrets Manager** — versioned secrets with `AWSCURRENT`/`AWSPREVIOUS` staging labels, each value
    KMS-encrypted; a 7–30 day recovery window (auto-rotation and custom `KmsKeyId` refused).
  - **EventBridge** — scheduled rules (six-field AWS cron, evaluated in UTC) and event-pattern routing to
    Lambda/SQS targets with durable delivery; a triggered target runs under the **rule creator's**
    authority, verified at `PutTargets`, never the shim's own.
  - **RDS** — **real PostgreSQL** via CloudNativePG: asynchronous provisioning with a genuine
    `available` state, a reachable Service endpoint, and real snapshot → restore (MultiAZ, read replicas,
    point-in-time recovery, and `StorageEncrypted` are refused rather than faked; in-database
    authorization is Postgres's own, outside the Cedar policy world — documented, not hidden).
  - **CloudWatch Logs** — ordered, byte-identical read-back with original millisecond timestamps,
    terminating pagination, and **genuinely-enforced** per-group retention (Logs Insights refused).
  - **STS** additionally gains `AssumeRole` / `AssumeRoleWithWebIdentity` (stateless, Vault-custodied
    sealing key), and the **DynamoDB** front door gains atomic `TransactWriteItems`/`TransactGetItems`
    (over the documentdb Postgres behind FerretDB) and TTL.

  Each service carries deliberate, documented **divergences** rather than silent approximations; a service
  the shim has not made faithful still returns an honest `501`. Opt-in, OFF by default
  (`components.awsShim: true`). See [`docs/aws-shim.md`](docs/aws-shim.md).
- **CloudFormation engine (`cfn`).** Read a CloudFormation template — or CDK's synthesized
  output, which is CloudFormation JSON — and provision the corresponding open-infra resources.
  `cfn plan` is a read-only dry-run that maps each resource onto a kind and reports what it can
  and cannot provision; `cfn deploy` creates a stack fail-closed and dependency-ordered, rolling
  back with no orphans on failure; `cfn changeset` / `cfn update` diff and apply a change,
  rolling back to the exact prior stack if any step fails; `cfn destroy` tears a stack down in
  reverse order honoring `DeletionPolicy`; `cfn drift` reports resources changed or deleted out
  of band without reconciling them. It never silently drops or approximates — an unsupported
  resource type, intrinsic function, or property is refused with an exact reason. The claim is
  exactly the committed mapping and translator tables, **not** full CloudFormation compatibility.
  See [`docs/cloudformation.md`](docs/cloudformation.md).
- **DynamoDB `UpdateItem` and `Query`** on the AppSync engine's Dynamo-shaped data source,
  alongside the existing `GetItem`/`PutItem`/`DeleteItem`/`Scan`. UpdateItem (SET with arithmetic
  / `if_not_exists` / `list_append`, REMOVE, ADD, and condition expressions) and Query (key
  conditions, a secondary index, filter expressions, sort order, and pagination) are supported as
  a faithful common subset; forms outside it — batch and transactional writes, TTL, and the like —
  fail loud rather than approximate. See [`docs/aws-migration.md`](docs/aws-migration.md).
- **DynamoDB front door in the AWS shim.** Point a DynamoDB SDK client at the shim and it speaks
  the DynamoDB wire protocol (AWS JSON 1.0, `X-Amz-Target`) directly against a FerretDB-backed
  store: `CreateTable`, `DescribeTable`, `GetItem`, `PutItem`, `DeleteItem`, `Query`, `UpdateItem`,
  `Scan`, and the batch item APIs `BatchGetItem` / `BatchWriteItem` (non-transactional and capped at
  DynamoDB's 100/25 limits, like the real service), sharing the same expression evaluator as the
  AppSync data source. Every call is authorized through the platform's own IAM (SigV4 →
  `SubjectAccessReview`). Atomic transactions (`TransactWriteItems`/`TransactGetItems`) and TTL are now
  supported (see the shim-doorways entry above); the operations still outside the built slice —
  `ProjectionExpression`, `ListTables`, `DeleteTable`, and streams — return an honest `501` rather than a
  silent approximation. Opt-in, off by default. See [`docs/aws-shim.md`](docs/aws-shim.md).

## v2.7.0 — 2026-08-31

### Security & compliance
- **Air-gap support (opt-in, off by default).** A two-phase, reversible air-gapped posture:
  front-load an in-cluster, PVC-backed registry mirror plus a prefetch that derives the image set from
  what is actually running, then — as a separate, deliberate election — a cluster-wide public-egress
  cutoff that keeps the LAN, cluster, and DNS reachable while severing the public internet. The cutoff
  is CNI-specific and auto-selected (a Cilium `CiliumClusterwideNetworkPolicy` or, on Calico/Canal, a
  `GlobalNetworkPolicy`), and the per-node runtime mirror config (`registries.yaml` for k3s or RKE2) is
  automated. A fresh install keeps full internet access and no air-gap machinery. Enable with
  `components.airgap`; the egress cutoff is a second flag (`airgap.denyPublicEgress`). Still maturing —
  see [`docs/airgapping.md`](docs/airgapping.md).
- **Access recertification (AC-2 / AC-6).** A read-only, per-account report of the standing access each
  principal holds — group memberships and the ClusterRoles they confer, any active temporal `kind: Grant`,
  and when the account was last seen acting — with a review-flag worklist (privileged, dormant,
  disabled-but-retaining-access, no-recent-activity, no-sign-in-credential, inert-group-membership,
  active-grant). At **Security & Identity → Access Review**, served from `/api/iam/access-review`
  (admin-gated). "Last seen" is drawn from the audit store over a bounded window; when that source is
  unreachable the report discloses it and withholds the activity flags rather than mark every account
  inactive.

### Data

- **`kind: DatabaseProxy` — RDS-Proxy-equivalent connection pooling, verified across six client drivers.**
  The TDS pool's pin-vs-multiplex decisions are live-verified against go-mssqldb, Tedious, the Microsoft
  JDBC driver, pyodbc / msodbcsql18, Microsoft.Data.SqlClient (.NET), and SQLAlchemy (coverage grid
  `tds-proxy/grid.jsonl`). A driver's connect-time `SET TRANSACTION ISOLATION LEVEL` — and any SET-only
  opening batch — is treated as a re-applied login prelude rather than session state, so drivers that issue
  one (Tedious, .NET SqlClient) pool instead of pinning; a non-SET statement or session-context state pins.
  The proxy **terminates client TLS** (strict and tunnelled), so a client that negotiates login-time TLS
  even with encryption disabled (e.g. the Microsoft JDBC driver) is handled. Integrated (SSPI) and
  federated (Azure AD / FEDAUTH) logins are **refused** — the same posture as AWS RDS Proxy — so distinct
  principals never collapse onto one pooled backend. MARS is **declined** to preserve pooling (again
  matching RDS Proxy; a multiplexed demux is a demand-gated future option). Opt-in per-transaction
  multiplexing (`-tx-multiplex`) shares fewer backends across autocommit and explicit transactions.
  Behaviour **under a backend fault** is verified for every driver too: a backend failover during an
  open transaction surfaces a clean error with no silent commit, a mid-result-set drop surfaces a clean
  error rather than a truncated set, and the pool's pinned-discard and connection-ceiling guards hold —
  across all six drivers plus the SQLAlchemy ORM (grid `tds-proxy/grid.jsonl`).

### Compute & networking

- **`kind: FeatureGroup` — online feature store (SageMaker Feature Store), experimental.** A low-latency
  online store for real-time inference: each group provisions a per-group Valkey and a small first-party
  API service exposing PutRecord (`POST /records`) and GetRecord (`GET /records/{id}`), so a model endpoint
  looks up the latest features for a record id in milliseconds. Values keep their JSON types; optional
  per-record TTL. From the console (Compute → Feature Store) and Terraform. v1 is online-only; an offline
  (object-store history, for training) store is a planned follow-up. See
  [`docs/feature-store.md`](docs/feature-store.md).

- **`kind: ModelMonitor` — scheduled drift monitoring (SageMaker Model Monitor), experimental.** A CronJob
  that, on a schedule, compares recent data against a baseline dataset, computes per-numeric-feature mean
  drift, writes a report (report-<ts>.json + latest.json) to the object store, and flags features that
  drift beyond a threshold. The drift check is **built in** (an inline check on a stock python image) — no
  monitoring container to write and no first-party image. From the console (Compute → Model Monitor) and
  Terraform (the float `threshold` is a stated gap until the provider gains a float type). v1 is a tabular
  mean-shift data-quality monitor. See [`docs/model-monitor.md`](docs/model-monitor.md).

- **`kind: ProcessingJob` — general data processing (SageMaker Processing), experimental.** A run-once,
  GPU-capable job with N named inputs and outputs in the object store — for preprocessing, feature
  engineering, dataset validation, or model evaluation. Each channel is injected as
  INPUT_<NAME>_BUCKET/PREFIX and OUTPUT_<NAME>_BUCKET/PREFIX + S3 creds (with INPUTS/OUTPUTS listing the
  channels). More general than `kind: BatchTransform` (single-model inference); completes the SageMaker
  jobs family (Training/Processing/Transform/Tuning). From the console (Compute → Processing Jobs) and
  Terraform. See [`docs/processing-jobs.md`](docs/processing-jobs.md).

- **`kind: TuningJob` — hyperparameter tuning (SageMaker Automatic Model Tuning), experimental.** A
  grid-search sweep: given a base training spec, a search space, and an objective, it runs a
  `kind: TrainingJob` per hyperparameter combination (up to `maxParallel` at a time), reads each trial's
  reported metric from its logs (`OPENINFRA_METRIC=<value>` or a custom `metricRegex`), and records the
  best trial and hyperparameters in status. Each trial is a real Training Job, so tuning reuses the whole
  training data plane. Like `kind: Execution` it is a controller-owned run (started from the console or
  kubectl, not Terraform); deleting it garbage-collects its trials. v1 is grid search only. See
  [`docs/tuning-jobs.md`](docs/tuning-jobs.md).

- **`kind: BatchTransform` — offline batch inference (SageMaker Batch Transform), experimental.** A run-once
  job that loads a model, scores a whole input dataset, and writes predictions to the object store, then
  exits — the offline counterpart to `kind: Model` (a live endpoint). Same run-once, GPU-capable Job +
  object-store wiring as `kind: TrainingJob` (INPUT_/OUTPUT_/ARTIFACT_ + S3 creds injected); `gpu: 0`
  (default) runs CPU-only. From the console (Compute → Batch Transform) and Terraform. See
  [`docs/batch-transform.md`](docs/batch-transform.md).

- **`kind: ModelPackage` — model registry + train→serve loop (SageMaker Model Registry), experimental.** A
  versioned, approvable registry record of a trained artifact (modelName group + version + artifact + serving
  image + metrics), with an approval gate (PendingManualApproval → Approved). `kind: Model` gains a `serve`
  path — serve an arbitrary trained artifact (BYO serving container + object-store artifact) behind the same
  key-gated endpoint, instead of only the Ollama catalog — so a TrainingJob's output can be registered,
  approved, and promoted to a served endpoint. From the console (Compute → Model Registry: approve + Deploy)
  and Terraform. See [`docs/model-registry.md`](docs/model-registry.md).

- **`kind: TrainingJob` — GPU model training (SageMaker Training Jobs equivalent), experimental.** The
  training-loop counterpart to `kind: Model` (inference): a run-once batch Job that runs your training
  container to completion on a GPU node of the chosen tier (`smallgpu` / `largegpu`), with
  hyperparameters passed as env and S3-compatible object-store credentials injected so it can read a
  dataset and write model artifacts to MinIO (the bucket is created on demand). `gpu: 0` runs CPU-only.
  Managed from the console (Compute → Training Jobs) and expressible in Terraform; run status is the
  underlying Job's. See [`docs/training-jobs.md`](docs/training-jobs.md).

- **`kind: StateMachine` — workflow orchestration (Step Functions equivalent), experimental.** Define a
  workflow in Amazon States Language (the same JSON as `aws_sfn_state_machine.definition`) and run it by
  creating a `kind: Execution`. An owned, dependency-free engine interprets the ASL — no Argo/Temporal —
  invoking `kind: Function` Task states over their cluster-local URL. v1 covers Task, Choice, Wait, Pass,
  Succeed and Fail, with Retry/Catch, TimeoutSeconds, and JSONPath data shaping
  (InputPath/Parameters/ResultPath/OutputPath); Parallel, Map and the Express type are not yet
  implemented (they fail loudly with `States.Runtime`, never silently). Executions checkpoint into their
  status for durable resume across a controller restart (so Task handlers should be idempotent). Managed
  from the console (Compute → State Machines) and expressible in Terraform; executions are runtime
  objects, started from the console or `kubectl` rather than Terraform. See
  [`docs/state-machines.md`](docs/state-machines.md).

- **VM direct-LAN networking — `kind: VirtualMachine` `network: macvtap`.** A VM can attach directly to
  the physical LAN through a macvtap device on the host NIC, pulling its own DHCP lease as a first-class
  LAN host (reachable on every port, e.g. SMB/445) while keeping a pod NIC for in-cluster access. Opt-in
  via `networking.vmLan`; the installer wires Multus (as the primary CNI delegating to Cilium), the
  macvtap device plugin, and the KubeVirt binding, and auto-labels nodes that carry the LAN NIC. The
  earlier `network: bridge` mode is superseded — a macvlan sub-interface cannot be a KubeVirt bridge port.
  See [`docs/virtual-machines.md`](docs/virtual-machines.md).

### Portability

- **Configurable audit-log source path.** The audit-trail features (off-siting and the console CloudTrail
  view) read the API-server audit log from a configurable host directory (`cluster.auditLogDir`, default
  the k3s path) rather than a hard-coded k3s location, with an install-time preflight that warns when the
  node's audit log isn't where configured — so the audit trail works on non-Rancher distributions. See
  [`docs/portability.md`](docs/portability.md).

## v2.6.0 — 2026-08-16

### Security & compliance
- **Signed compliance attestation.** A **Security & Identity → Attestation** console page (and
  `/api/compliance/attestation`) shows live NIST 800-53 control coverage with evidence gathered from
  the cluster right now — grants, classifications, customer keys, destruction certificates, data
  flows, off-site audit-chain head — not a static claim. An opt-in daily CronJob snapshots each
  attestation immutably to the WORM audit store (`attestations/<date>/`), and the same document can be
  GPG-signed out-of-band with the release key (kept out of the cluster) and verified with the
  published public key. Controls: CA-2/CA-7, AU, SI-12. See [`docs/compliance-attestation.md`].
  Completes the government feature *build* track — the control machinery is now shipped;
  certification itself remains external, lives with the deployer's substrate, and is a maintained state,
  not a shipped feature.
- **Data lineage — provenance of data movement.** A new **Data → Lineage** console page (and
  `/api/lineage`) reads the DataFlow, Migration, Replication, and Stream topology and shows every data
  movement — source → sink, with its type — so you can trace where data comes from and where it goes.
  Derived from live resources (can't drift) and assembled server-side (so the compliance attestation
  can vouch for it). Controls: SI-12 / AU. See [`docs/lineage.md`]. Part of the government feature track.
- **Crypto-erase — `kind: Destruction` (NIST SP 800-88).** Destroying a customer-owned key makes every
  byte it wrapped — primary, replica, backup, snapshot — permanently unrecoverable, the fast provable
  alternative to overwriting terabytes. A `Destruction` names an `EncryptionKey` and must repeat its
  name in `confirm` (a typo-guard); a dedicated destroyer (separate, more-privileged than the key
  reconciler, which cannot destroy) crypto-erases the Vault Transit key and writes an immutable
  **destruction certificate** to the WORM audit store, while the request's lifecycle is captured
  tamper-evidently in the off-sited audit log. Admin-only, opt-in. Controls: MP-6, SP 800-88, AU. See
  [`docs/destruction.md`]. Part of the government feature track.
- **Encryption with customer-owned keys.** A new opt-in `encryption` component: `kind: EncryptionKey`
  provisions a customer-owned key in a HashiCorp Vault **Transit** KMS (open-infra never sees the key
  material), a reconciler creates/rotates it and reflects its state on the console **Security &
  Identity → Encryption Keys** page, and an additive encrypted Longhorn StorageClass (LUKS) plus a
  documented MinIO SSE-KMS / etcd-KMS runbook wire storage layers to it. Destroying a key crypto-erases
  what it protects (the basis for the next item). Off by default; Vault is operator-initialized.
  Controls: SC-12/13/28/28(1). See [`docs/encryption.md`]. Part of the government feature track.
- **`kind: DataClassification` — categorize data, then check its handling.** A DataClassification names
  a sensitivity level (public→restricted) and the handling requirements data at that level must meet
  (encryption at rest, network restriction, no public exposure, backup, residency, retention). Tag a
  workload with `openinfra.dev/classification=<name>` and the console **Security & Identity → Data
  Classification** page (and `/api/compliance/classification`) reports whether it meets its class —
  checking public exposure, network restriction, and residency from the live cluster today, and
  reporting not-yet-verifiable requirements honestly as unknown. Admin/security-team managed (not
  grantable by a Policy). Controls: RA-2, MP-3, AC-4/SC-28. See [`docs/data-classification.md`].
  Part of the government feature track.
- **Audit off-siting — a tamper-evident, immutable copy of the audit trail.** The API-server audit log is
  now shipped off the node it is written on, as a SHA-256 **hash chain** of segments, into a MinIO bucket
  under **Object Lock (COMPLIANCE mode)** — undeletable by anyone, including root, until retention expires
  (default ~7 years). An hourly job re-verifies the whole chain from the segments' own contents and the
  console **Audit** page shows whether it is intact; any deleted, reordered, or edited segment (or record)
  is detected. An optional external S3 sink keeps a copy on a separate system. Controls: AU-9, AU-9(2),
  AU-9(3), AU-11. See [`docs/audit-offsite.md`]. Part of the government feature track.

### Console
- **Live disk usage on the Nodes page.** Each node card now shows root-filesystem utilization —
  used / total with a fill bar (amber past 75%, red past 90%) — beside CPU, memory, and pods. The
  figure is read live from the cluster's Prometheus (node-exporter) through a BFF endpoint gated by
  the same `list nodes` permission as the page, refreshes on its own, and is simply omitted when no
  metrics backend is reachable.
- **Resource creation, rewritten.** Creating a resource is moving from cramped modal
  pop-ups to a full-page, schema-driven experience: essential fields up front with everything else
  under a collapsed **Advanced settings**, optional fields marked (rather than required), inline help
  drawn from each field's CRD description, a live **YAML preview** of exactly what will be applied, and
  a Create button that is never disabled — it validates and shows precise inline errors. **Application**
  is the first resource on the new flow (a full page at `/applications/new`); the remaining kinds
  follow, all sharing one create framework instead of a bespoke dialog each.
- **`kind: GraphQLApi` console feature.** A **GraphQL** section under Compute: a live list, and a detail
  page with **Test / Overview / Schema / Resolvers / Data sources / Subscriptions / YAML** tabs and a
  Danger Zone. The **Test** tab renders a resolver's request/response mapping templates against a sample
  `$ctx` (no data source touched) via the engine's `/test-resolver`, proxied through a BFF route that
  verifies the target engine Service. List, create, and delete use the standard RBAC-gated Kubernetes proxy.

### Abstractions
- **Configurable storage class — portability off Longhorn.** The data-plane kinds now take an optional
  storage class: `spec.database.storageClass` on managed databases, and `spec.storageClass` on `Stream`,
  `DataFlow`, `Migration`, `Directory`, `FileShare`, and `VMImage`. Each keeps its previous default, so
  existing resources are unchanged — the six `spec.storageClass` kinds default to `longhorn`, and managed
  databases to `local-path` (Longhorn only where an engine needs node-independent storage). Point it at
  any cluster StorageClass (`local-path`, a CSI driver, an operator-provided class) to run those planes
  where Longhorn is not present. Not yet configurable: VM root disks and standalone `Volume`s still pin
  `longhorn`/`longhorn-migratable` (live-migration needs the RWX class). Mirrored in the Terraform provider.
- **`kind: Grant` — temporal (just-in-time) access.** A Grant binds a User or Group to a ClusterRole for
  a bounded duration with a recorded reason, then revokes itself — the analog of AWS STS AssumeRole with a
  session duration, and an answer to standing privilege. What it can confer is deliberately narrow: a
  `kind: Role` or one of the two bounded built-in console roles, never full admin or a provider role (the
  composition renders no binding otherwise). A once-a-minute reconciler removes a Grant when
  `creation + duration` passes (hard-capped at 24h; anything invalid or over-cap is revoked, not kept), and
  Crossplane tears down the binding with it; the reconciler is itself alerted on so expiry can't silently
  stall. The grant and its revocation are audited. Government controls: AC-2(2), AC-6(2)/(5), AU. Part of the
  government feature track.
- **open-appsync — GraphQL query execution.** Named and inline fragments (with unknown-fragment and
  cycle rejection); variable coercion against declared wrapped types (nullability, lists, enums, and
  input objects with defaults; mismatches rejected as `ValidationError`); nested `__typename`;
  `@skip`/`@include`; per-nested-field resolvers (a field declared with `type: <ObjectType>` runs its own
  resolver with the parent object as `$ctx.source`); interface/union polymorphic dispatch (type
  conditions applied against each object's concrete type); and multiple operations per document selected
  by `operationName`.
- **open-appsync — schema type system + introspection.** `spec.schema` (SDL) parses into an in-memory
  type graph; `__schema`/`__type` answer over it, and standard GraphQL tooling (graphql-js
  `buildClientSchema`, graphql-codegen) builds a client schema and TypeScript types from the result.
  Introspection is a toggle on the hostile-load seam — `spec.limits.introspection`: `enabled` (default),
  `disabled`, or `authenticated-only`.
- **open-appsync — AWS auth directives.** The five AppSync auth directives are parsed and reported in
  introspection, and all five are enforced through open-infra's single policy world (Kubernetes SAR):
  `@aws_api_key` (a key maps to a Kubernetes identity, configured in a Secret), `@aws_iam` (SigV4 verified
  at the aws-shim), `@aws_oidc` / `@aws_cognito_user_pools` (OIDC/Cognito JWT verified at the shim;
  `@aws_cognito_user_pools(cognito_groups:)` requires the caller's groups to include one of the named
  open-infra groups, fail-closed), and `@aws_lambda` (a Lambda-authorizer `kind: Function` invoked at the
  shim — see below). Enforcing these relocates authorization to Kubernetes RBAC — group rules become RBAC
  bindings — which a migrating schema must account for. `@aws_subscribe` declares a subscription's
  triggering mutations in the SDL.
- **open-appsync — data sources.** Added a **NONE** source (`type: none`): a resolver with no backend,
  resolved entirely in the mapping templates (the request template's `payload` becomes `$ctx.result`) —
  for pub/sub-only fields, local computation, and stitching. Added a **Lambda** source (`type: lambda`):
  a resolver invokes a `kind: Function` over HTTP with AppSync's Invoke payload shape and the function's
  JSON response becomes `$ctx.result`. Added an **OpenSearch** source (`type: opensearch`): search/index
  requests to an OpenSearch domain in AppSync's `{operation, path, params}` shape, returning the response
  JSON, with optional HTTP basic auth from a Secret. Added an **RDS** source (`type: rds`): SQL over
  PostgreSQL/Aurora-PostgreSQL in AppSync's
  `{statements, variableMap}` shape, with `:name` parameters bound safely (never interpolated) and rows
  returned as JSON; the connection string comes from a Secret (`connectionSecret`), never the CR. Added an
  **EventBridge** source (`type: eventbridge`): a `PutEvents` operation publishes each entry to the
  platform NATS event bus and returns a PutEvents-shaped receipt (per-entry `EventId`, or an error entry,
  with `FailedEntryCount`) — a *publish* source rather than call-and-return, wired to the platform NATS by
  default (or a NATS URL via `endpoint`). All sit behind the same neutral data-source contract as the
  DynamoDB and HTTP sources. Custom scalars are
  validated through a neutral per-scalar seam, with AWS scalar formats (AWSDateTime, AWSJSON, and others)
  supplied at the edge. Byte-exact fidelity against a live AWS round trip is a separate later item per source.
- **open-appsync — multi-replica subscriptions.** Each engine replica consumes the subscription event
  stream with its own ephemeral consumer, so subscriptions fan out correctly when the engine runs more
  than one replica; event durability remains in the stream.
- **open-appsync — Prometheus metrics.** The engine now exposes `/metrics`: request rate, error rate,
  latency and concurrency (by outcome and authentication mode); per-data-source-type backend health
  (Execute count and latency by source type and outcome, captured behind the neutral data-source
  contract); and live subscription connections. The platform's Prometheus discovers every engine
  automatically through one ServiceMonitor, installed and removed with the monitoring stack. Metric
  labels are bounded so a crafted query or header cannot explode cardinality, and no request content
  is recorded.
- **open-appsync — default-deny, pod-scoped ingress for the engine.** Each GraphQLApi renders an
  ingress-only NetworkPolicy so the engine's ClusterIP answers only its legitimate front doors, each
  scoped to a specific namespace **and pod**: the aws-shim (the SigV4/JWT/Lambda-authorizer front door),
  the console BFF (Test Resolver), and Prometheus (metrics). Because the engine trusts the identity headers
  the shim sets, any pod that could reach it might forge them — so there is no blanket same-namespace
  allow: a co-tenant pod cannot reach the engine and impersonate (defense in depth; SC-7 boundary
  protection, secure by default). Egress stays open so resolvers reach their data-source hosts.

### AWS compatibility
- **Lambda — async (`Event`) + `DryRun` invocation, and per-function memory/timeout.** The aws-shim's
  Lambda service now supports all three invocation types: `RequestResponse` (synchronous, as before),
  `Event` (asynchronous — the shim durably queues the payload to JetStream and returns `202`; a
  background worker delivers it to the function with retries and dead-lettering, surviving shim restarts
  and shared across replicas; refused with `503` if the shim has no NATS, never silently dropped), and
  `DryRun` (runs the authorization SubjectAccessReview and returns `204` without invoking). `kind:
  Function` gains `memory` (a Kubernetes quantity → guaranteed container memory) and `timeout` (seconds →
  the Knative revision timeout) — the AWS Lambda memory-size and timeout knobs — mirrored in the
  Terraform provider. Management APIs (CreateFunction, versions/aliases, layers) remain deliberately
  un-fronted; Functions are managed declaratively as `kind: Function`.
- **open-appsync — per-resolver response caching.** A resolver can declare `caching: { ttlSeconds, keys }`
  (AppSync's caching behavior): the engine serves a cached response and skips the data source on a hit,
  and stores the result for the TTL on a miss. It is best-effort (a miss or backend error just runs the
  resolver — correctness never depends on it) and **never caches Mutations**. The cache key always folds
  in the caller identity on top of the author's `$context` keys, so per-user data can't be served across
  callers even if an identity key is omitted — safer than AppSync, where omitting it silently shares one
  entry. Two backends behind one contract, chosen at load: a **shared NATS JetStream KV** bucket (one per
  API) when the engine has NATS, so every replica sees the same entries like AppSync's external cache;
  otherwise a per-process in-memory cache (per-replica, never wrong). Both are best-effort, so a NATS
  failure degrades to per-replica caching, not a broken engine; the shared backend's live round-trip is
  integration-tested. This completes the data-source / caching breadth: memory, none, dynamodb, http,
  lambda, rds, opensearch, eventbridge, plus caching.
- **open-appsync — @aws_lambda enforced: all five AWS auth modes now gate fields.** The last auth mode
  graduated. The aws-shim invokes the API's **Lambda authorizer** (a `kind: Function`) with the caller's
  token in AppSync's authorizer event shape; on `isAuthorized` the authorizer's `resolverContext` supplies
  the subject + groups, which the shim namespaces and forwards as auth mode `aws_lambda`, and the engine
  gates `@aws_lambda` fields on it and runs the field's SAR — the same one policy world as every other
  mode, never a parallel auth layer. Any authorizer error or denial fails closed. It is mutually exclusive
  with OIDC/Cognito (both own the single non-SigV4 token path). The authorizer's `deniedFields` and
  `ttlOverride` are deliberately **not** honored — honoring `deniedFields` would relocate field
  authorization into the tenant's Lambda, outside the one policy world; field-level control stays with the
  resolver's SAR auth. (Migration cost stated where it's configured and in introspection.)
- **open-appsync — the JS runtime now runs real APPSYNC_JS unmodified and is behavior-faithful too.**
  `jsruntime` now accepts a **real APPSYNC_JS module** (`import { util } from '@aws-appsync/utils'` +
  `export function request/response`) — the only shape AWS accepts (verified: a bare top-level function
  gets `MISSING_MAPPING_EXPORT`), which goja can't parse. The engine strips the ES-module framing (it
  injects `util` as a global) so a team's existing APPSYNC_JS resolver runs here unchanged. A second
  goldens harness (`probe/goldens-js/`) diffs those same modules against real AWS via the `evaluate-code`
  API and is green — so the JS runtime is **behavior-faithful**, sharing the same `$util` as the VTL
  runtime.
- **open-appsync — the runtime is now behavior-faithful: goldens captured from real AWS AppSync, two
  fidelity bugs fixed.** The runtime goldens (`open-appsync/probe/goldens/`) were captured from a live
  AppSync account via the `evaluate-mapping-template` API (one turnkey command, `capture.sh`) and the CI
  diff is green against them — so `$util`/VTL output is checked against what AppSync *does*, not just
  what it documents. The capture immediately surfaced two real divergences from the DynamoDB-SDK shape
  we'd assumed, now fixed in the engine: AppSync emits **`N` as a JSON number** (`{"N":36}`, not
  `{"N":"36"}`) and **`NULL` as JSON `null`** (`{"NULL":null}`, not `{"NULL":true}`); `fromDynamoDB`
  normalizes either form back to plain values. The corpus was also broadened to the fidelity-critical
  set (nested map / list / null / bool / int / negative / float / string, composite keys, multi-attribute
  PutItem). This clears the runtime maturity gate — the runtime is no longer labeled experimental
  (the authoring plane and subscriptions keep their own separate gates; the JS runtime's
  fidelity gate is cleared by the entry above).

### Abstractions
- **open-appsync — open-infra's own AppSync engine (opt-in, experimental, OFF by default).**
  The AppSync surface is aimed at teams locked into AWS AppSync by their resolver investment (VTL
  templates, data-source wiring, `$util` helpers), so the engine is **resolver-first and
  VTL-faithful** by design — not GraphQL-over-tables wearing a mask (that would be a leaky
  abstraction the moment a specialist writes a resolver it can't model). **Slice 1 — VTL over one
  DynamoDB-style data source — runs live:** `components.openAppsync` deploys the real engine
  (`cmd/open-appsync`), and on-cluster a SigV4-signed GraphQL client → the shim → open-appsync → a
  real VTL resolver (with `$util.dynamodb` typed marshalling, `$util.autoId`, etc.) → the data
  source (in-memory, or FerretDB for durable) → `{data}`. It stays **experimental**: VTL/`$util`
  fidelity is anchored on AWS's *documented* behavior (a corpus probe, green in CI), not diffed
  against a live AWS AppSync. (Replaces the earlier Hasura-backed AppSync placeholder, now removed.)
- **open-appsync — neutral authoring plane, a real runtime extension point, and a test-resolver loop
  (experimental — a new rung, on its own bar).** Two independent maturity gates, kept separate: the
  *runtime* de-labels only when its goldens are captured from real AppSync (below); this authoring
  work ships labeled experimental regardless of the runtime's maturity.
  - **The `runtime` field is a genuine extension point** (`internal/runtime`), not a name for AWS's two
    dialects. A three-term frozen contract — In (`$ctx`), Out (a **neutral data-source Operation**),
    Error/null — lets a third party add a runtime we never wrote, which AWS structurally can't allow.
    VTL is extracted into the *first tenant* (`internal/vtlruntime`) and drives the resolver lifecycle
    through the public interface with **no backstage pass**; a second, trivial runtime proves the seam
    in tests. The interface stays internal/changeable until a real second tenant lands.
  - **`kind: GraphQLApi`** — the neutral authoring plane. **One** object carries a schema plus inline
    data sources and resolvers, each resolver declaring a `runtime` (today `appsync-vtl`) and its
    inline request/response templates. It renders exactly like `kind: HttpApi` (XRD + go-templating
    Composition, **no bespoke controller**) into a ConfigMap in the shape the engine already reads +
    the engine Deployment/Service, with a config-checksum annotation that rolls the pod on change.
    Deliberately one kind, not AWS's separate `Resolver`/`DataSource` management nouns. **Fail-closed:**
    the engine validates every template on load and an **invalid resolver never serves** (the pod stays
    not-ready with the parse error) — not "rejected at apply instant" (there is no webhook). A
    specialist's VTL is byte-for-byte identical inside the `runtime` field — **zero retraining**; only
    the person wiring resolvers sees a new envelope, and Stage 2 (later) makes AWS's `CreateResolver`
    a patch onto this same object. Grantable via `kind: Policy` (added to the boundary in all its
    synchronized copies), render-tested, and mirrored in the Terraform provider (`openinfra_graphql_api`).
  - **`POST /test-resolver`** — the probe harness on user input: submit a resolver + a sample `$ctx`
    and see exactly what its templates produce (the neutral request Operation, and the response when a
    sample result is supplied), errors surfaced with their `errorType`. Authoring with feedback.
  - **Runtime goldens harness (`probe/goldens/`, the runtime gate).** The format, the deterministic diff (via
    the engine's injectable `AutoID`/`Now`), and the CI wiring ship now, green against goldens seeded
    from AWS's *documented* behavior; a status test reports how many are still documented vs captured.
    Capturing them from a real AppSync account (maintainer, once) and turning the diff green is the
    **only** thing that removes "experimental" from the runtime.
- **open-appsync — Stage-2 AWS management wire protocol: AWS AppSync tooling drives open-infra
  unchanged (experimental; per-verb graduation).** The aws-shim now fronts the AppSync **management**
  plane at `/v1/...` (told apart from the GraphQL data plane by path; both sign for service `appsync`).
  It translates AWS management verbs into a **patch on the neutral `kind: GraphQLApi` object** —
  `CreateResolver`, `UpdateResolver`, `DeleteResolver`, `GetResolver`, `CreateDataSource`,
  `DeleteDataSource` so far — so CloudFormation/CDK/`aws appsync ...` can author on open-infra without
  changes. The **skin owns AWS's `(apiId, typeName, fieldName)` identity mapping** (apiId =
  `<namespace>.<name>`); the neutral kind never learns AWS addressing. AWS's `APPSYNC_JS` runtime maps
  to `appsync-js`, `AMAZON_DYNAMODB`/`HTTP` data-source types to `dynamodb`/`http`. The caller is gated
  by the same impersonated `SubjectAccessReview` as every other front door (`update graphqlapis` in the
  target namespace, cluster RBAC added for the shim SA), and an unhandled verb answers an honest
  `NotImplemented`. Front door + negatives proven; end-to-end (a real CloudFormation stack) reserved,
  and the docs say exactly the verbs proven — never "AppSync management API compatible".
- **open-appsync — the durable subscription bus at runtime, the node-kill chaos instrument, and a
  turnkey goldens capture (the two remaining gates driven as far as code can go).** The NATS JetStream
  bus now compiles into the engine binary and is selected at runtime when `NATS_URL` is set (durable,
  multi-node, reconnect/resume across a node kill) — otherwise the single-node in-memory bus; its live
  test is `integration`-tagged. The **node-kill chaos scenario** (`chaos/scenario-subscription-
  reconnect.sh`) is now **self-provisioning and runnable** (status PENDING): it deploys a 2-replica
  open-appsync engine wired to the platform NATS JetStream (`chaos/sandbox/appsync-engine.yaml` +
  `lib-sandbox.sh` helpers), drives createTodo mutations across an engine-pod kill, and asserts every
  acknowledged onCreateTodo event survives on the durable subject — the proven `scenario-stream-noloss`
  message-count oracle. Keyless, so it is NOT in the lottery; runnable via workflow_dispatch and
  graduates after its green streak (no verified green yet — the honest PENDING state). And
  **`probe/goldens/capture.sh`** makes the runtime-goldens capture one command against a real AWS account (via
  `aws appsync evaluate-mapping-template`). These are the two external gates — the nightly chaos green
  streak and the real-AWS capture — reduced to a single run each; the label stays experimental until
  those runs happen, on the cluster's / the maintainer's clock.
- **open-appsync — subscriptions: the WebSocket front door (`graphql-transport-ws`), wiring the rung
  end-to-end (experimental; label still HELD for the chaos bar).** The engine now serves subscriptions
  at **`/graphql-ws`** over the modern graphql-transport-ws protocol (connection_init/ack, subscribe,
  next, complete) — proven end-to-end with a real WebSocket client. A subscription's **arguments become
  an equality filter** (AppSync's default: `onCreateTodo(owner:"ada")` receives only `owner == "ada"`
  events). A **successful mutation auto-publishes** to the subscriptions it triggers, via a minimal
  executor publish hook (fires on mutations, never on queries). Declarable on `kind: GraphQLApi`
  (`spec.subscriptions[]`: field, response, triggeredBy, auth, subject) and mirrored in the Terraform
  provider; the deployed demo serves `onCreateTodo`. The default engine uses the single-node in-memory
  bus; the durable multi-node JetStream bus is the `integration`-tagged build. **The label stays held:**
  the remaining gate is the *temporal* node-kill chaos run — the transport is wired, the proof is not.
- **open-appsync — subscriptions: the setup-then-push semantic core (experimental; label HELD for a
  temporal chaos bar).** Subscriptions invert the lifecycle — subscribe (authorize + register a filter),
  publish (a mutation's result to a subject), push (each node fans out to its matching local
  subscribers) — so they are their own lifecycle, and their event source is a **push source (a Bus),
  NOT a `datasource.Store`** (the same call-vs-stream split the data-source contract draws). Built and unit/integration-proven: the **enhanced
  subscription-filter engine** (eq/ne/in/contains/beginsWith/ranges, dotted fields, AND-within /
  OR-across — the genuinely hard part), the connection-scoped **registry** with naive O(subscribers)
  fanout (a filter index deferred until load proves it's needed), a **Bus port** with an in-memory bus
  and a **NATS JetStream** bus (`integration`-tagged; a durable consumer gives reconnect/resume), and
  the **Manager** (setup-then-push, subscribe-time auth gate, filtered fanout — proven end-to-end).
  **The label is held on purpose:** this rung's graduation bar is *temporal, not a unit test* — a
  node-kill chaos run proving reconnect/resume with no lost/duplicated events past the ack point, on the
  nightly clock — plus the WebSocket front door (the "easy half"). The code is done; the proof is not,
  and the CHANGELOG says exactly that.
- **open-appsync — field-level authorization: one policy world, now at field granularity
  (experimental).** A resolver may declare an `auth` requirement (a k8s RBAC verb on a resource). The
  executor consults an injected authorizer **before** running the field's resolver; on denial the field
  is `Unauthorized` and null, and the resolver — and its data source — **never runs** (proven by a
  negative probe). The production authorizer (`internal/k8sauth`) performs an **impersonated
  `SubjectAccessReview`** against the cluster — the *same* RBAC + permission boundary the console,
  Terraform, and the aws-shim use, so this is not a parallel rule engine. The caller's identity comes
  from the shim's SigV4→principal chain (headers `X-OpenInfra-User`/`-Groups`) and is exposed to
  templates as `$ctx.identity`. Authorization is a lifecycle concern — no auth vocabulary leaks into the
  neutral runtime/step contract. Out of cluster the engine logs loudly that field auth is not enforced.
  Expressible on `kind: GraphQLApi` (`resolvers[].auth`) and the Terraform provider. (SAR done over lean
  REST — no client-go — so the engine stays small and the whole path is httptest-covered.)
- **open-appsync — the data-source family: a neutral `Store` contract + an HTTP source, proving the
  operation model is genuinely neutral (experimental).** The call-source contract (`datasource.Store`)
  moved into its own package — out of `dynamodb` — so nothing in the engine or resolver lifecycle owes
  anything to one source's shape. A second, differently-shaped call-source (`internal/httpsource`,
  operations like `{"method":"POST","resourcePath":"/x","params":{…}}`) now flows through the **exact
  same** lifecycle and executor as the DynamoDB store, coexisting in one engine — with **no code path
  branching on data-source type** (only a `Store` knows its own shape). This answers the "is the neutral
  Operation genuinely neutral, or a DynamoDB op in a trench coat" question: genuinely neutral. Declared
  on `kind: GraphQLApi` via `dataSources[].type: http` + `endpoint`, and mirrored in the Terraform
  provider. (A subscription's push source remains a separate thing — not a `Store`.)
- **open-appsync — a second runtime tenant: sandboxed JavaScript resolvers, which BLESS the runtime
  interface stable (the runtime rung is experimental; the interface claim is not).** `runtime:
  appsync-js` lets a resolver carry a JavaScript module (`request(ctx)`/`response(ctx)`) instead of VTL.
  It is the second, real, non-VTL tenant of the extension point — and it runs through the exact same
  lifecycle and executor as VTL, coexisting in one registry with no backstage pass (proven end-to-end:
  a JS PutItem + GetItem, a JS resolver beside a VTL one, a JS `util.error()` surfacing its errorType).
  That second tenant is the bar for **calling the runtime interface stable**, so it
  now is — a statement about the *interface*, distinct from JS-as-a-runtime, which ships experimental
  like any rung. **Sandboxing:** JS runs on goja (pure-Go ECMAScript) with **no** `require`/Node
  APIs/fs/net/fetch/timers — capability-by-injection, deny-by-absence; the only capability is the
  injected `util` (the *same* `$util` implementation as VTL — no drift). A resolver reaching for
  ambient capability fails closed, proven by a negative probe (prove the "no"). A malformed module
  fails Load closed. Expressible on `kind: GraphQLApi` (`runtime: appsync-js`, module in `request`) and
  the Terraform provider.
- **open-appsync — the step/lifecycle fork, pipeline resolvers, and hostile-load hardening
  (experimental; three independent rungs, each on its own bar).**
  - **The runtime contract is the STEP contract, not the resolver contract.**
    `runtime.Runtime` was derived from the one shape that existed (unit resolver) and its Out term baked
    in "every step targets a data source" — which pipelines bend and subscriptions break. Resolved
    *before* the Terraform/ConfigMap surface hardened: the Out term is now **optional** (a step may
    return a nil Operation = "transformed `$ctx` only; no data-source call"), `Runtime` is re-documented
    as one **step**, and a **lifecycle** layer composes steps. `unit` is byte-identical to slice 1 (its
    tests pass unchanged). The data-source parallel is named too: `Store.Execute` is the **call-source**
    contract (DynamoDB/HTTP/Lambda/RDS fit "call → result"); a subscription's push source is a separate
    thing, not a `Store`. This is what keeps pipelines/subscriptions **extensions**, not forks.
  - **Pipeline resolvers.** `before → [function…] → after`, with `$ctx.stash` shared across steps and
    `$ctx.prev.result` threaded function-to-function; `before`/`after` are no-Operation steps. Proven
    end-to-end (before → 2 functions → after, stash threaded, a before-step that emits no Operation, and
    an abort that stops the pipeline before any function runs) at the resolver, config-loader, and HTTP
    levels. Expressible on `kind: GraphQLApi` (`resolvers[].before/after/functions[]`) and in the
    Terraform provider.
  - **Hostile-load hardening (safe by default).** The neutral engine now enforces, before any resolver
    runs: query **depth** limiting, **cost** (field-count) limiting, and an optional **persisted-query**
    allow-list. Defaults are ON (depth 10, cost 1000); `kind: GraphQLApi`'s `limits` block tunes them; a
    negative value is an explicit opt-out. Each guard has a negative probe proving the rejection fires.
    Honest label until each rung graduates: *trusted-client / internal use* — not yet "safe against
    hostile load" as a blanket claim.
- **`kind: HttpApi` — an API-Gateway-style HTTP front door.** Declare a `domain` and a list of
  `path → backend` routes onto `kind: Function` or `kind: Application` backends; the composition
  renders one Traefik Ingress with cert-manager TLS. It's the genuine capability expressed as a
  first-class kind over the pieces open-infra already has (Traefik + Knative + Functions), not an
  emulator — the AWS API Gateway management wire protocol can be fronted by the shim later, on top
  of this real backend. Grantable via `kind: Policy` (added to the permission boundary in all its
  synchronized copies), render-tested, and mirrored in the Terraform provider (`openinfra_http_api`).

### AWS compatibility
- **An AWS-SDK shim — unmodified AWS SDK apps can talk to open-infra (experimental, opt-in, OFF
  by default).** A new server-side component (`kind`-less platform service `aws-shim`) presents an
  AWS-shaped front door: an app pointed at it via `AWS_ENDPOINT_URL` believes it is talking to AWS,
  and the shim verifies the request's SigV4 signature against an open-infra access key, resolves
  the caller to their open-infra principal, enforces the **same** RBAC + permission boundary as the
  console (the shared `internal/iam` authorization core — one policy world, not a parallel auth),
  calls the real backend, and re-dresses the response in AWS's byte-shape. It is **not** an
  emulator: it fronts durable backends. Its first fronted service is **S3 over MinIO** (put/get/
  head/delete/list, S3-faithful ETags/headers/error codes) — proven **byte-faithful** by a
  compatibility probe (`probe/aws-shim-s3.sh`) that fires real AWS SDK calls and asserts identical
  bytes plus the two negatives that earn the trust: a valid key ID with a wrong secret is rejected
  (no authentication theater), and a reader attempting a write is denied by the boundary. Access
  keys are a sub-resource of `kind: User`, stored one-Secret-per-key (the store holds the real
  secret because SigV4 verification is symmetric). v1 authorization is a real but coarse read-vs-
  write gate; per-bucket authorization + per-principal MinIO identity are the flagged graduation
  steps. Validated end-to-end against a live deployment (real AWS CLI v2 → the shim → MinIO): the
  byte-identical round-trip and both negatives pass. **aws-chunked** uploads (the framing an AWS
  SDK adds when it sends a trailing checksum) are decoded before storage so the object is stored
  raw, not with the chunk framing — guarded by a decoder unit test and a probe step that *forces*
  a chunked upload (`--checksum-algorithm CRC32`) and asserts byte-identity. Enable with
  `components.awsShim: true`. See [docs/aws-shim.md](docs/aws-shim.md).
- **The shim is now multi-service — a router with pluggable per-service handlers.** It authenticates
  SigV4 once (shared, so no handler grows its own weaker auth) and dispatches by the AWS service the
  client signed for. Beyond S3 it now fronts **STS** `GetCallerIdentity` (the identity check tooling
  probes first — it reflects the SigV4-proven principal as an open-infra ARN, no backend to get
  wrong) and **Lambda** `Invoke` over `kind: Function`/Knative (`POST …/functions/{name}/invocations`
  → the Function's cluster-local address, authorized by the same impersonated SubjectAccessReview,
  with Lambda's JSON error dialect). Each service carries its own decoder, authorization mapping, and
  error dialect. Services whose backend speaks a different wire protocol (DynamoDB→Mongo, …) are
  deliberately **not** stubbed — they return an honest `501` and graduate the same gated way (built →
  probed → counted), because narrow and proven beats broad and hand-wavy.
- **AppSync (GraphQL) is a fronted service — front door proven, engine (open-appsync) not yet.**
  The shim's `appsync` handler SigV4-verifies a GraphQL `POST {query,variables}`, runs the coarse
  impersonated `SubjectAccessReview` gate, and forwards to the **open-appsync** engine
  (`components.openAppsync`), conveying the verified principal as the engine's auth context
  (`X-OpenInfra-User`) and never forwarding client headers. open-appsync is our own engine, so it
  enforces fine-grained authz internally against the same principals — no foreign admin secret, no
  vendor role header. The front-door auth is unit-tested; the engine is a placeholder and **un-proven**
  until its slice-1 compatibility probe (VTL over a data source, against real AppSync) lands. See
  [docs/aws-shim.md](docs/aws-shim.md).

### Observability
- **The audit trail is now observable — a console "Audit" view (CloudTrail).** The
  Kubernetes API-server audit log — the authoritative who-did-what record, carrying
  `impersonatedUser` so console/`kubectl`/Terraform/Argo actions are all attributed to a
  person — used to live only on the control-plane node's disk: recorded, but greppable
  only over SSH. promtail now ships it to Loki (job `k3s-audit`, mutations + authorization
  decisions; reads dropped to keep it lean — the full record stays on disk), and a new
  **Security & Identity → Audit** page renders it, filterable by user / resource / time.

  The BFF `/api/audit` endpoint (admin-gated by the same SubjectAccessReview as IAM) merges
  two streams into one person-attributed trail: the API-server audit log, and the console's
  own `iam:` logs — needed because the BFF-native IAM handlers act as the ServiceAccount, so
  the audit log alone would attribute "create user" to the SA, but the console logged
  `by=<person>`. Degrades gracefully if Loki is unavailable.

### Security
- **The permission boundary can no longer silently drift.** `kind: Policy`'s boundary is
  spelled out in five hand-maintained copies — the composition whitelist, the provider RBAC
  grant, the BFF `policyResources`, the XRD claim plurals, and `policy-boundary.yaml`. A new
  CI test (`TestPolicyBoundaryNoDrift`) asserts all five agree, so widening the boundary in
  one place without the others fails the build instead of quietly granting (or dropping) an
  action. Item 1 of the schema-drift spec: *verify, don't generate* — the boundary is never
  auto-derived, only checked.
- **The embedded Grafana was readable without signing in.** The console's `/grafana/*`
  reverse proxy was mounted outside the `/api` auth gate, and Grafana runs with anonymous
  Viewer for the dashboard kiosk — so anyone who could reach the console, including an
  unauthenticated caller on an internet-exposed one, could read every dashboard, metric and
  log. It now sits behind a session gate (`requireSignedIn`) that still allows Grafana's own
  `POST /api/ds/query` panel calls (which lack the console's CSRF header).
- **The console BFF no longer uses the MinIO root credentials.** It now runs as a scoped
  `openinfra-console` user (MinIO's `readwrite` policy: full S3 CRUD for the bucket browser,
  but no admin API), minted by a Sync hook. Defense-in-depth: a bug misusing the S3 client
  can no longer reach MinIO's user/policy/server admin surface.
- **The Trino query engine is locked down.** Trino runs untrusted, user-supplied SQL but had
  no `securityContext`; it now matches the per-query pod hardening — non-root, no privilege
  escalation, all capabilities dropped, read-only rootfs, seccomp `RuntimeDefault`, and no
  ServiceAccount token.
- **A standing banner when auth is disabled.** With `AUTH_MODE=none` the console API is
  unauthenticated (anyone who reaches it has cluster admin); previously the only signal was a
  startup log line. The SPA now shows a persistent, non-dismissable security banner on every
  page whenever auth is off.
- **Fault injection is off by default (behavior change).** The Chaos surface is no longer
  shown in the console unless a deployment sets `CHAOS_UI_ENABLED=true` — least functionality
  (NIST CM-7): a privileged, break-things tool should not sit one click from Monitoring. The
  BFF exposes `chaosUiEnabled` in `/api/config`; the SPA hides the nav item, the command-
  palette entry, and the `/chaos` route unless opted in.
- **A NIST 800-53 security & compliance posture is now documented** ([docs/security-and-compliance.md](docs/security-and-compliance.md)):
  an honest, control-level implementation mapping (AC/AU/IA/SC/CM/SI/CP) plus the continuous
  flaw-remediation loop (Trivy → code-scanning → Dependabot → CI), framed as
  control-implementation evidence, not a certification claim. It also records the platform's
  substrate portability and a point-in-time validation: open-infra was deployed and chaos-tested on a
  certified FIPS-mode substrate (SLES 15 + RKE2) — evidence of running on a certified base, not a
  certification of open-infra itself.

### Reliability
- **A public, auto-generated chaos-scenario gallery** ([docs/chaos-scenarios.md](docs/chaos-scenarios.md),
  linked from the [README](README.md#continuous-chaos-testing)). One Mermaid diagram per scenario shows
  the resource **chain**, the **⚡ fault-injection point**, and the **invariant** that must hold
  (recover / tolerate / deny) — so anyone can see what we break nightly and what's expected to survive.
  It's generated from a single source-of-truth ([`chaos/scenarios.json`](chaos/scenarios.json)) by a
  stdlib-only Go tool ([`tools/chaosdoc`](tools/chaosdoc)); `go run ./tools/chaosdoc -check` fails the
  build if the page drifts. Backfilled across every batch to date — the nightly suite plus the
  hand-driven composite and targeted runs (64 scenarios at first publish) — and findings are recorded
  honestly (e.g. a managed non-HA MariaDB has `log_bin` off, so it can't be a CDC source). Each
  scenario shows **which sandbox nodes** it used; a resource spread across nodes (HA primary/replica,
  Galera, Longhorn replicas, VM live-migration) is drawn as one **subgraph per node** with the
  instances tied together. A top **index table** plus collapsible per-scenario diagrams (findings
  stay expanded) keep the page navigable as scenarios accumulate — it grows with distinct scenarios,
  not nightly runs (those update status in place).
- **Known limitation surfaced by the chaos runs: a managed MariaDB can't be a CDC source unless it's
  HA.** A single-instance managed MariaDB (an `Application`'s `database` without `highAvailability`)
  ships with `log_bin` **off**, so Debezium can't capture from it — a `Stream`/`Migration`/`DataFlow`
  using it as a *source* silently produces nothing (it works fine as an apply *target*). A cross-engine
  mesh with a non-HA managed MariaDB therefore replicates one-way. Enable `highAvailability` (Galera
  turns binlog on) for a MariaDB that must originate changes; documented in
  [migrations](docs/migrations.md), [streaming](docs/streaming.md), and [dataflow](docs/dataflow.md).
- **The scheduled nightly now runs the chaos lottery.** The nightly cron executes the seeded-draw
  lottery (2–4 composed faults) rather than a single fixed scenario; the individual scenarios remain
  the on-demand library it composes from (runnable via `workflow_dispatch`). The nightly also records
  its result into `chaos/nightly-status.json`, regenerates the public gallery, and commits it back —
  so [docs/chaos-scenarios.md](docs/chaos-scenarios.md) shows a live "Last nightly" status.
- **The chaos oracle went "fully wide open" — one framework, three modes, ten adapters across the
  whole workload plane** ([docs/chaos-oracle.md](docs/chaos-oracle.md)). What began as a
  multi-master convergence harness is now a single oracle runner (a *contract*, not a replication
  test) with small per-kind adapters dropped onto it. Three verdict **modes** cover the ways a
  workload can be judged: **`recover`** (conservation — after the fault heals, no acknowledged unit
  of work was lost), **`tolerate`** (a continuous SLO measured *while the fault is live*), and
  **`deny`** (a negative invariant — a thing that must NEVER happen, verified with zero tolerance).
  On those modes ride **ten adapters**, one per blast-zone-testable kind: replication (convergence),
  migration (fidelity), availability, security-deny, stream-noloss, directory-recover,
  fileshare-durable, volume-durable, vm-resilience, and dataflow-converge — so the suite now
  exercises databases, identity (`Directory`), files (`FileShare`), block storage (`Volume`),
  compute (`VirtualMachine`), and the `DataFlow` topology, not just the mesh. (`Query` is the one
  kind deliberately excluded: its Job runs in the shared `minio` namespace, outside the sandbox, so
  a fault there would escape containment.) Every adapter is proven **fail-loud** — RED on a genuine
  fault, GREEN only on a survivable one — because an oracle that only ever prints green is worthless.
- **Chaos Mesh's mTLS/webhook certs no longer churn on every Argo sync.** Chaos Mesh mints
  its controller↔daemon certs with Helm `genSignedCert`, which is non-deterministic under
  `helm template` (how Argo renders), so every sync rewrote the four cert Secrets and the
  webhook `caBundle`s. Pods that restarted got new certs; those that didn't kept the old —
  the trust chain drifted, `NetworkChaos` silently failed to inject (`unable to flush ip
  sets`), and the nightly partition scenario converged too fast and tripped its false-green
  guard (the 2026-07-23 red). Argo `ignoreDifferences` now freezes the cert `/data` and
  webhook `caBundle`s, so the chain is created once and kept. If certs must be rotated, do it
  deliberately and restart both the controller Deployment and the chaos-daemon DaemonSet.
- **`RespectIgnoreDifferences` closes the cert-freeze gap.** `ignoreDifferences` stops
  *drift*-triggered syncs from churning the Chaos Mesh certs, but a sync fired for another
  reason (a chart bump, a values edit) would still re-render and overwrite them. The
  chaos-mesh app now also sets `RespectIgnoreDifferences=true`, so the live cert Secrets
  survive every sync (verified on Argo v3.4.4; cert hash unchanged across a sync).
- **A capacity-starved chaos run is INCONCLUSIVE, not a false red.** If a node is down and
  the survivors are full, the nightly sandbox can't schedule and the scenario would time out
  RED — an infrastructure shortfall blamed on the product. A new
  [capacity pre-flight](chaos/preflight-capacity.sh) sums schedulable headroom and aborts
  INCONCLUSIVE (neither red nor green, so it doesn't advance the graduation clock). It
  deliberately does not require every node Ready (the GPU box is off nightly) and fails open.
- **The chaos suite gained a magnitude axis (Epoch 2, Phase 1).** The nightly partition ran at
  one magnitude (a clean cut); the highest-value multi-master bugs live in the *limping* zone.
  Two new variants, each with its own proof-of-fire and its own oracle expectation
  ([docs/chaos-oracle.md](docs/chaos-oracle.md)):
  - **`partition-flapping`** — the cut is injected/healed in short repeated cycles while
    conflicting writes flow; the mesh must reconverge byte-identical **after** flapping stops,
    with ≥1 cut confirmed live. *(verified live before folding in.)*
  - **`partition-latency`** — a *degrade*, not a cut: 800ms both ways on the sink↔B apply path.
    The oracle expectation **inverts** — a degrade never severs, so the mesh must **keep
    converging** and there is no `MIN_ELAPSED` floor (fast convergence is the goal, not a false
    green). *(verified live: converged — 220 keys / 20 conflicts / zero lost — under sustained
    800ms, a ~4× slower apply path.)* Required a composition fix: Chaos Mesh rejects a netem
    `delay` with `direction: both` unless a peer `target` block is present, so the FaultInjection
    composition now emits that block for **any** peer-scoped `NetworkChaos`, not just partitions.
  - **`partition-isolation`** — a harsher cut: severs site B from its **whole** mesh at once
    (both the inbound a-b-sink→B and the outbound b-dbz→B links), so **both** members diverge
    and both must reconverge — vs the default partition's one-sided cut. One peer selector does
    it via the shared `openinfra.dev/replication` label; this surfaced a latent omission —
    that label was on the replication Deployments' metadata but **not** their pod templates,
    so Chaos Mesh and NetworkPolicy (which select pods) couldn't see it. Now on the pods.
    *(verified live: both diverged, reconverged byte-identical in 126s, cut confirmed.)*
  - **`partition-loss`** — a *degrade* like latency: drop 15% of the sink↔B packets, mesh must
    keep converging (no `MIN_ELAPSED`). Proof-of-fire is **statistical** (`probe-loss.sh`:
    20 handshakes, a non-trivial impaired fraction — a single connect can't witness
    probabilistic loss). Deliberately calibrated to 15%: TCP throughput falls ~1/√p, so past
    ~20% an established link brown-outs into a de-facto slow cut — the 40% attempt correctly
    *failed* to converge (a throughput brownout, not a safety fault), which is why the value is
    tuned down. *(verified live: converged byte-identical in 22s under sustained 15% loss.)*
  - The proof-of-fire probe now **times** the handshake (busybox `time`, 0.01s resolution) and
    classifies `up`/`slow`/`down`, so one probe witnesses both cuts and degrades — a degraded
    link an up/down probe would have misread as "up = no fault fired." This completes the
    magnitude axis: cut → total isolation → latency → loss → flapping.
- **Chaos axis 2 (timing/overlap) — first increment: HEALING ORDER.** `healing-order` overlaps a
  partition and a held-down sink (pod-failure) on the a→b path, then heals them in a controlled
  ORDER with a gap, asserting the mesh reconverges byte-identical either way — a sink that comes
  back into a still-cut network (or a network that heals while the sink is down) must not drop
  its NATS consumer or lose its offset. Both faults are proof-of-fired independently (partition
  via the probe, sink via PodChaos `AllInjected`). *(Shaken out live BOTH orders:
  partition-first converged 62s, sink-first 74s — recovery is heal-order-independent.)*
- **Chaos axis 3 (fault variety) — first increment: CPU pressure.** `stress-cpu` saturates the
  a→b apply-sink's CPU (2 workers @100% inside its 1-core cgroup); a degrade like latency/loss,
  so the mesh must keep converging (no MIN_ELAPSED), proof-of-fire via StressChaos `AllInjected`.
  *(Shaken out live: injected + converged zero-lost. Honest caveat: the apply-sink is
  I/O/network-bound, so CPU starvation is a mild stressor for this workload — it confirms
  resilience but isn't a hard squeeze.)* A second increment, **`stress-mem`**, puts 300MB of
  memory pressure on site B's Postgres (sized under its 512Mi limit so it degrades, not OOMs) —
  a different fault type on a different target; the DB stays queryable and the mesh converges
  zero-lost. **DNS was evaluated and found INERT on this cluster** — a full `dns-error` path
  (XRD type + DNSChaos composition mapping + provider RBAC + a resolv-witness probe) was built
  and exercised, but Chaos Mesh's DNS injector *panics* on inject (`exit 101 … Os NotFound`,
  `Not Injected`, `injectedCount:0`) — the same Rust-injector-panic class as io-latency's `toda`,
  a runtime/host incompatibility, not a config. Rather than carry a second silently-inert fault
  type (the project is trying to *remove* io-latency from the enum, not add more), the DNS work
  was reverted; the finding is recorded here. **disk-fill** has no native Chaos Mesh primitive.
  So fault-variety on this cluster is stress-cpu + stress-mem; DNS and disk-fill are documented
  gaps (DNS would light up for free if a Chaos Mesh upgrade fixes the injector).
- **Chaos axis 4 (target selection) — first increment: SINK-KILL MID-DRAIN.** `sinkdrainkill`
  targets the apply-sink in its hardest *state* — mid-backlog-drain — rather than idle (scenario 3):
  it cuts a→b, piles a 10k-row backlog into NATS, heals, catches the sink partway through draining,
  and kills it, asserting pg-b still receives ALL 10k rows (a sink that acked before applying would
  drop the in-flight batch). Two-part proof-of-fire (backlog actually staged; kill actually landed
  mid-drain, pod replaced); INCONCLUSIVE if the drain finishes before the kill can land.
  *(Shaken out live: killed at pg-b=1701/10000, resumed from offset to 10000/10000, zero lost.)*
- **Chaos axis 5 (correlation) — THE LOTTERY (`scenario-lottery.sh`), the capstone.** A seeded
  draw ([chaos/lottery-draw.py](chaos/lottery-draw.py)) picks 2–4 concurrent faults from the
  composable palette, ~75% biased toward a shared surface tag (interaction bugs live where faults
  overlap) with a wildcard tail; the driver applies them all, PROVES each fired (Chaos Mesh
  `AllInjected` / pod-replaced — a partial draw is INCONCLUSIVE, never green), drives the
  convergence harness through the combination, heals, and requires byte-identical reconvergence.
  Seeded + **replayable** (a red reruns with `LOTTERY_SEED=<seed>`), draw-without-replacement,
  blast-cap 2–4. A conflict model keeps draws physically composable (never a netem fault paired
  with a pod-kill of its peer pod — the peer IP churns and the netem can't inject). Inert faults
  (io-latency, dns) are excluded from the pool. *(Shaken out live: seed 7 `[latency, capture-kill,
  stress-mem]` converged 250s; seed 42 `[isolation, stress-mem, sink-failure]` — max blast —
  reconverged 599s; the draw engine is deterministic with 0 invalid combos across 4000 seeds.)*
  Bandit-weighting is the tracked refinement; v1 uses the surface-tag correlation bias.
- **Scenario 5 (storage replica-loss) is real now — the honest test io-latency was a stand-in
  for.** The sandbox DBs can run on Longhorn (`longhorn-chaos` StorageClass, 2 replicas on
  distinct disposable chaos nodes); `chaos/scenario-storage-replica-loss.sh` loses a replica of
  pg-b's volume mid-write and asserts the volume degrades-but-survives, the DB stays queryable
  off the surviving replica, the mesh converges with zero lost writes, and Longhorn rebuilds to
  healthy. Production storage is fenced off the chaos nodes (`allowEmptyNodeSelectorVolume: false`
  + node tags), proven both directions. *(Shaken out live as admin; not yet nightly-wired — that
  needs a deliberately-scoped `longhorn-system` RBAC grant, since deleting a replica is a
  cross-namespace privileged action.)*
- **`io-latency` is a confirmed permanent dead end (cgroup v1 ↔ kubelet).** Booting the chaos
  nodes to cgroup v1 (to give Chaos Mesh's FUSE injector the `devices` controller it needs) was
  tried and reverted: **this k3s's kubelet refuses to run on cgroup v1**, so the nodes went
  NotReady. io-latency needs cgroup v1; the kubelet needs cgroup v2 — mutually exclusive. It
  stays disabled and should be dropped from the `FaultInjection` XRD enum; Scenario 5's purpose
  is now served by real replica-loss instead.
- **`io-latency` FaultInjection root-caused (still inert).** Re-tested after the cert freeze;
  it is **not** cert drift — it's a cgroup-v2 incompatibility: Chaos Mesh 2.7.2's
  `fusedev.GrantAccess` wants a legacy cgroup-v1 `devices` controller, so on a unified-v2 host
  `toda` never gets `/dev/fuse` and every IOChaos sits "Not Injected". Documented; `io-latency`
  stays disabled on this host.
- **Three correctness bugs fixed:** the `test.yml` `paths:` filter now watches
  `platform/console/manifests/**` (RBAC-role drift there shipped green before); the Longhorn
  creds-refresh CronJob compares **both** MinIO credential values, not just the access-key ID
  (a password-only rotation silently broke backups); and a new `TestArgoExcludeListNoDrift`
  guards the hand-maintained `install.sh` Argo exclude-list, so a stray non-resource file
  under a platform area can no longer wedge the whole app-of-apps sync unnoticed.

### Data
- **The Redis cache is now Valkey, on an owned manifest.** Bitnami purged its public
  versioned image tags (Aug 2025), leaving the Redis chart pinned to an unmaintained
  `bitnamilegacy/*` mirror. Replaced with an owned manifest running **Valkey** (the
  BSD-licensed, actively-maintained Redis fork, Redis-protocol compatible) — same endpoint
  (`redis.redis.svc:6379`), password bootstrapped out of git, pod hardened (non-root,
  read-only rootfs, dropped caps). Drops the Bitnami dependency entirely.

### Fixes
_Three product bugs in cross-resource interactions that per-kind unit tests miss — caught by
composite, cross-kind chaos runs:_
- **Cross-engine `Migration`/`DataFlow` into MySQL or SQL Server dropped the primary key,
  leaving the target empty.** The schema-sync step maps a source Postgres `text`/UUID-as-text
  primary-key column to the target engine's `TEXT` type, but MySQL forbids a `TEXT`/`BLOB`
  column in a key without a prefix length (`Error 1170: BLOB/TEXT column used in key
  specification without a key length`) and SQL Server forbids `(MAX)`/`TEXT` in a key — so the
  `CREATE TABLE` failed, the target was never created, and the stream applier then looped
  forever (`… has no primary key (required for upsert)`) with zero rows delivered. A
  primary-key (or unique-key) LOB column is now coerced to a bounded type — `VARCHAR(255)`
  (MySQL) / `NVARCHAR(255)` (SQL Server) — so the key is valid and the load completes.
  Postgres→Postgres and integer-key migrations were never affected. Unit-tested
  (`TestBoundKeyType`); the direct parallel to the earlier cross-engine `DATE` coercion fix.
- **`kind: Application` with both `securityGroups` and a managed `database` couldn't form its
  database.** The Application composition stamped the app's Security Group labels onto the
  managed-database pods too, but a Security Group's ingress only opens the app's port — so the
  database was fenced on the wrong ports: its operator couldn't read pod status (cluster stuck
  below quorum), a replica couldn't join, and the app couldn't reach its own database. Security
  Group labels are no longer propagated to any managed-DB tier (CNPG/MariaDB/FerretDB/Babelfish);
  a Security Group fences the app's ingress, and the database is reached over its injected
  connection secret and its own operator, so it must not be an SG member.
- **`kind: DataFlow` nodes with hyphenated names produced invalid Postgres replication slots.**
  A node name was interpolated directly into the logical-replication slot name, which only
  permits `[a-z0-9_]`; a hyphen (or other punctuation) yielded a slot Postgres rejected. Node
  names are now sanitized (and length-bounded) when composing the slot name.

### Dependencies
- **Load-bearing bumps recorded** (not silent plumbing): the Go toolchain `1.25 → 1.26`, the
  Kubernetes client `client-go 0.33 → 0.36`, the SQL Server driver `go-mssqldb → 1.10`, and —
  the one that matters for the clock — **`nats.go 1.34.1 → 1.52.0` in apply-sink**, the
  transport every nightly mesh run rides (`db → Debezium → NATS → apply-sink`). See the
  *re-epoch note* below.
- **CVE-2026-56852** — bumped `golang.org/x/text 0.38 → 0.39` (an infinite-loop DoS in
  `norm.Iter` on invalid UTF-8; surfaced by Trivy code-scanning, indirect dep, verified).
- Enabled **Dependabot version updates** (Go / npm / Actions, grouped) and added a **UI
  typecheck+build CI gate** so console dependency bumps can no longer merge unverified.
- **Dependabot now also watches container base images.** The `docker` ecosystem was missing, so
  the `FROM` images in the five Dockerfiles we build and ship (apply-sink, babelfish, console-api,
  query, and the hello-web example) never got base-image bumps or CVE fixes. Added, grouped
  weekly, majors separate — closing the last un-watched dependency surface.

> **Note — nightly-chaos graduation clock: RE-EPOCHED (Epoch 2).** The `nats.go 1.34.1 →
> 1.52.0` bump landed in **apply-sink** and ran in the nightly. NATS is the transport *every*
> nightly convergence run exercises (`db → Debezium → NATS → apply-sink`), regardless of
> engine — so by the SUT-vs-harness test used for the 2026-07-23 night, this **is** a change
> to the system under test and the 30-night clock **re-epochs**. **Epoch 2 begins with the
> first nightly on the nats.go-1.52 binary; Epoch 1's ~15 nights are retained as history of
> the pre-bump binary, not chained across the dependency change.** The exact streak count
> lives in the Actions run history, not this file.
>
> *(An earlier revision of this note said "not re-epoched" — it checked the DB drivers
> (pgx/mysql/mssqldb) and missed that `nats.go`, the message bus, is on the nightly data path
> for every engine. Corrected here.)*

## v2.5.0 — 2026-07-22

### Terraform
- **A first-party Terraform provider, published as
  [`harn3ss/openinfra`](https://registry.terraform.io/providers/harn3ss/openinfra/latest).**
  Every open-infra kind is now a typed resource with full CRUD and `terraform import`, plus a
  data source for reading. open-infra CRDs could always be managed with the generic
  `kubernetes_manifest`, so this is about ergonomics rather than raw capability — real
  attributes and plan-time validation instead of an untyped YAML blob, and the ability to put
  a database, its CDC stream and your DNS in a single plan.

  Three resources are hand-written (`application`, `database`, `virtual_machine`) because they
  carry behaviour a schema can't express. The other thirteen are generated from a table: every
  CRD has the same lifecycle, so a resource per kind meant ~250 lines of identical CRUD each
  and thirteen separate places to drift from the XRD. Adding a field is now one line.

  Verified clean-room — empty CLI config, no dev override — `terraform init` downloads it from
  the Registry, verifies the GPG signature, and a plan/apply/destroy creates and removes a real
  resource on the cluster. Source: [harn3ss/terraform-provider-openinfra](https://github.com/harn3ss/terraform-provider-openinfra).
  Docs: [docs/terraform.md](docs/terraform.md).

  Note the coupling: **the provider mirrors these CRD schemas by hand and nothing enforces it.**
  A field added to an XRD without a matching provider change is silently unexpressible in HCL.

### Security
- **Console identities are declarative: `kind: User` and `kind: Group` (IAM stage 1).**
  Accounts used to exist only as a base64 JSON blob inside the `console-auth` Secret, so
  adding a person or changing their access was a `kubectl edit` of an opaque field with no
  review trail. Users and groups are now ordinary resources in a **separate API group,
  `iam.openinfra.dev`** — separate on purpose, because RBAC is additive and the existing
  read-only role grants `openinfra.dev: ["*"]`, which would have silently handed every
  reader access to the objects that define who may do what, the moment those kinds existed.

  Sign-in consults the **Secret first, then Users**: bootstrap `root` keeps working as
  break-glass even if the CRDs are missing or a Composition is broken. A User's
  `spec.groups` become the `Impersonate-Group` values *directly*, so authority comes from
  the ClusterRoleBindings `kind: Group` creates rather than from a role keyword — and empty
  groups authorize **nothing** instead of falling back to a default. Passwords are never in
  the CR: a User points at a Secret holding a bcrypt hash, so User objects stay safe to read,
  GitOps and render. Verified end-to-end on the live cluster, including a user with no groups
  being denied reads that its role keyword alone would have allowed, and the audit log
  recording `impersonatedUser: openinfra:<name>` for both outcomes.

  Two defects this shook out, both fixed here:
  - The `SubjectAccessReview` checks built their subject from the role keyword while the
    proxy impersonated using the session's groups — so a CR-backed user in `openinfra:admins`
    would have been *authorized* as a reader. Both now derive the identity from one function.
  - `CoreV1().RESTClient()` can return a **typed nil**, which passes `!= nil` and panics on
    first use; the login handler would have crashed rather than degrading. Caught by a test.

  Known ceiling, documented in [docs/iam.md](docs/iam.md): a `kind: Group` only takes effect
  if its name is in the impersonator ClusterRole's `resourceNames`. That pin is what stops
  the console impersonating `system:masters`, so widening it is deliberately an operator
  action. The console now rewrites the resulting 403 into a message that names the group and
  says what to do, instead of the API server's version, which blames the console's own
  ServiceAccount and reads like a bug.

- **IAM policies and roles: `kind: Policy` and `kind: Role`, managed from the console (stage 2).**
  AWS-style attachable policies for open-infra, with AWS's anti-escalation guarantee. A **Policy**
  is a document of Allow statements over open-infra resources (`virtualmachines:*`, `volumes:Get`,
  …) that compiles to a labelled ClusterRole; a **Role** bundles policies into an aggregated
  ClusterRole; pointing a Group at `openinfra-role-<name>` grants it.

  The safety story is a **permission boundary**: a Policy can only ever grant on the `openinfra.dev`
  product surface. That is enforced structurally — the composition hardcodes
  `apiGroups: [openinfra.dev]` and drops any rule outside a 15-resource whitelist — and by RBAC:
  the rendering ServiceAccount holds *exactly* that surface, so the API server refuses anything
  beyond it. The console's `/api/iam/*` endpoints are SAR-gated on `iam.openinfra.dev` (admins
  only), and the BFF rejects an out-of-boundary action with a clear message rather than silently
  dropping it. Verified live: a policy naming `secrets` is refused; a member of a group bound to a
  `virtualmachines:*, volumes:Get/List` role could delete VMs and read volumes but not delete
  volumes, read secrets, or touch applications; a read-only user is 403'd on every IAM write.

  One honest note on privilege: aggregated ClusterRoles require the RBAC `escalate` verb to create
  at all (a Kubernetes rule the boundary doesn't satisfy), so the provider is granted it — but it
  is bounded by the `bind` fence, not by escalate. `bind` stays restricted to the three built-in
  roles and the provider holds no secrets/RBAC, so it can *create* a powerful ClusterRole yet never
  *bind* one exceeding the boundary to a person. Escalate widens what can be created, never what can
  be granted. See [docs/iam.md](docs/iam.md).

- **Users and Groups are managed from the console, not just `kubectl`.** IAM stage 1 made
  sign-in read `kind: User` / `kind: Group`, but adding a person still meant `kubectl apply` of a
  User plus a hand-built bcrypt-hash Secret. There is now a **Users** and a **Groups** page under
  Security & Identity — create, edit, delete, set/reset passwords, manage group membership.

  It is not a privilege back door: every `/api/iam/*` handler runs a `SubjectAccessReview` as the
  signed-in user against `iam.openinfra.dev` before acting, so it is exactly as restricted as
  `kubectl` — only admins get through (verified live: a read-only user is 403'd on both listing and
  creating). A User never holds its password (a bcrypt hash in a Secret; the create rolls the Secret
  back if the User fails, so a retry isn't blocked), and `root` is refused because it's the
  break-glass account, not a User. The UI surfaces the impersonation ceiling rather than hiding it:
  a Group whose `openinfra:<name>` is outside the impersonator ClusterRole's allow-list is flagged
  **inert**, and a user placed in one gets a warning — the trap [docs/iam.md](docs/iam.md)
  documents, made visible where the mistake happens.

### GitOps
- **Fixed a wedged platform sync.** `platform/security/audit-policy.yaml` sat inside the root
  app's `security/*.yaml` include glob, so Argo tried to `kubectl apply` an `audit.k8s.io/v1`
  Policy — a kind no API server serves. Because Argo aborts an entire sync when any task fails
  validation, **nothing** in `open-infra-platform` had synced since that file landed. The audit
  policy is kube-apiserver config read off disk, not a cluster resource, so it moved to
  `security/apiserver/` and is now excluded by name. Worth knowing: Argo compiles these globs
  *without* a path separator, so `*` spans directories — moving a file deeper does **not** hide
  it from an include glob. The exclude list is now substituted into `root-app.yaml` via an
  `__EXCLUDE__` placeholder rather than `sed`-matching the literal default, which would have
  silently stopped matching the first time that default changed.

### Backup
- **Database snapshots — "final snapshot before you deprovision" (RDS-style).** Take a
  snapshot of a Postgres database before deleting it, and restore it into a new one. A
  logical `pg_dump -Fc` streamed to MinIO, decoupled from the database so it **survives
  deletion** — validated end-to-end through the console API (write a row → snapshot →
  delete the database entirely → restore into a fresh cluster → the row returns). Logical
  rather than a CSI volume snapshot because managed DB data is on `local-path` (no CSI
  snapshot support) — and logical is engine-portable and the artifact obviously outlives
  the resource. New console **Backup → Snapshots** page (list / restore / delete) and a
  *"Take a final snapshot before deleting"* checkbox in a database's Danger Zone that waits
  for the snapshot to finish before removing the database. Honest limits: in-cluster (MinIO)
  durability not off-cluster DR; MinIO root creds for now (scoping is a follow-up). See
  [docs/snapshots.md](docs/snapshots.md).
- **Managed engines (babelfish / MySQL / Mongo) snapshot via durable Longhorn CSI backup.**
  These engines are Longhorn StatefulSets, not CNPG-on-local-path, so they route to a
  different console detail page that previously had **no snapshot UI at all** — and a
  `pg_dump` is *wrong* for babelfish (it drags in the babelfish extensions + `sys`/`master_`/
  `msdb_` catalog schemas). The console-api now takes a `VolumeSnapshot` (`longhorn-backup`,
  `type: bak`) of the data PVC, which uploads to MinIO and **survives full deletion of the
  source** (verified: back up → destroy the source PVC → restore into a new volume → data
  returned). New **Snapshots tab** + final-snapshot-before-delete checkbox on the managed
  database page; the unified Snapshots list and delete span both mechanisms.
- **Restore-as-new for babelfish snapshots.** The BFF pre-seeds the target's data PVC *from*
  the snapshot (the new StatefulSet adopts it by name) and creates a data-only Application — no
  pre-existing target needed. The restored disk carries the source's password, so babelfish's
  entrypoint now reconciles the app + superuser password to the injected secret on every boot
  (making the k8s Secret authoritative); the restored instance comes up with its own working
  credentials. Proven end-to-end on a throwaway (canary → snapshot → restore → remote client
  with the new secret returns the canary; `sys` catalog intact). MySQL/Mongo restore is next.
- **VM snapshots + restore-as-new** (the "or a virtual machine" half). For a VM with
  `highAvailability` (Longhorn root disk), the console takes a durable `longhorn-backup` snapshot
  of the root PVC — capturing the VM's shape (os/cpu/memory/cpuModel/network) — and restore
  pre-seeds `<target>-root` from it and creates a new `VirtualMachine` that adopts it via
  `existingRootClaim`, reproducing the spec and starting Halted. New **Snapshots** tab +
  final-snapshot checkbox on the VM page; VMs join databases on **Backup → Snapshots**. Local-path
  (non-HA) VM roots have no CSI snapshot — the console says so and disables the button. Validated
  live: gating, snapshot with correct captured spec, and restore creating the right PVC (RWX Block
  on longhorn-migratable) + VM (existingRootClaim, Halted).
- **Snapshots now cover every database engine, by the right mechanism.** Correcting an earlier
  over-broad assumption (that all managed engines were on Longhorn): only **babelfish** is —
  Postgres, **Mongo** (FerretDB/DocumentDB), and **MySQL** (MariaDB) are on local-path, which has
  no CSI snapshot. So Mongo now snapshots via `pg_dump` of its **Postgres backend** (`POSTGRESQL_URL`)
  and MySQL via `mariadb-dump`; both restore into a pre-created target (`pg_restore` / `mariadb`).
  **Both validated end-to-end** (canary round-trip: snapshot → new DB → restore → row returns).
  Also added the **Snapshots tab** to the Postgres detail page (it only had the Danger-Zone
  checkbox), with the Take-snapshot button disabled while the DB is stopped.
- **Fixed: mysql databases never provisioned** (a bug surfaced while validating mysql snapshots).
  The `openinfra-provider-kubernetes` ClusterRole enumerates every API the Crossplane provider may
  manage but **omitted `k8s.mariadb.com`**, so the provider could create the mysql Secret/NetworkPolicy
  but *not* the MariaDB CR — every mysql-engine database silently stuck at "mysql not yet ready".
  Added the `mariadbs` grant; mysql now provisions (and snapshots) correctly.
- **Fixed: the Longhorn backup target silently broke on a MinIO reprovision.** The setup job
  copies MinIO's root creds into `longhorn-minio-creds` only on Argo sync, so when MinIO's
  root creds rotated the copy went stale → `InvalidAccessKeyId` → **all Longhorn backups
  failed**. Added a self-healing refresh CronJob that re-copies when they drift.

### Replication
- **Fixed: `kind: Replication` / `DataFlow` could not capture from open-infra's own
  managed (CloudNativePG) databases.** Debezium defaults to
  `publication.autocreate.mode=all_tables`, which issues `CREATE PUBLICATION … FOR ALL
  TABLES` — a **superuser-only** statement. CNPG (correctly) makes the app user a
  non-superuser, so the capture failed to start outright; the bug was masked because the
  raw `postgres` image makes its user a superuser. The compositions now set
  `autocreate.mode=filtered` wherever an explicit table list exists (always for
  Replication; the named-table path for DataFlow), publishing only those tables — which
  needs table *ownership*, not superuser. DataFlow's capture-all path keeps `all_tables`
  (it genuinely wants every table, and still requires a superuser source). Found by the
  new chaos Scenario 4.

### Reliability
- **Nightly Chaos Suite — the containment foundation.** The road from *"convergence is
  hand-tested"* to *"convergence is proven nightly, or the release is blocked."* This
  lands the safety model first: a disposable `chaos-sandbox` namespace with a
  `ResourceQuota` + `LimitRange` + a low non-preempting `PriorityClass` (sandbox pods
  evict first under pressure), and a `chaos-runner` ServiceAccount whose write authority
  is scoped to the sandbox **only** — "runner creds = chaos creds", so a fat-fingered
  fault selector is *rejected by the API server*, not merely discouraged. A **pre-flight
  guard** resolves a fault's selector and aborts if it could reach any pod outside the
  sandbox. All **validated live** (RBAC deny-tests pass; the guard aborts a kube-system
  target and an `app=minio` selector). Ships alongside the **Scenario 1**
  (`multimaster-partition`) kit — disposable members, a checked-in multi-master mesh, the
  partition fault, an orchestration script, and a self-hosted nightly workflow.
  **Scenario 1 is validated end-to-end on the live cluster**: baseline convergence in
  13s, and under a real partition the mesh diverges then re-converges byte-identical in
  ~108s (200 keys / 20 conflicts / zero lost writes). The first run also surfaced that
  the mesh is *pod-mediated* (a member↔member partition injects nothing) and drove a
  platform enhancement — `kind: FaultInjection` gained **`partitionPeer`** for
  peer-scoped network-partitions (cut A↔B while both stay reachable by outside clients).
  **Scenario 2 (`clock-skew`, the T6 regression) also validated live**: rather than real
  TimeChaos, the HLC physical-clock read gained an injectable offset (`mm_hlc_state.clk_off`,
  default 0 — production untouched; Postgres already had a session-GUC hook, now
  generalized and added to MySQL, which T6 hit). Forcing the clock −1h backward, the HLC
  stayed monotonic (Δ=1) instead of stamping a ~2.4×10¹¹-lower version that would silently
  lose last-write-wins. **Scenarios 3 (`sink-kill`) and 4 (`cnpg-failover`) also validated
  live**: the apply-sink is killed mid-write and the mesh still converges (durable NATS
  consumer redelivers), and a real CNPG primary is killed mid-write — CNPG promotes the
  replica, the `-rw` service follows, and the mesh converges across the promotion with zero
  lost writes. Scenario 4 is what surfaced the `publication.autocreate.mode` bug above.
  **Scenario 6 (`mesh-under-concurrent-chaos`) — the graduation acceptance test — also
  passes**: capture-kill + partition + sink-kill injected *simultaneously* while the harness
  writes, and the mesh still converged byte-identical (124s, the cut genuinely biting).
  Every scenario now **asserts its fault actually landed, while the harness is still
  running, and that a timed cut actually delayed convergence** — several false greens (a
  partition that injected nothing; a fault applied after the test finished; chaos landing on
  already-converged data and "passing" in 21s; a silently-ignored `CONV_TIMEOUT` that left
  Scenario 1 with 13s of hidden margin) were caught and fixed rather than shipped.
  Scenarios 1–4 + 6 all pass, so the 30-consecutive-night graduation clock can start.
  **Scenario 5 (`longhorn-replica-loss`) is parked, deliberately**: faulting a real Longhorn
  replica would degrade the 11 real volumes backing VMs/databases/MinIO (forbidden by the
  safety model, and refused by the pre-flight guard — it needs the separate validation
  cluster the design already calls for), and the safe alternative is blocked by the bug
  below. See [docs/chaos-suite.md](docs/chaos-suite.md).

### Known issues
- **`kind: FaultInjection` type `io-latency` is inert on this cluster.** Chaos Mesh's FUSE
  injector (`toda`) panics (`Send through channel failed`, `Starting toda … encounter an
  error`), so the IOChaos is created but sits at `phase: Not Injected/Wait,
  injectedCount: 0` **silently** — the fault looks applied and does nothing. The XRD still
  advertises the type. Found by the chaos suite asserting `AllInjected=True` rather than
  mere object existence. Not yet fixed; `io-latency` should be considered non-functional.

## v2.4.0 — 2026-07-14

### Billing
- **New Cost Explorer — "what AWS would've charged."** The last unbuilt AWS-equivalent
  ships: a console **Billing → Cost Explorer** page that prices your live cluster
  (node vCPU/memory, GPUs, PVC storage, LoadBalancers) against AWS public on-demand
  list rates and shows the monthly/annual estimate next to your actual cost ($0). A
  read-only BFF endpoint (`/api/cost`) computes it from cluster state — compute at
  Fargate rates, GPU at g4dn class, EBS gp3, ALB base — plus a by-namespace compute
  breakdown. Rates are overridable via `COST_*` env. See [docs/cost.md](docs/cost.md).

### Security
- **`kind: Query` is no longer root over all of object storage (hardening).** The query
  Job previously ran with the **MinIO root** credentials — any user who could submit a
  Query had full read/write to *every* bucket (Velero/Longhorn/CNPG backups, golden VM
  images, every app bucket), with no network sandbox and running as root. Fixed on five
  fronts:
  - **Least-privilege S3 identity.** A new `query-runtime.yaml` mints a scoped MinIO
    user + policy that can **read only an allow-list of buckets** (`query-data`,
    `lakehouse`, `query-results`) and **write only to `query-results`**; the composition
    uses it instead of root. Verified: the query identity reads `query-results` but gets
    `AccessDenied` on `longhorn`/`velero`. The lakehouse (Trino/iceberg) likewise moved
    off a root-copy secret to a user scoped to `s3://lakehouse` only.
  - **Network sandbox.** A `NetworkPolicy` on query pods permits egress only to DNS +
    MinIO + Trino, so `httpfs` can't exfiltrate to an external URL and SQL can't SSRF
    cluster services / the metadata endpoint.
  - **Pod hardening.** Query pods run `runAsNonRoot` (uid 65532), `readOnlyRootFilesystem`,
    all capabilities dropped, `automountServiceAccountToken: false`, seccomp
    `RuntimeDefault`; the image ships a non-root `USER`. iceberg-rest moved off root
    (uid 1000 + `fsGroup`, no chmod-0777 init) — validated Ready as non-root.
  - **DuckDB confinement.** The runner disables local-filesystem access and locks
    configuration for the untrusted user SQL, so a query can't read `/etc/passwd` or
    `/proc/self/environ` (env/cred exfil) or re-enable it via a COPY-wrapper breakout;
    S3 still works.
  - Follow-ups: per-namespace query identities/workgroups, and Trino pod hardening.

### Analytics
- **The lakehouse is now installed by GitOps.** The Trino + Iceberg REST catalog
  manifests moved under `platform/query/manifests/` behind a child Argo `Application`
  (`platform/query/query.yaml`), and `query` was added to the app-of-apps include
  glob — so `install.sh` brings the whole lakehouse up on a fresh cluster instead of
  it needing hand-applied resources. A one-shot `lakehouse-setup` Job (Sync hook,
  earlier sync-wave) creates the `lakehouse` bucket on MinIO and copies the MinIO root
  credentials into `lakehouse/minio-creds` — no secret is committed. Toggle it off with
  `components.lakehouse: false`. Argo `ignoreDifferences` on the Trino Deployment's
  replicas so selfHeal doesn't fight the idle-stop reconciler.

## v2.3.0 — 2026-07-12

### Analytics
- **The lakehouse — Trino + an Iceberg REST catalog (Athena's Glue half).** Phase 2
  of `kind: Query` lands as a second **engine**, not a second kind. The same
  `kind: Query` now takes `spec.engine: duckdb | trino` (default `duckdb`):
  - **`duckdb`** — the serverless, schema-on-read path from v2.2.0: query files by
    path (`read_parquet('s3://…')`), a pod per query, **$0 at idle**.
  - **`trino`** — a single-node **Trino** coordinator wired to a shared **Iceberg
    REST catalog** (open-infra's **Glue Data Catalog**) over MinIO, for
    `database.table` querying and cross-source joins. Both engines write the *same*
    result contract (`<ns>/<name>.csv` + `.metadata.json`), so the console reads
    either identically.
- **Trino idle-stop.** The lakehouse coordinator ships `replicas: 0`; a console
  autostop reconciler scales it 0↔1 based on the newest `engine: trino` query and
  scales back after ~10 min idle — the warehouse engine costs nothing at rest, and
  DuckDB queries never touch it.
- **Engine picker + catalog-aware Data tree in the console.** Each query tab has a
  small engine picker (**DuckDB** *— lake files, serverless* / **Trino** *— catalog &
  federation*). The Data panel follows it: buckets→files for DuckDB (insert
  `read_parquet(...)`), or **catalog → schemas → tables** for Trino (insert
  `iceberg.<schema>.<table>`). The catalog tree reads the always-on REST catalog, so
  it browses even while Trino is idle-stopped. Validated end-to-end (both engines →
  same result contract → console; idle-stop scaled 1→0 automatically).
  See [docs/query.md](docs/query.md).

### Console
- **Databases show *Stopped* when paused, like VMs.** A database whose claim is
  stopped now reports `Stopped` in the Databases list Status column instead of an
  unhealthy/unknown state.

## v2.2.0 — 2026-07-12

### Analytics
- **New `kind: Query` — open-infra's Athena.** Serverless SQL over the data lake
  (MinIO), with no database to load into: point SQL at files in a bucket
  (`read_parquet('s3://…')`) and get results back. Each query is an *execution*
  (Athena's `StartQueryExecution` model) — it runs once in a throwaway **DuckDB** pod
  (a first-party, Trivy-scanned + cosign-signed `open-infra-query` image, extensions
  preloaded) against MinIO and writes the results (CSV) plus an `<id>.metadata.json`
  (state / row count / run time) to an output location; the console reads those back
  (the browser never runs SQL itself). The console **Data → Query** page is an
  Athena-style three-pane editor: a real SQL **code editor** (CodeMirror — syntax
  highlighting, gutter, **⌘/Ctrl+Enter**, run-the-selection-else-all), a left **Data**
  tree that browses buckets/files and inserts `read_parquet(...)` snippets, a
  **resizable results grid** (stats line + Download CSV), tabbed queries, and a
  **Recent queries** history — all rendered in the console's own theme. Phase 2 will
  swap the engine for **Trino** + a **`kind: Catalog`** (Glue equivalent) for
  distributed, `database.table` querying *without changing the `kind: Query`
  contract*. Validated end-to-end (claim → serverless Job → DuckDB → results in
  MinIO → console). See [docs/query.md](docs/query.md).

## v2.1.0 — 2026-07-11

### CI
- **The test suite now gates image build + release** (it was advisory — tests ran but
  nothing consumed the result, so a tag could ship signed images with red tests).
  `test.yml` is now a reusable workflow that `release.yml`, `build-console.yml`, and
  `build-apply-sink.yml` each run as a required `test` job the build/package job
  `needs:` — no image is built, signed, or pushed unless `go test -race` + `vet` pass
  on that ref, regardless of where a tag points (branch protection alone wouldn't
  suffice, since tags can target any commit). Verified with a live red build (a
  deliberately failing test → `build` skipped, no image shipped). See
  [docs/ci.md](docs/ci.md).

### Managed databases
- **New `engine: babelfish`** on an `Application`'s `database:` block — a **SQL-Server-compatible**
  managed database via Babelfish for PostgreSQL (TDS `1433` + T-SQL, backed by PostgreSQL 17). Point
  unmodified SQL Server / T-SQL apps at it with no code changes; the connection secret carries both a
  `SQLSERVER_URL` and a native-Postgres `DATABASE_URL`. The TDS + Postgres listeners are
  **TLS-encrypted** (cert-manager cert; `Encrypt=mandatory`, verified `encrypt_option=TRUE`), it runs
  on **open-infra's own cosign-signed image** (`ghcr.io/…/open-infra-babelfish` — patched Postgres +
  extensions **built from source** via `build-babelfish.yml`, `apt upgrade`d to 0 fixable CVEs), and
  it's a selectable engine in the console's **New
  Database** dialog. **Experimental**: single-instance StatefulSet on Longhorn (not CNPG — no
  streaming HA yet; durability via Longhorn + Velero), and it covers a large-but-incomplete T-SQL
  subset (run *Babelfish Compass* first). Start/Stop supported. Validated end-to-end (T-SQL over
  encrypted TDS via `sqlcmd`, through the composition-generated credentials). See
  [docs/databases.md](docs/databases.md#babelfish--sql-server-compatible-experimental).

### Active Directory (`kind: Directory`)
- **Windows domain join now works end-to-end.** The DC exposes the full standard AD port
  surface — **LDAPS `636`** + **Global Catalog `3268`/`3269`**, **CLDAP `389/UDP`** (the
  DC-locator ping Windows and `samba-tool gpo` require), and the **RPC endpoint mapper `135`
  + a pinned dynamic RPC range `49152-49164`** (machine-account creation) — rather than only
  the TCP LDAP/SMB/Kerberos basics. The RPC range is pinned in Samba (sambacc globals) so it's
  forwardable through the LoadBalancer.
- **The DC advertises its LoadBalancer VIP in AD DNS, not its pod IP.** It previously
  self-registered its ephemeral pod IP (unreachable from the LAN, re-registered on every roll)
  across five zone nodes (`@`, `dc1`, the pod-hostname node, `DomainDnsZones`, `ForestDnsZones`),
  so clients round-robined onto dead addresses. A `dns-vip` sidecar reconciles all of them to
  the VIP, and Samba's `dnsupdate` task is disabled so it never re-registers a pod IP — clients
  resolve the DC to a reachable, stable address with no per-client hosts-file pins.
- **Pod rolls are non-destructive.** The re-provision guard (`/etc/samba/smb.conf`) is persisted
  on the PVC, so a rolled or rescheduled DC serves the existing domain instead of re-provisioning
  a blank one over it (which had silently wiped imported users / OUs / GPOs).

### Console
- **Read-only AD Explorer** for `kind: Directory` — browse the DC's LDAP tree (OUs, groups,
  users, attributes) and search the directory over LDAPS, from the Directory detail page.
- **VM provisioning failures are visible.** The Virtual Machines views read the root disk's
  CDI DataVolume, so a stuck or failed clone shows a red **Disk error** with the reason (or a
  live **Cloning disk 45%** progress) instead of an indefinite "Provisioning" spinner.

### Networking
- **SecurityGroup changes apply to running VMs live — no restart** (matching the EC2 model).
  Editing a VM's `securityGroups` is reconciled onto the running launcher pod within seconds by
  a background reconciler in the console backend; previously the change only took effect on the
  next VM restart, because KubeVirt stamps pod labels only at creation.

### Virtual machines
- **Windows VMs provision reliably.** The fixed Windows root disk is floored above the golden
  image size — CDI refuses to clone a source into a smaller target, which wedged Windows VMs in
  `CloneScheduled` indefinitely. Paired with the console Disk-error surfacing above.

### Security
- Bumped `github.com/Azure/go-ntlmssp` (CVE-2026-32952 — a malicious NTLM challenge could panic
  the process) in the console backend; a transitive dependency of the new LDAP client.

## v2.0.0 — 2026-07-02

Multi-master data movement (`kind: DataFlow`), node-independent VMs with live
migration, and chaos engineering — plus, new in this release, the project's first
**correctness gate** (CI + tests, incl. a multi-master convergence harness) and
**honest maturity tiers**. The major bump reflects the breaking changes below
(chiefly the migration engine re-platform off Airbyte).

### ⚠️ Breaking changes
- **Airbyte and `provider-terraform` are removed; `kind: Migration` is re-platformed**
  onto open-infra's own Debezium + apply-sink engine. Migrations are now **continuous
  by default** (the manual "sync" trigger is gone) and `target.engine` accepts
  `postgres` / `mysql` / `sqlserver` (was Postgres-only). Airbyte-backed Migrations
  from v1.x must be recreated.
- **NATS names are namespace-qualified** (`<ns>-<name>` for streams / subjects /
  durables). Streams and consumers from older flows have different names — recreate
  flows (the orphan GC reaps the old ones); two same-named flows in different
  namespaces no longer share a stream.
- **`kind: DataFlow`: the per-edge `tables` field is removed** (scope is per-flow).
  Move any per-edge `tables` up to the flow level.
- **Console: list pages no longer have inline "fast-delete."** A row opens a detail
  page; destructive actions live in a red **Danger Zone** tab. No API change — a
  muscle-memory change.

### Maturity & guarantees (new — see [README](README.md#maturity--guarantees))
open-infra now states each capability's tier explicitly, because the two audiences it
serves have very different tolerance for failure:
- **Stable:** `Application`, `Model`, `Function`, `VirtualMachine`, `Volume`,
  `FileShare`, `Directory`, and managed databases (Postgres / MySQL / Mongo, incl. HA
  and Start/Stop). Failure here is a restart or rollback.
- **Experimental:** `Replication` (multi-master), cross-engine `Migration`, and
  multi-master `DataFlow` — the Debezium → NATS → apply-sink + HLC last-write-wins
  path. A conflict-resolution bug here is a **silent lost/diverged write**, not a
  crash. Use it, but keep an authoritative source until convergence is automatically
  tested end-to-end (see Known limitations).

### Testing, CI & correctness (new)
- **Stage A CI** (`.github/workflows/test.yml`) — `go vet` + `go test -race` across
  `apply-sink`, `console-api`, and a new `test/render` module, on every push/PR that
  touches Go or the compositions. The correctness gate the project previously lacked.
- **apply-sink unit tests** for the pure CDC logic — driver dialects, cross-engine
  type mapping, and the temporal-coercion buckets behind the cross-engine `DATE` fix.
- **MySQL HLC integration test** (build-tag `integration`) proving the Hybrid Logical
  Clock stays monotonic across a backward wall-clock jump (the T6 fix, now guarded).
- **Composition-render tests** (`test/render`, stdlib only) that assert template logic
  directly — e.g. "Start" always writes `cnpg.io/hibernation: "off"`, and HA renders
  `instances: 2` + required anti-affinity. Proven to catch the hibernation regression
  that once shipped.
- **Multi-master convergence harness** (`apply-sink`, build-tag `convergence`;
  [docs/convergence-harness.md](docs/convergence-harness.md)) — drives concurrent and
  deliberately conflicting writes across a running flow, then asserts every member ends
  byte-identical with zero lost writes. Run it under a `kind: FaultInjection`
  (partition / kill / skew) to prove convergence survives partition and node loss.

### Storage — FileShare node access
- **`spec.nodeIP` on `kind: FileShare`** — also answer SMB 445 on that node's LAN IP
  (Service `externalIPs`), so a masquerade-networked VM (which can't reach a MetalLB
  VIP) can mount `\\<nodeIP>\<name>`. Off unless set; existing shares are unchanged.

### Data Flows — visual data-movement (`kind: DataFlow`)
- **New `kind: DataFlow`** — one resource describing a graph of data-movement nodes
  (databases, message **topics**, transform **functions**, object-store **buckets**) and
  edges. Edge types: `replication` (two-way, optional `bootstrap` to seed an empty
  member), `migration` (one-way, schema auto-create), `stream` (publish CDC to a topic),
  and `pipe` (one-way ETL into a function/database/bucket). `tables: ["*"]` captures
  every table. Compiles onto the existing Debezium + NATS + apply-sink engine.
- **Drag-and-drop console canvas** (Data → Data Flows): palette of engines/topics/
  functions/buckets, edge types inferred from what you connect, fan-out by connecting one
  source to many targets, right-click **Configure** or **Peek metrics**, and a guided
  **Set up replication** wizard that explains the plan and deploys a star topology.
  Migrations and Replication are now modes within Data Flows (folded out of the sidebar).
- **Live observability** — per-edge lag/dead-letter overlay + per-node **Peek**
  (captured / per-table throughput / inbound backlog / retries / dead-letters), via
  `POST /api/dataflows/{ns}/{name}/status`.
- **apply-sink** gains `MODE=pump` (the ETL transform stage: stream → HTTP function →
  stream). Throughput + correctness hardening surfaced by load testing: per-batch
  transactions (one commit per fetch), deterministic `(table, PK)` apply order to avoid
  mesh deadlocks, and a 512 MB per-stream reservation. See [docs/dataflow.md](docs/dataflow.md).
- **Automatic table sync (`spec.autoSyncTables`)** — for multi-master flows, a table
  created on *any* member is auto-created on every other member (cross-engine, with type
  mapping) and made multi-master-ready (version/origin columns + stamping trigger), with no
  spec edit. A per-flow `reconcile` worker drives it; implies capture-all CDC. Verified
  across PostgreSQL + MySQL + MariaDB + SQL Server. Caveat: a table created *already full of
  data* needs a Debezium incremental snapshot to back-load existing rows (create-then-insert
  syncs fully).
- **Durability + correctness hardening:** Debezium offsets/schema-history moved from `emptyDir` to a
  per-node **Longhorn PVC** (a capture-pod restart no longer triggers a full re-snapshot);
  mm-prep now **backfills** version/origin on pre-existing rows (a `NULL` version could never
  win last-write-wins → silent divergence); consumer **`AckWait` 2m** (a slow batch is no
  longer redelivered mid-transaction); unchanged **TOASTed** Postgres columns are no longer
  clobbered with Debezium's unavailable-value placeholder; SQL Server **CDC auto-enabled**
  per table for auto-synced sources; injective (length-prefixed) apply sort key; system/CDC
  schemas excluded from discovery; capture pods given resource limits; an orphan
  **stream/DLQ garbage-collector** reaps JetStream resources left by deleted flows.
- **Accessibility** — edge status no longer relies on colour alone (WCAG 1.4.1): line
  **pattern** (solid = in sync, dashed = lagging, dotted = dead-letters, sparse-dots = not
  provisioned) + a shape glyph + a colour-blind-safe (Okabe-Ito) palette.
- Removed the unimplemented per-edge `tables` field from the schema (scope is per-flow).
- **Namespace-qualified NATS names** — streams/subjects/durables are now `<ns>-<name>`-scoped
  (they're cluster-global, unlike k8s objects), so two DataFlows with the same name in different
  namespaces can no longer share streams (cross-tenant cross-feed). Composition + GC + status BFF
  updated in lockstep.
- **Cross-engine DATE coercion** — a Debezium DATE (days since epoch) applied to a column the
  target introspects as `timestamp` is no longer misread as seconds (1970); small temporal
  integers are now treated as days.

### Managed databases (RDS) — console + lifecycle
- **Peek (live engine internals)** on the `/databases` pages — connections, replication-slot
  / CDC lag, and **top queries**, via `POST /api/databases/{ns}/{name}/stats`. The BFF
  resolves host + credentials from the database's own generated Secret (namespace-scoped,
  never client-supplied). PostgreSQL (CNPG) + managed MySQL; MongoDB has no SQL stats.
- **`pg_stat_statements`** is now preloaded and created on managed Postgres (with
  `pg_read_all_stats` granted to the app user) so Peek shows real query history. Foreign
  DataFlow source engines (which we can't modify) gracefully fall back to active queries.
- **Start/Stop (`spec.database.stopped`)** — RDS-style stop/start that retains data: Postgres
  hibernates (CNPG), MySQL/Mongo scale to zero, PVCs are kept. A Start/Stop button on the
  database detail pages toggles it. See [docs/databases.md](docs/databases.md).
- **Convert non-HA ↔ HA on demand** — a High-availability toggle on the database detail pages
  flips `spec.database.highAvailability` on a running DB without a recreate: Postgres (CNPG)
  scales the instance count live (adds/removes a streaming-replication standby — verified
  1→2 in ~30s), Mongo scales the FerretDB proxy tier, MySQL converts to a 3-node Galera.
- **CNPG operator upgraded 1.24.1 → 1.25.1** (Helm chart `0.22.1` → `0.23.2`) — online, no
  Postgres restart. 1.25 unlocks `spec.postgresql.synchronous.dataDurability`, so an HA Postgres
  can run **synchronous** replication that stays available when a standby is down (zero data loss
  while both are up, auto-degrades to async otherwise) instead of the pre-1.25 write-freeze. HA
  failover was validated end-to-end (primary node lost → standby promoted in ~4s, a
  primary-selecting LoadBalancer endpoint follows the new primary; zero data loss).

### Virtual machines — node-independent storage & live migration
- **`spec.highAvailability`** on `kind: VirtualMachine` provisions the root disk on **Longhorn**
  as a migratable RWX block volume (new **`longhorn-migratable`** StorageClass) and sets
  `evictionStrategy: LiveMigrate` — so the VM survives a node loss (reschedule + boot from a
  replica) and **live-migrates** off a drained node with zero downtime. Default stays local-path
  NVMe (faster, but node-pinned). Verified: a Windows VM live-migrated between nodes, running.
- **`spec.cpuModel`** — pin a guest CPU model every node supports so migration/reschedule works on
  a cluster with **heterogeneous CPUs** (`host-model`, the default, ties a VM to its node's exact
  CPU). HA VMs default to `Nehalem`.
- **`spec.existingRootClaim`** — boot from a pre-existing PVC instead of cloning the OS image
  (disk migration / restore); no root DataVolume is provisioned.
- **Golden images now live on Longhorn** (were node-pinned local-path, blocking provisioning when
  that node was down), and **`spec.existingGoldenClaim`** on `kind: VmImage` adopts/clones an
  existing golden so a built image can move to a new storage class without reinstalling. The VM
  Images page shows an adopted (cloned) golden as **Ready** once its PVC binds (no installer VM
  runs). See [docs/virtual-machines.md](docs/virtual-machines.md).

### Chaos engineering (`kind: FaultInjection`) — Fault Injection Simulator
- **Chaos Mesh** installed declaratively (Argo app, k3s containerd socket wired) + a
  **`kind: FaultInjection`** abstraction that compiles a small curated spec to a Chaos Mesh
  experiment with the **blast radius enforced** (always namespace + label-selector scoped,
  time-boxed). Types: pod-kill/pod-failure, network latency/loss/partition, cpu/memory stress,
  clock-skew, io-latency. A **console page** (Observability → Chaos) lists/creates/deletes
  experiments. See [docs/chaos.md](docs/chaos.md).
- **GameDays run** against disposable resources: validated Longhorn volume durability, MariaDB
  stateful recovery, CNPG HA failover, a 9-piece mixed mesh+migration+stream pipeline (converged
  under concurrent capture-kill + partition + sink-kill), and a 4-engine migration relay chain
  (recovered from a mid-chain capture+sink kill).
- **Monotonic-clock guard for MySQL/MariaDB stamping (T6).** A `clock-skew` experiment showed
  MySQL/MariaDB stamping had no monotonic HLC guard, so a backward clock produced a lower
  `_mm_version` → the write lost last-write-wins and silently diverged. MySQL/MariaDB now use a
  monotonic `mm_hlc_state` HLC (+ observe remote versions) like Postgres/SQL Server; re-running
  the same experiment, the version advanced +1 (not backward) and the write converged.

### Security
- Cleared all open Trivy image CVEs: apply-sink Go toolchain 1.22 → 1.26 (43 stdlib CVEs,
  incl. critical) and `jackc/pgx/v5` 5.5.5 → 5.10.0 (2 critical); console-api crypto/net bumps.

### Replication console
- **`kind: Replication` is now a first-class console page** (Data → Replication):
  list, create (both sites + tables), and a detail view showing **both directions**
  of the multi-master pipeline — each with its own lag, per-table throughput, and
  dead-letter panel (shared with the Migration view). Backed by the
  `/api/replications/{ns}/{name}/status` endpoint.

### Observability
- **Migration detail page** with a live apply-pipeline view (SymmetricDS/DMS-style):
  a Capture → Buffer → Apply strip, the headline **replication lag** (events
  captured but not yet applied), **per-table** event counts, and a **dead-letter**
  panel for rows that failed to apply. Backed by a new BFF
  `GET /api/migrations|replications/{ns}/{name}/status` that reads JetStream
  stream/consumer + DLQ info (lag, throughput, errors) the browser can't see.

### Bidirectional / multi-master replication
- **`kind: Replication`** — keep two database sites in sync both ways (each is
  source and target), **across engines** — PostgreSQL, MySQL/MariaDB, and SQL
  Server can each be source *and* target. Built on the same Debezium + NATS +
  apply-sink engine, with **origin-marker loop prevention**, **last-write-wins
  conflict resolution on a Hybrid Logical Clock** (clock-skew-safe; ties broken by
  origin), and capped streams + dead-lettering.
- An `mm-prep` Job installs the version/origin columns + a per-site stamping trigger
  on every engine — Postgres `BEFORE`/HLC, SQL Server `AFTER` (with a nestlevel
  guard, since it has no `BEFORE`-row triggers), MySQL `BEFORE` — so writes to any
  engine are auto-stamped with no application changes. The apply path skips its own
  stamping via a per-engine session flag.
- For 3+ nodes, compose pairwise links into a mesh or a ring; a
  **PostgreSQL + SQL Server + MySQL** round-robin was validated end-to-end (a write
  on any engine reaches the other two; a 3-way conflict converges to the newest).

### Database migration (DMS) — re-platformed off Airbyte
- **`kind: Migration` now runs on open-infra's own engine**: Debezium Server
  captures the source's changes onto NATS JetStream and the new **apply-sink**
  service applies them to the target as idempotent upserts/deletes, auto-creating
  the target schema with **cross-engine type mapping**.
- **Any SQL target** — `target.engine` is now `postgres`, `mysql`, or `sqlserver`
  (was Postgres-only), and the source may differ from the target (e.g. SQL Server →
  Postgres). Source engines: Postgres, MySQL/MariaDB, SQL Server.
- **Continuous by default** — a Migration snapshots then streams CDC; the manual
  "sync" trigger is gone (like AWS DMS continuous tasks).
- **Airbyte and `provider-terraform` are removed entirely** — a much lighter stack
  (no Temporal / workers / second Postgres). The apply-sink image is Trivy-scanned
  and cosign-signed by CI like the console.

### Fixes
- **Buckets page self-heals on MinIO credential rotation** — the console cached its MinIO client
  forever, so a MinIO restart with rotated root credentials 502'd the Buckets page until the
  console was restarted. It now re-reads the secret and rebuilds the client whenever the creds
  change (cache keyed by the credentials).

### Known limitations
- **Multi-master convergence** is verified by a harness, but injecting the fault
  (partition / kill / skew) is still driven by hand — not yet a single-command run.
- **Incremental back-load** — a table added to a flow that is *already full of data*
  needs a Debezium incremental snapshot to back-load existing rows (create-then-insert
  syncs fully).
- **VM `network: bridge` is experimental and not currently working** — a macvlan
  sub-interface can't be a KubeVirt bridge port, so a bridged VM crash-loops. VMs reach
  in-cluster services via `<nodeIP>:<nodePort>` (or a FileShare's `nodeIP`); a working
  bridge (macvtap) is planned. The `install.sh` vmLan block installs this plumbing and
  still carries an over-broad path-remap `sed` to fix.
- **Redis** pins Bitnami's legacy image mirror as a stopgap (Bitnami purged its public
  versioned tags in Aug 2025); migrating off Bitnami is tracked.

## v1.0.0 — 2026-06-23

The first stable release. Since v0.1.0 the platform gained real network security,
streaming + database migration, managed Active Directory, and EBS/FSx-style
storage — and the web console grew to manage all of it. AWS-equivalents are noted
in [`docs/architecture.md`](docs/architecture.md).

### Networking & Security
- **Cilium is now the cluster CNI** (full kube-proxy replacement), replacing
  flannel + the embedded kube-proxy/network-policy controller. This gives real
  `ipBlock`/CIDR NetworkPolicy enforcement. `install.sh` installs it.
- **`kind: SecurityGroup`** — AWS-style, reusable, stateful firewall rule sets,
  enforced by Cilium. Rules use **Type presets** (SSH/RDP/HTTP/… auto-fill
  protocol + port), sources of CIDR / another security group / namespace, and
  optional per-rule descriptions.
- **Dual-surface management in the console, mirroring EC2**: a **Security tab** on
  every VM, Application, Function, and Database (attached groups + aggregated
  read-only inbound/outbound rules + *Change security groups*), and a **security
  group detail page** (Inbound/Outbound/Used-by tabs, edit rules, copy to new).
- New resources get a sensible **default access group** at launch (SSH 22 for
  Linux, RDP 3389 for Windows), like the EC2 launch wizard.

### Data & streaming
- **`kind: Stream`** — change-data-capture from a source database to NATS
  JetStream via Debezium Server (Postgres / MySQL / MariaDB / SQL Server / Mongo).
- **`kind: Function` stream triggers** — event-source mapping: a function
  cold-starts on each CDC event and scales back to zero.

### Database migration (DMS)
- **`kind: Migration`** — Airbyte-backed full-load + CDC into managed Postgres,
  with a console wizard (source → target → table picker → run + monitor). Sources
  include Postgres, MySQL/MariaDB, SQL Server, and MongoDB.

### Identity
- **`kind: Directory`** — managed Active Directory via Samba AD DC, with Windows
  domain-join (and a *Join domain* picker in the New VM dialog).

### Storage
- **`kind: Volume`** (EBS) and **`kind: FileShare`** (FSx-style SMB) with console
  management pages; volume hotplug attach/detach to running VMs.
- MinIO HA and the data plane are pinned by node label, not hostnames.

### Virtual machines
- `spec.ports` publishes extra TCP/UDP ports on the VM's LAN IP; exposure is now
  driven by the attached security groups (`externalTrafficPolicy: Local` so source
  rules can match real clients).
- QEMU guest-agent / virtio fixes (IP reporting, hotplug visibility, snapshots).

### Fixes
- An Application's namespace LimitRange no longer caps co-located VM launcher pods
  (which broke VM launch with "request greater than limit").
- Console: action buttons no longer also open the YAML drawer; long values no
  longer overflow dialogs; assorted RBAC grants for new resource pages.

### Supply chain
- The console image is built, **Trivy-scanned, and cosign-signed** (keyless,
  Sigstore) by CI, and on a `v*` tag is published to GHCR with the version tag.

## v0.1.0 — 2026-06-20

First public release.
