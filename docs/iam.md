# IAM: users, groups, policies, roles and accounts

open-infra's IAM works like AWS IAM. **An IAM policy is the only thing that grants access**, and the same
policy decides the same way wherever a request comes from: the console, the AWS CLI and SDKs (through the
AWS front door), and CloudFormation stacks. If you know AWS IAM, you know this; the differences are listed
where they matter.

Everything below is done from the console (**Security & Identity**) or with the AWS CLI pointed at the
platform (`AWS_ENDPOINT_URL`). Nothing needs `kubectl`.

## Users

A user is a person or a program with its own credentials. Create one from **IAM → Users → Create user**,
or:

```sh
aws iam create-user --user-name alice
aws iam create-access-key --user-name alice            # programmatic access
aws iam attach-user-policy --user-name alice --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

- **Console access** is an option on the create form (a password the console stores hashed). Access keys
  are created and rotated from the user's page or with `create-access-key` / `update-access-key` /
  `delete-access-key`.
- **A user with no policy can do nothing**, as on AWS: it can sign in and see who it is, and every page
  and API call answers access denied. Changing its own password needs `iam:ChangePassword` on itself (as
  AWS's `IAMUserChangePassword` grants).
- **The name `root` is reserved** for the account's root user, which is not an IAM user (see
  [The root user](#the-root-user)).

### Console passwords (login profiles)

A user's console password is its login profile. Manage it from the user's page, or with the IAM API:

```sh
aws iam create-login-profile --user-name alice --password '…' --password-reset-required
aws iam get-login-profile    --user-name alice
aws iam update-login-profile --user-name alice --password '…'    # an administrator sets a new one
aws iam delete-login-profile --user-name alice                   # no more console sign-in
aws iam change-password --old-password '…' --new-password '…'    # the user, as itself
```

- **Password reset required**: the user's next sign-in can only change the password. Every other page
  answers `PasswordResetRequired` until it does.
- **The account password policy** (`get-`, `update-` and `delete-account-password-policy`) governs every
  password in the account: length, character classes, reuse (`PasswordReusePrevention`) and maximum age
  (`MaxPasswordAge`). Past that age the user must choose a new password at sign-in; with `HardExpiry` it
  cannot sign in until an administrator sets one. Until you set a policy, AWS's default applies: at least
  8 characters, three of uppercase, lowercase, numbers and symbols, and not the account name. Each account
  has its own.
- **Changing your own password** is allowed when the account policy sets `AllowUsersToChangePassword`, or
  when a policy grants `iam:ChangePassword` on the user itself. An explicit deny wins either way. Only an
  IAM user can call it: not a role session, and not root.
- Login profiles are for local users. A user from a directory (LDAP, Active Directory, OIDC) signs in
  with the directory's password.
- Only a bcrypt hash is kept, in the platform's credential store beside the access keys. It is never kept
  in the console's namespace, where the root user's credentials live; an admission policy holds the AWS
  front door to that.

## Groups

A group is a **container for policies**, as on AWS: its members get the policies attached to it. It is not
a permission tier.

```sh
aws iam create-group --group-name developers
aws iam attach-group-policy --group-name developers --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
aws iam add-user-to-group --group-name developers --user-name alice
aws iam put-group-policy --group-name developers --policy-name s3-team --policy-document file://s3-team.json
```

## Policies

Policies are AWS IAM policy documents (`Version`, `Statement` with `Effect`, `Action` / `NotAction`,
`Resource` / `NotResource`, `Condition`), stored as written. Attach them to users, groups and roles, or
embed them inline.

```sh
aws iam create-policy --policy-name s3-team --policy-document file://s3-team.json
```

### AWS managed policies

The platform ships AWS's managed policies under their AWS names and ARNs
(`arn:aws:iam::aws:policy/<Name>`), each with AWS's document limited to the services the platform serves
(each policy's description says what it leaves out). The job-function policies:

| Policy | What it allows |
|---|---|
| `AdministratorAccess` | everything |
| `PowerUserAccess` | everything except IAM, Organizations and Account management (it can still list roles and create service-linked roles, as AWS's document allows) |
| `ReadOnlyAccess` | every served service's read actions (`Describe*`, `Get*`, `List*` and the like) |
| `ViewOnlyAccess` | list and describe, no data reads |

and the service ones the AWS estates we have seen use most: `AmazonS3FullAccess` /
`AmazonS3ReadOnlyAccess`, `IAMFullAccess`, `AWSLambdaBasicExecutionRole`,
`AWSLambdaVPCAccessExecutionRole`, `AmazonSQSFullAccess`, `AmazonDynamoDBFullAccess`,
`AWSStepFunctionsFullAccess`, `AmazonRDSFullAccess`, `CloudWatchFullAccess`, `AmazonSSMFullAccess`,
`AWSCloudFormationFullAccess`, `AmazonCognitoPowerUser`, `SecretsManagerReadWrite`,
`AmazonSSMManagedInstanceCore`, the ECR policies and more; the console's **Policies** page lists them all.
A managed policy for a service the platform does not serve can be attached; it grants nothing, and says
so.

### How a request is decided

AWS's evaluation logic:

1. An explicit `Deny` in any applicable policy wins.
2. Otherwise an `Allow` from an identity policy (the user's own, its groups', or the role's) or from the
   resource's policy (a bucket, queue, topic, key, function or repository policy) allows it — within the
   same account, either is enough; across accounts, both sides must allow it.
3. A permissions boundary and a session policy (an assumed role's) narrow what identity policies allow.
4. Anything not allowed is denied.

**Conditions** supported: `aws:SourceIp` (`IpAddress` / `NotIpAddress`), string conditions such as
`aws:username` (`StringEquals`, `StringLike` and their negations), and `aws:CurrentTime` windows
(`DateGreaterThan` / `DateLessThan`). A statement whose condition the platform cannot evaluate is never
read more broadly than written: an `Allow` with it grants nothing, and a `Deny` with it applies
unconditionally. The policy's page reports which statements that affected.

**One difference from AWS:** the platform has an operator surface (its Kubernetes objects: workloads,
nodes, Secrets) that AWS has no service for. Its actions are `openinfra-operator:*`. A policy grants them
only by naming them or with `"Action": "*"` (as `AdministratorAccess` does); an "everything except …"
`NotAction` allow (as `PowerUserAccess` is) never reaches them.

**When access is denied** the answer is AWS's: `AccessDenied` / `AccessDeniedException` (EC2:
`UnauthorizedOperation`), with a message naming the action and the resource ARN — `You are not authorized
to perform: s3:DeleteBucket on resource: arn:aws:s3:::reports`.

## Roles

A role is assumed for temporary credentials, by a user, another role, a workload or a web identity:

```sh
aws iam create-role --role-name deployer --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name deployer --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
aws sts assume-role --role-arn arn:aws:iam::<account>:role/deployer --role-session-name ci
```

- **Trust** entries name principals by ARN (`arn:aws:iam::<account>:user/alice`, `…:role/…`,
  `…:root` for a whole account) or a federated provider for `AssumeRoleWithWebIdentity`.
- Sessions last up to the role's `MaxSessionDuration` (1 hour by default, at most 12).
- **Instance roles:** a virtual machine's role (`IamInstanceProfile` in a stack, the VM's role in the
  console) gives the guest credentials through the instance metadata service, as on EC2.
- "Revoke active sessions" on a role's page ends every session issued before that moment, as AWS's does.

### Passing a role (`iam:PassRole`)

Naming a role on something that later acts with that role's credentials — a VM's instance role
(`IamInstanceProfile`), a state machine's `RoleArn` — needs `iam:PassRole` on the role, as on AWS.
`AdministratorAccess` includes it; `PowerUserAccess` does not, so a power user launches such a resource
only once someone grants `iam:PassRole` on that role:

```json
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::<account>:role/deployer"}]}
```

## Accounts and Organizations

Each install is an organization, and its **management account** is the install's own account (its id is
in every ARN the platform has handed out). Member accounts are separate accounts: their own IAM, their own
resources, their own account id in their ARNs, and isolation from other accounts.

```sh
aws organizations describe-organization
aws organizations list-accounts
aws organizations create-account --email team-a@example.com --account-name team-a
aws organizations describe-create-account-status --create-account-request-id car-…
```

- A new member account gets an `OrganizationAccountAccessRole` that trusts the management account and
  holds `AdministratorAccess`, as AWS creates it.
- **Switch role:** the console's account menu switches into a member account's role (and back), as the
  AWS console does. From the CLI it is `sts assume-role` into that role's ARN.
- **Across accounts**, access works as on AWS: a role's trust policy names the other account (or a
  principal in it), or a resource policy grants it, and the other side's identity policy must allow it
  too.
- Organizations is served to the management account only; a member account's caller is denied.
- **Each account's resources are its own** at every front door that keeps resources: queues, topics,
  tables, streams, secrets, parameters, keys, rules, alarms, log groups, functions, state machines, ECS
  clusters and task definitions, EC2 instances and key pairs, Run Command, APIs, user pools,
  repositories, buckets (bucket names stay global, as on AWS), DB instances and snapshots, and stacks.
  The same name lives in each account independently, ARNs carry the account's id, and an account lists
  only its own. Glue and Athena serve the management account only: a member account's call is
  AccessDenied.
- **Service-linked roles:** the platform's services act in a member account through service-linked
  roles, as AWS services do (`AWSServiceRoleForECS`, `AWSServiceRoleForRDS`). The service defines each
  role, every member account has it from creation, and the account's own principals cannot change it. An
  operator finds them as the ClusterRoles named `openinfra:service-linked:<service>`. The IAM compiler
  binds them in each member account's home namespace.

### Service Quotas

Each account has quotas under AWS's own service and quota codes, read and raised with Service Quotas as on
AWS:

```sh
aws service-quotas list-services
aws service-quotas list-service-quotas --service-code lambda
aws service-quotas get-service-quota --service-code lambda --quota-code L-B99A9384
aws service-quotas get-aws-default-service-quota --service-code lambda --quota-code L-B99A9384
aws service-quotas request-service-quota-increase --service-code lambda --quota-code L-B99A9384 --desired-value 2000
aws service-quotas list-requested-service-quota-change-history
```

| Service | Quota | Code | Default here |
|---|---|---|---|
| `lambda` | Concurrent executions | `L-B99A9384` | 1,000 (enforced) |
| `ec2` | Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances | `L-1216C47A` | 64 vCPUs |
| `ec2` | EC2-VPC Elastic IPs | `L-0263D0A3` | 5 |
| `cloudformation` | Stacks | `L-0485CB21` | 2,000 |
| `s3` | General purpose buckets | `L-DC2B2D3D` | 10,000 (account-wide) |
| `dynamodb` | Maximum number of tables | `L-F98FE922` | 2,500 |

- `get-service-quota` answers the account's applied value; `get-aws-default-service-quota` answers AWS's
  own default.
- An increase request is `PENDING` until an operator approves it, then reads `APPROVED` (or `DENIED`).
  One request per quota may be pending at a time, and the value asked must be above the current one.
- Lambda's concurrent executions is enforced where the platform's compliance component runs: in each of
  the account's namespaces, its burstable functions (`spec.burstable`) together run at most that many
  instances. The other quotas are reported as the account's quotas, not enforced.
- Calls are authorized as `servicequotas:<Operation>`; a request's resource is the quota's ARN,
  `arn:aws:servicequotas:<region>:<account>:<service-code>/<quota-code>`.

## The root user

The account's root user is the console's break-glass sign-in, created with the install. It is not an IAM
user and has every permission in its account; no policy can lock it out. Keep its password offline, use
IAM users and roles for daily work, and use root only when IAM itself needs repair.

## Temporary access: grants

A **grant** gives a user another set of permissions for a bounded time (at most 24 hours) and then
revokes itself — just-in-time access instead of standing privilege. A grant is a request: it gives
nothing until a second person approves it, and a requester cannot approve their own (**Security &
Identity → Grants**). Every grant, approval and revocation is in the audit trail.

---

## Running the cutover (operators)

*Operator-facing: this section is Kubernetes-shaped by design.*

The platform moved from Kubernetes RBAC tiers (`admins`, `powerusers`, `readers`) to IAM policy as the
only authority. How far IAM policy decides is a switch, `IAM_AUTHZ`, read from an out-of-git ConfigMap
`openinfra-iam` in each component's namespace (so ArgoCD's self-heal never undoes a step):

| `IAM_AUTHZ` | The console and the AWS front door |
|---|---|
| `legacy` (unset) | decide as before (RBAC tiers) |
| `shadow` | decide as before, and log the IAM decision next to it (`iam-shadow allow|deny …`); a User or Role labelled `openinfra.dev/iam-authz: enforce` is decided by IAM policy (a canary) |
| `enforce` | IAM policy decides for every principal |

The compiler (`iam-compiler`, `IAM_COMPILER_MODE` `report` or `apply` in the same ConfigMap in
`open-infra-authz`) turns IAM policy into what Kubernetes still enforces: generated RBAC (labelled
`openinfra.dev/generated-by: iam-compiler`) and the IAM corpus the authorization webhook reads. RBAC is
generated, never hand-written; a CI check (`test/render/rbac_user_authority_test.go`) fails on any
hand-written grant to a user.

`hack/iam-cutover.sh <step> [--rollback] [--yes]` runs the cutover one reversible step at a time. Each
step first proves the break-glass root (SubjectAccessReviews for its floor, then a console sign-in as root
that writes IAM and creates a resource — set `ROOT_PASSWORD`), shows what it will change, applies,
verifies and prints its rollback. State is kept in `~/.local/state/openinfra-iam-cutover`.

| Step | Does | Rollback |
|---|---|---|
| 0 | the webhook's root floor; a corpus regen; console and front door in `shadow` | back to `legacy` |
| 1 | `hack/iam-migrate --apply`: each tier's AWS managed policy attached to its group, documents next to the old forms (additive) | restores every changed object from its snapshot, deletes what it created |
| 2 | the IAM probes as canaries: `probe/iam-parity.sh`, `probe/iam-no-policy.sh`, `probe/iam-managed-policies.sh` (`PRINCIPAL_MODE=canary`); optionally `CANARY_USER` | unlabel the canary user |
| 3 | the compiler's apply rights (and the RBAC corpus that carries them), the compiler in `apply` (generated RBAC + IAM corpus), then `enforce`, and only then the RBAC corpus without user principals; the probes again for every principal | `shadow`, compiler `report`, generated RBAC deleted, the full RBAC corpus back |
| 4 | checks nothing names the implicit `openinfra:users` group; the impersonation ceilings are a commit | revert that commit |
| 5 | the estate mirror's namespace becomes its own member account (`MIRROR_NAMESPACE`, `MIRROR_ACCOUNT_ID` to override the discovered namespace and derived id), with its claims checked as Ready as before | delete the account and unlabel the namespace |
| 6 | after 24 h clean: `hack/iam-migrate --drop-legacy`, then the repo changes it prints (legacy bindings, the kebab-case alias policies) | none — roll back step 3 before this |

A canary is decided by IAM policy alone, at every door, for every read. A write that the console or the
AWS front door makes on the cluster as the principal (a stack, an instance's state, a volume, a bucket, an
ECS service) also needs the RBAC the compiler generates, which step 3 applies: until then a canary user
can be refused such a write that its policy allows. The probes' canaries write only resources that do not
exist, so none of their writes reaches the cluster as them.

The probes run on their own too (`SHIM_ENDPOINT` to reach the AWS front door; the console is reached
through a port-forward unless `CONSOLE_ENDPOINT` is set); `probe/aws-shim-organizations.sh` proves the
Organizations front door. A new principal reaches each door within 30 seconds (each caches its IAM policy
for that long); the probes wait `IAM_SETTLE_SECONDS` (35) for it. Once IAM policy decides, a front door
that writes to the cluster as the caller (S3 CreateBucket, CloudFormation, Organizations CreateAccount)
also needs the caller's compiled rights: the IAM compiler compiles a new principal within one pass (every
15 seconds) and the authorization webhook reloads them within 30 seconds, so a principal made a moment
ago can see AccessDenied for up to about 45 seconds, as AWS IAM changes take a moment to propagate; the
probes that write as a new caller wait for it with a SubjectAccessReview. Exit 0 is a pass, 1 a failure,
42 inconclusive (for instance IAM policy not deciding for the probe's principals).

## Approving a quota increase (operators)

*Operator-facing: this section is Kubernetes-shaped by design.*

A request from `request-service-quota-increase` is recorded in the ConfigMap `servicequota-requests` in
the AWS front door's namespace, one key per account (`<account-id>.json`). To approve it, set the value
on the account's `kind: Account`; the request then reads `APPROVED`:

```yaml
apiVersion: organizations.openinfra.dev/v1
kind: Account
metadata: { name: "<account-id>" }
spec:
  serviceQuotas:
    - { serviceCode: lambda, quotaCode: L-B99A9384, value: 2000 }
```

To deny it, set that request's `Status` to `DENIED` in the ConfigMap. The applied quotas are also written
to each member account's `openinfra-service-quotas` ConfigMap, and Lambda's concurrent executions becomes
the `openinfra.dev/function-concurrency` label on each of the account's namespaces. That label is what the
`compliance` component's `function-concurrency-quota` policy turns into a ResourceQuota on the namespace's
burstable function pods (see [function-admission.md](function-admission.md)); the account's value replaces
any value set on the namespace by hand. The management account's namespaces are the install's own, so
their label, if any, is set in the install's manifests rather than from its `kind: Account`.

## See also

- [policy-engine.md](policy-engine.md) — the policy engine underneath.
- [authz-webhook.md](authz-webhook.md) — the control-plane corpora and the root floor.
- [auth.md](auth.md) — console sign-in (local, LDAP, OIDC).
- [aws-shim.md](aws-shim.md) — the AWS front door and the services it serves.
