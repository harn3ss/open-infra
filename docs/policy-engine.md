# open-infra policy engine (WIP)

> Status: **in development** on `feat/policy-engine`. This documents the design and tracks what is
> actually built. The engine and its shim enforcement are built and the decision path is
> live-verified (see the build phases); enforcement only bites where the aws-shim data-plane front
> doors are enabled, which is opt-in and off by default, so no live platform traffic is governed
> today. The remaining live step is a fully-deployed shim answering a SigV4 call.

## Why

open-infra's control-plane authorization is today Kubernetes RBAC (impersonation → RBAC groups, gated
by SubjectAccessReview — see [`docs/security-and-compliance.md`](security-and-compliance.md)). RBAC is
the native authorization for the k8s surface, but it is **additive-only**: it has no explicit `Deny`,
and no request conditions (MFA, source IP, tags). That is exactly why the CloudFormation engine could
not translate AWS `IAM::Policy`/`Role`/`Group` — an AWS policy document (allow **and** deny over
`service:Action` on ARNs, with conditions) cannot be represented in RBAC without silently dropping a
`Deny` or a condition, which is a security hole, not a lossy cosmetic ([`docs/cloudformation.md`](cloudformation.md)).

This engine removes that barrier for the data plane: the CloudFormation engine now translates the
data-plane part of `IAM::Policy`/`ManagedPolicy` into an enforced `kind: Policy` (`Role`/`Group`
control-plane grants remain refused, pending the platform-wide work below). Its allow/deny/condition
model is also the basis for the decided move to make Cedar the authority for the whole platform, not
just the shim.

The policy engine closes that gap **where it actually bites** — the data planes — with a real
allow/deny/condition model, so a fine-grained data-plane grant can be expressed (and an AWS policy
can be imported) faithfully.

## Scope — data plane first, platform-wide as the destination

The interesting fine-grained policies are **data-plane** policies: `s3:GetObject` on a bucket,
`dynamodb:Query` on a table, `lambda:InvokeFunction` on a function. Those are exactly the surfaces
the aws-shim already fronts, and where AWS IAM actions map cleanly. So the **first** milestone is
narrow on purpose:

- **In scope, built today:** fine-grained authorization at the aws-shim front doors (S3 → MinIO,
  DynamoDB, Lambda), evaluated per request with allow/deny/conditions. This is Phase 1.
- **The decided destination:** Cedar becomes the platform-wide authorization authority, with the
  Kubernetes control plane (`kind:` CRUD) moving from RBAC to Cedar via a Kubernetes
  authorization-webhook — run alongside RBAC first to measure divergence, then RBAC leaves the
  chain. This is a **decided direction, not yet built**; until it lands, RBAC + the permission
  boundary remain the control-plane authority. It carries its own assurance burden (a Cedar corpus
  has no published CIS-style benchmark), which is part of the same plan.
- **Stays where it is:** AppSync field-level authorization remains inside open-appsync
  (per-field `@aws_*` + SAR) — a different enforcement point, not moved into this engine.

This keeps one enforcement class (the shim) instead of retrofitting every door, which is where the
cost and risk of a full engine live.

## Model

- **Evaluator: [Cedar](https://www.cedarpolicy.com/)** (`github.com/cedar-policy/cedar-go`) — AWS's
  open-source, formally-verified policy language. It is semantically closest to AWS IAM (explicit
  `permit`/`forbid` with `forbid` overriding, conditions, default-deny) and Go-native. We do **not**
  hand-roll an evaluator — authz bugs are breaches.
- **Principals:** an open-infra `User`, a `Group`, or an access key (the aws-shim's `iam-ak-*`
  identity) — the same principals the shim already authenticates via SigV4.
- **Actions:** namespaced per data plane — `s3:GetObject`, `dynamodb:Query`, `lambda:InvokeFunction`,
  `appsync:GraphQL` — matching the AWS action names the shim already receives, so the mapping is 1:1.
- **Resources:** the addressed object — a bucket, a table, a function, a GraphQL API.
- **Policies:** carried on the existing `kind: Policy` (one policy world — the shim shares the
  console's `internal/iam` authz). `kind: Policy` gains an optional `statements[]` block (effect /
  actions / resources / condition) that compiles to Cedar; its existing RBAC grant is unchanged.

## Evaluation & enforcement

1. The shim authenticates the request (SigV4 → an open-infra principal) — unchanged.
2. The coarse RBAC SubjectAccessReview runs — unchanged.
3. The engine evaluates the principal's compiled Cedar policy set: **explicit `forbid` wins, else a
   `permit` allows, else default-deny** (AWS-style). The final decision is `coarse AND engine`, so a
   policy can only **tighten** a grant RBAC already allowed — never widen it.

**Per-service governance (no cross-service surprise).** Governance is scoped to the request's
service (the action prefix — `s3`, `dynamodb`, `lambda`). A principal is governed for a service only
if one of their statements names that service (`s3:...`) or `*`. If none do, the coarse decision
stands untouched — so an S3 policy never affects a principal's DynamoDB access. Within a governed
service the model is AWS-style allow-list: only what a `permit` allows passes (so "block just one
action" is written the AWS way — `Allow s3:*` + `Deny s3:DeleteObject`).

**Fail-closed:** an engine load or compile error denies. No policy governing a principal's service =
that principal is unaffected there.

## AWS policy import

`policyengine.ImportAWS` maps an AWS IAM policy document onto the model for the actions the shim
supports (`s3:*`, `dynamodb:*`, `lambda:*`) — `Effect` → `permit`/`forbid`, ARNs → typed resources
(`arn:aws:s3:::reports/*` → `Bucket::reports`, a table ARN → `Table::metrics`). Everything it cannot
honor is **reported, never silently granted or dropped**: an action for a service with no data plane,
an unrecognizable ARN, a statement with no mappable `Resource`, and — deliberately — any `Condition`
(a silently-ineffective `Deny` condition is a security hole, so conditions are refused wholesale in
v1 rather than guessed; the engine evaluates conditions natively, so author them on `spec.dataPlane`).

This is what lets the CFN engine translate `AWS::IAM::Policy`: `translateIAMPolicy` runs the importer
and, being fail-closed to a fault, **blocks the whole resource** if the importer reports *any*
unsupported part (a partial security policy is worse than none) — so only a policy that is purely
data-plane actions on recognizable ARNs with no conditions becomes a `kind: Policy spec.dataPlane`,
attached to its `Users`/`Groups`. A `Roles` attachment blocks (the shim authenticates Users and
access keys, not assumed roles). See [`cloudformation.md`](cloudformation.md).

## Policy shape

A `kind: Policy` carries an optional `spec.dataPlane` block alongside its RBAC `statements`:

```yaml
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: analyst-scope, namespace: open-infra-console }
spec:
  dataPlane:
    appliesTo: ["User::analyst", "Group::analysts"]
    statements:
      - { effect: Allow, actions: ["s3:GetObject"], resources: ["Bucket::reports"] }
      - { effect: Deny,  actions: ["s3:DeleteObject"], resources: ["*"] }
      - { effect: Allow, actions: ["dynamodb:Query"], resources: ["Table::metrics"],
          condition: { authenticated: "true" } }
```

The shim lists these (cached, 30s), collects the statements whose `appliesTo` names the request's
principal or a group, compiles them to Cedar, and evaluates every request — AND'd with the coarse
RBAC check, so it can only tighten.

## Build phases (honest status)

- [x] **Cedar-go validated** — deny-overrides-allow + conditions + default-deny (a spike).
- [x] **Engine module** (`policyengine/`) — request/decision API over Cedar; the action/resource/
      principal model; open-infra `Statement` → Cedar compiler.
- [x] **Enforcement wired** — S3, DynamoDB, and Lambda front doors consult the engine
      (`internal/dataplaneauthz`), fail-closed, additive to the coarse SAR. `kind: Policy.dataPlane`
      is the source; the shim's ClusterRole gains read-only `list policies`. Handler tests prove a
      Deny blocks the op at the shim.
- [x] **Live-verified on the cluster** — a real `kind: Policy` with a `dataPlane` block round-trips
      through the CRD, and the real `K8sLoader` → Checker → Cedar engine decides correctly
      (deny-overrides, condition-gating, allow-list restriction, per-service governance). The
      remaining live step is the fully-deployed shim answering a SigV4 aws-cli call (generic shim
      HTTP plumbing, already proven for the shim's other paths).
- [ ] **AppSync** — deliberately NOT via this engine: AppSync's fine-grained authz is *inside*
      open-appsync (per-field `@aws_*` + SAR), which is the right layer; the shim can't identify a
      specific API. Left to open-appsync.
- [x] **AWS-policy importer + CFN `AWS::IAM::Policy` translator** — `policyengine.ImportAWS` maps an
      AWS policy document to data-plane statements (reporting, never dropping, what it can't honor);
      the cfn engine's `translateIAMPolicy` imports it into a `kind: Policy spec.dataPlane` and blocks
      on any unsupported part. **Live-verified**: `cfn deploy` of a pure data-plane `AWS::IAM::Policy`
      created a real `kind: Policy` (via the Crossplane composition, ARNs mapped, `Deny` preserved),
      the real `K8sLoader` → Checker → engine enforced it for a member of the attached group
      (allow/deny/allow-list/per-service governance all correct), and a mixed `ec2`+`s3` policy was
      refused at the translate gate with nothing applied.
- [~] **Assurance** — an initial security-review pass is done: it hardened the cache to serve the
      last-good policy snapshot through a control-plane blip instead of denying all data-plane traffic
      (a transient loader error was a shim-wide outage), and confirmed the enforcement is coarse-AND
      (data-plane runs after the SAR, so it only tightens), the request action/resource are matched as
      exact strings (only a *policy's* `*` becomes a wildcard), and a client-build failure disables the
      engine loudly rather than silently. Governed denies are logged. Remaining: a deeper external
      review, and the final live step — a fully-deployed shim answering a SigV4 aws-cli call against a
      governed principal (the loader → engine and CFN → enforced-policy paths are both live-verified
      above; standing up the shim front door on the live platform is the opt-in operator step).
