# open-infra policy engine (WIP)

> Status: **in development** on `feat/policy-engine`. This documents the design and tracks what is
> actually built. Nothing here is enforced on the live platform yet.

## Why

open-infra's control-plane authorization is Kubernetes RBAC (impersonation → RBAC groups, gated by
SubjectAccessReview — see [`docs/security-and-compliance.md`](security-and-compliance.md)). RBAC is
the right fit for the k8s surface, but it is **additive-only**: it has no explicit `Deny`, and no
request conditions (MFA, source IP, tags). That is exactly why the CloudFormation engine refuses to
translate AWS `IAM::Policy`/`Role`/`Group` — an AWS policy document (allow **and** deny over
`service:Action` on ARNs, with conditions) cannot be represented in RBAC without silently dropping a
`Deny` or a condition, which is a security hole, not a lossy cosmetic ([`docs/cloudformation.md`](cloudformation.md)).

The policy engine closes that gap **where it actually bites** — the data planes — with a real
allow/deny/condition model, so a fine-grained data-plane grant can be expressed (and an AWS policy
can be imported) faithfully.

## Scope — data plane first (the 80/20)

The interesting fine-grained policies are **data-plane** policies: `s3:GetObject` on a bucket,
`dynamodb:Query` on a table, `lambda:InvokeFunction` on a function. Those are exactly the surfaces
the aws-shim already fronts, and where AWS IAM actions map cleanly. So:

- **In scope now:** fine-grained authorization at the aws-shim front doors (S3 → MinIO, DynamoDB,
  Lambda, AppSync), evaluated per request with allow/deny/conditions.
- **Deliberately out of scope (stays RBAC):** the Kubernetes control plane (`kind:` CRUD). RBAC +
  the permission boundary remain the authority there. A platform-wide engine that also fronts the
  k8s API is a later, separate decision — not this build.

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
2. It builds a Cedar request `{principal, action, resource, context}` (context carries
   authenticated, sourceIp, etc.).
3. The engine evaluates the principal's compiled Cedar policy set: **explicit `forbid` wins, else an
   `permit` allows, else default-deny.**
4. **Fail-closed:** an engine/evaluation error denies. When a principal has no data-plane statements,
   the shim's existing coarse RBAC check stands (so this is additive, never a silent loosening).

## AWS policy import

Once the model exists, an AWS IAM policy document maps onto it faithfully for the actions the shim
supports (`s3:*`, `dynamodb:*`, `lambda:*`) — `Allow`/`Deny` → `permit`/`forbid`, `Condition` →
Cedar `when`/`unless`. Actions open-infra has no surface for are reported, never silently granted.
This is what lets the CFN engine eventually translate `AWS::IAM::Policy` for data-plane actions
instead of refusing.

## Build phases (honest status)

- [x] **Cedar-go validated** — deny-overrides-allow + conditions + default-deny (a spike).
- [ ] **Engine module** (`policyengine/`) — the request/decision API over Cedar; the open-infra
      action/resource/principal model; compile `kind: Policy` statements → Cedar. ← in progress
- [ ] **Enforcement slice** — the S3 front door consults the engine (fail-closed), behind a flag.
- [ ] **Remaining data planes** — DynamoDB, Lambda, AppSync.
- [ ] **AWS-policy importer** + the CFN `AWS::IAM::Policy` (data-plane) translator.
- [ ] **Assurance** — adversarial + precedence + condition tests, audit trail, security review.
