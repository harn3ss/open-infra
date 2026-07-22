# IAM — users, roles and policies (design)

> AWS equivalent: IAM. This is the **plan of record**; today only part of it exists — see
> [Status](#status). For what's actually shipped, read [`auth.md`](auth.md).

## The governing principle

**Kubernetes RBAC is the enforcement plane. open-infra's CRDs are a compiler front-end for it.**

The console must never be the thing that says no. It signs a user in, then proxies their calls
with impersonation so the API server decides — which means a permission holds no matter how the
action is attempted (console, `kubectl`, Terraform, Argo), and every decision lands in the audit
log attributed to a person. Every mature platform on Kubernetes converged on this: Rancher
compiles RoleTemplates to aggregated ClusterRoles, OpenShift's authorization objects *are* RBAC
objects. Nobody reimplements authorization for cluster resources in app code.

## The mapping

| AWS IAM | open-infra | Enforced by |
|---|---|---|
| IAM user | `kind: User` → `Impersonate-User: openinfra:<name>` | k8s authn |
| IAM group | `kind: Group` → `Impersonate-Group: openinfra:<name>` | k8s authn |
| Role (attachable set) | `kind: Role` → aggregated ClusterRole | RBAC |
| Managed policy | `kind: Policy` (Allow-only) → labelled ClusterRole | RBAC aggregation |
| Attach policy → role | an aggregation label | RBAC controller |
| Inline policy | `spec.inline` on a `kind: Role` | RBAC |
| **Explicit `Deny`** | `kind: Policy` with `effect: Deny` | **ValidatingAdmissionPolicy** |
| **`Condition`** | `spec.condition` on a Deny statement | **ValidatingAdmissionPolicy** |
| Permission boundary | *deliberately not built* | — |
| CloudTrail | k8s audit log (`impersonatedUser`) | already shipped |

## The constraint that shapes everything

**Kubernetes RBAC is purely additive. There are no deny rules.** It also has no conditions and
cannot match on resource attributes (labels, spec fields). So:

- The **`Allow` half** of an IAM-style policy maps cleanly onto RBAC rules.
- The **`Deny` half and every `Condition` do not**, and must be enforced at a different point —
  **admission**, where the object body and the requester's identity are both in scope.

Any design that pretends otherwise ships a policy editor that accepts JSON it cannot enforce.
That is the single most important thing to get right here.

Two further RBAC limits worth stating, because they look like they work and then don't:

- **`resourceNames` cannot restrict `list`, `watch`, `create` or `deletecollection`.** "Read only
  the VMs named X" is unachievable — `get` by name works, but the console lists constantly and
  `list` is all-or-nothing. Per-object scoping must be a **namespace** boundary or an admission
  condition, never `resourceNames`.
- **No glob matching on names.** `resourceNames: ["prod-*"]` is exact-string equality, not a
  pattern. Don't offer a wildcard field the backend can't honour.

## Staged plan

### Stage 0 — harden what exists
- ✅ **Pin impersonation.** `impersonate` on groups with no `resourceNames` is effectively
  cluster-admin (the holder can become `system:masters`). Pinned to the four `openinfra:*` groups.
- ✅ **SAR-gate the BFF's own endpoints.** Handlers that act as the ServiceAccount should issue a
  `SubjectAccessReview` *as the impersonated user* before acting, and fail closed. This is the
  documented way to defer an authorization decision, and it shrinks the one real hole in
  [`auth.md`](auth.md).
- ✅ **Guard role drift.** `open-infra-poweruser` enumerates kinds, so adding a `kind:` silently
  leaves powerusers without access. AWS solves this with `NotAction`; RBAC has no such thing, and
  a bare `resources: ["*"]` would be *worse* here because it would auto-grant future identity
  CRDs. The fix is a CI test asserting every CRD is either listed or explicitly excluded.

### Stage 1 — `kind: User` and `kind: Group` ✅
Replaces the JSON blob in the `console-auth` Secret, so accounts become GitOps-managed like
everything else.

```yaml
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: alice }
spec:
  displayName: Alice Example
  groups: [powerusers]
  source: local                 # local | ldap | oidc
  passwordSecretRef: { name: user-alice, key: hash }   # bcrypt hash, never a password
```

**Put identity CRDs in a separate API group (`iam.openinfra.dev`), not `openinfra.dev`.** The
existing `open-infra-readonly` role grants `openinfra.dev: ["*"]`, and because RBAC is additive a
wildcard *grants* new kinds the moment they exist — a reader would silently gain read access to
the identity objects. A separate group makes that boundary structural instead of a list someone
must remember to maintain.

The local `root` account stays in the Secret as documented break-glass.

**Sign-in order is Secret first, then `kind: User`.** That ordering is the whole point of
break-glass: if the CRDs are missing, a Composition is broken, or someone deletes their own
User, `root` still works. Losing the console because the thing that defines who may use the
console is broken would be the worst possible failure mode.

A User's `spec.groups` become the `Impersonate-Group` values **directly** — they are not
re-derived from a role keyword. The session still carries a role, but only for display and
for the read-only write gate on the BFF's own endpoints. Empty `spec.groups` therefore means
"can sign in, authorized for nothing" rather than defaulting to a role: forgetting to set
groups fails closed. Every name is `openinfra:`-prefixed, so a User asking for
`system:masters` gets the inert `openinfra:system:masters`.

#### The ceiling on group names (read this before creating a `kind: Group`)

Stage 0 pinned the impersonator ClusterRole's `resourceNames` to the four built-in groups,
because `impersonate` on groups without that pin is effectively cluster-admin. That pin is
also a hard ceiling on `kind: Group`: **a Group whose name is not in that list has no
effect.** Its ClusterRoleBinding is created, the user signs in fine, and then every API call
fails, because the console is not allowed to assert the group in the first place.

The console rewrites that 403 into an actionable message naming the group and the
ClusterRole, rather than passing through the API server's version, which blames the console's
ServiceAccount and reads like a bug.

So:

* Prefer the built-in groups — `admins`, `powerusers`, `readers` — and vary what they mean by
  pointing `spec.clusterRole` at a different ClusterRole.
* A genuinely new group name requires an operator to add `openinfra:<name>` to
  `open-infra-console-impersonator` in `platform/console/manifests/rbac-roles.yaml`. That is a
  deliberate, reviewable act, not something the console can do for you — anything able to widen
  its own impersonation list could grant itself `system:masters`.

### Stage 2 — `kind: Policy` (Allow-only) and `kind: Role`
Where the AWS-like UX actually appears, restricted to the half RBAC can enforce.

```yaml
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: VirtualMachineFullAccess }
spec:
  statements:
    - effect: Allow
      actions: ["virtualmachines:*", "volumes:Get", "volumes:List"]
      resources: ["*"]
```

Each `Allow` compiles to a **labelled ClusterRole**; `kind: Role` is an **aggregated ClusterRole**
selecting those labels. Attaching or detaching a policy in the UI is adding or removing a label.
This is exactly how Kubernetes' own `admin`/`edit`/`view` are built and where Rancher landed.

**Solve the escalation problem before writing the composition:** you cannot create a Role granting
verbs you don't hold unless you hold `escalate`. Whatever renders these ClusterRoles must hold a
superset of anything it can emit — there is no third option. Document the choice honestly.

#### What is built (2026-07-22) — and where it paused

`kind: Policy` and its **permission boundary** are shipped and live; `kind: Role` is blocked on
one decision. Honest current state:

- **`kind: Policy` works**, without granting anyone `escalate`. The boundary is enforced two ways:
  the composition **hardcodes `apiGroups: [openinfra.dev]`** into every rule and **whitelists the
  15 product resources**, so a policy naming `secrets` (or a typo) has that rule *dropped* rather
  than poisoning the whole role; and the rendering ServiceAccount is granted *exactly* the
  openinfra.dev surface, so the API server independently refuses anything beyond it. Proven live: a
  policy attempting `secrets:Get` compiled to an openinfra.dev-only ClusterRole with the bad rule
  gone. This is the open-infra analogue of an AWS permission boundary.
- **`kind: Role` is blocked.** A `Role` compiles to an *aggregated* ClusterRole, and Kubernetes
  requires `escalate` to create **any** ClusterRole carrying an `aggregationRule` — a rule the
  boundary does **not** satisfy (live error: *"must have cluster-admin privileges to use the
  aggregationRule"*). So the "there is no third option" above turns out to have a wrinkle specific
  to aggregation. The open decision:
    - **A** — grant the rendering SA `escalate` on clusterroles. Bounded-harmless here: the `bind`
      verb is still `resourceName`-fenced to the three built-in roles and the SA holds no
      secrets/RBAC, so it still cannot *bind* any over-boundary role to a user. The user-grantable
      surface is unchanged; only aggregated-role *creation* becomes possible.
    - **B** — no `escalate`, no arbitrary roles: attach policies to the three built-in tiers
      (aggregated once at install, where Argo already holds cluster-admin).
    - **C** — no `escalate`, keep arbitrary roles: add `function-extra-resources`, have a Role read
      its policies' rules and emit a *plain* unioned ClusterRole (no `aggregationRule`).
- **No BFF endpoints or console UI yet** for policies/roles — management is `kubectl` on the CRs
  until the decision above is made and the Users/Groups-style UI is extended.

### Stage 3 — `Deny` and conditions, via ValidatingAdmissionPolicy
Only when a concrete requirement appears (likeliest: "powerusers must not delete production VMs").
Compile `effect: Deny` statements to a **VAP + binding** rather than a ClusterRole. Use plain VAP
(CEL, in the API server) rather than Kyverno/Gatekeeper: nothing new to install, it cannot be down,
and it cannot fail open. Ship every generated Deny as `validationActions: [Warn, Audit]` first,
read the audit annotations, then flip to `Deny` — the same graduation discipline as the chaos suite.

**Be explicit in the UI that Deny is enforced at admission, not authorization.** It will not appear
in `SelfSubjectRulesReview`, so a denied action's button looks enabled and fails on click. Surface
the policy's message verbatim. The alternative — duplicating deny logic in the UI — is the drift
anti-pattern.

## Deliberately NOT building

- **Permission boundaries / SCPs.** Intersection semantics have no Kubernetes analogue; pure cost
  at this scale.
- **Resource-based policies.** No resource-side ACLs; one direction only.
- **A policy evaluation engine in the BFF.** No Allow/Deny resolution, no condition interpreter.
  The BFF compiles and displays; the API server decides. App-code checks bind to the HTTP route,
  not the resource — anyone with a kubeconfig walks around them, and the decisions never reach the
  audit log.
- **`resourceNames`-based per-object grants** (see the constraint above).
- **A `kind: Project`/tenancy abstraction** unless real multi-tenancy arrives.

The one legitimate exception is **product-feature gating** — may this user see the Cost page, open
a VNC console — which genuinely isn't a Kubernetes authorization question. Keep it small, in app
code, and *named* as a separate layer so it never grows into a shadow RBAC.

## UX (from the AWS console)

Ranked by value-for-effort, for whenever the Users/Roles screens get built:

1. **One permissions table per user, with an "Attached via" column** (Directly / Group: dba /
   Boundary). Never split direct vs inherited across tabs — inherited authority is what people
   forget. Make destructive buttons say what they'll do ("this removes you from `dba`, which also
   removes X and Y").
2. **Access-level grouping of verbs** — List / Read / Write / Delete / **Permissions management**.
   `get,list,watch` → Read; `create,update,patch` → Write; `bind,escalate,impersonate` →
   Permissions management, flagged in a warning colour everywhere. One ~40-line lookup table makes
   every other screen better.
3. **Summary view with a Summary | YAML toggle**, including a "show remaining kinds" expander that
   reveals what is *not* granted, and inline warnings for rules that grant nothing.
4. **Full-screen 3-step create-user wizard**, with "copy permissions from an existing user" (cheap
   to build, the most-used real-world path) and a one-time credential screen.
5. **Live validation with three severities** — errors block save; security warnings for `*` and
   `escalate`; suggestions for typo'd kinds validated against live API discovery.
6. **Last-used data** on bindings, surfaced *inside* the removal flow.

**Anti-patterns to avoid**, learned from AWS's scars: don't let a visual editor silently rewrite
hand-authored documents (AWS's own docs warn "you should not compare JSON policy documents as
strings"); don't hide inherited permissions on a second tab; don't let a policy that grants nothing
save silently; don't put the correctness-checking tool on a different page from the editor.

## Status

| Stage | State |
|---|---|
| Impersonation pinned to `openinfra:*` groups | ✅ shipped |
| Audit logging with `impersonatedUser` | ✅ shipped |
| SAR-gating BFF-native endpoints | ✅ shipped (verified live: readonly 403s, root passes) |
| Poweruser drift guard | ✅ shipped (CI test, mutation-tested) |
| `kind: User` / `kind: Group` | ✅ shipped — sign-in reads Users; `root` stays in the Secret as break-glass |
| Custom group names beyond the built-in four | ⬜ needs an operator edit to the impersonator ClusterRole (see above) |
| `kind: Policy` + permission boundary | ✅ platform shipped, boundary proven live (out-of-boundary rules dropped); no BFF/UI yet |
| `kind: Role` (aggregated) | ⏸ deployed but blocked — aggregation needs `escalate`; A/B/C decision pending (see Stage 2) |
| `Deny` + conditions via VAP | ⬜ not started |
| Users/Groups UI | ✅ shipped — Security & Identity → Users/Groups (create/edit/delete, password reset, group membership; admins-only via SAR) |

## See also

- [`auth.md`](auth.md) — what authentication and authorization actually do today.
- [`architecture.md`](architecture.md) — how the console and BFF fit together.
