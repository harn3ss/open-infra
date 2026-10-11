# Continuous compliance — `kind: ConfigRule`

`kind: ConfigRule` is the AWS Config analog: it continuously evaluates cluster resources against a
rule and **records** which ones comply — both at admission and as a background scan of resources that
already exist. One `ConfigRule` compiles to a [Kyverno](https://kyverno.io) `ClusterPolicy` in **Audit**
mode, and Kyverno's `PolicyReports` are the compliance history. It **reports, it does not enforce** —
exactly like AWS Config (a rule records compliance; it does not block the resource).

`kind: ConfigRule` rides the opt-in **`compliance`** component (the Kyverno install). It is
**experimental**.

## How it maps

| AWS Config | open-infra | Kyverno |
|---|---|---|
| Config rule | `kind: ConfigRule` | one `ClusterPolicy` (Audit) |
| Rule scope (which resources) | `spec.match` (`kinds` + `namespaces`) | `rule.match.any[].resources` |
| Rule logic (the compliant shape) | `spec.requirePattern` | `rule.validate.pattern` |
| Compliance timeline | Kyverno `PolicyReport` / `ClusterPolicyReport` | per-resource pass/fail, refreshed by the background scan |
| Configuration recorder | the background scan | re-evaluates existing resources continuously |

## Example

```yaml
apiVersion: openinfra.dev/v1
kind: ConfigRule
metadata: { name: bucket-versioning, namespace: team-a }
spec:
  description: object buckets must have versioning enabled
  match:
    kinds: [Bucket]          # the open-infra kinds this rule governs
    namespaces: [team-a]     # omit to evaluate all namespaces
  requirePattern:            # the shape a compliant resource MUST have
    spec:
      versioning: true
  message: "bucket must enable versioning to comply"
  severity: medium
```

`requirePattern` is a Kyverno validate pattern — it supports `*`/`?*` wildcards and anchors, so a rule
like "every Application must carry an `owner` label" is `requirePattern: { metadata: { labels: { owner: "?*" } } }`.

A `ConfigRule` never blocks admission (`validationFailureAction: Audit`, `failurePolicy: Ignore`): a
non-compliant resource is still created, and simply shows up as a **fail** in its PolicyReport.

## Honest scope

- **Audit only** (v1): records compliance, does not enforce or remediate. Enforcement
  (`validationFailureAction: Enforce`) and auto-remediation are later phases.
- **`requirePattern` is the one rule form** today (a required-shape check — the bulk of AWS managed
  Config rules: "must be encrypted", "must have tag", "must not be public"). CEL expressions and
  cross-resource checks are later phases.
- **Managed-rule library:** AWS ships ~500 managed Config rules; open-infra ships the `ConfigRule`
  kind and grows a library of ready-made rules against the open-infra kinds that actually matter —
  it does not claim parity with the AWS managed-rule catalog.

## Enabling the `compliance` component

`kind: ConfigRule` needs Kyverno installed (the backend that evaluates the policies). Enabling the
`compliance` component:

1. Install Kyverno (the `compliance` component — an ArgoCD Application pulling the Kyverno chart,
   background + reports controllers on; admission webhooks stay `failurePolicy: Ignore`).
2. Regenerate the Cedar control-plane corpus so the Crossplane provider may create `kyverno.io`
   `ClusterPolicies` (the provider RBAC grant for `kyverno.io` is already in `provider-setup.yaml`,
   but the corpus is a per-type snapshot — same regen step as any new backing group).

Until the component is enabled, the `kind: ConfigRule` CRD exists but a claim cannot materialize its
ClusterPolicy (no Kyverno) — the kind is latent, like `kind: EmailSender` without the `mail` component.
