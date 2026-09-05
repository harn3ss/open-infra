# Cedar control-plane corpus baseline (CM-6 artifact) + corpus assessment (CA-2)

The CM-6 configuration-settings artifact for platform-wide Cedar authorization, and the CA-2/CA-7
assessment of that corpus. Companion to `evidence/nist-800-53-cedar-authz-mapping.md` and #109.

**Rails:** built ≠ verified ≠ certified. This is the *current* control-plane authorization corpus
derived from live RBAC; it documents the baseline and its least-privilege debt honestly. It is NOT a
claim that Cedar is enforcing (the webhook is still shadow — see the mapping doc).

## What this replaces (and why it's needed)

Under RBAC, the **CIS Kubernetes Benchmark** supplied the authorization baseline for free (no
cluster-admin sprawl, no wildcard permissions, service accounts minimally privileged — the "policies"
section, scanned via kube-bench `rke2-cis`). When Cedar becomes the base grantor, that inherited
baseline's premise no longer holds. This document + the corpus checker are the project-owned
replacement: an authored, machine-checkable Cedar configuration baseline (CM-6) that a checker
assesses on a cadence (CA-2/CA-7).

## How the baseline is produced (reproducible)

The corpus is generated deterministically from the live cluster's RBAC:

```
rbac-to-cedar   # (console-api/cmd/rbac-to-cedar) reads all ClusterRoles/Roles/Bindings,
                # emits one kind: Policy (spec.controlPlane) per principal — the Cedar corpus
corpus-check    # (console-api/cmd/corpus-check) audits the generated grants; -strict fails on HIGH
```

Baseline snapshot (2026-09-05): **160 principal grants** from **378 ClusterRoles / 166
ClusterRoleBindings / 67 RoleBindings**. Full corpus is regenerable via `rbac-to-cedar`; the audit
output is committed at `evidence/corpus-audit-2026-09-05.txt`.

## CA-2 assessment (2026-09-05): 160 principals, 137 findings (17 HIGH, 73 WARN, 47 INFO)

The corpus checker (`internal/corpuscheck`) flags: cluster-admin-equivalent (`*` on `*`),
wildcard-resource, cluster-wide secret reads, and escalation verbs — the machine-checkable equivalents
of the CIS-K8s RBAC controls.

### The 17 HIGH — cluster-admin-equivalent grants (the least-privilege debt)

All 17 are `*`-on-`*` grants. Every one is a **third-party operator's own ServiceAccount** (installed
by its upstream chart with cluster-admin) or a built-in masters group — not open-infra's own
console/shim principals:

- `Group::system:masters`, `Group::crossplane:masters` (built-in break-glass groups)
- Operators/controllers: `crossplane-system/crossplane`, `kubevirt/kubevirt-{controller,operator}`,
  `cdi/cdi-{operator,sa}`, `chaos-mesh/chaos-{controller-manager,dashboard,dns-server}`,
  `argocd/argocd-application-controller`, `knative-operator/knative-operator`, `velero/velero-server`,
  `longhorn-system/longhorn-support-bundle`, `kube-system/{multus,helm-traefik,helm-traefik-crd}`

**Honest reading:** this is the real least-privilege state of the cluster *today*, inherited from how
these operators ship. Cedar-as-base-grantor would inherit it unless each is tightened. This is exactly
what CIS "no cluster-admin sprawl" flags — now surfaced as a machine-checkable finding rather than a
manual-review WARN. Tightening these (scoping operator SAs to the APIs they actually use) is the
least-privilege (AC-6) work that Cedar makes assertable; it is tracked, not silently passed.

WARN (73): mostly cluster-wide Secret reads + wildcard-resource on scoped verbs. INFO (47): narrower
grants worth noting. See the committed audit for the full list.

## CA-7 continuous monitoring

`platform/security/corpus-audit-cronjob.yaml` runs `corpus-check` on a schedule, logging the audit so
the finding trend is observable over time (a control-plane analogue of the periodic CIS scan). It runs
non-strict (the 17 HIGH are current reality, not a regression to fail CI on); the count is the metric
to drive down. A `-strict` gate belongs in CI once the HIGH count is deliberately zero.

## Open items (feed #109 Phase 2 / the RBAC-removal gate)

- The 17 HIGH cluster-admin grants must be reduced before RBAC removal makes Cedar the sole authority
  (else the removal preserves the debt without RBAC's inherited assurance).
- The webhook is still **shadow**; this corpus is not yet enforced. Divergence measurement
  (RBAC vs Cedar on real traffic) is the next Phase-2 step.
- `-strict` corpus-check as a CI gate is deferred until the HIGH count is intentionally zero.
