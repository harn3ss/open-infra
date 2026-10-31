# Argo CD bootstrap overrides (applied by `install.sh`, NOT GitOps-synced)

Argo CD itself is installed from the upstream manifests (`install.sh` §3), so its config
(`argocd-cm`) is **not** managed by the GitOps app-of-apps (that would be circular). Anything Argo CD
needs beyond the vanilla install is applied here, by `install.sh`, right after the upstream apply —
and must be re-applied on every run because re-applying the upstream manifests resets `argocd-cm`.

This directory lives **outside** `platform/` on purpose: `platform/` is the path the root app syncs,
and a raw merge-patch JSON is not a valid manifest, so Argo CD must never try to apply it.

## `argocd-cm-ingress-health.patch.json`

A health-assessment override for `networking.k8s.io/Ingress`: a *synced* Ingress is reported
**Healthy**.

Why: Traefik in this cluster does not publish `status.loadBalancer` on Ingress objects, so Argo CD's
**default** Ingress health check sits at `Progressing` forever. For an Ingress created inside a sync
wave, that wedges the whole sync (it waits for a health state that never arrives) — which once stalled
the platform sync for 11h on a single placeholder Ingress. Since the default check provides *zero*
signal here (no Ingress ever gets an LB status), treating a synced Ingress as Healthy is strictly
better and loses nothing.
