# open-infra console

A Go BFF (backend-for-frontend) that serves the React SPA and proxies the
Kubernetes API so the browser never needs direct cluster access. Installed as a
platform component via the Argo CD app-of-apps at sync-wave 4.

## What this deploys

| File | Resource |
|---|---|
| `console.yaml` | Argo CD `Application` that syncs `platform/console/manifests/` |
| `manifests/serviceaccount.yaml` | `ServiceAccount` named `console` |
| `manifests/rbac.yaml` | `ClusterRole` + `ClusterRoleBinding` (scoped — see Security) |
| `manifests/deployment.yaml` | Single-replica `Deployment` from GHCR |
| `manifests/service.yaml` | `ClusterIP` Service on port 80 → 8080 |
| `manifests/ingress.yaml` | Traefik `Ingress` with cert-manager TLS |

## Pointing at a real domain

Edit the `host` value in `manifests/ingress.yaml` (two occurrences). The file
ships with the RFC 5737 documentation placeholder `console.192-0-2-1.sslip.io`.

**sslip.io pattern (no DNS setup needed):**
Replace `192-0-2-1` with your k3s node/load-balancer IP using dashes instead
of dots. For example, if the node IP is `10.0.1.50`:

```
console.10-0-1-50.sslip.io
```

**Real domain:**
Set the host to `console.yourdomain.com`, create a DNS A record pointing to
the node/LB IP, and optionally swap the `cert-manager.io/cluster-issuer`
annotation to an ACME issuer for a publicly trusted certificate.

## Wiring up Grafana

The console embeds Grafana **same-origin** (no CORS, no cross-origin cookies, no
site-specific URL). Two env vars in `manifests/deployment.yaml`:

- `GRAFANA_BASE_URL: "/grafana"` — the SPA embeds dashboards at this relative path.
- `GRAFANA_PROXY_TARGET` — the in-cluster Grafana the BFF reverse-proxies `/grafana/*` to:
  ```
  http://kube-prometheus-stack-grafana.monitoring.svc.cluster.local
  ```
  (Grafana must serve from the `/grafana` sub-path — set in the kube-prometheus-stack values.)

## Security / RBAC

The console runs as UID 65532 (nonroot) on an `alpine` runtime with a read-only
root filesystem. Its `ClusterRole` (`open-infra-console` in `manifests/rbac.yaml`)
is **intentionally not cluster-admin**:

- **Read-only** on core workloads, nodes, namespaces, events, pods/log, services,
  configmaps, PVCs, apps workloads, batch jobs, CRD schemas, Argo CD Applications,
  and KubeVirt VM/guest/disk status.
- **Full CRUD** on the `openinfra.dev` product CRDs — applications, functions,
  models, virtualmachines, vmimages, volumes, fileshares, directories, migrations,
  streams — the kinds users manage via the console.
- **Secrets**: `get` + create/manage, scoped to connection info (a Model's API key,
  a DB/bucket secret) and the DMS wizard's credential secret.
- **KubeVirt subresources**: the VNC console + VM start/stop.

Operators who need the console to manage additional resource types can add an
aggregated ClusterRole without modifying this file:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: open-infra-console-extended
  labels:
    rbac.open-infra.dev/extend-console: "true"
rules:
  - apiGroups: [batch]
    resources: [jobs, cronjobs]
    verbs: [get, list, watch, create, update, patch, delete]
```

Then add an `aggregationRule` to the `open-infra-console` ClusterRole to pick
up any role with that label (the base ClusterRole ships without aggregation to
keep the default surface minimal).
