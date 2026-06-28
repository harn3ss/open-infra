# console-api — open-infra console BFF

The **backend-for-frontend (BFF)** for the open-infra console: a small Go service
that lets a browser drive a Kubernetes (k3s) cluster *without ever holding cluster
credentials*. It also embeds and serves the built React SPA, so the whole console
ships as a **single container** (the [Headlamp](https://headlamp.dev) pattern).

```
browser ──HTTPS──> console-api (this) ──ServiceAccount creds──> Kubernetes API
                        │
                        └── serves the embedded React SPA at "/"
```

## How it works

The browser talks only to the BFF, same-origin. The BFF holds the pod's
**ServiceAccount** token and forwards browser requests to the API server with it.
The browser is never given a kubeconfig or token.

- **TLS + bearer token** are injected by client-go's `rest.TransportFor(config)`,
  built from `rest.InClusterConfig()` in-cluster (or a kubeconfig for local dev).
- **Authorization is 100% the ServiceAccount's RBAC.** The BFF performs *no*
  authorization of its own — it faithfully relays whatever the API server allows
  or denies (e.g. a `403` from RBAC comes straight back to the browser).

## Endpoints

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/healthz` | Liveness probe. Returns `200 ok`. |
| `GET` | `/api/config` | Runtime config as JSON: `{clusterName, grafanaBaseUrl, version}`. Read from env on every request (**not** baked into the SPA), so one image runs in any cluster. |
| `*` | `/api/k8s/*` | Reverse proxy to the API server (the `/api/k8s` prefix is stripped). All methods + query params pass through; the SA's RBAC is the authorization. The generic CRUD surface for k8s/CRD resources. |
| `GET` | `/api/watch?path=<list-path>&resourceVersion=<rv>` | Opens a Kubernetes watch and re-emits it as **Server-Sent Events**. See below. |
| `GET` | `/api/crd-schema?name=<crd>` | CRD → storage-version `openAPIV3Schema`, normalized for [react-jsonschema-form](https://github.com/rjsf-team/react-jsonschema-form) create forms. |
| `GET` | `/api/grafana/dashboards` | Server-side proxy to Grafana's dashboard search (populates the picker; avoids CORS). |
| `GET`·`POST`·`DELETE` | `/api/buckets`, `/api/buckets/{bucket}` | MinIO (S3): list / create / delete buckets. |
| `GET`·`PUT`·`DELETE` | `/api/buckets/{bucket}/objects`, `…/object` | Browse, upload, download, delete objects. |
| `GET`·`POST` | `/api/queues`, `/api/queues/publish`, `/api/queues/{stream}/purge` | NATS JetStream: stats, publish, purge. |
| `POST` | `/api/models/{ns}/{name}/chat` | Proxy to a Model's gated endpoint (API key stays server-side) — the playground. |
| `GET`·`POST` | `/api/functions/{ns}/{name}/routes`·`/invoke` | List a Function's routes / invoke it (the Test tab). |
| `POST` | `/api/migrations/discover` | DMS wizard: discover a source DB's tables. (A Migration runs continuously — Debezium + apply-sink — so there is no manual sync trigger.) |
| `GET` | `/api/migrations\|replications/{ns}/{name}/status` | DMS observability: live apply-pipeline status (JetStream lag, per-table counts, dead-letter) the browser can't read from NATS. |
| `POST` | `/api/dataflows/{ns}/{name}/status` | Data Flows observability: given the topology's edge list, returns per-directed-leg status (lag, in-flight, retries, dead-letters, per-table throughput). Powers the canvas edge overlay + per-node **Peek**. |
| `*` | `/grafana/*` | Same-origin reverse proxy to in-cluster Grafana (when `GRAFANA_PROXY_TARGET` is set) for iframe embedding. |
| `GET` | `/*` | The embedded SPA, with history-mode fallback (unknown non-API, non-asset paths → `index.html`). |

### `/api/config`

```json
{ "clusterName": "...", "grafanaBaseUrl": "...", "version": "..." }
```

Sourced from `CLUSTER_NAME`, `GRAFANA_BASE_URL`, and the build-time `version`
(injected via `-ldflags "-X main.version=..."`).

### `/api/watch` (SSE)

Opens `<apiserver><path>?watch=true&resourceVersion=<rv>&allowWatchBookmarks=true`
on the authenticated transport, reads the newline-delimited JSON watch stream, and
emits each event as an SSE frame:

```
id: <object.metadata.resourceVersion>
data: {"type":"ADDED","object":{...}}

```

- Response headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`,
  `Connection: keep-alive`, `X-Accel-Buffering: no`; the stream is flushed after
  every event.
- **Reconnect:** the browser's `EventSource` resends the last id via the
  `Last-Event-ID` header; the BFF uses it as the `resourceVersion`, taking
  precedence over the query param.
- **410 Gone:** when the API server's watch expires (an `ERROR` event whose
  `Status.code == 410`), the BFF emits `event: expired` so the client can drop its
  cache and relist, then closes the stream.
- **Disconnect:** client disconnects are detected via the request context and tear
  down the upstream watch.

### `/api/crd-schema`

Example: `GET /api/crd-schema?name=applications.openinfra.dev`. The returned schema
is normalized for RJSF:

- every `x-kubernetes-*` key is stripped recursively;
- `nullable: true` is rewritten into a draft-07 union type (e.g.
  `{"type":"string"}` → `{"type":["string","null"]}`);
- a top-level `"$schema": "http://json-schema.org/draft-07/schema#"` is added.

(The SA needs `get` on `customresourcedefinitions` in `apiextensions.k8s.io`.)

## Configuration (environment variables)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `CLUSTER_NAME` | `""` | Surfaced via `/api/config`. |
| `GRAFANA_BASE_URL` | `""` | Surfaced via `/api/config`. |
| `LISTEN_ADDR` | `:8080` | Address the HTTP server binds. |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `KUBECONFIG` | (unset) | Local-dev only: path to a kubeconfig. Ignored in-cluster. |

Logs are structured JSON via `log/slog`.

## Local development

In-cluster config is tried first; outside a cluster it falls back to your
kubeconfig (`$KUBECONFIG`, else `~/.kube/config`).

```bash
cd console-api

# Point at a cluster you can reach with a scoped context.
export KUBECONFIG=~/.kube/config
export CLUSTER_NAME=dev
export GRAFANA_BASE_URL=http://localhost:3000

go run ./cmd/server
# -> console-api listening on :8080

curl -s localhost:8080/healthz                       # ok
curl -s localhost:8080/api/config                    # {"clusterName":"dev",...}
curl -s 'localhost:8080/api/k8s/api/v1/namespaces'   # proxied to the API server
curl -s 'localhost:8080/api/crd-schema?name=applications.openinfra.dev'
```

The committed `web/index.html` is a placeholder; the real SPA is embedded at image
build time (see below). `go run` serves the placeholder, which is fine for backend
work.

Run the checks:

```bash
go build ./...
go vet ./...
go test ./...
```

## Container image

Multi-stage build (Node → Go → Alpine). **The build context must be the repo
root** so both `ui/` and `console-api/` are visible:

```bash
# from the repository root
docker build -f console-api/Dockerfile \
  --build-arg VERSION="$(git describe --tags --always 2>/dev/null || echo dev)" \
  -t open-infra-console:dev .
```

Stages:

1. `node:22-alpine` — `npm ci` + `npm run build` in `ui/` → `ui/dist`.
2. `golang:1.25-alpine` — copies `ui/dist` into `console-api/web/`, then
   `CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=..."`.
   (Go **1.25**, matching the `go.mod` toolchain; `k8s.io/client-go` v0.33.x needs ≥1.24.)
3. `alpine:3.20` — minimal runtime, **non-root uid 65532**, `EXPOSE 8080`,
   `HEALTHCHECK` against `/healthz`.

Run it:

```bash
docker run --rm -p 8080:8080 \
  -e CLUSTER_NAME=homelab -e GRAFANA_BASE_URL=https://grafana.example \
  open-infra-console:dev
```

In-cluster, the pod's mounted ServiceAccount is used automatically — no env or
kubeconfig needed for cluster access.

## Security

- **The ServiceAccount MUST be narrowly scoped — never `cluster-admin`.** Anyone
  who can reach the console can do exactly what the SA's RBAC permits, no more and
  no less. Grant only the verbs/resources the UI actually needs (typically `get`,
  `list`, `watch` broadly, plus `create`/`update`/`patch`/`delete` on the specific
  CRDs the console manages, e.g. `applications.openinfra.dev`).
- **CRUD authorization is entirely the SA's RBAC.** The BFF adds no allow/deny
  logic; it relays the API server's decision. Audit access by auditing the SA's
  Role/ClusterRole bindings.
- The browser never receives a token or kubeconfig. Client-supplied
  `Authorization` / `X-Forwarded-*` headers are stripped before forwarding so a
  browser cannot smuggle alternate credentials or spoof its origin upstream.
- Put authentication (who may reach the console at all) in front of this service —
  e.g. an authenticating Ingress / identity-aware proxy. The BFF assumes its
  callers are already authenticated; it only enforces *authorization*, via RBAC.

## Package layout

```
console-api/
├── cmd/server/        # main + per-resource handlers (alongside main.go):
│   ├── main.go        #   route table, /api/config, graceful shutdown, slog
│   ├── spa.go         # embedded-SPA handler (history-mode fallback)
│   ├── services.go    # MinIO (S3), NATS queues, model chat, functions, Grafana
│   ├── queues_actions.go # NATS JetStream publish / purge
│   ├── discover.go    # DMS wizard: source table discovery
│   └── migration_status.go # DMS observability: JetStream lag / per-table / dead-letter
├── internal/
│   ├── k8s/           # REST config (in-cluster | kubeconfig) + authed transport
│   ├── proxy/         # /api/k8s/* reverse proxy (prefix strip, header scrub)
│   ├── watch/         # /api/watch Kubernetes-watch → SSE bridge
│   └── crd/           # CRD fetch + RJSF schema normalization
├── web/               # //go:embed target (placeholder locally; SPA in image)
├── webui.go           # the //go:embed directive (must sit beside web/)
├── Dockerfile         # 3-stage build; context = repo root
└── README.md
```
