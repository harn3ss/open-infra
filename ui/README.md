# open-infra console (web UI)

The web console for **open-infra** — an AWS-console-class management UI for your
self-hosted k3s/Kubernetes mini-cloud. It gives you a live view of your
cluster and a one-click way to spin up resources on demand, with the project's
own visual identity (deep indigo/slate + teal, dark by default).

It is a single-page app that talks **only** to a same-origin Go **BFF**
(backend-for-frontend) under `/api` — never to the Kubernetes API directly. In
production the BFF serves this app's built `dist/`.

## Features

- **Dashboard** — resource counts, a cluster-health panel, and a live event feed.
- **The nine `openinfra.dev` abstractions**, each with a live list + detail page:
  **Applications, Functions, Models** (with a chat playground), **Virtual Machines**
  (VNC console, start/stop, disk hotplug), **Volumes, File Shares, Directories,
  Migrations** (the DMS wizard), and **Streams** (CDC). Create forms are generated
  from each CRD's JSON Schema (rjsf); delete-with-confirm throughout.
- **Data services** — **Databases**, **Buckets** (MinIO S3 object browser:
  upload/download/delete), **Queues** (NATS JetStream: publish/purge).
- **Cluster** — **Workloads** (Pods/Deployments/Services), **Nodes** (capacity +
  GPU), **Network**.
- **Monitoring** — embedded Grafana (same-origin), driven by `grafanaBaseUrl`
  from runtime config.
- App shell with a collapsible sidebar, namespace switcher, global filter,
  breadcrumbs, and a dark/light toggle.

Everything cluster-specific (cluster name, Grafana URL, version) comes from
`GET /api/config` at runtime — nothing is hardcoded, so the repo is public-safe.

## Tech stack

- [Vite](https://vitejs.dev/) + [React 19](https://react.dev/) + TypeScript (strict)
- [Tailwind CSS v4](https://tailwindcss.com/) + [shadcn/ui](https://ui.shadcn.com/) (Radix primitives)
- [TanStack Router](https://tanstack.com/router), [Query](https://tanstack.com/query),
  [Table](https://tanstack.com/table), [Virtual](https://tanstack.com/virtual)
- [react-jsonschema-form](https://rjsf-team.github.io/react-jsonschema-form/) (`@rjsf/core` + `@rjsf/validator-ajv8`) for CRD-driven forms
- [lucide-react](https://lucide.dev/) icons

> Built on **Node 22 LTS ("Jod")** — Vite 8 requires Node `^20.19 || >=22.12`.
> Use `nvm use` (see `.nvmrc`); the CI/Docker UI build stage runs `node:22-alpine`.

## Prerequisites

- Node.js **22 LTS** (`nvm use`) — Node 18 can no longer build (Vite 8).
- The open-infra **BFF** running locally (default `http://localhost:8080`) for
  live data during development.

## Develop

```bash
cd ui
npm install
npm run dev          # http://localhost:5173
```

`npm run dev` proxies `/api` to the BFF so both `fetch` and the SSE watch
stream (`EventSource`) hit a single origin (no CORS). Point it elsewhere with:

```bash
VITE_BFF_TARGET=http://my-bff:8080 npm run dev
```

(Copy `.env.example` to `.env` to persist that.)

## Build

```bash
npm run build        # type-checks, then emits dist/
npm run preview      # serve the production build locally
```

The output in `dist/` is a static bundle. In production the open-infra BFF
serves it and handles `/api/*` itself.

## How it pairs with the BFF

The console expects the BFF to expose:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/config` | `{ clusterName, grafanaBaseUrl, version }` — fetched once at startup. |
| `GET /api/k8s/<path>` | Raw Kubernetes REST (CRUD via GET/POST/PUT/DELETE). |
| `GET /api/watch?path=<list path>&resourceVersion=<rv>` | SSE stream of k8s watch events (`{ type, object }`); a named `expired` event triggers a relist. |
| `GET /api/crd-schema?name=<crd>` | Normalized JSON Schema used to render the "New Application" form. |

The watch contract is implemented by `useK8sWatch` (`src/hooks/use-k8s-watch.ts`):
it lists via React Query, then merges live `ADDED`/`MODIFIED`/`DELETED` events
into the same query cache with `queryClient.setQueryData`, and relists on
`expired`.

## Project layout

```
src/
  app.tsx                 # providers + config bootstrap (renders after /api/config)
  main.tsx                # entry; QueryClient + theme
  router.tsx              # TanStack Router route tree
  index.css               # Tailwind v4 theme tokens (the open-infra palette)
  components/
    ui/                   # shadcn/ui primitives (Radix-based)
    layout/               # app shell: sidebar, topbar, breadcrumbs, ...
    common/               # shared widgets: tables, states, YAML viewer, ...
  features/               # one folder per resource area:
    dashboard/            #   landing page: stats, health, events
    applications/ functions/ models/ virtualmachines/   # compute + AI
    volumes/ fileshares/ directories/                    # storage + identity
    databases/ migrations/ streams/ buckets/ queues/     # data
    workloads/ nodes/ network/ monitoring/               # cluster + observability
  hooks/                  # useK8sWatch, delete, list filter
  lib/                    # api client, k8s paths, formatting, contexts
  types/                  # k8s + openinfra.dev resource typings
```

## License

Apache-2.0, as part of the [open-infra](../README.md) project.
