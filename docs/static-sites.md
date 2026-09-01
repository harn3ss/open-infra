# Static sites (`kind: StaticSite`)

`kind: StaticSite` hosts a built single-page app (a `dist/` tree) over HTTP + TLS — the
S3-static-website-plus-CDN-origin-shaped primitive. One claim provisions:

- a **MinIO bucket** for the built assets (created if absent), with a `<name>-minio` connection
  secret (endpoint + credentials) for uploads;
- an **nginx server** that continuously syncs the bucket and serves it, with **SPA history-fallback**
  (unknown paths serve `index.html` so client-side routing works);
- a **Traefik Ingress** with cert-manager TLS on your domain.

```yaml
apiVersion: openinfra.dev/v1
kind: StaticSite
metadata:
  name: web
  namespace: my-app
spec:
  domain: app.example.com
  spa: true            # history-fallback for client-side routes (default)
  # bucket: web-site   # defaults to <name>-site
```

Then upload your build output to the bucket. The `<name>-minio` secret holds `MINIO_ENDPOINT`,
`MINIO_BUCKETS`, `MINIO_ACCESS_KEY`, and `MINIO_SECRET_KEY`; point any S3 client at it:

```sh
aws --endpoint-url "$MINIO_ENDPOINT" s3 sync ./dist/ "s3://web-site/" --delete
```

The server re-syncs every `spec.syncIntervalSeconds` (default 30s), so a new upload goes live
without redeploying. For a plain multi-file site (no client-side router), set `spec.spa: false` and
optionally `spec.errorDocument: 404.html`.

## Per-PR preview environments (a CI recipe, not a controller)

Previews are a **CI pattern**, not a platform controller — deliberately, so the preview lifecycle
lives with your pipeline. Render one `StaticSite` per pull request and tear it down on close. Using
the published `harn3ss/open-infra` action (the same one `examples/hello-web` deploys with):

```yaml
# .github/workflows/preview.yml
on:
  pull_request:
    types: [opened, synchronize, reopened, closed]
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build          # produces ./dist

      # On open/update: apply a per-PR StaticSite and upload the build.
      - if: github.event.action != 'closed'
        uses: harn3ss/open-infra/action@v1
        with:
          manifest: |
            apiVersion: openinfra.dev/v1
            kind: StaticSite
            metadata: { name: pr-${{ github.event.number }}, namespace: previews }
            spec: { domain: pr-${{ github.event.number }}.preview.example.com, spa: true }
      - if: github.event.action != 'closed'
        run: aws --endpoint-url "$MINIO_ENDPOINT" s3 sync ./dist/ "s3://pr-${{ github.event.number }}-site/" --delete

      # On close: delete the StaticSite (and its bucket assets) for that PR.
      - if: github.event.action == 'closed'
        run: kubectl delete staticsite pr-${{ github.event.number }} -n previews --ignore-not-found
```

A platform-native preview controller (auto-provisioning environments from Git state) is a separate,
much larger feature and is intentionally out of scope of this first cut.
