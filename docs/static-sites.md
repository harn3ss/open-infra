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

## More hostnames and response headers

`spec.domains` serves the site on additional hostnames alongside `spec.domain` — each gets an Ingress
rule and joins the TLS certificate. `spec.responseHeaders` adds HTTP headers to every response, error
responses included — the place for security headers:

```yaml
spec:
  domain: app.example.com
  domains: [www.example.com]
  responseHeaders:
    - { name: Strict-Transport-Security, value: "max-age=31536000; includeSubDomains" }
    - { name: Content-Security-Policy,   value: "default-src 'self'" }
    - { name: X-Frame-Options,           value: DENY }
```

Header names are letters, digits and hyphens; values are printable ASCII without double quotes,
backslashes or dollar signs. Headers the server sets itself (`Content-Type`, `Content-Length`,
`Server`, `Date`, `Last-Modified`, `ETag`, …) can't be replaced this way. Changing the headers rolls the
server pod so the new set takes effect.

## From a CloudFormation template (CloudFront)

A CloudFormation **`AWS::CloudFront::Distribution`** in front of a private S3 bucket — the standard
SPA-hosting template — deploys as a `kind: StaticSite` through the [CloudFormation engine](cloudformation.md#cloudfront-a-static-site-subset):
the bucket stays a `kind: Bucket`, the distribution's `Aliases` become `domain`/`domains`, the SPA
`CustomErrorResponses` (403/404 → `/index.html`, 200) become `spa: true`, a response headers policy
becomes `responseHeaders`, and the ACM certificate is replaced by cert-manager TLS. There is no edge
cache: the CloudFront features beyond a single-origin static site refuse at plan with their reason.

> **Where to run the upload.** `MINIO_ENDPOINT` in the `<name>-minio` secret is the **cluster-internal**
> MinIO address (`minio.minio.svc.cluster.local:9000`), so the `s3 sync` above works from **inside the
> cluster** — a CI runner that deploys in-cluster (see the per-PR recipe below), or a one-shot Job/pod.
> From a **developer laptop** off the cluster, either run it through a `kubectl port-forward`
> (`kubectl -n minio port-forward svc/minio 9000:9000`, then `--endpoint-url http://localhost:9000`), or,
> once a LAN-reachable TLS S3 endpoint is in place, point `--endpoint-url` at that. A first-class
> LAN-reachable publish endpoint is the open item (it shares the routed-ingress exposure work).

## Managed build (`spec.build`) — the Amplify analog

> AWS equivalent: **Amplify Hosting's connected-repo build** (git push → build → deploy).

Instead of uploading pre-built assets, point a site at a git repo and let the platform build it:

```yaml
apiVersion: openinfra.dev/v1
kind: StaticSite
metadata: { name: web, namespace: team-a }
spec:
  domain: app.example.com
  build:
    repo: https://github.com/me/app.git
    branch: main                         # default main
    buildCommand: npm ci && npm run build # default
    outputDir: dist                       # default — published to the bucket
    image: node:20-alpine                 # build toolchain
    pollSeconds: 300                      # how often to check for new commits
    # secret: web-git   # optional: Secret with key GIT_TOKEN for a private repo
    # env: [{ name: VITE_API, value: https://api.example.com }]
```

A CronJob polls `branch` and, **only when its HEAD changed** since the last build (tracked as a
small marker object in the bucket), clones the repo, runs `buildCommand`, and publishes `outputDir`
to the site bucket — the server then serves it on its next sync. The first build runs on the first
poll.

The build step runs **sandboxed**: non-root, **no cluster credentials**
(`automountServiceAccountToken: false`), capability-dropped, and resource-capped — your repo's build
command is untrusted code and is treated as such. It can reach the git host and the site bucket; a
tighter egress NetworkPolicy and build-time secret injection are follow-ons. Omit `spec.build`
entirely to keep uploading assets yourself (above).

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
