# Static sites (`kind: StaticSite`)

`kind: StaticSite` hosts a built single-page app (a `dist/` tree) over HTTP + TLS — the
S3-static-website-plus-CDN-origin-shaped primitive. One claim provisions:

- a **MinIO bucket** for the built assets (created if absent), with a `<name>-minio` connection
  secret (endpoint + credentials) for uploads;
- an **nginx server** that continuously syncs the bucket and serves it, with **SPA history-fallback**
  (unknown paths serve `index.html` so client-side routing works);
- a **Traefik Ingress** with cert-manager TLS on your domain.

Deleting the claim deletes its connection secret and its TLS secret with it. The bucket reaper then
removes the site's MinIO user and, once it is empty, its bucket; a bucket that still holds assets is
kept, because no sweep deletes data. To remove everything, empty the bucket first
(`aws s3 rm s3://<bucket>/ --recursive`) and then delete the StaticSite.

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
without redeploying. Each successful sync records the time it started, served on the site's in-cluster status
port (`8081`, reachable only by the aws-shim): for a site a CloudFormation stack created, that is what
`aws cloudfront create-invalidation` / `wait invalidation-completed` wait on ([aws-shim.md](aws-shim.md#cloudfront-a-stacks-distribution-its-invalidations-and-reads-probe-proven)). For a plain multi-file site (no client-side router), set `spec.spa: false` and
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

> **Where to run the upload.** From anywhere on your network: a laptop or a CI runner uploads through the
> platform's S3 endpoint with your own access key, as it would to S3.
>
> ```sh
> export AWS_ENDPOINT_URL=https://s3.<your open-infra domain>
> export AWS_CA_BUNDLE=$PWD/openinfra-root-ca.crt     # the platform root CA (see the aws-shim guide)
> aws s3 sync ./dist/ "s3://<site bucket>/" --delete
> aws cloudfront create-invalidation --distribution-id <id> --paths '/*'
> ```
>
> The key needs `s3:PutObject` and `s3:DeleteObject` on the site's bucket. Inside the cluster, the
> `MINIO_ENDPOINT` in the `<name>-minio` secret is the bucket's direct address, for platform jobs.

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
lives with your pipeline. Deploy one stack per pull request, upload the build to its bucket, and
delete the stack on close: the same AWS CLI steps you would run against AWS, against the platform's
endpoint. The stack is the standard SPA template, a private bucket behind a CloudFront distribution:

```yaml
# preview.yaml
Parameters:
  SiteDomain: { Type: String }
Resources:
  SiteBucket:
    Type: AWS::S3::Bucket
  SiteOriginAccess:
    Type: AWS::CloudFront::OriginAccessControl
    Properties:
      OriginAccessControlConfig:
        Name: !Sub "${AWS::StackName}-site"
        OriginAccessControlOriginType: s3
        SigningBehavior: always
        SigningProtocol: sigv4
  SiteCertificate:
    Type: AWS::CertificateManager::Certificate
    Properties: { DomainName: !Ref SiteDomain, ValidationMethod: DNS }
  SiteDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        Aliases: [!Ref SiteDomain]
        DefaultRootObject: index.html
        Origins:
          - Id: site
            DomainName: !GetAtt SiteBucket.RegionalDomainName
            S3OriginConfig: { OriginAccessIdentity: "" }
            OriginAccessControlId: !GetAtt SiteOriginAccess.Id
        DefaultCacheBehavior:
          TargetOriginId: site
          ViewerProtocolPolicy: redirect-to-https
          CachePolicyId: 658327ea-f89d-4fab-a63d-7e88639e58f6   # CachingOptimized
        CustomErrorResponses:
          - { ErrorCode: 403, ResponseCode: 200, ResponsePagePath: /index.html }
          - { ErrorCode: 404, ResponseCode: 200, ResponsePagePath: /index.html }
        ViewerCertificate:
          AcmCertificateArn: !Ref SiteCertificate
          SslSupportMethod: sni-only
          MinimumProtocolVersion: TLSv1.2_2021
  SiteBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref SiteBucket
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: { Service: cloudfront.amazonaws.com }
            Action: s3:GetObject
            Resource: !Sub "${SiteBucket.Arn}/*"
            Condition:
              StringEquals:
                AWS:SourceArn: !Sub "arn:aws:cloudfront::${AWS::AccountId}:distribution/${SiteDistribution}"
Outputs:
  Bucket: { Value: !Ref SiteBucket }
  DistributionId: { Value: !Ref SiteDistribution }
```

```yaml
# .github/workflows/preview.yml
on:
  pull_request:
    types: [opened, synchronize, reopened, closed]
jobs:
  preview:
    runs-on: ubuntu-latest
    env:
      AWS_ENDPOINT_URL: https://s3.<your open-infra domain>
      AWS_CA_BUNDLE: openinfra-root-ca.crt          # committed, or fetched from /v1/ca-bundle
      AWS_ACCESS_KEY_ID: ${{ secrets.OPENINFRA_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.OPENINFRA_SECRET }}
      AWS_REGION: us-east-1
      STACK: preview-pr-${{ github.event.number }}
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build          # produces ./dist

      # On open/update: deploy the stack, upload the build, invalidate.
      - if: github.event.action != 'closed'
        run: |
          aws cloudformation deploy --stack-name "$STACK" --template-file preview.yaml \
            --parameter-overrides SiteDomain=pr-${{ github.event.number }}.preview.example.com
          out() { aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
          aws s3 sync ./dist/ "s3://$(out Bucket)/" --delete
          aws cloudfront create-invalidation --distribution-id "$(out DistributionId)" --paths '/*'

      # On close: empty the bucket (a non-empty bucket can't be deleted, as on AWS), then delete the stack.
      - if: github.event.action == 'closed'
        run: |
          b=$(aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='Bucket'].OutputValue" --output text)
          aws s3 rm "s3://$b/" --recursive
          aws cloudformation delete-stack --stack-name "$STACK"
          aws cloudformation wait stack-delete-complete --stack-name "$STACK"
```

A platform-native preview controller (auto-provisioning environments from Git state) is a separate,
much larger feature and is intentionally out of scope of this first cut.
