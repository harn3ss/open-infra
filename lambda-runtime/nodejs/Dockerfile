# open-infra Lambda runtime base image (Node.js 20). Prebuilt + first-party; a user's handler CODE is
# injected at runtime into /var/task (a ConfigMap mount for inline handlers, or the shim fetches+unzips
# the code bucket object at cold start), and bootstrap.js serves it over HTTP. The Node sibling of the
# python image — same spec.code contract, same env vars.
#
# Built + pushed by .github/workflows/build-lambda-runtimes.yml as
# ghcr.io/harn3ss/open-infra-lambda-nodejs. Plain interpreter; NOT FIPS (FIPS is a substrate property,
# not a first-party image one — see docs).
FROM node:20-slim

LABEL org.opencontainers.image.source="https://github.com/harn3ss/open-infra" \
      openinfra.dev/component="lambda-runtime-nodejs" \
      openinfra.dev/fips="false"

# unzip: Node has no stdlib zip-archive reader, so the bucket-source .zip is extracted with the system
#        tool (the python shim uses stdlib zipfile for the same job).
# @aws-sdk/client-s3: the bucket (S3/MinIO) code-source path. Installed globally + put on NODE_PATH so
#        the shim can require() it; the inline-ConfigMap path never loads it (lazy require).
# apt-get upgrade: pull Debian bookworm security updates for base-image OS packages
#        (perl-base, libgnutls30, libpcre2-8-0, libcap2, …) so the image isn't pinned to the
#        base layer's snapshot — the durable fix for the recurring OS-package CVE treadmill.
# rm npm/npx: the function runtime only runs `node bootstrap.js`; handler deps arrive as
#        prebuilt layer node_modules, never an in-image `npm install`. npm's own bundled
#        node_modules (tar, minimatch, glob, brace-expansion, sigstore, pacote, …) are pure
#        build-tooling CVE surface that nothing here executes, so the npm CLI is removed after
#        our one global install rather than carried (and futilely dep-bumped).
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends unzip ca-certificates \
 && npm install -g @aws-sdk/client-s3@3 \
 && npm cache clean --force \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
 && rm -rf /var/lib/apt/lists/*

ENV NODE_PATH=/usr/local/lib/node_modules

# The shim lives outside /var/task so a handler can never shadow it.
COPY bootstrap.js /opt/open-infra/bootstrap.js

# /var/task is the handler code root — a mountpoint at runtime (ConfigMap or the fetched+unzipped code).
# /opt is the Lambda LAYER root — the shim extracts layer zips there (nodejs/node_modules) at cold
# start. Both owned by the non-root runtime user so it can write them (the shim at /opt/open-infra stays
# root-owned + world-readable).
RUN install -d -o 1000 -g 1000 /var/task /opt /opt/nodejs

ENV OPENINFRA_TASK_DIR=/var/task \
    PORT=8080 \
    NODE_ENV=production

USER 1000:1000
WORKDIR /var/task
EXPOSE 8080
CMD ["node", "/opt/open-infra/bootstrap.js"]
