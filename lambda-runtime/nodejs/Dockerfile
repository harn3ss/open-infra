# open-infra Lambda runtime base image (Node.js 20). Prebuilt + first-party; a user's handler CODE is
# injected at runtime into /var/task (a ConfigMap mount for inline handlers, or the shim fetches+unzips
# the code bucket object at cold start), and bootstrap.js serves it over HTTP. The Node sibling of the
# python image — same spec.code contract, same env vars.
#
# Built + pushed by .github/workflows/build-lambda-runtimes.yml as
# ghcr.io/harn3ss/open-infra-lambda-nodejs. Plain interpreter; NOT FIPS (FIPS is a substrate property,
# not a first-party image one — see docs).
# NODE_VERSION selects the base (20 = the default image, 22 = the open-infra-lambda-nodejs22 build) AND
# the handler-facing AWS SDK it ships (@aws-sdk v3 for >=18, monolithic aws-sdk v2 for <=16 — matching
# what AWS Lambda's own runtimes bundle). The bootstrap shim itself is version-independent.
ARG NODE_VERSION=20
FROM node:${NODE_VERSION}-slim

LABEL org.opencontainers.image.source="https://github.com/harn3ss/open-infra" \
      openinfra.dev/component="lambda-runtime-nodejs" \
      openinfra.dev/fips="false"

# Re-declare NODE_VERSION after FROM so the RUN below can read it (ARGs before FROM are out of stage scope).
ARG NODE_VERSION
# Pinned AWS SDK versions — NEVER a floating major (a floating `@aws-sdk/client-s3@3` is exactly what
# required Node >= 18 and broke every older runtime). Bump deliberately.
# 3.726.0 transitively bundled fast-xml-parser 4.4.1 (CVE-2026-25896 critical + -26278/-33036 high); the
# current SDK no longer depends on fast-xml-parser at all (verified across all 12 clients), so this pin
# clears those 36 image CVEs by removing the package rather than patching it.
ARG AWS_SDK_V3=3.1159.0
ARG AWS_SDK_V2=2.1692.0

# unzip: Node has no stdlib zip-archive reader, so the bucket-source .zip is extracted with the system
#        tool (the python shim uses stdlib zipfile for the same job).
# AWS SDK (handler-facing, version-matched to AWS Lambda): AWS's Node runtimes ship the SDK so a handler
#        can require() it WITHOUT bundling it — nodejs18/20/22 ship @aws-sdk v3, nodejs<=16 shipped the
#        monolithic aws-sdk v2. We mirror that so a mirrored Lambda runs byte-identical to its source
#        (no vendoring/transform of the customer package). PINNED, not floating. IMPORTANT: bootstrap.js
#        does NOT use the SDK — it fetches the code bucket with a built-in SigV4 GET (crypto + http), so
#        cold start works on every Node version; the SDK here is purely for handler code. v3 ships a
#        common client set (extend the list as the estate declares more clients; v2 is one package = all).
# apt-get upgrade: pull Debian security updates for base-image OS packages (perl-base, libgnutls30,
#        libpcre2-8-0, libcap2, …) so the image isn't pinned to the base layer's snapshot.
# rm npm/npx: the runtime only runs `node bootstrap.js`; npm is used once at build for the SDK install
#        then removed — its bundled node_modules (tar, minimatch, glob, sigstore, pacote, …) are
#        build-tooling CVE surface that nothing here executes.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends unzip ca-certificates \
 && if [ "${NODE_VERSION%%.*}" -ge 18 ] 2>/dev/null; then \
      npm install -g \
        @aws-sdk/client-s3@${AWS_SDK_V3} @aws-sdk/client-dynamodb@${AWS_SDK_V3} \
        @aws-sdk/lib-dynamodb@${AWS_SDK_V3} @aws-sdk/client-sns@${AWS_SDK_V3} \
        @aws-sdk/client-sqs@${AWS_SDK_V3} @aws-sdk/client-lambda@${AWS_SDK_V3} \
        @aws-sdk/client-sts@${AWS_SDK_V3} @aws-sdk/client-ssm@${AWS_SDK_V3} \
        @aws-sdk/client-secrets-manager@${AWS_SDK_V3} @aws-sdk/client-kms@${AWS_SDK_V3} \
        @aws-sdk/client-eventbridge@${AWS_SDK_V3} @aws-sdk/client-cloudwatch-logs@${AWS_SDK_V3} ; \
    else \
      npm install -g aws-sdk@${AWS_SDK_V2} ; \
    fi \
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
