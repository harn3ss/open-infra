# open-infra-nats-box — the NATS CLI (`nats`), built FROM SOURCE and world-readable.
#
# Replaces the reconcile-time pull of the mutable public `natsio/nats-box:latest` (docker.io) in the
# queue/stream/dataflow/migration/replication setup Jobs (polyhedron#165 — the same external-`:latest`
# shape that broke when quay.io/minio/mc:latest started 401-ing). Building `nats` from a pinned release
# against the current Go toolchain rebuilds away stale Go stdlib/dep CVEs, and re-materializing it at
# 0755 (world-readable) + USER 65532 keeps the setup pods restricted-PSA clean — the same treatment as
# open-infra-mc.
#
# The setup Jobs run `nats --server … stream add/edit/info` directly (this image is the container, its
# command overridden to `sh -c "nats …"`), so alpine's /bin/sh + nats on PATH is all they need.
#
# Bump NATSCLI_VERSION periodically (latest at https://github.com/nats-io/natscli/releases).
# --platform=$BUILDPLATFORM keeps the build stage NATIVE on the builder and cross-compiles via GOARCH,
# so the multi-arch build never emulates the Go toolchain under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG NATSCLI_VERSION=v0.5.0
ARG TARGETARCH
RUN git clone --depth 1 --branch ${NATSCLI_VERSION} https://github.com/nats-io/natscli /src
WORKDIR /src
# The CLI main lives in ./nats (the documented `go install .../natscli/nats` path). Recompiling with the
# current Go clears stdlib CVEs from the stale prebuilt.
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /nats ./nats

FROM alpine:3.24
# not a Go build artifact carrying a FIPS claim — plain upstream nats CLI
LABEL openinfra.dev/fips=false
# `apk upgrade` so a rebuild picks up base-image security patches.
RUN apk upgrade --no-cache
COPY --from=build /nats /usr/bin/nats
RUN chmod 0755 /usr/bin/nats && /usr/bin/nats --version
# The nats CLI resolves a config directory even with an explicit --server, and PANICS as a non-root
# user with no home/USER ("user: Current requires cgo or $USER set"). natsio/nats-box got away with it
# by running as root; we run non-root (restricted-PSA), so give it a writable, resolvable config home.
# Baked into the image ENV so the setup Jobs (which override `command` but not `env`) inherit it — no
# per-Job env edits needed.
RUN mkdir -p /home/nats/.config && chown -R 65532:65532 /home/nats
ENV HOME=/home/nats XDG_CONFIG_HOME=/home/nats/.config USER=nats
USER 65532:65532
ENTRYPOINT ["/usr/bin/nats"]
