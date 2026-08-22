# open-infra-mc — the MinIO client (`mc`), built FROM SOURCE and world-readable.
#
# Two jobs in one:
#   1. Freshness/CVEs — the stock `minio/mc:latest` binary lags Go security releases, so Trivy flags
#      40+ Go stdlib + dependency CVEs in it (net/http, crypto/tls, crypto/x509, x/net, x/crypto/ssh,
#      grpc, …). Building mc from a pinned release against the current Go toolchain, with its flagged
#      deps bumped to patched releases, rebuilds those away rather than shipping the stale prebuilt.
#   2. World-readable binary — the stock image ships /usr/bin/mc mode ~0750 root-owned, so the
#      `fetch-mc` init containers in the WORM audit / attestation / crypto-erase jobs (which stage mc
#      into a shared emptyDir for a hardened, non-root main container) could only copy it running as
#      ROOT — rejected under `restricted` Pod Security. Re-materializing mc at 0755 lets the copy run
#      unprivileged, so those pods stay restricted-PSA clean.
#
# Bump MC_VERSION periodically (latest at https://github.com/minio/mc/releases) to stay current.
FROM golang:1.26 AS build
ARG MC_VERSION=RELEASE.2025-08-13T08-35-41Z
RUN git clone --depth 1 --branch ${MC_VERSION} https://github.com/minio/mc /src
WORKDIR /src
# Recompiling with the current Go clears the stdlib CVEs; bumping the Trivy-flagged deps clears theirs.
# (prometheus is a transitive dep mc embeds for metrics — its two flagged CVEs are server-side
# remote-read/Azure-SD paths mc never uses, but bumping to the fixed release clears them cleanly.)
RUN go get golang.org/x/crypto@latest golang.org/x/net@latest golang.org/x/text@latest google.golang.org/grpc@latest github.com/prometheus/prometheus@v0.311.3 \
 && go mod tidy \
 && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/minio/mc/cmd.Version=${MC_VERSION} -X github.com/minio/mc/cmd.ReleaseTag=${MC_VERSION}" \
      -o /mc .

FROM alpine:3.20
COPY --from=build /mc /usr/bin/mc
RUN chmod 0755 /usr/bin/mc && /usr/bin/mc --version
USER 65532:65532
ENTRYPOINT ["/usr/bin/mc"]
