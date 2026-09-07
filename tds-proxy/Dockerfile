# tds-proxy — TDS-aware connection multiplexer. Stdlib-only, static, minimal runtime.
FROM golang:1.27-alpine AS build
ARG GOFIPS140=v1.0.0   # Go native FIPS 140-3 module — amd64 default; build-arm64 overrides to empty (non-FIPS arm64)
ENV GOFIPS140=${GOFIPS140}
WORKDIR /src
COPY go.mod ./
COPY tds/ ./tds/
COPY classify/ ./classify/
COPY pool/ ./pool/
COPY *.go ./
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags "-s -w" -o /out/tds-proxy .

FROM alpine:3.24 AS runtime
ARG OPENINFRA_FIPS=true   # amd64 default; build-arm64 sets false via the label
LABEL openinfra.dev/fips=${OPENINFRA_FIPS}
# `apk upgrade` first so a rebuild picks up base-image security patches (libssl3/libcrypto3).
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
USER 65532:65532
COPY --from=build /out/tds-proxy /usr/local/bin/tds-proxy
EXPOSE 1433 9114
ENTRYPOINT ["/usr/local/bin/tds-proxy"]
