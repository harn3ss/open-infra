# syntax=docker/dockerfile:1
#
# open-infra console — single-container image (BFF + embedded React SPA).
#
# IMPORTANT — BUILD CONTEXT MUST BE THE REPO ROOT, not console-api/. Both the UI
# (ui/) and the BFF (console-api/) are needed, so build with the repo root as
# context:
#
#     docker build -f console-api/Dockerfile -t open-infra-console:dev .
#
# (run from the repository root). All COPY paths below are relative to that root.
#
# NOTE on the Go toolchain version: keep this in lock-step with go.mod's `go`
# directive. `go mod tidy` raised it to 1.25 (a transitive dep of minio-go/v7
# requires Go >= 1.25), so the builder must be >= 1.25.

# ---------------------------------------------------------------------------
# Stage 1 — build the React SPA (produces ui/dist).
# ---------------------------------------------------------------------------
FROM node:22-alpine AS ui-builder
WORKDIR /ui

# Install dependencies first so this layer caches unless the lockfile changes.
# `npm ci` requires a package-lock.json; it gives reproducible installs.
COPY ui/package.json ui/package-lock.json* ./
RUN npm ci

# Build the app. Vite/CRA emit static assets into ui/dist.
COPY ui/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 — build the Go BFF with the SPA embedded.
# ---------------------------------------------------------------------------
FROM golang:1.25-alpine AS go-builder
WORKDIR /src

# Module graph first for layer caching (re-downloads only when go.mod/sum change).
COPY console-api/go.mod console-api/go.sum ./
RUN go mod download

# BFF source.
COPY console-api/ ./

# Drop the built SPA into the embed target (web/) so `//go:embed all:web` picks
# up the production assets instead of the committed placeholder. We replace the
# directory contents but keep web/ itself.
RUN rm -rf web && mkdir -p web
COPY --from=ui-builder /ui/dist/ ./web/

# Build version is stamped via ldflags and surfaced at /api/config. Override at
# build time with: --build-arg VERSION=$(git describe --tags --always).
ARG VERSION=dev

# Static, stripped binary for a minimal runtime. CGO off => no libc dependency.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/console-api ./cmd/server

# ---------------------------------------------------------------------------
# Stage 3 — minimal runtime.
# ---------------------------------------------------------------------------
FROM alpine:3.20 AS runtime

# wget (busybox) is used by the healthcheck; ca-certificates lets the BFF verify
# the API server / Grafana TLS chains when needed.
RUN apk add --no-cache ca-certificates

# Run as a non-root, non-privileged user. 65532 is the conventional "nonroot"
# uid (matches distroless), avoiding any reliance on a named account.
USER 65532:65532

COPY --from=go-builder /out/console-api /usr/local/bin/console-api

EXPOSE 8080

# Liveness: the BFF answers /healthz with 200 once it is serving.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/console-api"]
