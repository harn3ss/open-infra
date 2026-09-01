# open-appsync — open-infra's resolver-first, VTL-faithful AppSync engine. Static Go on distroless.
# Build context is the repo ROOT — this module requires the shared dynamodb module via a local
# replace (../dynamodb), so that sibling is copied in beside it.
FROM golang:1.26 AS build
ARG GOFIPS140=v1.0.0   # Go native FIPS 140-3 module — amd64 default; build-arm64 overrides to empty (non-FIPS arm64)
ENV GOFIPS140=${GOFIPS140}
WORKDIR /src
COPY dynamodb/ dynamodb/
COPY open-appsync/go.mod open-appsync/go.sum open-appsync/
WORKDIR /src/open-appsync
RUN go mod download
COPY open-appsync/ ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /open-appsync ./cmd/open-appsync

FROM gcr.io/distroless/static-debian12
ARG OPENINFRA_FIPS=true   # amd64 default; build-arm64 sets false via the label
LABEL openinfra.dev/fips=${OPENINFRA_FIPS}
EXPOSE 8080
USER 65532:65532
COPY --from=build /open-appsync /open-appsync
ENTRYPOINT ["/open-appsync"]
