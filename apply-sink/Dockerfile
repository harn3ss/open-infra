# open-infra apply-sink — the generic CDC apply engine for kind: Migration.
# Static Go binary on distroless.
FROM golang:1.27 AS build
ARG GOFIPS140=v1.0.0   # Go native FIPS 140-3 module — amd64 default; build-arm64 overrides to empty (non-FIPS arm64)
ENV GOFIPS140=${GOFIPS140}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# All Go sources (main.go + schema_drift.go + any future files); go build . ignores _test.go.
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /applysink .

FROM gcr.io/distroless/static-debian12
ARG OPENINFRA_FIPS=true   # amd64 default; build-arm64 sets false via the label
LABEL openinfra.dev/fips=${OPENINFRA_FIPS}
COPY --from=build /applysink /applysink
ENTRYPOINT ["/applysink"]
