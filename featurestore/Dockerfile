# open-infra featurestore — the kind: FeatureGroup online store API. Pure-stdlib
# (a tiny RESP client), so no go.sum: a static Go binary on distroless.
FROM golang:1.26 AS build
ARG GOFIPS140=v1.0.0   # amd64 default; build-arm64 overrides to empty (non-FIPS arm64)
ENV GOFIPS140=${GOFIPS140}
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /featurestore .

FROM gcr.io/distroless/static-debian12
ARG OPENINFRA_FIPS=true
LABEL openinfra.dev/fips=${OPENINFRA_FIPS}
COPY --from=build /featurestore /featurestore
USER 65532:65532
ENTRYPOINT ["/featurestore"]
