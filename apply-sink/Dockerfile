# open-infra apply-sink — the generic CDC apply engine for kind: Migration.
# Static Go binary on distroless.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# All Go sources (main.go + schema_drift.go + any future files); go build . ignores _test.go.
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /applysink .

FROM gcr.io/distroless/static-debian12
COPY --from=build /applysink /applysink
ENTRYPOINT ["/applysink"]
