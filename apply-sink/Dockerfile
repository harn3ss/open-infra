# open-infra apply-sink — the generic CDC apply engine for kind: Migration.
# Static Go binary on distroless.
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /applysink .

FROM gcr.io/distroless/static-debian12
COPY --from=build /applysink /applysink
ENTRYPOINT ["/applysink"]
