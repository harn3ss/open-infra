# tds-proxy — TDS-aware connection multiplexer. Stdlib-only, static, minimal runtime.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY tds/ ./tds/
COPY classify/ ./classify/
COPY main.go ./
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags "-s -w" -o /out/tds-proxy .

FROM alpine:3.24 AS runtime
RUN apk add --no-cache ca-certificates
USER 65532:65532
COPY --from=build /out/tds-proxy /usr/local/bin/tds-proxy
EXPOSE 1433 9114
ENTRYPOINT ["/usr/local/bin/tds-proxy"]
