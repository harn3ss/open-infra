# open-appsync — open-infra's resolver-first, VTL-faithful AppSync engine. Static Go on distroless.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /open-appsync ./cmd/open-appsync

FROM gcr.io/distroless/static-debian12
EXPOSE 8080
USER 65532:65532
COPY --from=build /open-appsync /open-appsync
ENTRYPOINT ["/open-appsync"]
