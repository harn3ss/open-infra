# open-infra Lambda runtime base image (.NET 8). Prebuilt + first-party; a user's PUBLISHED .NET
# handler (the build output: handler assembly + its deps) is injected at runtime into /var/task (a
# ConfigMap mount, or the shim fetches+unzips the code bucket object at cold start), and bootstrap.dll
# loads + reflects the declared handler and serves it over HTTP. The .NET sibling of the python/node
# images — same spec.code contract + env vars. .NET has a stdlib zip reader, so no unzip tool is needed.
#
# Built + pushed by .github/workflows/build-lambda-runtimes.yml as
# ghcr.io/harn3ss/open-infra-lambda-dotnet. NOT FIPS (FIPS is a substrate property, not a first-party
# image one — see docs).
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish bootstrap.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/runtime:8.0

LABEL org.opencontainers.image.source="https://github.com/harn3ss/open-infra" \
      openinfra.dev/component="lambda-runtime-dotnet" \
      openinfra.dev/fips="false"

# The shim lives outside /var/task so a handler can never shadow it.
COPY --from=build /app /opt/open-infra

# /var/task is the handler code root — a mountpoint at runtime (ConfigMap or the fetched+unzipped
# publish output). /opt/dotnet is the Lambda LAYER dir the shim resolves handler deps from. Both owned
# by the non-root runtime user (the shim at /opt/open-infra stays root-owned + world-readable).
RUN install -d -o 1000 -g 1000 /var/task /opt /opt/dotnet

ENV OPENINFRA_TASK_DIR=/var/task \
    PORT=8080 \
    DOTNET_EnableDiagnostics=0

USER 1000:1000
WORKDIR /var/task
EXPOSE 8080
CMD ["dotnet", "/opt/open-infra/bootstrap.dll"]
