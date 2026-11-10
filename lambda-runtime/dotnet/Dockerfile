# open-infra Lambda runtime base image (.NET 8 or .NET 10, by NET_VERSION). Prebuilt + first-party; a user's PUBLISHED .NET
# handler (the build output: handler assembly + its deps) is injected at runtime into /var/task (a
# ConfigMap mount, or the shim fetches+unzips the code bucket object at cold start), and bootstrap.dll
# loads + reflects the declared handler and serves it over HTTP. The .NET sibling of the python/node
# images — same spec.code contract + env vars. .NET has a stdlib zip reader, so no unzip tool is needed.
#
# Built + pushed by .github/workflows/build-lambda-runtimes.yml as
# ghcr.io/harn3ss/open-infra-lambda-dotnet (dotnet8) and open-infra-lambda-dotnet10. NOT FIPS (FIPS is a substrate property, not a first-party
# image one — see docs).
# NET_VERSION selects the .NET the host runs on and targets (8.0 = dotnet8, the default image; 10.0 =
# dotnet10): a handler published for net<version> runs on the image of that version, as on Lambda. (Not
# DOTNET_VERSION: Microsoft's images set that environment variable to the patch version.)
ARG NET_VERSION=8.0
FROM mcr.microsoft.com/dotnet/sdk:${NET_VERSION} AS build
ARG NET_VERSION
WORKDIR /src
COPY . .
RUN dotnet publish bootstrap.csproj -c Release -p:NetVersion=${NET_VERSION} -o /app

FROM mcr.microsoft.com/dotnet/runtime:${NET_VERSION}

LABEL org.opencontainers.image.source="https://github.com/harn3ss/open-infra" \
      openinfra.dev/component="lambda-runtime-dotnet" \
      openinfra.dev/fips="false"

# Pull Debian security updates for base-image OS packages (perl-base, … — CVE hygiene) so the
# image isn't pinned to the runtime base layer's package snapshot. Runs as root, before USER.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

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
