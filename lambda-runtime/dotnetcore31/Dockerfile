# open-infra Lambda runtime base image (.NET Core 3.1) — EOL escape-hatch fixture.
# The .NET Core 3.1 sibling of lambda-runtime/dotnet (net8): same spec.code contract + env vars + shim
# behaviour, ported for 3.1 (the event JSON is built with Utf8JsonWriter instead of the .NET 6+
# System.Text.Json.Nodes DOM). Lets a mirrored dotnetcore3.1 Lambda run byte-identical to its source;
# a net8 assembly cannot run on this runtime and vice-versa, so this is a separate image, not a rebuild.
#
# ⚠️ .NET Core 3.1 is END OF LIFE. Its Debian buster base no longer gets OS security updates and buster's
# apt repos are archived, so `apt-get upgrade` is intentionally OMITTED (it would fail, and there are no
# fixes to pull). This image therefore carries unpatched base-layer OS packages — acceptable ONLY for a
# marked, isolated, egress-denied, scale-to-zero EOL-runtime fixture, NEVER a production image. Same
# trade as the Node EOL fixtures. Because it can't meet the canonical Trivy/CVE bar, it is built into
# ecr-registry as an EOL fixture, NOT by the first-party build-lambda-runtimes workflow.
FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /src
COPY . .
RUN dotnet publish bootstrap.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/runtime:3.1

LABEL org.opencontainers.image.source="https://github.com/harn3ss/open-infra" \
      openinfra.dev/component="lambda-runtime-dotnetcore31" \
      openinfra.dev/fips="false" \
      openinfra.dev/eol="true"

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
