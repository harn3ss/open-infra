# open-infra Lambda runtime base image (Python 3.12). Prebuilt + first-party; a
# user's handler CODE is injected at runtime into /var/task (a ConfigMap mount for
# inline handlers, or an init-container that fetches+unzips the code bucket object),
# and bootstrap.py serves it over HTTP. Stdlib-only shim — no third-party deps, so
# the image stays small and has a minimal CVE surface.
#
# Built + pushed by .github/workflows/build-lambda-runtimes.yml as
# ghcr.io/harn3ss/open-infra-lambda-python. Plain CGO-free interpreter; NOT FIPS
# (FIPS is a substrate property, not a first-party image one — see docs).
# PY_VERSION selects the base (3.12 = the default image, 3.13 = the open-infra-lambda-python313
# build). The stdlib-only bootstrap shim is version-independent, so one Dockerfile builds both.
ARG PY_VERSION=3.12
FROM python:${PY_VERSION}-slim

LABEL org.opencontainers.image.source="https://github.com/harn3ss/open-infra" \
      openinfra.dev/component="lambda-runtime-python" \
      openinfra.dev/fips="false"

# Pull Debian security updates for base-image OS packages (CVE hygiene) so the image isn't
# pinned to the base layer's package snapshot. Keeps parity with the node/dotnet runtimes.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# boto3 for the bucket (S3/MinIO) code-source path. The shim imports it lazily, so the
# ConfigMap (inline) source never pays for it at runtime — it's here so bucket sources work.
# The transitive/base packages are floored to their patched versions to clear Trivy CVE
# findings on the runtime image — urllib3 (pulled by botocore) CVE-2026-97687 + CVE-2026-97689,
# setuptools (from the python base image) CVE-2025-47273, msgpack GHSA-6v7p-g79w-8964. botocore
# allows urllib3 <3 on Python >=3.10, so these floors do not conflict with boto3's own pins.
RUN pip install --no-cache-dir \
      "boto3>=1.34,<2" \
      "urllib3>=2.8.0" \
      "msgpack>=1.2.1" \
      "setuptools>=78.1.1" \
    && python -m pip uninstall -y pip \
    && rm -rf /root/.cache/pip
# pip is a BUILD-time tool — the runtime only runs bootstrap.py (stdlib) + boto3; a handler brings its
# own deps (bundled or a layer), never `pip install` at cold start. Removing pip also removes its
# _vendor bundle, which ships its OWN pinned copies of urllib3/msgpack/setuptools (vendor.txt) that
# Trivy flags separately from the top-level packages above — those vendored copies are the real source
# of the python-pkg CVE alerts, and they can't be upgraded without upgrading pip itself. Dropping pip
# clears them and shrinks the runtime's CVE surface to the stdlib shim + boto3.

# The shim lives outside /var/task so a handler can never shadow it.
COPY bootstrap.py /opt/open-infra/bootstrap.py

# /var/task is the handler code root — a mountpoint at runtime (ConfigMap or the
# fetched+unzipped code). /opt is the Lambda LAYER root — the shim extracts layer
# zips there at cold start. Both owned by the non-root runtime user so it can write
# them (the shim at /opt/open-infra stays root-owned + world-readable).
RUN install -d -o 1000 -g 1000 /var/task /opt /opt/python

ENV OPENINFRA_TASK_DIR=/var/task \
    PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 1000:1000
WORKDIR /var/task
EXPOSE 8080
CMD ["python", "/opt/open-infra/bootstrap.py"]
