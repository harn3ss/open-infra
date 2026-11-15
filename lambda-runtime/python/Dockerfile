# open-infra Lambda runtime base image (Python 3.12). Prebuilt + first-party; a
# user's handler CODE is injected at runtime into /var/task (a ConfigMap mount for
# inline handlers, or an init-container that fetches+unzips the code bucket object),
# and bootstrap.py serves it over HTTP. Stdlib-only shim — no third-party deps, so
# the image stays small and has a minimal CVE surface.
#
# Built + pushed by .github/workflows/build-lambda-runtimes.yml as
# ghcr.io/harn3ss/open-infra-lambda-python. Plain CGO-free interpreter; NOT FIPS
# (FIPS is a substrate property, not a first-party image one — see docs).
# PY_VERSION selects the base (3.12 = the default image; 3.8, 3.9, 3.10, 3.11, 3.13 and 3.14 = the
# open-infra-lambda-python<NN> builds). The stdlib-only bootstrap shim is version-independent, so one
# Dockerfile builds them all. 3.8 to 3.10 are past their upstream end of life (AWS has deprecated them and
# still creates functions on them until its block dates, cfn/lambda_runtimes.go): their base images and
# the newest packages they can install are what they get.
ARG PY_VERSION=3.12
FROM python:${PY_VERSION}-slim

LABEL org.opencontainers.image.source="https://github.com/harn3ss/open-infra" \
      openinfra.dev/component="lambda-runtime-python" \
      openinfra.dev/fips="false"

# Pull Debian security updates for base-image OS packages (CVE hygiene) so the image isn't
# pinned to the base layer's package snapshot. Keeps parity with the node/dotnet runtimes.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# boto3 for the bucket (S3/MinIO) code-source path. The shim imports it lazily, so the
# ConfigMap (inline) source never pays for it at runtime — it's here so bucket sources work, and because
# AWS's Python runtimes ship boto3 for handlers.
# Everything is UPGRADED (-U) to the newest release the interpreter supports: a plain install leaves the
# base image's own setuptools and wheel where they are, with their CVEs (setuptools vendors its own wheel
# and jaraco.context; 84.2.1 on Python >= 3.10 and 82.0.1 on 3.9 carry fixed copies). urllib3 (pulled by
# botocore) is floored where botocore allows 2.x (Python >= 3.10). On 3.8 and 3.9 the newest botocore
# still pins urllib3 < 1.27, as AWS's own runtimes for them do, and 3.8's newest setuptools is 75.3.4:
# those images keep what their interpreter allows. wheel is a build tool nothing here runs: removed.
RUN if python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then \
      pip install --no-cache-dir -U "boto3>=1.34,<2" "urllib3>=2.8.0" "setuptools>=84.2.1" ; \
    else \
      pip install --no-cache-dir -U "boto3>=1.34,<2" "setuptools" ; \
    fi \
    && python -m pip uninstall -y wheel \
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
