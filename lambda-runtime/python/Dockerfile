# open-infra Lambda runtime base image (Python 3.12). Prebuilt + first-party; a
# user's handler CODE is injected at runtime into /var/task (a ConfigMap mount for
# inline handlers, or an init-container that fetches+unzips the code bucket object),
# and bootstrap.py serves it over HTTP. Stdlib-only shim — no third-party deps, so
# the image stays small and has a minimal CVE surface.
#
# Built + pushed by .github/workflows/build-lambda-runtimes.yml as
# ghcr.io/harn3ss/open-infra-lambda-python. Plain CGO-free interpreter; NOT FIPS
# (FIPS is a substrate property, not a first-party image one — see docs).
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/harn3ss/open-infra" \
      openinfra.dev/component="lambda-runtime-python" \
      openinfra.dev/fips="false"

# boto3 for the bucket (S3/MinIO) code-source path. The shim imports it lazily, so the
# ConfigMap (inline) source never pays for it at runtime — it's here so bucket sources work.
RUN pip install --no-cache-dir "boto3>=1.34,<2" && rm -rf /root/.cache/pip

# The shim lives outside /var/task so a handler can never shadow it.
COPY bootstrap.py /opt/open-infra/bootstrap.py

# /var/task is the handler code root — a mountpoint at runtime (ConfigMap or the
# fetched+unzipped code). Create it owned by the non-root runtime user.
RUN install -d -o 1000 -g 1000 /var/task

ENV OPENINFRA_TASK_DIR=/var/task \
    PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 1000:1000
WORKDIR /var/task
EXPOSE 8080
CMD ["python", "/opt/open-infra/bootstrap.py"]
