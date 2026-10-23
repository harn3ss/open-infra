# Machine cluster-state collector (polyhedron#314). Read-only observer; commits snapshots to
# harn3ss/cluster-state and rewrites the pinned front-page issue. Runs as a non-root CronJob.
FROM python:3.12-slim

# git for the one-commit-per-snapshot push; no build toolchain needed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY collect.py .

# non-root; /tmp is writable for the shallow clone.
RUN useradd -u 10001 -m collector
USER 10001
ENV HOME=/home/collector
ENTRYPOINT ["python", "/app/collect.py"]
