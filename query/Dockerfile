# open-infra's first-party query-engine image (the Athena engine, Phase 1: DuckDB).
# A single static DuckDB CLI + the S3/parquet/json extensions PRELOADED at build,
# so a query pod needs no network to the extension repository at run time. The
# composition runs it as a serverless-per-query Job (see query-composition.yaml).
#
# Phase 2 swaps/augments this with a Trino coordinator + a kind: Catalog metastore
# for distributed, multi-source federation; the kind: Query contract stays the same.
FROM debian:12-slim

ARG DUCKDB_VERSION=v1.1.3
ENV DEBIAN_FRONTEND=noninteractive
# DuckDB resolves extensions under $HOME/.duckdb; pin it so build-time INSTALL and
# run-time LOAD agree regardless of which user the pod runs as.
ENV HOME=/duckdb

# curl (Trino readiness probe) + python3 (Trino REST client, engine=trino) are kept;
# unzip is only needed to unpack the DuckDB CLI.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip python3 \
    && curl -fsSL "https://github.com/duckdb/duckdb/releases/download/${DUCKDB_VERSION}/duckdb_cli-linux-amd64.zip" -o /tmp/duckdb.zip \
    && unzip -q /tmp/duckdb.zip -d /usr/local/bin \
    && rm /tmp/duckdb.zip \
    && apt-get purge -y unzip && apt-get autoremove -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Preload the extensions the runner LOADs (offline at query time).
RUN mkdir -p "$HOME" && duckdb -c "INSTALL httpfs; INSTALL parquet; INSTALL json;"

COPY run.sh /usr/local/bin/run.sh
COPY trino_query.py /usr/local/bin/trino_query.py
RUN chmod 0755 /usr/local/bin/run.sh /usr/local/bin/trino_query.py

ENTRYPOINT ["/usr/local/bin/run.sh"]
