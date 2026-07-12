#!/usr/bin/env bash
# open-infra query runner (the Athena engine, Phase 1: DuckDB).
#
# Executes one SQL query with DuckDB against MinIO (S3) and writes the results to
# the query's output location as CSV — the Athena "output location" model — plus a
# sidecar <id>.metadata.json the console reads for state/stats (GetQueryExecution).
# Serverless per query: this runs as a Job pod that executes once and exits.
set -uo pipefail

: "${SQL:?SQL is required}"
: "${OUTPUT_S3:?OUTPUT_S3 is required (s3://bucket/<query-id>.csv)}"
: "${S3_ENDPOINT:?}" "${S3_ACCESS_KEY:?}" "${S3_SECRET_KEY:?}"

META="${OUTPUT_S3%.csv}.metadata.json"

# httpfs/parquet/json are baked into the image; LOAD is offline. A DuckDB SECRET
# carries the MinIO creds (path-style, plaintext HTTP inside the cluster).
SETUP="LOAD httpfs; LOAD parquet; LOAD json;
CREATE SECRET minio (TYPE S3, KEY_ID '${S3_ACCESS_KEY}', SECRET '${S3_SECRET_KEY}',
  ENDPOINT '${S3_ENDPOINT}', USE_SSL false, URL_STYLE 'path');"

sql_escape() { printf '%s' "$1" | sed "s/'/''/g"; }

start=$(date +%s%3N)
if duckdb -c "${SETUP} COPY (${SQL}) TO '${OUTPUT_S3}' (FORMAT CSV, HEADER);" 2>/tmp/err; then
  end=$(date +%s%3N)
  # count the result rows; grep the pure-digit line so the CREATE SECRET success
  # line in SETUP can't leak into the value.
  rows=$(duckdb -noheader -list -c "${SETUP} SELECT count(*) FROM read_csv_auto('${OUTPUT_S3}');" 2>/dev/null | grep -E '^[0-9]+$' | tail -1)
  duckdb -c "${SETUP} COPY (SELECT 'SUCCEEDED' AS state, CAST(${rows:-0} AS BIGINT) AS row_count,
    CAST($((end - start)) AS BIGINT) AS execution_time_ms, '${OUTPUT_S3}' AS result_location)
    TO '${META}' (FORMAT JSON, ARRAY false);" 2>/dev/null || true
  echo "query SUCCEEDED: ${rows:-?} rows in $((end - start))ms -> ${OUTPUT_S3}"
else
  err=$(sql_escape "$(head -c 4000 /tmp/err | tr '\n' ' ')")
  duckdb -c "${SETUP} COPY (SELECT 'FAILED' AS state, '${err}' AS error)
    TO '${META}' (FORMAT JSON, ARRAY false);" 2>/dev/null || true
  echo "query FAILED: $(head -c 4000 /tmp/err)" >&2
  exit 1
fi
