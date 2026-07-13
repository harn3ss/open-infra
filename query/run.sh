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

# The query is wrapped as COPY (<sql>) TO … — an editor's trailing ';' would land
# inside the parens and be a parse error. Strip trailing whitespace/semicolons so a
# normal "SELECT … ;" just works.
SQL=$(printf '%s' "$SQL" | sed 's/[[:space:];]*$//')

META="${OUTPUT_S3%.csv}.metadata.json"

# httpfs/parquet/json are baked into the image; LOAD is offline. A DuckDB SECRET
# carries the MinIO creds (path-style, plaintext HTTP inside the cluster). temp/spill
# goes to /tmp — the only writable path under the read-only root filesystem.
SETUP="SET temp_directory='/tmp'; LOAD httpfs; LOAD parquet; LOAD json;
CREATE SECRET minio (TYPE S3, KEY_ID '${S3_ACCESS_KEY}', SECRET '${S3_SECRET_KEY}',
  ENDPOINT '${S3_ENDPOINT}', USE_SSL false, URL_STYLE 'path');"

# Sandbox applied to the UNTRUSTED user SQL only: block all local-filesystem access
# (so a query can't read /etc/passwd or /proc/self/environ to exfiltrate the pod's
# env/creds, nor read/write arbitrary local files) and lock the configuration so a
# SQL breakout of the COPY(...) wrapper can't re-enable it. S3 (httpfs) still works.
SECURE="SET disabled_filesystems='LocalFileSystem'; SET lock_configuration=true;"

write_fail() { # $1 = error text (already quote-safe)
  duckdb -c "${SETUP} COPY (SELECT 'FAILED' AS state, '$1' AS error) TO '${META}' (FORMAT JSON, ARRAY false);" 2>/dev/null || true
}

# ── engine=trino: run against the Trino coordinator (catalog + federation) instead
#    of DuckDB. Same result contract (CSV + metadata.json to OUTPUT_S3), so the
#    console reads it identically. Trino may be idle-stopped, so wait for it to come
#    up first (the autostop reconciler scales it to 1 when a trino query appears).
if [ "${ENGINE:-duckdb}" = "trino" ]; then
  : "${TRINO_URL:?TRINO_URL is required for engine=trino}"
  echo "waiting for Trino at ${TRINO_URL} (may be scaling up from idle)…"
  ready=0
  for _ in $(seq 1 90); do
    if curl -sf "${TRINO_URL}/v1/info" >/dev/null 2>&1; then ready=1; break; fi
    sleep 3
  done
  if [ "$ready" != 1 ]; then
    write_fail "Trino did not become ready in time"
    echo "Trino not ready" >&2
    exit 1
  fi
  start=$(date +%s%3N)
  if python3 /usr/local/bin/trino_query.py "$SQL" > /tmp/tout.csv 2>/tmp/err; then
    end=$(date +%s%3N)
    rows=$(($(wc -l < /tmp/tout.csv) - 1))
    [ "$rows" -lt 0 ] && rows=0
    # re-emit through DuckDB to land the result at OUTPUT_S3 (reuses the S3 secret).
    [ -s /tmp/tout.csv ] && duckdb -c "${SETUP} COPY (SELECT * FROM read_csv_auto('/tmp/tout.csv', ALL_VARCHAR=true, header=true)) TO '${OUTPUT_S3}' (FORMAT CSV, HEADER);" 2>/dev/null || true
    duckdb -c "${SETUP} COPY (SELECT 'SUCCEEDED' AS state, CAST(${rows} AS BIGINT) AS row_count,
      CAST($((end - start)) AS BIGINT) AS execution_time_ms, '${OUTPUT_S3}' AS result_location)
      TO '${META}' (FORMAT JSON, ARRAY false);" 2>/dev/null || true
    echo "trino query SUCCEEDED: ${rows} rows in $((end - start))ms -> ${OUTPUT_S3}"
    exit 0
  else
    write_fail "$(head -c 800 /tmp/err | tr -d "'\"\\\\" | tr '\n' ' ')"
    echo "trino query FAILED: $(head -c 800 /tmp/err)" >&2
    exit 1
  fi
fi

start=$(date +%s%3N)
if duckdb -c "${SETUP} ${SECURE} COPY (${SQL}) TO '${OUTPUT_S3}' (FORMAT CSV, HEADER);" 2>/tmp/err; then
  end=$(date +%s%3N)
  # count the result rows; grep the pure-digit line so the CREATE SECRET success
  # line in SETUP can't leak into the value.
  rows=$(duckdb -noheader -list -c "${SETUP} SELECT count(*) FROM read_csv_auto('${OUTPUT_S3}');" 2>/dev/null | grep -E '^[0-9]+$' | tail -1)
  duckdb -c "${SETUP} COPY (SELECT 'SUCCEEDED' AS state, CAST(${rows:-0} AS BIGINT) AS row_count,
    CAST($((end - start)) AS BIGINT) AS execution_time_ms, '${OUTPUT_S3}' AS result_location)
    TO '${META}' (FORMAT JSON, ARRAY false);" 2>/dev/null || true
  echo "query SUCCEEDED: ${rows:-?} rows in $((end - start))ms -> ${OUTPUT_S3}"
else
  # Strip quotes/backslashes + cap length so the error text can't break the
  # metadata COPY (it must always write, or the console spins on RUNNING forever).
  err=$(head -c 800 /tmp/err | tr -d "'\"\\\\" | tr '\n' ' ')
  duckdb -c "${SETUP} COPY (SELECT 'FAILED' AS state, '${err}' AS error)
    TO '${META}' (FORMAT JSON, ARRAY false);" 2>/dev/null || true
  echo "query FAILED: $(head -c 4000 /tmp/err)" >&2
  exit 1
fi
