#!/usr/bin/env python3
"""Run one SQL statement against Trino via its REST protocol and emit CSV on stdout.

Used by run.sh for engine=trino. No JDBC/CLI (and so no Java-version coupling) — just
POST /v1/statement and follow nextUri, accumulating columns + rows. Errors go to
stderr with a non-zero exit so the runner writes FAILED metadata.
"""
import csv
import json
import os
import sys
import urllib.request

SERVER = os.environ["TRINO_URL"].rstrip("/")
CATALOG = os.environ.get("TRINO_CATALOG", "iceberg")
SCHEMA = os.environ.get("TRINO_SCHEMA", "")
SQL = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()

HEADERS = {"X-Trino-User": "openinfra", "X-Trino-Catalog": CATALOG}
if SCHEMA:
    HEADERS["X-Trino-Schema"] = SCHEMA


def fetch(req):
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def main():
    resp = fetch(
        urllib.request.Request(
            SERVER + "/v1/statement", data=SQL.encode(), headers=HEADERS, method="POST"
        )
    )
    cols = None
    writer = csv.writer(sys.stdout)
    while True:
        if resp.get("error"):
            sys.stderr.write(resp["error"].get("message", "query error"))
            sys.exit(1)
        if cols is None and resp.get("columns"):
            cols = [c["name"] for c in resp["columns"]]
            writer.writerow(cols)
        for row in resp.get("data", []) or []:
            writer.writerow(["" if v is None else v for v in row])
        nxt = resp.get("nextUri")
        if not nxt:
            break
        resp = fetch(urllib.request.Request(nxt))
    # a statement with no result columns (DDL/DML) still succeeds with 0 rows
    if cols is None:
        writer.writerow([])


if __name__ == "__main__":
    main()
