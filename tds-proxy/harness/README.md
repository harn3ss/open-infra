# tds-proxy compatibility harness

Populates the compatibility grid ([`../grid.jsonl`](../grid.jsonl)) with **real captures**: drive a
client through the proxy against a **throwaway** backend and record how each shape classifies. The proxy
*is* the tap — run it with `TDSPROXY_DEBUG=1` to log every classified message (type, pin/prelude verdict,
reason, text). Never point this at a real database.

## Run

```bash
BACKEND=$(./throwaway-backend.sh)                       # docker SQL Server 2022 on 127.0.0.1:21433
../.. && go build -o /tmp/tds-proxy ./tds-proxy         # or use your build
TDSPROXY_DEBUG=1 /tmp/tds-proxy -listen 127.0.0.1:23433 -backend "$BACKEND" -metrics 127.0.0.1:29114 &

# host-feasible drivers (no container):
( cd tedious && npm i && HOST=127.0.0.1 PORT=23433 USER=sa PW='Grid#Test2026!' node run.js )
( cd jdbc && curl -sLO https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/12.8.1.jre11/mssql-jdbc-12.8.1.jre11.jar \
    && mv mssql-jdbc-12.8.1.jre11.jar mssql-jdbc.jar && javac -cp mssql-jdbc.jar Run.java \
    && HOST=127.0.0.1 PORT=23433 USER=sa PW='Grid#Test2026!' java -cp ".:mssql-jdbc.jar" Run )

curl -s localhost:29114/status            # per-run verdicts
./throwaway-backend.sh --down             # tear down
```

Container-gated drivers (no host install): pyodbc/`msodbcsql18` in a `python:3`+`apt msodbcsql18`
container, `Microsoft.Data.SqlClient` in `mcr.microsoft.com/dotnet/sdk` — each forcing `Encrypt=no`.

## Findings so far (see grid.jsonl)

- **go-mssqldb** sends raw `SQLBatch`es: a `#temp`/`BEGIN TRAN` is **session-scoped** → pins. Parameterized
  goes via `sp_executesql` → multiplexes. (Verified vs live SQL Server *and* Babelfish.)
- **tedious** wraps every statement in `sp_executesql`, so a `#temp` created there is **exec-scoped**
  (dropped on return) → it multiplexes where go-mssqldb pins. Its raw-batch path (`execSqlBatch`) pins
  as expected. tedious also issues `SET TRANSACTION ISOLATION LEVEL` in its connect prelude — which the
  classifier now treats as a **poolable login prelude** (re-applied per connection), so tedious went from
  100% pinned to fully poolable. `.NET`'s SqlClient sets isolation the same way and benefits identically.
- **mssql-jdbc / msodbcsql18 / Microsoft.Data.SqlClient**: even with `encrypt=false` these negotiate
  **login-time TLS** the plaintext proxy can't satisfy, so the handshake fails → **unhandled** until the
  proxy terminates TLS (issue C3F57E74). Only the `encryption=disable` column is capturable until then.
