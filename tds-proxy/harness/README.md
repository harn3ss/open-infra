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
container (`harness/pyodbc/`, run against a TLS-terminating proxy — see the driver notes below),
`Microsoft.Data.SqlClient` in `mcr.microsoft.com/dotnet/sdk`.

## Fault axis (issue #4)

`fault/` is a Go fault-injection client (its own module, `go-mssqldb`) that drives failure scenarios
through the proxy against the throwaway backend and reads the verdicts from `/status`. The proxy stays
stdlib-only; the dependency lives only in the harness.

```bash
BACKEND=$(./throwaway-backend.sh)
../.. && go build -o /tmp/tds-proxy ./tds-proxy
/tmp/tds-proxy -listen 127.0.0.1:23433 -backend "$BACKEND" -metrics 127.0.0.1:29114 -pool-max 2 -acquire-timeout-ms 800 &
cd harness/fault && go build -o /tmp/fault .
PROXY=127.0.0.1:23433 STATUS=http://127.0.0.1:29114/status SCENARIO=pinned-drop     /tmp/fault
PROXY=127.0.0.1:23433 STATUS=http://127.0.0.1:29114/status SCENARIO=stampede        /tmp/fault
PROXY=127.0.0.1:23433 STATUS=http://127.0.0.1:29114/status SCENARIO=handshake-drop  /tmp/fault
PROXY=127.0.0.1:23433 STATUS=http://127.0.0.1:29114/status SCENARIO=midresult-drop  /tmp/fault
PROXY=127.0.0.1:23433 STATUS=http://127.0.0.1:29114/status BACKEND=127.0.0.1:21433 CONTAINER=tdsgrid-mssql SCENARIO=backend-failover /tmp/fault
./throwaway-backend.sh --down
```

Verified live against SQL Server 2022 (2026-08-21), rows in `grid.jsonl`:

- **client-disconnect-while-pinned** → **pinned-discard**: a session that pins (`CREATE #temp`) then drops
  triggers pinned-discard (`sessions_pinned+1`, `pool_discards+1`) and frees the token — a fresh client
  connects immediately, so a pinned session cannot leak a pool slot.
- **pool-exhaustion-stampede** → **backpressure**: 6 concurrent pinned sessions vs `pool-max=2` → exactly 2
  acquire a backend, the other 4 hit acquire-timeout backpressure; the pool never opens more than 2 backends
  (the per-key semaphore ceiling holds, no over-issue, no leak).
- **connection-drop-mid-handshake** → **clean**: truncated PRELOGIN connects dropped before login reserve no
  pool slot (`pool_cold_opens` unchanged) and leave the proxy usable.
- **client-drop-mid-result-set** → **backend-discarded**: a client that hard-closes its socket mid-result-set
  (a capturing dialer supplies the raw conn, since `database/sql` would otherwise drain on Close) causes the
  proxy to **discard** the mid-stream backend (`pool_discards+1`) rather than return a half-read one; a fresh
  client gets a clean backend.
- **backend-failover-during-txn** → **clean-error-and-recover**: restarting the backend while a client holds
  an open `BEGIN TRAN` makes the in-flight statement fail cleanly (`Read: EOF`, no hang), discards the dead
  backend (`pool_discards+1`), and a fresh client connects+queries once the backend is back (no leak).

The token-leak / over-issue invariants these demonstrate are also proven deterministically under `-race` in
`pool/pool_test.go`. All five fault scenarios from issue #4 are now captured.

## Findings so far (see grid.jsonl)

- **go-mssqldb** sends raw `SQLBatch`es: a `#temp`/`BEGIN TRAN` is **session-scoped** → pins. Parameterized
  goes via `sp_executesql` → multiplexes. (Verified vs live SQL Server *and* Babelfish.)
- **tedious** wraps every statement in `sp_executesql`, so a `#temp` created there is **exec-scoped**
  (dropped on return) → it multiplexes where go-mssqldb pins. Its raw-batch path (`execSqlBatch`) pins
  as expected. tedious also issues `SET TRANSACTION ISOLATION LEVEL` in its connect prelude — which the
  classifier now treats as a **poolable login prelude** (re-applied per connection), so tedious went from
  100% pinned to fully poolable. `.NET`'s SqlClient sets isolation the same way and benefits identically.
- **mssql-jdbc** (12.8.1): negotiates login-time TLS even at `encrypt=false`, so it needed **TLS
  termination** (#6). Now connects at `encrypt=on` (tunneled) *and* `encrypt=strict` (TDS 8.0, via a
  PKCS12 truststore). A `#temp` pins; a single `prepareStatement` goes via `sp_executesql` → multiplexes;
  `autoCommit(false)` uses `SET IMPLICIT_TRANSACTIONS` (a poolable prelude). The prelude allowlist built
  from go-mssqldb held for it unchanged — no false-pin, no leak.
- **pyodbc / msodbcsql18** (18.6.2): also TLS-only; runs at `Encrypt=yes` (tunneled) and `Encrypt=strict`
  (via the `ServerCertificate` keyword). Two ODBC-specific findings: (1) it issues
  `[sys].sp_datatype_info_100` on **every connect** — a benign read-only metadata RPC that the classifier
  fail-safe-pinned as unrecognized, false-pinning *every* ODBC connection and killing pooling; fixed by
  whitelisting the read-only ODBC catalog procs. (2) a parameterized query is framed as **`sp_prepexec`**
  (a real server-side prepared handle) → **pins**, where JDBC/go-mssqldb's `sp_executesql` multiplexes — a
  legitimate driver-framing difference; the classifier's verdict is correct for each. No leak in any shape.

Build the pyodbc image + run against a TLS-terminating proxy:

```bash
docker build -t tdsgrid-pyodbc harness/pyodbc
# proxy started with -tls-cert/-tls-key; cert mounted for strict
docker run --rm --network host -v /path/proxy.crt:/proxy.crt:ro \
  -e HOST=127.0.0.1 -e PORT=23443 -e USER=sa -e PW='…' -e ENCRYPT=strict -e CERT=/proxy.crt tdsgrid-pyodbc
```
