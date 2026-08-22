# tds-proxy — a TDS-aware connection pool (RDS-Proxy-equivalent)

The open-infra analog of AWS RDS Proxy for the managed SQL-Server / Babelfish engine (TDS on 1433).
It **terminates each client's TDS handshake**, borrows a backend connection from a **bounded
per-credential pool**, and hands that backend back for the next client to reuse whenever the session
left no unsharable state — **pinning** (temp tables, explicit txns, prepared handles, cursors, …) to a
dedicated backend otherwise. The per-key cap means a client stampede **queues** instead of exhausting
the database's connection slots. Design:
[`docs/design/rds-proxy-tds-multiplexing.md`](../docs/design/rds-proxy-tds-multiplexing.md).

Ships as a resource — `kind: DatabaseProxy` (the analog of `aws_db_proxy`): see
`platform/abstraction/databaseproxy-{xrd,composition}.yaml` and `openinfra_database_proxy` in the
Terraform provider.

## What it does

- **TDS framing + handshake** (`tds/`) — packet/EOM reassembly, SQLBatch (UCS-2) + RPC parsing, LOGIN7
  identity parsing, a synthesized no-encryption PRELOGIN response, and the RESETCONNECTION bit. Stdlib only.
- **The pin classifier** (`classify/`) — SET options, `SET TRANSACTION ISOLATION LEVEL`, temp tables,
  cursors, `USE`, `CONTEXT_INFO`, explicit transactions, applocks, `>16 KB` statements,
  `sp_prepare`/`sp_prepexec`/`sp_cursor*`, bulk load, and a **fail-safe pin on anything unrecognized**;
  plus the driver **login-prelude** exception. Exhaustively unit-tested.
- **The pool** (`pool/`, `main.go`) — a per-credential-key semaphore caps open backends (the connection
  ceiling); the first login is captured cold and **replayed** to warm clients, which get a reset-clean
  backend. Clean sessions **return** their backend for reuse; pinned sessions **discard** theirs on close.
  `/status` reports `pool_cold_opens`, `pool_warm_reuses`, `pool_returns`, `pool_discards`,
  `pool_acquire_timeouts`, `pool_reuse_ratio`, `pool_dead_evicted`, `mars_requested`,
  `integrated_auth_refused`, and the multiplex-opportunity + per-reason pin breakdown.
- **Fault tolerance** — a pooled backend can die or leave residual bytes while idle (backend restart,
  network blip). Before handing a warm backend to a client the pool **probes** it (a short non-blocking
  read: timeout ⇒ clean+alive, EOF/reset or pending bytes ⇒ evict) and opens a fresh one instead, so a
  backend fault is transparent rather than a first-query failure after a "successful" login
  (`pool_dead_evicted`; verified by restarting the backend under a warm pool). A backend that dies
  *mid-session* still surfaces a clean connection error to that one client, which retries; pool exhaustion
  queues up to the acquire timeout.
- **TLS termination** (`-tls-cert`/`-tls-key`, opt-in) — TDS negotiates TLS *inside* the protocol, so the
  proxy terminates it as the TLS peer and relays **plaintext to the backend** (the managed engine is
  TDS-no-TLS): **TDS 8.0 strict** (TLS-first, detected by peeking the ClientHello) and legacy
  **`encrypt=on`/mandatory** (the TLS handshake tunneled inside PRELOGIN packets, then raw). This unblocks
  the JDBC/ODBC/.NET drivers that default to encryption. A client that *requires* encryption when no cert
  is configured is refused, never silently downgraded (`tls_terminated_{strict,on}`,
  `tls_handshake_errors`). Via `kind: DatabaseProxy` the cert is issued by cert-manager (`spec.tls`).
- **MARS visibility** — `mars_requested` counts clients that ask for MARS (Multiple Active Result Sets)
  in PRELOGIN. The pool does **not** grant MARS (the synthesized PRELOGIN response omits the option), so
  those sessions run single-request-per-connection. Counting the *requests* is a measurement no pooler
  (AWS RDS Proxy included) surfaces — a MARS-heavy fleet is one a future per-transaction multiplexer must
  pin or specially handle. Detecting whether a session *actually interleaves* (vs merely negotiates) MARS
  is the next step, deliberately deferred until the per-request SMID header offset is confirmed against a
  real capture.

**Verified live** against real SQL Server 2022 and Babelfish (identical classify verdicts;
[`grid.jsonl`](grid.jsonl)); the pool tested end-to-end against Babelfish — cold→warm reuse, clean-return
vs pinned-discard, and the connection cap (6 concurrent clients, cap 3 → only 3 backends opened).

TLS termination (`encrypt=on`/`strict`) is verified live via go-mssqldb against SQL Server 2022 (all three
of disable/on/strict connect through the proxy; the backend stays plaintext).

**Not yet built:** **per-transaction** multiplexing *within* a session (a session holds its backend for
its lifetime; reuse is across sessions, not per-statement), and granting MARS (it is counted, not granted).
Client attention/cancel **is** forwarded promptly (a slow query cancels immediately, not after it finishes).

## Run

```bash
go build -o tds-proxy .
./tds-proxy -listen :1433 -backend <babelfish-host>:1433 -metrics :9114 -pool-max 20
curl localhost:9114/status
```

Clients connect with `encrypt=disable` (Babelfish is TDS-no-TLS). The proxy answers PRELOGIN with
no-encryption and pools per `(backend, user, database, password)` — **SQL auth only**. Integrated/Windows
(SSPI) logins carry no credential to key on (the identity is a per-connection SSPI blob), so the pool
**refuses** them cleanly (`integrated_auth_refused`) rather than risk collapsing distinct Windows
identities onto one backend; a transparent pass-through mode for them is a follow-up.
