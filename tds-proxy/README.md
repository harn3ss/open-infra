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
  `pool_acquire_timeouts`, `pool_reuse_ratio`, `mars_requested`, and the multiplex-opportunity +
  per-reason pin breakdown.
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

**Not yet built:** **per-transaction** multiplexing *within* a session (a session holds its backend for
its lifetime; reuse is across sessions, not per-statement), MARS, mid-response attention/cancel, and TLS
termination (`Encrypt=mandatory`/`strict` — the engine is TDS-no-TLS, so those are out of scope for now).

## Run

```bash
go build -o tds-proxy .
./tds-proxy -listen :1433 -backend <babelfish-host>:1433 -metrics :9114 -pool-max 20
curl localhost:9114/status
```

Clients connect with `encrypt=disable` (Babelfish is TDS-no-TLS). The proxy answers PRELOGIN with
no-encryption and pools per `(backend, user, database, password)`.
