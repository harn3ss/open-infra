# Design: RDS-Proxy-equivalent for the SQL-Server / TDS (Babelfish) engine

> **Status: pooling built + exposed as a resource** ([`tds-proxy/`](../../tds-proxy)). The TDS framing,
> the pin classifier (the pin-trigger list below), **and the connection pool that acts on the verdict**
> are implemented and unit-tested. The proxy now terminates each client's TDS handshake itself (answering
> PRELOGIN, reading LOGIN7), borrows a backend from a **bounded per-credential pool**, and returns it
> reset-clean for the next client to reuse — replaying the captured LOGIN7 response and issuing the TDS
> RESETCONNECTION bit — while pinning sessions that leave unsharable state and discarding their backend
> on close. Verified live against real **SQL Server 2022** and a **Babelfish** instance (identical
> classify verdicts; grid rows in [`tds-proxy/grid.jsonl`](../../tds-proxy/grid.jsonl)), and the pool
> tested end-to-end against Babelfish: cold-open → warm-reuse (login-replay + reset), clean-return vs
> pinned-discard, and the connection ceiling (6 concurrent clients, cap 3 → only 3 backends opened).
>
> It ships as a **resource** — `kind: DatabaseProxy` (XRD + composition in `platform/abstraction/`, the
> `ghcr.io/harn3ss/open-infra-tds-proxy` image, and `openinfra_database_proxy` in the Terraform provider)
> — the open-infra analog of AWS RDS Proxy's `aws_db_proxy`. Still proposed: **per-transaction**
> multiplexing *within* one session (v1 holds a backend for the session's lifetime, reusing across
> sessions, not per-statement), MARS, mid-response attention/cancel, and TLS termination (see §6).

open-infra's managed SQL-Server engine (`database: { engine: babelfish }`, TDS on 1433) has no
connection multiplexer. AWS RDS Proxy is the reference: it pools a few backend connections and lets
many clients share them — **multiplexing** — dropping to a dedicated 1:1 **pin** whenever a client
leaves session state on the connection that can't be safely shared. This spec defines the pin model,
the v1 pin-trigger list, the compatibility grid it must satisfy, and the capture harness that populates
that grid empirically. The pin model, the classifier, and the connection **pool are now implemented and
verified** (see the status note above and [`tds-proxy/`](../../tds-proxy)); the **compatibility grid**
remains the design's open scaffold — a first slice is captured ([`tds-proxy/grid.jsonl`](../../tds-proxy/grid.jsonl):
go-mssqldb × 5 shapes × SQL Server + Babelfish), and the driver/auth/encryption/fault axes below are
still to be filled by real captures.

## 1. The model — why multiplexing needs pinning

A TDS connection carries **session state**: SET options, the current database, temp tables, prepared-
statement handles, open cursors, transaction context, `CONTEXT_INFO`. A pooled backend connection can
only be handed to the *next* client if it is **clean** — no residual state that would leak between
tenants or change results. So the multiplexer's core invariant:

> Return a backend to the pool only at a transaction boundary **and** only if the session state is
> reset-clean. Otherwise **pin** the backend to the current client for the life of the session.

Pinning is correctness-preserving but throughput-reducing (a pinned backend serves one client). v1
optimizes for **correctness over efficiency**: pin liberally, on any condition we can't prove safe.
This mirrors RDS Proxy's default posture (it emits `DatabaseConnectionsBorrowedPinned` and logs the
reason).

Two ways to end a pin cleanly, in order of preference:
1. **Reset** — issue a reset (SQL Server: `sp_reset_connection`, the TDS `RESETCONNECTION` bit on the
   next batch) and return to the pool. Requires the backend to *support* a faithful reset.
2. **Discard** — close the backend and open a fresh one. Always correct, most expensive.

**Babelfish caveat (load-bearing):** Babelfish is SQL-Server-*wire*-compatible on PostgreSQL, not SQL
Server. `sp_reset_connection`, server-side prepared handles (`sp_prepare`), `#temp` semantics, and
`CONTEXT_INFO` may be **partial or absent**. So the grid must be run against **both** real SQL Server
(reference behavior) **and** Babelfish (the actual backend), and where Babelfish lacks a faithful
reset, the only safe multiplex-return is **discard** — which may make some cells "pins" on Babelfish
that "multiplex" on SQL Server.

## 2. v1 pin-trigger list

Derived from RDS Proxy's documented SQL-Server pinning conditions + TDS/T-SQL session-state semantics.
Each is a hypothesis to confirm empirically (§4). **Fail safe: pin on anything unrecognized.**

| # | Trigger | Why it pins | Detection (in the TDS stream) |
|---|---|---|---|
| 1 | `SET` of a session option (ANSI_NULLS, ARITHABORT, LOCK_TIMEOUT, TEXTSIZE, DATEFORMAT, LANGUAGE, QUOTED_IDENTIFIER, …) | changes result/behavior for the whole session | SQLBatch containing `SET …` (excluding the driver's known login-time prelude — see below) |
| 2 | `SET TRANSACTION ISOLATION LEVEL` | session-scoped isolation | SQLBatch `SET TRANSACTION ISOLATION LEVEL …` |
| 3 | Server-side prepared statement (`sp_prepare` / `sp_prepexec` / `sp_cursorprepare`) | prepared handle is session-scoped | RPC to `sp_prepare`/`sp_prepexec` (ProcID 11/13) |
| 4 | Temp tables (`#t`, `##t`) | session/tempdb-scoped object | SQLBatch `CREATE TABLE #…` |
| 5 | Cursors (`DECLARE … CURSOR`, `sp_cursoropen`) | session-scoped | `DECLARE CURSOR` batch / `sp_cursoropen` (ProcID 1) |
| 6 | Open explicit transaction across the return point | uncommitted work can't be shared | TDS transaction-descriptor stays non-zero at batch end; `BEGIN TRAN` without matching COMMIT/ROLLBACK |
| 7 | `USE <db>` (database context change) | subsequent batches bind to the new DB | SQLBatch `USE …` / envchange token (DB) |
| 8 | `SET CONTEXT_INFO` / session context | per-session blob | SQLBatch `SET CONTEXT_INFO` / `sp_set_session_context` |
| 9 | Large statement text (> ~16 KB) | AWS's heuristic ceiling; also correlates with uncacheable/complex work | batch payload length threshold |
| 10 | `WAITFOR`, `sp_getapplock`, session-scoped locks | holds session resources | RPC/batch match |
| 11 | Bulk load (`INSERT BULK` / TDS Bulk Load token) | streams over the session | TDS Bulk Load (token 0x81) / `INSERT BULK` |
| 12 | **Unrecognized** RPC/batch we can't classify | can't prove clean | default branch |

**Not a pin (must stay multiplexable) — the common path:**
- Simple `SQLBatch` autocommit `SELECT`/`INSERT`/`UPDATE`/`DELETE`.
- Parameterized statements via `sp_executesql` (ProcID 10) — **no** server-side handle, so no pin.
- The driver's **login-time SET prelude** (drivers send a fixed batch of SETs right after login;
  these are re-applied on every fresh backend by the proxy, so they don't pin — this is the single
  most important exception, or every connection pins immediately).

## 3. The compatibility grid (the "manifest")

Verdict per cell ∈ **{ multiplexes | pins | unhandled }**, run twice (SQL Server = reference,
Babelfish = target). Dimensions:

- **Driver + version:** ODBC `msodbcsql18`/`17`; JDBC `mssql-jdbc`; .NET `Microsoft.Data.SqlClient`;
  Go `microsoft/go-mssqldb`; Python `pyodbc`, `pymssql`; Node `tedious`; PHP `sqlsrv`; plus common
  ORMs on top (EF Core, SQLAlchemy, Hibernate, GORM) since ORMs choose the statement shape.
- **Auth:** SQL auth (user/pw); Windows/AD (Kerberos/NTLM) — *Babelfish support is an open question*;
  Azure AD — N/A for Babelfish. (Auth affects whether the proxy can re-auth a pooled backend as the
  client, or must pin per-identity.)
- **Encryption:** `Encrypt=strict` (TDS 8.0 / TLS-first), `Encrypt=mandatory` (TLS after prelogin),
  `Encrypt=optional`, off. **Babelfish gotcha: TDS-no-TLS** — so `strict`/`mandatory` cells may be
  "unhandled" on Babelfish until TLS termination is added to the engine or the proxy.
- **Statement-shape:** simple-autocommit; `sp_executesql`-parameterized; server-prepared; temp-table;
  explicit-txn; SET-heavy session; cursor; bulk/TVP.
- **Fault (resilience axis):** backend restart mid-session; network blip; pool exhaustion; TLS/auth
  token expiry mid-session; failover. (These test whether a *pinned* vs *multiplexed* connection
  survives or surfaces a clean error.)

The grid is stored as one source-of-truth table (`grid.jsonl`, one row per cell) with columns
`{driver, version, auth, encryption, shape, fault, backend, verdict, evidence_ref, notes}`. `verdict`
starts `unknown`; the harness fills it.

## 4. Capture-harness spec (how the grid gets populated — empirical, not guessed)

Goal: for each grid cell, drive a real client and observe the raw TDS to classify multiplex/pin/unhandled.

```
[matrix runner] --(config: driver×auth×enc×shape)--> [TDS tap / proxy] --> [backend: SQL Server | Babelfish]
       |                                                     |
       +-- tags each run by cell                             +-- captures raw TDS both directions
```

Components:
1. **Backends (containers):** `mcr.microsoft.com/mssql/server` (reference) and the open-infra
   `open-infra-babelfish` image (target). Same schema seeded into both.
2. **TDS tap:** a lightweight passthrough proxy on 1433 that mirrors both directions to a capture file
   (or Wireshark with the `tds` dissector + `SSLKEYLOGFILE` for the TLS cells). The tap also runs the
   §2 classifier live so each run is auto-labeled.
3. **Matrix runner:** for each cell, a small program in that driver/language opens a connection with
   the cell's auth+encryption, executes the shape's statement(s), then **returns the connection to its
   own pool and asks for it again** — the moment that reveals whether residual state exists. The
   runner records: did a pin-trigger appear? did the driver send a reset? did the second borrow see
   leaked state?
4. **Fault injection:** for the fault axis, kill/restart the backend or drop the network mid-run and
   record whether the client got a clean, retryable error or a corrupt session.
5. **Classifier → verdict:**
   - `multiplexes` — no pin-trigger observed, backend returns reset-clean (or the shape is provably
     stateless), second borrow sees no leaked state.
   - `pins` — a §2 trigger fired; record which one (the `evidence_ref` points at the capture offset).
   - `unhandled` — the proxy/engine can't process it faithfully (e.g. TDS-strict on no-TLS Babelfish,
     or a reset the backend doesn't honor) → surfaces as a divergence between the SQL-Server and
     Babelfish runs of the same cell.

Output: the populated `grid.jsonl` + the capture bundle, so every verdict is backed by a real TDS
trace, not an assumption — the same honest-by-construction bar as the substrate work.

## 5. v1 scope & non-goals

- **In:** SQL auth + optional/off encryption + the common statement shapes, against both backends;
  the §2 triggers; the harness. A conservative multiplexer that pins on every §2 trigger and on any
  unknown is a correct v1.
- **Out (later):** minimizing pins (transforming `sp_prepare`→`sp_executesql`, temp-table→table-var
  rewriting), Windows/AD auth, TDS-8.0-strict TLS termination in the proxy, cross-backend session
  migration. Each is a grid region that starts `pins`/`unhandled` and graduates as the engine gains
  the capability — measured, not asserted.

## 6. Open questions to resolve first
- Does Babelfish implement `sp_reset_connection` faithfully? If not, v1 multiplex-return = discard-only.
- Babelfish's `sp_prepare`/server-prepared support — present, emulated, or ignored?
- Does the proxy terminate TLS (so it can read the TDS to classify), or pass through (then it can't
  classify encrypted sessions and must pin them)? This single choice reshapes the encryption column.
