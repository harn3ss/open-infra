package main

// Per-transaction multiplexing within a session (issue #7), opt-in via -tx-multiplex. v1/default holds one
// backend for the whole client session; here a session RETURNS its backend to the pool at each safe boundary
// while it has left no state that outlives a transaction, so one backend serves many mostly-idle clients
// (RDS Proxy's headline throughput). Two things gate a release:
//
//   - STICKY (session-surviving state): the moment the session leaves state that outlives a transaction —
//     temp table, prepared handle, cursor, CONTEXT_INFO, applock, USE, a mid-session SET — it holds the one
//     backend for the rest of the session and discards it on close, exactly like v1. The sticky trigger is
//     the v1 pin verdict MINUS the transaction reasons, so this can only ever be more conservative than v1.
//   - OPEN TRANSACTION (v2.1): an explicit transaction opened via the TDS transaction manager (what drivers
//     send for BeginTx/Commit) does NOT make the session sticky. Its begin/commit/rollback are tracked from
//     the TM request subtype (tds.TxMgrRequestType), so the backend is held for the transaction's lifetime
//     and released exactly at COMMIT/ROLLBACK — a transaction runs entirely on ONE backend, never spanning
//     them, because release only happens at txn depth 0. (SQL Server does not set DONE_INXACT on the begin-ack
//     DONE, so the request side is the reliable signal.) A raw "BEGIN TRAN" batch or SET IMPLICIT_TRANSACTIONS
//     ON — whose commit we can't reliably pair — falls back to sticky instead.
//
// The client logs in once; a re-borrowed backend is RESETCONNECTION-wiped and the client's captured
// login-prelude SET batch is replayed before its request, so session options survive the backend swap.
// See docs/design §7.
//
// It relays each response synchronously (it does not read the client mid-response), so a client ATTENTION
// cancel is not forwarded until the response completes — a deliberate trade to keep borrow/return race-free;
// the default session-level relay keeps prompt attention forwarding.

import (
	"log"
	"net"

	"openinfra-tds-proxy/classify"
	"openinfra-tds-proxy/pool"
	"openinfra-tds-proxy/tds"
)

// txMultiplexRelay runs the per-transaction multiplexing loop for one client session. `first` is the
// backend already acquired + logged-in by handle(); firstNeedReset is whether it is a warm reuse (its first
// client message must carry RESETCONNECTION). It returns/discards whatever backend it still holds on exit.
func txMultiplexRelay(client net.Conn, first *pool.Backend, firstNeedReset bool, key, backendAddr string, backendPre, lRaw []byte, id int64) {
	held := first
	needReset := firstNeedReset
	sticky := false
	sawReal := false
	txnDepth := 0        // open explicit-transaction nesting (from TM begin/commit/rollback); >0 = hold
	var prelude [][]byte // client login-prelude SET messages (raw), replayed onto each re-borrowed backend

	defer func() {
		if held == nil {
			return
		}
		if sticky {
			discards.Add(1)
			backendPool.Discard(key, held)
		} else {
			returns.Add(1)
			backendPool.Return(key, held)
		}
	}()

	for {
		mType, body, raw, err := tds.ReadMessage(client) // client is idle here; blocks for the next request
		if err != nil {
			if sticky {
				pinnedSessions.Add(1)
			} else {
				cleanSessions.Add(1)
			}
			return // client closed — defer returns/discards the held backend
		}

		// Borrow a backend if the previous request released one.
		if held == nil {
			be, reset, ok := reacquireBackend(key, backendAddr, backendPre, lRaw)
			if !ok {
				acquireTimeouts.Add(1)
				log.Printf("tds-proxy: session %d: pool at cap on re-borrow — timed out", id)
				return
			}
			held = be
			needReset = reset
			if err := applyPrelude(held.Conn, prelude, &needReset); err != nil {
				discards.Add(1)
				backendPool.Discard(key, held)
				held = nil
				return
			}
		}

		// Forward the request (RESETCONNECTION on the first message to a reused backend), relay the response.
		out := raw
		if needReset {
			out = tds.WithResetConnection(raw)
			needReset = false
		}
		if _, err := held.Conn.Write(out); err != nil {
			discards.Add(1)
			backendPool.Discard(key, held)
			held = nil
			return
		}
		if !relayResponseSync(client, held.Conn) {
			discards.Add(1) // client dropped mid-response or backend died
			backendPool.Discard(key, held)
			held = nil
			return
		}

		// Classify and update session state.
		if isClientWork(mType) {
			v := classify.Classify(mType, body)
			preludeExempt := v.Prelude && !sawReal
			switch {
			case v.ImplicitTxn:
				// SET IMPLICIT_TRANSACTIONS ON (e.g. JDBC autoCommit(false)): statements auto-open txns with
				// no explicit begin/commit pair we can track, so per-transaction release isn't safe — hold
				// the one backend for the session (v1). Checked first, before the prelude-capture case.
				if !sticky {
					recordReasons([]string{"implicit transactions"})
				}
				sticky = true
			case v.Pin && v.Txn && mType == tds.TypeTxMgr:
				// Explicit transaction via the TDS transaction manager (what drivers send for BeginTx/Commit).
				// Track its begin/commit/rollback so the backend is held for the transaction's lifetime and
				// released exactly at COMMIT/ROLLBACK (#7 v2.1) — never mid-transaction, so a txn can't span
				// backends. Unparseable TM request → assume it opens a txn (hold), the safe direction.
				sawReal = true
				if rt, ok := tds.TxMgrRequestType(body); ok {
					switch rt {
					case tds.TMBeginXact:
						txnDepth++
					case tds.TMCommitXact:
						if txnDepth > 0 {
							txnDepth--
						}
					case tds.TMRollbackXact:
						txnDepth = 0
					}
				} else {
					txnDepth++
				}
			case v.Pin && v.Txn:
				// A text "BEGIN TRAN" batch (raw SQL, not the TM path). We can't reliably pair it with its
				// COMMIT/ROLLBACK on the wire, so be conservative: hold the one backend for the session.
				if !sticky {
					recordReasons([]string{v.Reason})
				}
				sticky = true
			case v.Pin && !preludeExempt:
				// Session-surviving state (temp table, prepared handle, cursor, CONTEXT_INFO, …) — hold the
				// one backend for the rest of the session and discard it on close, exactly like v1.
				if !sticky {
					recordReasons([]string{v.Reason})
				}
				sticky = true
			case v.Pin && preludeExempt:
				prelude = append(prelude, append([]byte(nil), raw...)) // capture login prelude for replay
			default: // multiplexable real work
				sawReal = true
			}
		}

		// Release the backend at a safe boundary: past the connect prelude (sawReal), no session-surviving
		// state (sticky), and NO OPEN TRANSACTION (txnDepth==0). Because release only happens at txnDepth 0,
		// an explicit BEGIN…COMMIT holds ONE backend for its whole lifetime and frees it at COMMIT/ROLLBACK
		// — a transaction can never span backends.
		if sawReal && !sticky && txnDepth == 0 {
			txReturns.Add(1)
			backendPool.Return(key, held)
			held = nil
			needReset = false
		}
	}
}

// relayResponseSync streams one backend response to the client until its EOM, synchronously (no concurrent
// client read — see the file header on the attention trade-off). Returns false if the backend died or the
// client went away.
func relayResponseSync(client, backend net.Conn) bool {
	for {
		p, err := tds.ReadPacket(backend)
		if err != nil {
			return false
		}
		if _, err := client.Write(p.Raw); err != nil {
			return false
		}
		if p.EOM() && p.Type == tds.TypeTabular {
			return true
		}
	}
}

// reacquireBackend borrows a backend for the NEXT transaction of an ongoing session: a warm idle one
// (needReset=true so the caller wipes it), or a freshly dialed + logged-in cold one (needReset=false). The
// client is already logged in, so a cold backend's login response is consumed here, never sent to the client.
func reacquireBackend(key, backendAddr string, backendPre, lRaw []byte) (be *pool.Backend, needReset, ok bool) {
	be, warm, ok := acquireUsable(key, acquireTimeout)
	if !ok {
		return nil, false, false
	}
	if warm {
		warmReuses.Add(1)
		return be, true, true
	}
	bc, ok2 := coldLogin(backendAddr, backendPre, lRaw, key)
	if !ok2 {
		backendPool.Discard(key, nil) // release the reserved slot the cold acquire took
		return nil, false, false
	}
	coldOpens.Add(1)
	return bc, false, true
}

// coldLogin dials a fresh backend and performs the login by replaying the client's PRELOGIN + LOGIN7,
// consuming (and capturing) the login response. It does NOT write to the client — used for a mid-session
// cold re-borrow where the client is already logged in.
func coldLogin(backendAddr string, backendPre, lRaw []byte, key string) (*pool.Backend, bool) {
	bc, err := net.Dial("tcp", backendAddr)
	if err != nil {
		return nil, false
	}
	if _, err := bc.Write(backendPre); err != nil {
		bc.Close()
		return nil, false
	}
	if _, _, _, err := tds.ReadMessage(bc); err != nil { // backend PRELOGIN response (discarded)
		bc.Close()
		return nil, false
	}
	if _, err := bc.Write(lRaw); err != nil { // client LOGIN7 → backend
		bc.Close()
		return nil, false
	}
	_, _, loginRaw, err := tds.ReadMessage(bc) // backend LOGIN7 response (consumed, not sent to client)
	if err != nil {
		bc.Close()
		return nil, false
	}
	backendPool.CaptureLogin(key, loginRaw)
	return &pool.Backend{Conn: bc, Fresh: true}, true
}

// applyPrelude replays the captured login-prelude SET messages onto a freshly borrowed backend before the
// client's request, so session options survive the backend swap. The first message carries RESETCONNECTION
// when *needReset (a warm backend), which is then cleared. Each replayed message's response is drained.
func applyPrelude(backend net.Conn, prelude [][]byte, needReset *bool) error {
	for _, msg := range prelude {
		out := msg
		if *needReset {
			out = tds.WithResetConnection(msg)
			*needReset = false
		}
		if _, err := backend.Write(out); err != nil {
			return err
		}
		if err := drainOneResponse(backend); err != nil {
			return err
		}
	}
	return nil
}

// drainOneResponse reads and discards one full backend response (until its EOM), used for the responses to
// replayed prelude messages, which the client never sent and must not see.
func drainOneResponse(backend net.Conn) error {
	for {
		p, err := tds.ReadPacket(backend)
		if err != nil {
			return err
		}
		if p.EOM() && p.Type == tds.TypeTabular {
			return nil
		}
	}
}
