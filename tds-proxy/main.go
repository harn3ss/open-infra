// openinfra-tds-proxy — a TDS-aware connection pool for the managed SQL-Server / Babelfish engine, the
// open-infra analog of AWS RDS Proxy. It terminates each client's TDS handshake itself (answering
// PRELOGIN, reading LOGIN7), then borrows a backend connection from a bounded per-credential pool for the
// life of the session. A session that never leaves unsharable state (see package classify) returns its
// backend to the pool reset-clean for the next client to reuse — skipping a fresh TCP connect + login —
// while a session that pins (temp tables, explicit txn, prepared handles, cursors, …) keeps its backend
// 1:1 and discards it on close. The per-key semaphore caps how many backend connections can ever open,
// so a client stampede queues instead of exhausting the database's connection slots.
//
// Reuse across clients is what makes it a pool: the backend's LOGIN7 response is captured on the first
// (cold) login and replayed to later (warm) clients, and the borrowed backend is wiped with the TDS
// RESETCONNECTION bit on the new client's first batch. v1's classifier and multiplex-opportunity metric
// are retained; this adds the pooling that acts on the verdict.
//
// Not yet handled (pinned/passthrough, honestly scoped): per-transaction multiplexing within one session
// (a session holds its backend for its lifetime, not per-statement), MARS, and attention/cancel that
// arrives mid-response. TLS-terminated (encrypt=strict) sessions are out — the engine is TDS-no-TLS.
package main

import (
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"openinfra-tds-proxy/classify"
	"openinfra-tds-proxy/pool"
	"openinfra-tds-proxy/tds"
)

var (
	sessionsTotal   atomic.Int64
	sessionsActive  atomic.Int64
	pinnedSessions  atomic.Int64
	cleanSessions   atomic.Int64
	coldOpens       atomic.Int64
	warmReuses      atomic.Int64
	returns         atomic.Int64
	discards        atomic.Int64
	acquireTimeouts atomic.Int64
	pinReasonsMu    sync.Mutex
	pinReasonCounts = map[string]int64{}

	backendPool  *pool.Pool
	preloginResp = tds.BuildPreloginResponse()
)

func main() {
	listen := flag.String("listen", ":1433", "listen address for TDS clients")
	backend := flag.String("backend", "", "backend TDS address host:port (the SQL Server / Babelfish)")
	metrics := flag.String("metrics", ":9114", "address for the /metrics + /status endpoints")
	poolMax := flag.Int("pool-max", 20, "max backend connections per credential key (the connection ceiling)")
	acquireMs := flag.Int("acquire-timeout-ms", 10000, "how long a client waits for a backend when the pool is at its cap")
	flag.Parse()
	if *backend == "" {
		log.Fatal("tds-proxy: -backend host:port is required")
	}
	backendPool = pool.New(*poolMax)
	acquireTimeout := time.Duration(*acquireMs) * time.Millisecond

	go serveMetrics(*metrics)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("tds-proxy: listen %s: %v", *listen, err)
	}
	log.Printf("tds-proxy: pooling on %s → backend %s (pool-max %d/key, metrics %s)", *listen, *backend, *poolMax, *metrics)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("tds-proxy: accept: %v", err)
			continue
		}
		go handle(c, *backend, acquireTimeout)
	}
}

// handle terminates one client's handshake, borrows a backend, relays the session, and returns or
// discards the backend based on the classifier verdict.
func handle(client net.Conn, backendAddr string, acquireTimeout time.Duration) {
	id := sessionsTotal.Add(1)
	sessionsActive.Add(1)
	defer sessionsActive.Add(-1)
	defer client.Close()

	// 1. Terminate the client PRELOGIN ourselves (no encryption), so we can pick a backend by the
	//    identity in the LOGIN7 that follows.
	pType, _, preRaw, err := tds.ReadMessage(client)
	if err != nil || pType != tds.TypePreLogin {
		return
	}
	if _, err := client.Write(preloginResp); err != nil {
		return
	}

	// 2. Read the client LOGIN7 and key the pool on (backend, user, db, password).
	lType, lBody, lRaw, err := tds.ReadMessage(client)
	if err != nil || lType != tds.TypeLogin7 {
		return
	}
	info, ok := tds.ParseLogin7(lBody)
	if !ok {
		return
	}
	key := poolKey(backendAddr, info)

	// 3. Acquire a backend: a warm idle one to reuse, or a reserved slot to open a cold one.
	be, warm, ok := backendPool.Acquire(key, acquireTimeout)
	if !ok {
		acquireTimeouts.Add(1)
		log.Printf("tds-proxy: session %d: pool at cap for %s@%s — timed out", id, info.User, info.Database)
		return
	}

	needReset := false
	if warm {
		// Reuse: replay the captured LOGIN7 response to the client; wipe the backend on its first batch.
		loginResp := backendPool.LoginResp(key)
		if loginResp == nil {
			backendPool.Discard(key, be)
			return
		}
		if _, err := client.Write(loginResp); err != nil {
			backendPool.Discard(key, be) // backend is fine, but client is gone — reclaim the slot
			return
		}
		needReset = true
		warmReuses.Add(1)
	} else {
		// Cold: open a backend and do the real login, forwarding the client's PRELOGIN + LOGIN7 verbatim.
		bc, err := net.Dial("tcp", backendAddr)
		if err != nil {
			backendPool.Discard(key, nil) // release the reserved slot
			log.Printf("tds-proxy: session %d: dial backend: %v", id, err)
			return
		}
		if _, err := bc.Write(preRaw); err != nil { // client PRELOGIN → backend
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		if _, _, _, err := tds.ReadMessage(bc); err != nil { // backend PRELOGIN response (discarded)
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		if _, err := bc.Write(lRaw); err != nil { // client LOGIN7 → backend
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		_, _, loginRaw, err := tds.ReadMessage(bc) // backend LOGIN7 response
		if err != nil {
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		if _, err := client.Write(loginRaw); err != nil {
			bc.Close()
			backendPool.Discard(key, nil)
			return
		}
		backendPool.CaptureLogin(key, loginRaw)
		be = &pool.Backend{Conn: bc, Fresh: true}
		coldOpens.Add(1)
	}

	// 4. Relay the session synchronously (TDS is request/response), classifying each client message.
	pinned, reasons, returnable := relaySession(client, be.Conn, needReset)

	// 5. Return the backend for reuse only if the session stayed clean AND the backend is quiescent.
	if pinned {
		pinnedSessions.Add(1)
		recordReasons(reasons)
		log.Printf("tds-proxy: session %d PINNED (%s@%s): %v — backend discarded", id, info.User, info.Database, reasons)
	} else {
		cleanSessions.Add(1)
	}
	if returnable {
		returns.Add(1)
		backendPool.Return(key, be)
	} else {
		discards.Add(1)
		backendPool.Discard(key, be)
	}
}

// relaySession runs the synchronous request/response loop: each client message is forwarded to the
// backend (with RESETCONNECTION set on the first message when reusing a pooled backend) and classified,
// then the backend's full response is streamed back. It returns whether the session pinned, the distinct
// pin reasons, and whether the backend is returnable (clean session AND quiescent at loop exit).
func relaySession(client net.Conn, backend net.Conn, needReset bool) (pinned bool, reasons []string, returnable bool) {
	seen := map[string]bool{}
	sawRealBatch := false
	quiescent := true // no outstanding backend response between requests
	first := true

	for {
		mType, body, mRaw, err := tds.ReadMessage(client)
		if err != nil {
			break // client closed — if between requests, quiescent stays true
		}
		if first {
			if needReset {
				mRaw = tds.WithResetConnection(mRaw)
			}
			first = false
		}
		quiescent = false
		if _, err := backend.Write(mRaw); err != nil {
			break
		}

		// Classify client work; apply the login-prelude exception (a SET-only first batch is the driver
		// prelude, re-applied by the client on every backend, so it does not pin).
		if isClientWork(mType) {
			v := classify.Classify(mType, body)
			if v.Pin {
				if v.Prelude && !sawRealBatch {
					// driver prelude — not a pin
				} else if !seen[v.Reason] {
					pinned = true
					seen[v.Reason] = true
					reasons = append(reasons, v.Reason)
				} else {
					pinned = true
				}
			}
			if mType == tds.TypeSQLBatch && !v.Pin {
				sawRealBatch = true
			}
		}

		// Stream the full backend response back to the client.
		_, _, rRaw, err := tds.ReadMessage(backend)
		if err != nil {
			break // backend closed mid-session — not returnable
		}
		if _, err := client.Write(rRaw); err != nil {
			break
		}
		quiescent = true // response complete; backend idle again
	}
	returnable = quiescent && !pinned
	return pinned, reasons, returnable
}

func isClientWork(t byte) bool {
	return t == tds.TypeSQLBatch || t == tds.TypeRPC || t == tds.TypeBulkLoad || t == tds.TypeTxMgr
}

func poolKey(backendAddr string, info tds.Login7Info) string {
	h := fnv.New64a()
	h.Write(info.PassField)
	return fmt.Sprintf("%s|%s|%s|%x", backendAddr, info.User, info.Database, h.Sum64())
}

func recordReasons(reasons []string) {
	pinReasonsMu.Lock()
	for _, r := range reasons {
		pinReasonCounts[r]++
	}
	pinReasonsMu.Unlock()
}

func serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		clean := cleanSessions.Load()
		done := clean + pinnedSessions.Load()
		ratio := 0.0
		if done > 0 {
			ratio = float64(clean) / float64(done)
		}
		reuse := 0.0
		if tot := coldOpens.Load() + warmReuses.Load(); tot > 0 {
			reuse = float64(warmReuses.Load()) / float64(tot)
		}
		fmt.Fprintf(w, "sessions_total %d\nsessions_active %d\nsessions_clean %d\nsessions_pinned %d\n",
			sessionsTotal.Load(), sessionsActive.Load(), clean, pinnedSessions.Load())
		fmt.Fprintf(w, "multiplex_opportunity %.3f\n", ratio)
		fmt.Fprintf(w, "pool_cold_opens %d\npool_warm_reuses %d\npool_returns %d\npool_discards %d\npool_acquire_timeouts %d\n",
			coldOpens.Load(), warmReuses.Load(), returns.Load(), discards.Load(), acquireTimeouts.Load())
		fmt.Fprintf(w, "pool_reuse_ratio %.3f\n", reuse)
		pinReasonsMu.Lock()
		for reason, n := range pinReasonCounts {
			fmt.Fprintf(w, "pin_reason{reason=%q} %d\n", reason, n)
		}
		pinReasonsMu.Unlock()
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("tds-proxy: metrics server: %v", err)
	}
}
